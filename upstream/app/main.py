"""
本地日志接收端（模拟真实后台，TLS 版）。

进程内三个监听：
  * uvicorn(FastAPI) 0.0.0.0:8000 明文：/docs 演示控制面、/events 查询、/admin/tls
    证书与握手延迟管理 —— 仅用于本地演示与取证；
  * TLS 终结器 127.0.0.1:8444：共享 SSLContext（运行时可换证书），终结后把
    明文转发给 uvicorn；
  * 延迟前门 0.0.0.0:8443：代理的唯一业务上游。按 /admin/tls/delay 配置的
    秒数延迟后再接通 TLS 终结器，从而制造“可控握手延迟”；首包不是 TLS
    记录（明文 HTTP）直接关闭并计数 —— 明文回退在这里无处遁形。

两套 CA 签发的同名接收端证书（logs-receiver.local）放在 CERTS_DIR 下：
  server-ca1/server.crt|key   由 ca1 签发
  server-ca2/server.crt|key   由 ca2 签发
POST /admin/tls/cert/{ca1|ca2} 运行时切换，并默认关闭现存 TLS 会话
（模拟 CA 更替后旧信任会话失效）。
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import ssl
import time
from collections import deque
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field

MAX_STORED = int(os.environ.get("UPSTREAM_MAX_STORED", "200"))
CERTS_DIR = os.environ.get("CERTS_DIR", "/certs")
TLS_ACTIVE_DEFAULT = os.environ.get("TLS_ACTIVE_DEFAULT", "ca1")
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8000"))
TLS_TERMINATOR_PORT = int(os.environ.get("TLS_TERMINATOR_PORT", "8444"))
FRONT_PORT = int(os.environ.get("FRONT_PORT", "8443"))

log = logging.getLogger("log-receiver")

app = FastAPI(
    title="日志接收端（上游，TLS）",
    description=(
        "探针事件上报的模拟后台。业务上报只走 TLS 端口 8443；"
        "本控制面（8000 端口 /docs）用于演示换 CA、错误证书拒绝与握手交错。"
    ),
    version="2.0.0",
)


# --------------------------------------------------------------------------- #
# TLS 状态：共享 SSLContext，运行时整换证书链
# --------------------------------------------------------------------------- #


class TLSState:
    def __init__(self, certs_dir: str):
        self.certs_dir = certs_dir
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self.active: Optional[str] = None
        self.handshake_delay = 0.0
        self.tls_connections = 0       # 成功建立的 TLS 连接数（终结器口径）
        self.plaintext_probes = 0      # TLS 端口收到明文首包的次数
        self.lock = asyncio.Lock()

    def cert_dir(self, name: str) -> str:
        return os.path.join(self.certs_dir, f"server-{name}")

    def available(self) -> list[str]:
        try:
            names = sorted(
                d.removeprefix("server-") for d in os.listdir(self.certs_dir)
                if d.startswith("server-")
                and os.path.isdir(os.path.join(self.certs_dir, d)))
        except OSError:
            names = []
        return [n for n in names
                if os.path.exists(os.path.join(self.cert_dir(n), "server.crt"))
                and os.path.exists(os.path.join(self.cert_dir(n), "server.key"))]

    def load(self, name: str) -> None:
        cert = os.path.join(self.cert_dir(name), "server.crt")
        key = os.path.join(self.cert_dir(name), "server.key")
        if not (os.path.exists(cert) and os.path.exists(key)):
            raise FileNotFoundError(f"cert set {name!r} not found under {self.certs_dir}")
        # 共享 SSLContext 整换证书链：其后的新握手使用新证书，
        # 已建立的 TLS 会话不受影响（由调用方决定是否关闭）。
        self.ctx.load_cert_chain(cert, key)
        self.active = name
        log.info("serving certificate switched to set %r (%s)", name, cert)

    def active_cert_info(self) -> dict:
        if not self.active:
            return {}
        cert_path = os.path.join(self.cert_dir(self.active), "server.crt")
        info: dict = {"set": self.active, "cert_file": cert_path}
        try:
            with open(cert_path, "r", encoding="utf-8") as fh:
                pem = fh.read()
            der = ssl.PEM_cert_to_DER_cert(pem)
            info["sha256_fingerprint"] = hashlib.sha256(der).hexdigest()
        except (OSError, ValueError) as exc:
            info["fingerprint_error"] = str(exc)
        try:
            decoded = ssl._ssl._test_decode_cert(cert_path)  # noqa: SLF001
            info["subject"] = decoded.get("subject")
            info["issuer"] = decoded.get("issuer")
            info["not_before"] = decoded.get("notBefore")
            info["not_after"] = decoded.get("notAfter")
            info["subject_alt_names"] = decoded.get("subjectAltName")
        except Exception as exc:  # noqa: BLE001 - 展示信息，尽力而为
            info["decode_error"] = str(exc)
        return info


TLS_STATE = TLSState(CERTS_DIR)
ACTIVE_TLS_CLIENTS: set[asyncio.StreamWriter] = set()


# --------------------------------------------------------------------------- #
# TCP 管道：延迟前门 → TLS 终结器 → uvicorn
# --------------------------------------------------------------------------- #


async def _relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError, asyncio.IncompleteReadError):
        pass
    finally:
        try:
            if writer.can_write_eof():
                writer.write_eof()
            else:
                writer.close()
        except OSError:
            pass


async def _pipe_pair(a_reader: asyncio.StreamReader, a_writer: asyncio.StreamWriter,
                     b_reader: asyncio.StreamReader, b_writer: asyncio.StreamWriter,
                     ) -> None:
    await asyncio.gather(_relay(a_reader, b_writer), _relay(b_reader, a_writer))
    for writer in (a_writer, b_writer):
        try:
            writer.close()
        except OSError:
            pass


async def handle_tls_client(reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter) -> None:
    """TLS 终结器：握手已由 asyncio 用共享 SSLContext 完成，转发明文到 uvicorn。"""
    TLS_STATE.tls_connections += 1
    ACTIVE_TLS_CLIENTS.add(writer)
    peer = writer.get_extra_info("peername")
    log.info("TLS session established from %s (cert set=%s)", peer, TLS_STATE.active)
    try:
        try:
            app_reader, app_writer = await asyncio.open_connection(
                "127.0.0.1", HTTP_PORT)
        except OSError:
            writer.close()
            return
        await _pipe_pair(reader, writer, app_reader, app_writer)
    finally:
        ACTIVE_TLS_CLIENTS.discard(writer)


async def handle_front_client(reader: asyncio.StreamReader,
                              writer: asyncio.StreamWriter) -> None:
    """延迟前门：先按配置延迟（握手延迟），再接通 TLS 终结器。

    客户端的 ClientHello 在延迟期间滞留在内核缓冲区，对端看到的就是
    “ServerHello 迟迟不来”的真实握手延迟。
    """
    delay = TLS_STATE.handshake_delay
    if delay > 0:
        await asyncio.sleep(delay)
    try:
        first = await asyncio.wait_for(reader.read(4096), timeout=10)
    except (asyncio.TimeoutError, ConnectionError, OSError):
        writer.close()
        return
    if not first:
        writer.close()
        return
    if first[0] != 0x16:  # TLS 握手记录首字节必为 0x16（handshake）
        TLS_STATE.plaintext_probes += 1
        log.warning("plaintext bytes on TLS port: %r... —— 关闭，不回退明文",
                    first[:24])
        writer.close()
        return
    try:
        tls_reader, tls_writer = await asyncio.open_connection(
            "127.0.0.1", TLS_TERMINATOR_PORT)
    except OSError:
        writer.close()
        return
    tls_writer.write(first)
    await tls_writer.drain()
    await _pipe_pair(reader, writer, tls_reader, tls_writer)


# --------------------------------------------------------------------------- #
# 证据存储：记录“实际收到的请求”
# --------------------------------------------------------------------------- #


class Store:
    def __init__(self) -> None:
        self.records: deque[dict] = deque(maxlen=MAX_STORED)
        self.lock = asyncio.Lock()
        self.counter = 0

    async def add(self, record: dict) -> int:
        async with self.lock:
            self.counter += 1
            record["seq"] = self.counter
            self.records.append(record)
            return self.counter

    async def snapshot(self) -> list[dict]:
        async with self.lock:
            return list(self.records)

    async def clear(self) -> int:
        async with self.lock:
            n = len(self.records)
            self.records.clear()
            return n


STORE = Store()

# 控制面路径不记入证据（证据只反映代理转发上来的业务流量）。
CONTROL_PREFIXES = ("/admin", "/docs", "/openapi.json", "/health", "/favicon")


class EventIn(BaseModel):
    # 演示用：结构故意宽松，重点是代理层的 HTTP 分帧安全而非业务校验。
    event: Optional[str] = Field(default=None, description="事件名")
    payload: Optional[dict | list | str | int | float | bool] = Field(
        default=None, description="任意事件负载")


@app.middleware("http")
async def record_request(request: Request, call_next):
    # 演示延迟头：让上游慢一点，触发代理 2 秒总限时 / 观察连接池排队。
    delay = 0.0
    raw_delay = request.headers.get("x-demo-delay")
    if raw_delay:
        try:
            delay = max(0.0, min(10.0, float(raw_delay)))
        except ValueError:
            delay = 0.0

    body = await request.body()
    received_at = time.time()
    if delay:
        await asyncio.sleep(delay)

    path = request.url.path
    is_control = path.startswith(CONTROL_PREFIXES)
    peername = request.scope.get("client") or ("?", 0)
    conn_key = f"{peername[0]}:{peername[1]}"

    seq: Optional[int] = None
    if not is_control:
        record = {
            "received_at": received_at,
            "method": request.method,
            "path": path,
            "http_version": request.scope.get("http_version"),
            # 注意：业务流量经 TLS 终结器转发，这里看到的是终结器的地址。
            "client_tcp": conn_key,
            # 关键证据：上游逐字看到的头与正文。代理重建后这里应只有一个 Content-Length。
            "headers": {k.decode("latin1"): v.decode("latin1")
                        for k, v in request.headers.raw},
            "body_bytes": len(body),
            "body_text": body.decode("utf-8", "replace"),
            "delay_seconds": delay,
        }
        seq = await STORE.add(record)
        request.state.record_seq = seq

    response: Response = await call_next(request)
    response.headers["X-Upstream-Conn"] = conn_key
    if seq is not None:
        response.headers["X-Upstream-Seq"] = str(seq)
    return response


# --------------------------------------------------------------------------- #
# 业务与控制面 API
# --------------------------------------------------------------------------- #


@app.post("/events", status_code=202)
async def ingest_events(request: Request, event: EventIn | None = None) -> dict:
    """接收探针事件。代理只允许把 POST /events 转发到这里（经 TLS 8443）。

    `event` 仅用于在 /docs 中展示请求体 schema；实际落库以中间件读到的
    原始字节为准（证据需要逐字还原代理重建后的 Content-Length 正文）。
    """
    seq = getattr(request.state, "record_seq", None)
    return {"accepted": True, "seq": seq, "stored_total": STORE.counter}


@app.get("/events", summary="查看上游实际收到的请求")
async def list_events(limit: int = 50) -> dict:
    items = await STORE.snapshot()
    return {"count": len(items), "items": items[-limit:]}


@app.delete("/events", summary="清空已记录请求（演示前重置证据）")
async def clear_events() -> dict:
    removed = await STORE.clear()
    return {"cleared": removed}


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.get("/admin/tls", summary="查看 TLS 状态（当前证书集、握手延迟、计数器）")
async def tls_status() -> dict:
    return {
        "active_cert": TLS_STATE.active_cert_info(),
        "available_cert_sets": TLS_STATE.available(),
        "handshake_delay_seconds": TLS_STATE.handshake_delay,
        "tls_connections_total": TLS_STATE.tls_connections,
        "tls_sessions_open": len(ACTIVE_TLS_CLIENTS),
        "plaintext_probes_total": TLS_STATE.plaintext_probes,
        "front_port": FRONT_PORT,
    }


@app.post("/admin/tls/cert/{name}",
          summary="切换接收端证书（同名 logs-receiver.local，另一 CA 签发）")
async def switch_cert(name: str, close_existing: bool = True) -> dict:
    """把 8443 端口呈现的证书换成 `server-{name}` 一套。

    `close_existing=true`（默认）立即关闭现存 TLS 会话，模拟 CA 更替后
    旧信任下的会话全部失效；代理侧必须重新握手才能继续上报。
    """
    async with TLS_STATE.lock:
        try:
            TLS_STATE.load(name)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        closed = 0
        if close_existing:
            for writer in list(ACTIVE_TLS_CLIENTS):
                writer.close()
                closed += 1
    return {
        "active_cert": name,
        "closed_tls_sessions": closed,
        "fingerprint": TLS_STATE.active_cert_info().get("sha256_fingerprint"),
    }


class DelayIn(BaseModel):
    seconds: float = Field(ge=0.0, le=10.0,
                           description="握手延迟秒数（0-10），用于演示握手交错")


@app.post("/admin/tls/delay", summary="设置 TLS 握手延迟秒数")
async def set_handshake_delay(cfg: DelayIn) -> dict:
    TLS_STATE.handshake_delay = cfg.seconds
    log.info("handshake delay set to %.2fs", cfg.seconds)
    return {"handshake_delay_seconds": TLS_STATE.handshake_delay}


# --------------------------------------------------------------------------- #
# 入口：同一事件循环跑 uvicorn + TLS 终结器 + 延迟前门
# --------------------------------------------------------------------------- #


async def _serve_all() -> None:
    TLS_STATE.load(TLS_ACTIVE_DEFAULT)
    log.info("loaded default certificate set %r; available=%s",
             TLS_STATE.active, TLS_STATE.available())

    tls_server = await asyncio.start_server(
        handle_tls_client, "127.0.0.1", TLS_TERMINATOR_PORT, ssl=TLS_STATE.ctx)
    front_server = await asyncio.start_server(
        handle_front_client, "0.0.0.0", FRONT_PORT)
    for sock in front_server.sockets:
        log.info("TLS ingest front listening on %s", sock.getsockname())

    config = uvicorn.Config(
        app, host="0.0.0.0", port=HTTP_PORT,
        log_level=os.environ.get("LOG_LEVEL", "info").lower())
    server = uvicorn.Server(config)
    async with tls_server, front_server:
        await server.serve()


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        asyncio.run(_serve_all())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
