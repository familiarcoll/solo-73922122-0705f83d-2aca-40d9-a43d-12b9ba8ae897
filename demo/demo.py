#!/usr/bin/env python3
"""
反走私代理演示客户端（仅标准库，原始字节操作）。

运行：
    python3 demo/demo.py
可选环境变量：
    PROXY_HOST    默认 127.0.0.1
    PROXY_PORT    默认 8080
    UPSTREAM_URL  默认 http://127.0.0.1:8000
    ADMIN_API_KEY 默认 demo-admin-key（与 docker-compose 一致）
    CERTS_DIR     默认 <仓库根>/certs

演示内容：
  1. 分片发送的合法 POST /events（逐字节 / 小块 TCP 分片）
  2. 同连接流水线两个合法请求
  3. chunked 请求（代理应重建单一 Content-Length）
  4. 六种 HTTP 请求走私 / 畸形分帧攻击（全部应被拒绝并断连，且不到达上游）
  5. 延迟响应：上游慢 2.5s，代理 2s 超时回 504 并销毁连接，后续请求仍正常
  6. 连接池容量 2：3 个并发慢请求体现两车道
  7. 路由白名单
  8. 错误证书拒绝：接收端换成另一 CA 签发的同名证书，代理 502 且正文不发出
  9. 凭管理密钥整份替换 CA 包：错密钥 403 / 坏包 400 / 成功版本持久化
 10. 握手交错：换代期间迟到的旧握手不得借出，上报不重发
 11. 已写出的上报可完成、随后销毁旧连接；池名额不泄漏
最后直接拉取上游“实际收到的请求”清单作为证据。
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

PROXY_HOST = os.environ.get("PROXY_HOST", "127.0.0.1")
PROXY_PORT = int(os.environ.get("PROXY_PORT", "8080"))
UPSTREAM_URL = os.environ.get("UPSTREAM_URL", "http://127.0.0.1:8000")
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", "demo-admin-key")
CERTS_DIR = Path(os.environ.get(
    "CERTS_DIR", Path(__file__).resolve().parent.parent / "certs"))

PASS = "PASS"
FAIL = "FAIL"


@dataclass
class Report:
    results: list[tuple[str, bool, str]] = field(default_factory=list)

    def add(self, name: str, ok: bool, detail: str) -> None:
        self.results.append((name, ok, detail))
        mark = "✅" if ok else "❌"
        print(f"  {mark} {name}: {detail}")

    def summary(self) -> int:
        passed = sum(1 for _, ok, _ in self.results if ok)
        print(f"\n==== 结果汇总：{passed}/{len(self.results)} 通过 ====")
        return 0 if passed == len(self.results) else 1


# --------------------------------------------------------------------------- #
# 原始 socket 工具
# --------------------------------------------------------------------------- #


def connect() -> socket.socket:
    s = socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=5)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s


def send_splintered(sock: socket.socket, data: bytes,
                    size: int = 3) -> None:
    """模拟 TCP 分片：把完整报文切成小块逐块发送，块间让出事件循环时间。"""
    for i in range(0, len(data), size):
        sock.sendall(data[i:i + size])
        time.sleep(0.002)


def read_response(sock: socket.socket, max_bytes: int = 65536) -> bytes:
    """按 Content-Length 精确读取一个完整 HTTP 响应；不依赖连接关闭。

    若对端在任何字节到达前就关闭（极端 RST），返回空串由调用方判定。
    """
    sock.settimeout(5)
    buf = b""
    # 阶段 1：读到完整头部
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            return buf
        buf += chunk
        if len(buf) > max_bytes:
            return buf
    head, rest = buf.split(b"\r\n\r\n", 1)
    cl = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            cl = int(line.split(b":", 1)[1].strip())
    # 阶段 2：按 CL 补齐正文（可能已随头部一起到达）
    while len(rest) < cl:
        chunk = sock.recv(min(4096, cl - len(rest)))
        if not chunk:
            break
        rest += chunk
    return head + b"\r\n\r\n" + rest[:cl]


def status_of(raw: bytes) -> int | None:
    if not raw:
        return None
    try:
        # 形如 "HTTP/1.1 202 "（h11 原因短语可能为空，结尾带空格）
        parts = raw.split(b"\r\n", 1)[0].split(b" ")
        return int(parts[1])
    except (IndexError, ValueError):
        return None


def expect_closed(sock: socket.socket) -> bool:
    """确认对端已关闭：读到 EOF 或收到 RST；超时未关才视为失败。"""
    sock.settimeout(3)
    try:
        data = sock.recv(4096)
        # 若错误响应之后仍有残余字节，继续读到 EOF 为止。
        while data:
            data = sock.recv(4096)
        return True
    except socket.timeout:
        return False
    except OSError:
        return True   # RST 同样证明连接已被销毁
    finally:
        try:
            sock.close()
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# HTTP 工具（urllib，面向控制面）
# --------------------------------------------------------------------------- #


def _request(method: str, url: str, body: bytes | None = None,
             headers: dict | None = None) -> tuple[int, dict]:
    req = urllib.request.Request(url, data=body, method=method,
                                 headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, {"raw": raw}


def http_get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=5) as resp:
        return json.loads(resp.read().decode())


def http_delete(url: str) -> dict:
    req = urllib.request.Request(url, method="DELETE")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode())


def http_post(url: str, body: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else b""
    return _request("POST", url, data,
                    {"Content-Type": "application/json"})


def proxy_admin(method: str, path: str, body: bytes | None = None,
                key: str | None = ADMIN_API_KEY) -> tuple[int, dict]:
    headers = {"Content-Type": "application/x-pem-bundle"}
    if key is not None:
        headers["X-Admin-Key"] = key
    return _request(method, f"http://{PROXY_HOST}:{PROXY_PORT}{path}",
                    body, headers)


def upstream_snapshot(limit: int = 500) -> list[dict]:
    return http_get(f"{UPSTREAM_URL}/events?limit={limit}")["items"]


def events_seen(snapshot: list[dict]) -> tuple[int, int]:
    """返回 (POST /events 条数, 非 /events 路径条数)，后者是走私成功的铁证。"""
    n_events = sum(1 for it in snapshot if it["path"] == "/events"
                   and it["method"] == "POST")
    n_other = sum(1 for it in snapshot if it["path"] != "/events")
    return n_events, n_other


def post_event_raw(body: bytes, extra_headers: bytes = b"") -> tuple[int | None, bool]:
    """经代理发一笔 POST /events，返回 (状态码, 响应是否声明 Connection: close)。"""
    req = (
        b"POST /events HTTP/1.1\r\nHost: probe.local\r\n"
        b"Content-Type: application/json\r\n" + extra_headers +
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )
    s = connect()
    try:
        s.sendall(req)
        raw = read_response(s)
        # 从响应头判定（h11 对错误响应一律 connection: close），
        # 不能用探测 EOF 的方式：成功响应是 keep-alive，探测会白等一个超时。
        closed = b"connection: close" in raw.lower()
        return status_of(raw), closed
    finally:
        s.close()


def post_event(body: bytes, extra_headers: bytes = b"") -> int | None:
    status, _ = post_event_raw(body, extra_headers)
    return status


def count_body(snapshot: list[dict], body: bytes) -> int:
    return sum(1 for it in snapshot if it["body_text"] == body.decode())


# --------------------------------------------------------------------------- #
# 演示场景（1-7：分帧安全，与纯文本时代一致）
# --------------------------------------------------------------------------- #


def case_splintered(report: Report) -> None:
    print("\n[1] 分片发送的合法请求（每 3 字节一个 TCP 段）")
    body = json.dumps({"event": "splintered", "ok": True}).encode()
    req = (
        b"POST /events HTTP/1.1\r\n"
        b"Host: probe.local\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )
    before, _ = events_seen(upstream_snapshot())
    s = connect()
    send_splintered(s, req, size=3)
    raw = read_response(s)
    after, other = events_seen(upstream_snapshot())
    ok = status_of(raw) == 202 and after == before + 1
    report.add("分片合法请求被正常转发", ok,
               f"status={status_of(raw)}, 上游 /events 新增 {after - before} 条")
    s.close()


def case_pipeline(report: Report) -> None:
    print("\n[2] 同连接流水线（一条 TCP 上连续两个合法请求）")
    b1 = json.dumps({"event": "pipeline-1"}).encode()
    b2 = json.dumps({"event": "pipeline-2"}).encode()
    req = (
        b"POST /events HTTP/1.1\r\nHost: p\r\nContent-Length: "
        + str(len(b1)).encode() + b"\r\n\r\n" + b1
        + b"POST /events HTTP/1.1\r\nHost: p\r\nContent-Length: "
        + str(len(b2)).encode() + b"\r\n\r\n" + b2
    )
    before, _ = events_seen(upstream_snapshot())
    s = connect()
    s.sendall(req)
    raw1 = read_response(s)
    raw2 = read_response(s)
    after, _ = events_seen(upstream_snapshot())
    # h11 不生成原因短语，状态行为 "HTTP/1.1 202 "，因此按状态码计数。
    count = sum(1 for raw in (raw1, raw2) if status_of(raw) == 202)
    ok = count == 2 and after == before + 2
    report.add("流水线两请求均独立处理", ok,
               f"202 响应数={count}, 上游 /events 新增 {after - before} 条")
    s.close()


def case_chunked(report: Report) -> None:
    print("\n[3] chunked 请求（代理应重建单一 Content-Length 再转发）")
    body = json.dumps({"event": "chunked-body", "n": 42}).encode()
    chunk = (
        b"POST /events HTTP/1.1\r\n"
        b"Host: p\r\nTransfer-Encoding: chunked\r\n\r\n"
        + hex(len(body))[2:].encode() + b"\r\n" + body + b"\r\n0\r\n\r\n"
    )
    before_items = upstream_snapshot()
    before_seqs = {it["seq"] for it in before_items}
    s = connect()
    # 再叠加分片，验证“分块 + TCP 分片”组合。
    send_splintered(s, chunk, size=5)
    raw = read_response(s)
    after_items = upstream_snapshot()
    # 按正文精确取回本请求对应的上游记录，避免被演示自身的 GET 查询干扰。
    new_records = [it for it in after_items if it["seq"] not in before_seqs]
    last = next((it for it in new_records
                 if it["body_text"] == body.decode()), None)
    if last is None:
        report.add("chunked 被重建为单一 Content-Length", False,
                   f"上游未找到本请求，新增记录={len(new_records)} 条")
        s.close()
        return
    cl = last["headers"].get("content-length")
    has_te = "transfer-encoding" in last["headers"]
    ok = (status_of(raw) == 202 and cl == str(len(body)) and not has_te
          and last["body_bytes"] == len(body))
    report.add("chunked 被重建为单一 Content-Length", ok,
               f"上游收到 Content-Length={cl!r}, 残留 TE={has_te}")
    s.close()


SMUGGLE_CASES = [
    (
        "重复 Content-Length",
        b"POST /events HTTP/1.1\r\nHost: p\r\n"
        b"Content-Length: 4\r\nContent-Length: 9\r\n\r\nGOOD\r\nBAD-BODY",
    ),
    (
        "单头逗号分隔双 CL",
        b"POST /events HTTP/1.1\r\nHost: p\r\n"
        b"Content-Length: 4, 9\r\n\r\nGOOD\r\nBAD",
    ),
    (
        "TE 与 CL 并存（TE.CL）",
        b"POST /events HTTP/1.1\r\nHost: p\r\n"
        b"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"0\r\n\r\nSMUGGLED",
    ),
    (
        "非法分块大小",
        b"POST /events HTTP/1.1\r\nHost: p\r\n"
        b"Transfer-Encoding: chunked\r\n\r\nZZZ\r\nxxxx",
    ),
    (
        "正文超过 64KiB",
        b"POST /events HTTP/1.1\r\nHost: p\r\n"
        b"Content-Length: 65537\r\n\r\n" + b"A" * (64 * 1024 + 1),
    ),
    (
        "CL.TE 经典走私（夹带后台请求）",
        (
            b"POST /events HTTP/1.1\r\nHost: p\r\n"
            b"Content-Length: 42\r\n\r\n"
            b"0\r\n\r\n"
            b"POST /admin HTTP/1.1\r\nHost: p\r\n"
            b"Content-Length: 0\r\n\r\n"
        ),
    ),
]


def case_smuggling(report: Report) -> None:
    print("\n[4] 请求走私 / 畸形分帧攻击（应全部拒绝并断连，且不到达上游）")
    for name, payload in SMUGGLE_CASES:
        before_events, before_other = events_seen(upstream_snapshot())
        s = connect()
        try:
            s.sendall(payload)
            raw = read_response(s)
            status = status_of(raw)
            closed = expect_closed(s)
        except OSError:
            raw, status, closed = b"", None, True
        after_events, after_other = events_seen(upstream_snapshot())
        delta_events = after_events - before_events
        delta_other = after_other - before_other
        ok = (status in (400, 413) or status is None) and closed \
            and delta_events == 0 and delta_other == 0
        report.add(f"拦截：{name}", ok,
                   f"status={status}, 连接关闭={closed}, "
                   f"上游新增事件={delta_events}, 走私到其他路径={delta_other}")


def case_timeout(report: Report) -> None:
    print("\n[5] 延迟响应：上游 sleep 2.5s，代理 2s 总限时回 504 并销毁连接")
    body = json.dumps({"event": "slow"}).encode()
    req = (
        b"POST /events HTTP/1.1\r\nHost: p\r\n"
        b"X-Demo-Delay: 2.5\r\nContent-Length: "
        + str(len(body)).encode() + b"\r\n\r\n" + body
    )
    s = connect()
    t0 = time.monotonic()
    s.sendall(req)
    raw = read_response(s)
    elapsed = time.monotonic() - t0
    closed = expect_closed(s)
    # 代理侧预算固定 2.00s；客户端计时还包含建连与 FIN 读取，故窗口放宽。
    ok = status_of(raw) == 504 and 1.8 <= elapsed <= 2.8 and closed
    report.add("2 秒超时回 504 且关闭连接", ok,
               f"status={status_of(raw)}, 耗时={elapsed:.2f}s（代理预算 2.00s）, 关闭={closed}")

    # 迟到响应不得交给下一调用者：新建连接做一笔正常请求，必须干净成功。
    # 注意：被超时的 slow 请求可能在 2.5s 后仍到达上游，因此按 body 精确比对，
    # 只认 after-timeout 这条，不认迟到的 slow 记录。
    before_items = upstream_snapshot()
    body2 = json.dumps({"event": "after-timeout"}).encode()
    req2 = (
        b"POST /events HTTP/1.1\r\nHost: p\r\nContent-Length: "
        + str(len(body2)).encode() + b"\r\n\r\n" + body2
    )
    s2 = connect()
    s2.sendall(req2)
    raw2 = read_response(s2)
    after_items = upstream_snapshot()
    before_seqs = {it["seq"] for it in before_items}
    new_items = [it for it in after_items if it["seq"] not in before_seqs]
    clean = any(it["body_text"] == body2.decode() and
                it["headers"].get("content-length") == str(len(body2))
                for it in new_items)
    ok2 = status_of(raw2) == 202 and clean
    report.add("超时后新连接请求不受迟到响应污染", ok2,
               f"status={status_of(raw2)}, 干净新请求到达={clean}, "
               f"期间新增记录={len(new_items)} 条（迟到 slow 不计）")
    s2.close()


def case_pool(report: Report) -> None:
    print("\n[6] 上游连接池容量 2：3 个并发 0.8s 延迟请求（应呈现两车道）")
    body = json.dumps({"event": "pool"}).encode()
    req = (
        b"POST /events HTTP/1.1\r\nHost: p\r\nX-Demo-Delay: 0.8\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )

    def one_request() -> int | None:
        sock = connect()
        try:
            sock.sendall(req)
            raw = read_response(sock)
            return status_of(raw)
        finally:
            sock.close()

    t0 = time.monotonic()
    # 线程仅用于并发触发 socket，代理本身是单进程 asyncio。
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool_exec:
        statuses = list(pool_exec.map(lambda _: one_request(), range(3)))
    elapsed = time.monotonic() - t0
    # 两车道：前两笔 ~0.8s 完成，第三笔排队后 ~1.6s 完成；
    # 线程调度与本机抖动下放宽到 2.6s，但绝不可能是 3 条并行（那将 ~0.8s）。
    ok = statuses == [202, 202, 202] and 1.4 <= elapsed <= 2.6
    report.add("池容量=2，第三笔排队而非开第三条连接", ok,
               f"statuses={statuses}, 总耗时={elapsed:.2f}s（两车道预期约 1.6s）")


def case_routing(report: Report) -> None:
    print("\n[7] 路由白名单：GET / 与 POST /admin 必须被拒绝")
    before_events, before_other = events_seen(upstream_snapshot())
    for raw_req, name in [
        (b"GET / HTTP/1.1\r\nHost: p\r\n\r\n", "GET /"),
        (b"POST /admin HTTP/1.1\r\nHost: p\r\nContent-Length: 0\r\n\r\n",
         "POST /admin"),
    ]:
        s = connect()
        s.sendall(raw_req)
        raw = read_response(s)
        closed = expect_closed(s)
        ok = status_of(raw) in (404, 405) and closed
        report.add(f"拒绝非白名单请求：{name}", ok,
                   f"status={status_of(raw)}, 关闭={closed}")
    after_events, after_other = events_seen(upstream_snapshot())
    report.add("被拒绝请求未到达上游",
               after_events == before_events and after_other == before_other,
               f"新增事件={after_events - before_events}, "
               f"新增其他路径={after_other - before_other}")


# --------------------------------------------------------------------------- #
# 演示场景（8-11：TLS 信任与 CA 轮换）
# --------------------------------------------------------------------------- #


def reset_trust_state() -> None:
    """把两侧对齐到初始信任：接收端用 CA1 证书，代理只信 CA1。可重复运行。"""
    code, _ = http_post(f"{UPSTREAM_URL}/admin/tls/cert/ca1")
    assert code == 200, f"接收端证书复位失败: {code}"
    ca1_pem = (CERTS_DIR / "ca1" / "ca.crt").read_bytes()
    code, _ = proxy_admin("PUT", "/admin/ca-bundle", ca1_pem)
    assert code == 200, f"代理 CA 包复位失败: {code}"
    http_post(f"{UPSTREAM_URL}/admin/tls/delay", {"seconds": 0})
    time.sleep(0.2)


def case_wrong_cert(report: Report) -> None:
    print("\n[8] 错误证书拒绝：接收端换成 CA2 签发的同名证书，代理仍只信 CA1")
    code, info = http_post(f"{UPSTREAM_URL}/admin/tls/cert/ca2")
    assert code == 200, f"切换接收端证书失败: {info}"
    time.sleep(0.3)  # 等现存 TLS 会话关闭传播到代理空闲连接

    before, _ = events_seen(upstream_snapshot())
    probes0 = http_get(f"{UPSTREAM_URL}/admin/tls")["plaintext_probes_total"]
    body = json.dumps({"event": "must-not-arrive"}).encode()
    status, closed = post_event_raw(body)
    after, _ = events_seen(upstream_snapshot())
    tls = http_get(f"{UPSTREAM_URL}/admin/tls")

    ok = status == 502 and after == before
    report.add("证书链不被信任 → 502 且正文未到达上游", ok,
               f"status={status}, 上游新增事件={after - before}（应为 0）")
    probes_delta = tls["plaintext_probes_total"] - probes0
    ok2 = probes_delta == 0
    report.add("不回退明文：验证失败后 TLS 端口未收到任何明文", ok2,
               f"plaintext_probes 增量={probes_delta}")
    ok3 = tls["tls_connections_total"] >= 0 and status == 502 and closed
    report.add("验证失败即断开，无业务字节发出", ok3,
               f"代理回 502 后关闭入站连接={closed}")


def case_ca_rotation(report: Report) -> None:
    print("\n[9] 凭管理密钥整份替换 CA 包（CA1 → CA2），成功版本持久化")
    ca2_pem = (CERTS_DIR / "ca2" / "ca.crt").read_bytes()
    ca2_sha = hashlib.sha256(ca2_pem).hexdigest()

    code, _ = proxy_admin("PUT", "/admin/ca-bundle", ca2_pem, key="wrong-key")
    report.add("错误管理密钥 → 403", code == 403, f"status={code}")

    _, st_before = proxy_admin("GET", "/admin/status")
    code, resp = proxy_admin("PUT", "/admin/ca-bundle", b"this is not a PEM")
    _, st_after = proxy_admin("GET", "/admin/status")
    ok = (code == 400
          and st_after["ca"]["version"] == st_before["ca"]["version"]
          and st_after["ca"]["sha256"] == st_before["ca"]["sha256"])
    report.add("坏 PEM 包 → 400 且旧版保留", ok,
               f"status={code}, version 仍为 {st_after['ca']['version']}")

    code, info = proxy_admin("PUT", "/admin/ca-bundle", ca2_pem)
    ok = (code == 200
          and info["version"] == st_before["ca"]["version"] + 1
          and info["sha256"] == ca2_sha
          and info["persisted_sha256"] == ca2_sha
          and info["persisted_matches_memory"])
    report.add("合法整包替换 → 200，版本+1 且落盘一致", ok,
               f"status={code}, version={info.get('version')}, "
               f"sha256={info.get('sha256', '')[:16]}…, "
               f"持久化一致={info.get('persisted_matches_memory')}")

    before, _ = events_seen(upstream_snapshot())
    body = json.dumps({"event": "after-rotation"}).encode()
    status = post_event(body)
    after, _ = events_seen(upstream_snapshot())
    ok = status == 202 and after == before + 1
    report.add("换 CA 后上报恢复 202（新信任链握手成功）", ok,
               f"status={status}, 上游新增事件={after - before}")


def _swap_proxy_ca(pem_path: Path) -> dict:
    code, info = proxy_admin("PUT", "/admin/ca-bundle", pem_path.read_bytes())
    assert code == 200, f"CA 包替换失败: {info}"
    return info


def case_handshake_interleave(report: Report) -> None:
    print("\n[10] 握手交错：换代期间迟到的旧握手不得借出，上报不重发")
    ca2 = CERTS_DIR / "ca2" / "ca.crt"
    http_post(f"{UPSTREAM_URL}/admin/tls/delay", {"seconds": 1.2})
    try:
        _swap_proxy_ca(ca2)          # 清空空闲连接，保证下一笔触发新握手
        stats0 = proxy_admin("GET", "/admin/status")[1]["pool"]
        tls0 = http_get(f"{UPSTREAM_URL}/admin/tls")["tls_connections_total"]
        before, _ = events_seen(upstream_snapshot())

        body = json.dumps({"event": "interleave"}).encode()
        result: dict = {}
        def worker() -> None:
            result["status"] = post_event(body)
        t = threading.Thread(target=worker)
        t0 = time.monotonic()
        t.start()
        time.sleep(0.3)              # H1 旧握手在途（延迟 1.2s）
        _swap_proxy_ca(ca2)          # 换代：H1 迟到成功也必须丢弃
        t.join(timeout=15)
        elapsed = time.monotonic() - t0

        after, _ = events_seen(upstream_snapshot())
        stats1 = proxy_admin("GET", "/admin/status")[1]["pool"]
        tls1 = http_get(f"{UPSTREAM_URL}/admin/tls")["tls_connections_total"]
        arrived = count_body(upstream_snapshot(), body)

        ok = (result.get("status") == 202 and arrived == 1
              and stats1["stale_discarded"] > stats0["stale_discarded"])
        report.add("迟到旧握手被丢弃，请求经新代际连接完成且只到达一次", ok,
                   f"status={result.get('status')}, 耗时={elapsed:.1f}s, "
                   f"上游该事件条数={arrived}, "
                   f"stale_discarded={stats0['stale_discarded']}→"
                   f"{stats1['stale_discarded']}")
        ok2 = tls1 - tls0 >= 2
        report.add("证据：两次成功 TLS 握手只对应一条上报", ok2,
                   f"TLS 连接数 {tls0}→{tls1}（H1 被弃 + H2 成交），"
                   f"上游新增事件={after - before}")
    finally:
        http_post(f"{UPSTREAM_URL}/admin/tls/delay", {"seconds": 0})


def case_inflight_no_resend(report: Report) -> None:
    print("\n[11] 已写出的上报可完成、随后销毁旧连接；池名额不泄漏")
    ca2 = CERTS_DIR / "ca2" / "ca.crt"
    warm = post_event(json.dumps({"event": "warmup"}).encode())
    assert warm == 202, f"热身请求失败: {warm}"  # 池内留下当前代际空闲连接

    stats0 = proxy_admin("GET", "/admin/status")[1]["pool"]
    before, _ = events_seen(upstream_snapshot())

    body = json.dumps({"event": "inflight"}).encode()
    result: dict = {}
    def worker() -> None:
        result["status"] = post_event(body, b"X-Demo-Delay: 1.0\r\n")
    t = threading.Thread(target=worker)
    t.start()
    time.sleep(0.3)                  # 请求已完整写出，交换在途（上游 sleep 1s）
    _swap_proxy_ca(ca2)              # 换代：在途旧连接不被动关闭、不重发
    t.join(timeout=10)

    after, _ = events_seen(upstream_snapshot())
    stats1 = proxy_admin("GET", "/admin/status")[1]["pool"]
    arrived = count_body(upstream_snapshot(), body)

    ok = result.get("status") == 202 and arrived == 1
    report.add("在途上报在旧连接上完成且只到达一次", ok,
               f"status={result.get('status')}, 上游该事件条数={arrived}")
    ok2 = stats1["destroyed"] > stats0["destroyed"]
    report.add("旧代际连接用后即毁，不回池", ok2,
               f"destroyed={stats0['destroyed']}→{stats1['destroyed']}")
    ok3 = (stats1["active"] <= 2
           and stats1["opened"] - stats1["destroyed"] == stats1["active"])
    report.add("池名额守恒（opened-destroyed==active<=2），不重复归还", ok3,
               f"opened={stats1['opened']}, destroyed={stats1['destroyed']}, "
               f"active={stats1['active']}, idle={stats1['idle']}")

    status = post_event(json.dumps({"event": "after-inflight"}).encode())
    report.add("换代后新请求走新代际连接正常 202", status == 202,
               f"status={status}, 期间上游新增={after - before} 条")


def show_upstream_evidence() -> None:
    print("\n[证据] 上游实际收到的请求（最新 8 条）")
    data = http_get(f"{UPSTREAM_URL}/events?limit=8")
    for item in data["items"]:
        cl = item["headers"].get("content-length", "-")
        te = item["headers"].get("transfer-encoding", "-")
        print(f"  #{item['seq']:<3} {item['method']} {item['path']} "
              f"tcp={item['client_tcp']} CL={cl} TE={te} "
              f"body={item['body_bytes']}B  {item['body_text'][:48]!r}")
    print(f"  上游累计收到 {data['count']} 条（走私尝试条数应为 0 条 /events 之外记录）")


def main() -> int:
    print(f"目标代理 {PROXY_HOST}:{PROXY_PORT}，上游 {UPSTREAM_URL}，证书目录 {CERTS_DIR}")
    try:
        cleared = http_delete(f"{UPSTREAM_URL}/events")
        print(f"已清空上游历史记录：{cleared}")
    except urllib.error.URLError as exc:
        print(f"无法连接上游 {UPSTREAM_URL}：{exc}")
        return 2

    try:
        reset_trust_state()
        print("信任状态已复位：接收端=CA1 证书，代理=只信 CA1，握手延迟=0")
    except Exception as exc:  # noqa: BLE001
        print(f"信任状态复位失败：{exc}")
        return 2

    report = Report()
    for fn in (case_splintered, case_pipeline, case_chunked, case_smuggling,
               case_timeout, case_pool, case_routing, case_wrong_cert,
               case_ca_rotation, case_handshake_interleave,
               case_inflight_no_resend):
        try:
            fn(report)
        except OSError as exc:
            report.add(fn.__name__, False, f"网络异常：{exc}")
    show_upstream_evidence()
    return report.summary()


if __name__ == "__main__":
    raise SystemExit(main())
