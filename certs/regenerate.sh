#!/usr/bin/env bash
# 重新生成本地演示用的两套 CA 与同名接收端证书（logs-receiver.local）。
# 仅用于本地演示，私钥直接提交在仓库中，禁止用于任何真实环境。
set -euo pipefail
cd "$(dirname "$0")"

DAYS=3650
SERVER_NAME="logs-receiver.local"

gen_ca() {
  local dir="$1" cn="$2"
  mkdir -p "$dir"
  openssl genrsa -out "$dir/ca.key" 4096 2>/dev/null
  openssl req -x509 -new -nodes -key "$dir/ca.key" -sha256 -days "$DAYS" \
    -out "$dir/ca.crt" \
    -subj "/O=Demo Log Platform/CN=$cn" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
}

gen_server() {
  local dir="$1" ca_dir="$2"
  mkdir -p "$dir"
  openssl genrsa -out "$dir/server.key" 2048 2>/dev/null
  openssl req -new -key "$dir/server.key" -out "$dir/server.csr" \
    -subj "/O=Demo Log Platform/CN=$SERVER_NAME"
  openssl x509 -req -in "$dir/server.csr" \
    -CA "$ca_dir/ca.crt" -CAkey "$ca_dir/ca.key" -CAcreateserial \
    -out "$dir/server.crt" -days "$DAYS" -sha256 \
    -extfile <(printf '%s\n' \
      "basicConstraints=critical,CA:FALSE" \
      "keyUsage=critical,digitalSignature,keyEncipherment" \
      "extendedKeyUsage=serverAuth" \
      "subjectAltName=DNS:$SERVER_NAME")
  rm -f "$dir/server.csr"
}

gen_ca ca1 "Log Platform Root CA 1"
gen_ca ca2 "Log Platform Root CA 2"
gen_server server-ca1 ca1
gen_server server-ca2 ca2
rm -f ca1/ca.srl ca2/ca.srl

echo "已生成："
echo "  ca1/ca.crt  ca2/ca.crt                       （两套根 CA）"
echo "  server-ca1/ server-ca2/                       （同名 $SERVER_NAME 证书，分别由 CA1/CA2 签发）"
