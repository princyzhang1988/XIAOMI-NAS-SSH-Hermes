# 小米智能存储 (Xiaomi NAS) — 获取 Root SSH + 部署 Hermes + 接入飞书

在小米智能存储（minas / RP05 / Realtek RTD1619B / aarch64 / Yocto 5.0.3）上完成三件事的完整实操记录：

1. **获取 Root SSH**：1.0.9.462 走「mTLS 取凭据 → UCI 注入 root SMB 共享 → cron 触发」的新链路；旧固件（≤1.0.9.425）的 WebDAV/mTLS 方法保留在 `scripts/` 作参考。
2. **部署 Hermes Agent**：用设备自带的 Docker 跑 `ghcr.io/nesquena/hermes-webui`（Web UI + 浏览器内嵌 TUI）。
3. **接入飞书**：启用 Hermes Gateway 的 `feishu` 适配器（WebSocket 长连接），即可在飞书里直接和 Hermes 对话。

> ⚠️ **前置声明**：整个过程会改动系统服务、`/etc/passwd`，临时创建 `force user=root` 的 SMB 共享，并通过 `ld.so.preload` + cron 触发 root shell。**仅限本人拥有或已明确授权的设备**，操作可能失去官方保修，固件升级会覆盖部分改动。请先备份重要数据。
>
> 📌 **版本**：Root 部分以 **1.0.9.462.F24C26D24-REL** 实测为准。462 修补了旧链路，**不要混用** `scripts/enable-ssh-macos.py`；旧固件请用该脚本，462 请用 `scripts/xiaomi-nas-root-macos.py`。
>
> 🔒 **脱敏说明**：文中的 `<NAS_IP>`、`<UID>`、`<USER>`、`<OPEN_ID>`、API Key / App Secret / SSH 公私钥均已替换为占位符。**请全部换成你自己的值**，切勿把真实密钥提交到公开仓库。

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
| `<UID>` | 米家数字 UID；脚本会从客户端证书自动解析，通常不用填 |
| `<USER>` | WebDAV/NAS 用户名，形如 `u<uid>`；脚本自动获取 |
| `<OPEN_ID>` | 飞书用户 open_id，仅 Part 3 使用 |

---

## Part 1：获取 Root SSH

> **适用版本**：`1.0.9.462.F24C26D24-REL`（RP05 / RTD1619B / aarch64）。
> 1.0.9.425 及更早的「WebDAV 视频路径命令注入」已被 462 修补；旧方法仅作参考保留在 `scripts/enable-ssh-macos.py`，**462 上不要执行**。

### 1.1 新链路（3 步）

462 把旧的 WebDAV 注入链修掉了（`realpath -sm` + argv、文件操作改 D-Bus），改成：

1. **mTLS 取凭据**：用 macOS 客户端证书请求 `get_pool_info`，拿到 WebDAV 用户名/密码（端口 5000）。
2. **UCI heredoc 注入**：WebDAV `MKCOL` 创建一个带换行符的目录名，配合 `add_samba_account` 的 `smb_mgr.sh` heredoc，写入 `force user = root` 的 `/etc` SMB 共享。
3. **SMB 写 + cron 触发**：通过该共享写 `/etc/ld.so.preload` 和现场汇编的 aarch64 `.so`；cron 每分钟的 root 任务加载 `.so`，启动：
   - socat root shell：`2323`
   - dropbear：`22`

脚本随后修复 462 的 dropbear（见 1.5），安装 `minas-sshd.service` 并清理注入痕迹。

### 1.2 前置条件

| 项 | 要求 |
|---|---|
| 设备 | 小米智能存储 RP05，固件 `1.0.9.462...` |
| Mac | 已安装并登录「小米智能存储.app」 |
| 证书 | App 包内 `.../extraResources/cert/`（脚本自动查找） |
| Python | `python3` + `keystone-engine` |
| 网络 | Mac 与 NAS 同一局域网，能访问 `<NAS_IP>:443/5000` |
| 授权 | **仅限本人拥有或明确授权的设备**；会改 `/etc`、`/etc/passwd`，写临时 SMB 共享和 cron，可能影响保修/OTA |

> 操作前备份重要数据。脚本会生成随机 SMB 口令并在结束后清理共享，但 root 改动本身是持久的。

### 1.3 运行

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install keystone-engine

# 基本用法（UID 自动从证书解析）
python scripts/xiaomi-nas-root-macos.py <NAS_IP>

# 证书不在默认路径
python scripts/xiaomi-nas-root-macos.py <NAS_IP> --cert-dir "/path/to/cert"

# 也可显式指定 UID
python scripts/xiaomi-nas-root-macos.py <NAS_IP> --uid <UID>
```

脚本会依次：

- 自动定位证书、解析 `<UID>` 与设备 SNI；
- 取 WebDAV 凭据，创建 `force user=root` 的 `/etc` SMB 共享；
- 写 `/etc/ld.so.preload` + `pwn.so`，等待 cron（≤90 秒）；
- 验证 `2323` / `22`，修复 dropbear，安装并 enable `minas-sshd.service`；
- 清理 `/etc/ld.so.preload`、`/etc/pwn.so`、`.rootpwn.sh`、staging 目录、注入的 SMB 共享/用户。

成功输出类似：

```text
✅ root 获取完成
   root shell:  nc <NAS_IP> 2323
   SSH:        ssh -i ~/.ssh/id_ed25519_minas root@<NAS_IP>
   SSH 可用:   是（/data/minas-ssh/dropbear + minas-sshd.service，已 enable）
```

### 1.4 验证

```bash
ssh -i ~/.ssh/id_ed25519_minas root@<NAS_IP> id
# uid=0(root) gid=0(root) ...

systemctl is-enabled minas-sshd   # enabled
systemctl is-active minas-sshd    # active
ss -lntp | grep ':22'
```

- `minas-sshd` 已 enable，重启后自动起。
- socat root shell `2323` **不持久化**；重启后需要时重跑脚本。
- root home 已迁到 `/home/rootx`（`/root` 是只读 erofs）。
- dropbear 的登录 shell 被替换为 `/bin/bash`，命令和 PTY 均可用。

### 1.5 462 的 SSH 坑：dropbear 硬编码 `mi-shell`

462 的 dropbear v2022.83 二进制里硬编码了 `/usr/sbin/mi-shell`，登录只打印 MINAS banner、忽略 `-c`，表现为「认证成功但命令没输出」。

修法（脚本自动完成）：

1. 把 `/usr/sbin/dropbear` 复制到可写的 `/data/minas-ssh/dropbear.new`；
2. 同长度把 `/usr/sbin/mi-shell` 替换为 `/bin/bash` + 9 个 NUL（`/usr/sbin` 在只读 erofs，不能原地改）；
3. 写 `/etc/systemd/system/minas-sshd.service`：
   - `ExecStart=/data/minas-ssh/dropbear -F -p 22 -r /etc/dropbear/dropbear_rsa_host_key -s`
   - `Conflicts=dropbear.socket`，避免和固件 socket 抢 22；
4. `disable --now dropbear.socket`，`enable --now minas-sshd`。

`-s` 表示禁用密码/空密码登录，只允许公钥。

### 1.6 macOS 适配的坑

上游 Linux 脚本在 macOS 直接跑会挂，主要修法：

| 问题 | 修法 |
|---|---|
| 上游用 `mount -t cifs` | macOS 改用 `mount_smbfs` |
| 共享名假设「30 个 M + uid」 | 实测修复后是 `etc-<uid>`，改为查 `get_samba_account` 现取 |
| 随机 SMB 口令含 `@ ( & % ~` | `mount_smbfs` URL 不做百分号解码，改成纯字母数字 |
| 清理依赖 GNU `timeout`/`nc` | 改用 Python socket + base64 下发 |
| SMB 服务在 UCI 变更后重启中 | 挂载失败自动重试 6 次 |

### 1.7 清理与回滚

脚本成功后会自动清理注入痕迹；失败时若 root shell 已就绪也会清理。无论结果，建议按本节检查残留。**有意保留**：

- `/home/rootx/.ssh/authorized_keys`
- `/etc/dropbear/authorized_keys`
- `/data/minas-ssh/dropbear` + `/etc/systemd/system/minas-sshd.service`
- `/etc/passwd` 中 root home → `/home/rootx`

回滚 SSH：

```bash
systemctl disable --now minas-sshd
rm -rf /data/minas-ssh
rm -f /etc/systemd/system/minas-sshd.service
systemctl daemon-reload
rm -f /home/rootx/.ssh/authorized_keys /etc/dropbear/authorized_keys
sed -i 's|:/home/rootx:|:/root:|' /etc/passwd
```

> `/root` 是只读 erofs；改回 `/root` 后公钥认证可能失效。需要再用时重跑脚本即可。
> 如果脚本中途被打断，先检查 `/etc/ld.so.preload` 是否残留；它会让全机动态程序加载 `pwn.so`，确认后删除。

### 1.8 安全加固

`minas-sshd` 已带 `-s`，只允许公钥。建议再验证一次：

```bash
ssh -o PreferredAuthentications=none -o BatchMode=yes root@<NAS_IP> exit
# 期望：Permission denied (publickey)
```

- 私钥只留本机（默认 `~/.ssh/id_ed25519_minas`），不要提交到仓库。
- 出厂 root 密码可能为空；`-s` 已封死密码通道。如需额外纵深，可设非空密码，但不要开启密码登录。
- 不要把 `2323` 暴露到公网；脚本只在局域网使用。

### 1.9 旧固件（≤1.0.9.425）

旧固件的 mTLS + WebDAV 视频路径注入链仍在 `scripts/enable-ssh-macos.py`，仅作历史参考；**462 上不要执行**，会被 `realpath -sm` / D-Bus 修补挡住。

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
| 固件升级后 SSH key 失效 | 462 重跑 `python3 scripts/xiaomi-nas-root-macos.py <NAS_IP>`；旧固件执行 `sh /data/fix-ssh-home.sh` |
| 空密码仍能登录 | 462 检查 `minas-sshd` 的 `ExecStart` 是否带 `-s`；旧固件检查 `/etc/default/dropbear` |

## 参考脚本

- [`scripts/xiaomi-nas-root-macos.py`](scripts/xiaomi-nas-root-macos.py) — **1.0.9.462 一键 root（macOS 适配）**，含 dropbear 修复与 `minas-sshd` 安装。
- [`scripts/enable-ssh-macos.py`](scripts/enable-ssh-macos.py) — 旧固件（≤1.0.9.425）的 mTLS + WebDAV 方法，仅作历史参考；**462 不要用**。
- [`scripts/fix-ssh-home.sh`](scripts/fix-ssh-home.sh) — 旧固件的 SSH 加固/恢复脚本；462 请重跑主脚本。

---

> 本仓库为个人 HomeLab 研究记录，仅供学习与自有设备管理。请勿用于越权访问他人设备。文中所有真实凭据均已脱敏。
