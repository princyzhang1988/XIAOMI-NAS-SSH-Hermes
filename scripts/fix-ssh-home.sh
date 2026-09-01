#!/bin/sh
# 小米NAS 固件升级后恢复 SSH：把 root HOME 迁回可写分区、恢复 authorized_keys、禁用空密码(-s)
#
# 背景：/root 是只读 erofs 分区，OTA 升级会重置 /etc/passwd（HOME 回 /root）和
#       /etc/default/dropbear（丢 -s）。此脚本幂等，可反复执行。
# 用法：sh /data/fix-ssh-home.sh

set -e

# 1) root HOME 迁到可写分区 /home/rootx（绕开只读 /root）
mkdir -p /home/rootx/.ssh
chmod 700 /home/rootx
chmod 600 /home/rootx/.ssh
sed -i 's|^root:x:0:0:root:/root:|root:x:0:0:root:/home/rootx:|' /etc/passwd

# 2) 恢复 authorized_keys（把下面公钥替换为你自己的）
mkdir -p /home/rootx/.ssh
printf '%s\n' "ssh-ed25519 AAAA<你的公钥> minas" > /home/rootx/.ssh/authorized_keys
chmod 600 /home/rootx/.ssh/authorized_keys

# 3) 禁用密码/空密码登录（-s）
printf 'DROPBEAR_EXTRA_ARGS=" -s"\n' > /etc/default/dropbear

# 4) root shell 设为可登录 shell
command -v chsh >/dev/null 2>&1 && chsh -s /bin/sh root 2>/dev/null || usermod -s /bin/sh root 2>/dev/null || true

# 5) 重启 dropbear
systemctl restart dropbear.socket 2>/dev/null || systemctl restart dropbear 2>/dev/null || true

echo "SSH 已加固：key-only + root home=/home/rootx"
