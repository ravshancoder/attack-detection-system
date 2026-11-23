#!/usr/bin/env bash
# =====================================================================
# Tashkilotga hujumlarni aniqlash va bartaraf etish tizimi - o'rnatuvchi
# Ubuntu Server 22.04 / 24.04 uchun. Ishga tushirish: sudo bash setup.sh
# =====================================================================
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "[!] Skriptni root sifatida ishga tushiring: sudo bash setup.sh"; exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IFACE="$(ip route show default | awk '/default/ {print $5; exit}')"
HOME_NET="$(ip -o -4 addr show dev "$IFACE" | awk '{print $4}' | head -n1)"
SSH_PORT="${SSH_PORT:-22}"

log() { echo -e "\n\033[1;32m[+] $*\033[0m"; }

# ---------------------------------------------------------------------
log "1/8 Paketlar o'rnatilmoqda (interfeys: $IFACE, tarmoq: $HOME_NET)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ufw fail2ban auditd audispd-plugins python3 curl \
                   software-properties-common nginx
add-apt-repository -y ppa:oisf/suricata-stable || true
apt-get update -y
apt-get install -y suricata

# ---------------------------------------------------------------------
log "2/8 Yadro (sysctl) himoyasi"
cat > /etc/sysctl.d/99-hardening.conf <<'EOF'
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.log_martians = 1
net.ipv6.conf.all.accept_redirects = 0
EOF
sysctl --system >/dev/null

# ---------------------------------------------------------------------
log "3/8 SSH qattiqlashtirish"
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/99-hardening.conf <<'EOF'
PermitRootLogin no
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
PermitEmptyPasswords no
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
# Parolli kirishni o'chirish uchun avval SSH kalit sozlang, keyin:
#   PasswordAuthentication no   (qo'lda qo'shing)
sshd -t && systemctl reload ssh || systemctl reload sshd

# ---------------------------------------------------------------------
log "4/8 UFW firewall"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow "${SSH_PORT}"/tcp comment 'SSH'
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'
ufw limit "${SSH_PORT}"/tcp   # SSH uchun tezlik cheklovi
ufw logging low
ufw --force enable

# ---------------------------------------------------------------------
log "5/8 Fail2ban"
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 3
backend  = auto
banaction = ufw

[sshd]
enabled = true
port    = ${SSH_PORT}
logpath = %(sshd_log)s

[nginx-http-auth]
enabled = true

[nginx-botsearch]
enabled = true
EOF
systemctl enable --now fail2ban
systemctl restart fail2ban

# ---------------------------------------------------------------------
log "6/8 Suricata IDS"
sed -i "s|^\( *HOME_NET:\).*|\1 \"[${HOME_NET}]\"|" /etc/suricata/suricata.yaml || true
# Interfeysni belgilash
sed -i "0,/interface: .*/s//interface: ${IFACE}/" /etc/suricata/suricata.yaml || true

cat > /etc/suricata/rules/local.rules <<'EOF'
# --- Maxsus qoidalar (sid 1000001+) ---
alert tcp any any -> $HOME_NET 22 (msg:"LOCAL SSH brute-force urinishi"; flow:to_server; flags:S; threshold:type both, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:1000001; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"LOCAL Port skanerlash (SYN)"; flags:S,12; threshold:type both, track by_src, count 20, seconds 10; classtype:attempted-recon; sid:1000002; rev:1;)
alert icmp any any -> $HOME_NET any (msg:"LOCAL ICMP flood"; itype:8; threshold:type both, track by_src, count 50, seconds 5; classtype:attempted-dos; sid:1000003; rev:1;)
alert http any any -> $HOME_NET any (msg:"LOCAL SQL injection urinishi"; flow:to_server,established; http.uri; content:"'"; pcre:"/(union.+select|or\s+1=1|or\s+'1'='1|--\s|;\s*drop\s)/i"; classtype:web-application-attack; sid:1000004; rev:1;)
alert http any any -> $HOME_NET any (msg:"LOCAL XSS urinishi"; flow:to_server,established; http.uri; content:"<script"; nocase; classtype:web-application-attack; sid:1000005; rev:1;)
EOF

# local.rules ni yoqish
if ! grep -q "local.rules" /etc/suricata/suricata.yaml; then
  sed -i '/^rule-files:/a\  - local.rules' /etc/suricata/suricata.yaml
fi

suricata-update || echo "[!] suricata-update internet talab qiladi, keyinroq qayta urinib ko'ring"
suricata -T -c /etc/suricata/suricata.yaml -v || echo "[!] Suricata konfiguratsiyasini tekshiring"
systemctl enable --now suricata
systemctl restart suricata

# ---------------------------------------------------------------------
log "7/8 auditd qoidalari"
cat > /etc/audit/rules.d/99-attack-detect.rules <<'EOF'
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config
-w /var/log/auth.log -p wa -k authlog
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_commands
EOF
augenrules --load || true
systemctl enable --now auditd

# ---------------------------------------------------------------------
log "8/8 monitor.py xizmati"
install -m 755 "${SCRIPT_DIR}/monitor.py" /usr/local/bin/attack-monitor.py
cat > /etc/systemd/system/attack-monitor.service <<'EOF'
[Unit]
Description=Hujumlarni avtomatik aniqlash va bloklash (monitor.py)
After=network.target suricata.service

[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/attack-monitor.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now attack-monitor

# ---------------------------------------------------------------------
echo
echo "=============================================================="
echo " O'rnatish yakunlandi. Holatni tekshirish:"
echo "   systemctl status suricata fail2ban attack-monitor"
echo "   ufw status verbose"
echo "   tail -f /var/log/suricata/fast.log"
echo "   tail -f /var/log/attack-monitor.log"
echo "=============================================================="
