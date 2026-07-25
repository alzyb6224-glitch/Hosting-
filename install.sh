#!/bin/bash
# ═══════════════════════════════════════════════════════
#  SK7 Hosting — سكريبت التثبيت التلقائي على VPS
# ═══════════════════════════════════════════════════════
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
PURPLE='\033[0;35m'; CYAN='\033[0;36m'; NC='\033[0m'
BOLD='\033[1m'

echo -e "${PURPLE}${BOLD}"
echo "  ███████╗██╗  ██╗███████╗    ██╗  ██╗ ██████╗ ███████╗████████╗██╗███╗   ██╗ ██████╗ "
echo "  ██╔════╝██║ ██╔╝╚════██║    ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██║████╗  ██║██╔════╝ "
echo "  ███████╗█████╔╝     ██╔╝    ███████║██║   ██║███████╗   ██║   ██║██╔██╗ ██║██║  ███╗"
echo "  ╚════██║██╔═██╗    ██╔╝     ██╔══██║██║   ██║╚════██║   ██║   ██║██║╚██╗██║██║   ██║"
echo "  ███████║██║  ██╗   ██║      ██║  ██║╚██████╔╝███████║   ██║   ██║██║ ╚████║╚██████╔╝"
echo "  ╚══════╝╚═╝  ╚═╝   ╚═╝      ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝╚═╝  ╚═══╝ ╚═════╝ "
echo -e "${NC}"
echo -e "${CYAN}  منصة الاستضافة المتقدمة — Production Ready${NC}"
echo "  ════════════════════════════════════════════════"

log(){ echo -e "${GREEN}[✓]${NC} $1"; }
warn(){ echo -e "${YELLOW}[!]${NC} $1"; }
err(){ echo -e "${RED}[✗]${NC} $1"; exit 1; }
step(){ echo -e "\n${PURPLE}${BOLD}━━ $1 ━━${NC}"; }

# ── Check root ──────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then err "شغّل السكريبت كـ root: sudo bash install.sh"; fi

step "1 — تحديث النظام"
apt-get update -qq && apt-get upgrade -y -qq
log "تم تحديث النظام"

step "2 — تثبيت المتطلبات الأساسية"
apt-get install -y -qq \
    curl wget git ufw fail2ban \
    python3 python3-pip python3-venv \
    nginx certbot python3-certbot-nginx \
    htop net-tools 2>/dev/null
log "تم تثبيت المتطلبات"

step "3 — تثبيت Node.js (اختياري — لمشاريع Node)"
if ! command -v node &>/dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - 2>/dev/null
    apt-get install -y -qq nodejs 2>/dev/null
    log "تم تثبيت Node.js"
else
    warn "Node.js مثبت مسبقاً"
fi

if command -v npm &>/dev/null && ! command -v pm2-runtime &>/dev/null; then
    npm install -g pm2 2>/dev/null && log "تم تثبيت PM2 (Cluster Mode لمشاريع Node)" \
        || warn "تعذر تثبيت PM2 — مشاريع Node ستعمل بوضع عادي (بدون Cluster) كبديل آمن"
else
    command -v pm2-runtime &>/dev/null && warn "PM2 مثبت مسبقاً"
fi

step "4 — تثبيت PHP (اختياري — لمشاريع PHP)"
if ! command -v php &>/dev/null; then
    apt-get install -y -qq php-cli 2>/dev/null
    log "تم تثبيت PHP"
else
    warn "PHP مثبت مسبقاً"
fi

step "5 — تثبيت Go (اختياري — لمشاريع Go)"
if ! command -v go &>/dev/null; then
    GO_VER="1.22.5"
    ARCH=$(dpkg --print-architecture 2>/dev/null || echo amd64)
    curl -fsSL "https://go.dev/dl/go${GO_VER}.linux-${ARCH}.tar.gz" -o /tmp/go.tar.gz 2>/dev/null \
        && tar -C /usr/local -xzf /tmp/go.tar.gz 2>/dev/null \
        && ln -sf /usr/local/go/bin/go /usr/local/bin/go \
        && ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt \
        && log "تم تثبيت Go ${GO_VER}" \
        || warn "تعذر تثبيت Go تلقائياً — ثبّته يدوياً لاحقاً إذا احتجت مشاريع Go (https://go.dev/dl)"
else
    warn "Go مثبت مسبقاً"
fi

step "6 — إعداد مجلد المشروع"
APP_DIR="/opt/sk7hosting"
mkdir -p "$APP_DIR"/{data,uploads,projects,logs}
cp -r . "$APP_DIR/" 2>/dev/null || true
cd "$APP_DIR"
log "مجلد المشروع: $APP_DIR"

step "7 — إنشاء البيئة الافتراضية Python"
python3 -m venv venv
source venv/bin/activate
pip install -q --upgrade pip
pip install -q -r requirements.txt
log "تم تثبيت مكتبات Python"

step "8 — إعداد Systemd Service"
cat > /etc/systemd/system/sk7hosting.service <<EOF
[Unit]
Description=SK7 Hosting Platform
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$APP_DIR
Environment=PATH=$APP_DIR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=$APP_DIR/venv/bin/gunicorn --bind 0.0.0.0:5000 --workers 3 --timeout 120 --access-logfile $APP_DIR/logs/access.log --error-logfile $APP_DIR/logs/error.log app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sk7hosting
systemctl start sk7hosting
log "تم إنشاء وتشغيل الـ Service"

step "9 — إعداد Nginx (Reverse Proxy)"
cat > /etc/nginx/sites-available/sk7hosting <<'EOF'
server {
    listen 80;
    server_name _;

    client_max_body_size 500M;
    proxy_read_timeout 300;
    proxy_connect_timeout 300;
    proxy_send_timeout 300;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy "strict-origin-when-cross-origin";

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Serve uploaded files directly for performance
    location /uploads/ {
        alias /opt/sk7hosting/uploads/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
EOF

ln -sf /etc/nginx/sites-available/sk7hosting /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx
log "تم إعداد Nginx"

step "10 — إعداد Firewall (UFW)"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 5000/tcp
ufw allow 9000:9200/tcp  # ports for hosted projects
ufw --force enable
log "تم إعداد الجدار الناري"

step "11 — إعداد Fail2Ban (حماية ضد Brute Force)"
cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5
ignoreip = 127.0.0.1/8

[sshd]
enabled = true

[nginx-http-auth]
enabled = true

[nginx-limit-req]
enabled  = true
filter   = nginx-limit-req
logpath  = /var/log/nginx/error.log
maxretry = 10
EOF

systemctl enable fail2ban
systemctl restart fail2ban
log "تم إعداد Fail2Ban"

step "12 — إنشاء سكريبت الإدارة"
cat > /usr/local/bin/sk7 <<'EOF'
#!/bin/bash
case "$1" in
    start)   systemctl start sk7hosting && echo "✅ تم التشغيل" ;;
    stop)    systemctl stop sk7hosting && echo "⏹️  تم الإيقاف" ;;
    restart) systemctl restart sk7hosting && echo "🔄 تم إعادة التشغيل" ;;
    status)  systemctl status sk7hosting ;;
    logs)    journalctl -u sk7hosting -f --no-pager ;;
    update)  cd /opt/sk7hosting && git pull && systemctl restart sk7hosting && echo "✅ تم التحديث" ;;
    backup)  tar -czf "/root/sk7backup_$(date +%Y%m%d_%H%M%S).tar.gz" /opt/sk7hosting/data /opt/sk7hosting/uploads && echo "✅ تم النسخ الاحتياطي" ;;
    ports)   ss -tlnp 2>/dev/null | grep -E ':(9[0-9]{3})' || echo "لا توجد مشاريع شغالة على منافذ 9000-9999" ;;
    *)       echo "الأوامر: start | stop | restart | status | logs | update | backup | ports" ;;
esac
EOF
chmod +x /usr/local/bin/sk7
log "تم إنشاء أمر sk7"

step "13 — النسخ الاحتياطي التلقائي (Cron)"
(crontab -l 2>/dev/null; echo "0 3 * * * tar -czf /root/sk7backup_\$(date +\%Y\%m\%d).tar.gz /opt/sk7hosting/data /opt/sk7hosting/uploads 2>/dev/null && find /root -name 'sk7backup_*.tar.gz' -mtime +7 -delete") | crontab -
log "تم إعداد النسخ الاحتياطي اليومي (3 صباحاً)"

step "اكتمل التثبيت! 🎉"
IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
echo ""
echo -e "${PURPLE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${GREEN}✅ SK7 Hosting يعمل بنجاح!${NC}"
echo ""
echo -e "  🌐 ${BOLD}الرابط:${NC}        http://$IP"
echo -e "  👑 ${BOLD}المطور:${NC}        DeV Sk7 and skinz"
echo -e "  🔑 ${BOLD}الباسورد:${NC}      sk7andskins"
echo -e "  🛡️  ${BOLD}الأدمن:${NC}        admin / admin123"
echo ""
echo -e "  📋 ${BOLD}أوامر الإدارة:${NC}"
echo -e "     sk7 status    — حالة الخدمة"
echo -e "     sk7 logs      — عرض السجلات"
echo -e "     sk7 restart   — إعادة التشغيل"
echo -e "     sk7 backup    — نسخ احتياطي"
echo -e "     sk7 ports     — عرض المنافذ النشطة"
echo ""
echo -e "  ⚠️  ${YELLOW}غيّر كلمة المرور فور الدخول!${NC}"
echo -e "${PURPLE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
