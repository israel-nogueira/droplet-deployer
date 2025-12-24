#!/bin/bash
set -e

#-----------------------------------------------------------------------------
# 01. PREPARO E CREDENCIAIS
#-----------------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then echo "Execute como root"; exit 1; fi
	
#-----------------------------------------------------------------------------
# 02. TIMEZONE E LOCALIZAÇÃO
#-----------------------------------------------------------------------------
timedatectl set-timezone America/Sao_Paulo
timedatectl set-ntp on

#-----------------------------------------------------------------------------
# 03. SISTEMA BASE, REPOS E AGUARDAR TRAVAS
#-----------------------------------------------------------------------------
echo -e "\n\n|--------------------------------------------------------------------"
echo "| 🔄 Aguardando processos do sistema finalizarem (Apt Lock)..."

wait_for_apt() {
    while fuser /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock >/dev/null 2>&1 ; do
        echo "| ⏳ O sistema está se auto-atualizando... aguardando 5 segundos..."
        sleep 5
    done
}

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

wait_for_apt

echo "| ✅ Sistema liberado! Preparando Repositórios..."
echo -e "|--------------------------------------------------------------------\n\n"
add-apt-repository universe -y

curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
wait_for_apt
LC_ALL=C.UTF-8 add-apt-repository ppa:ondrej/php -y
wait_for_apt

apt-get update
apt-get install -y software-properties-common dos2unix ca-certificates jq nodejs \
apache2 fail2ban ufw libapache2-mod-security2 modsecurity-crs \
php8.2 php8.2-fpm php8.2-mysql php8.2-curl php8.2-xml php8.2-mbstring php8.2-zip php8.2-gd php8.2-bcmath

#-----------------------------------------------------------------------------
# 04. CONFIGURAÇÃO APACHE (MPM EVENT & MODS)
#-----------------------------------------------------------------------------
# ATENÇÃO: Adicionado 'filter' e 'substitute' na ativação inicial
a2enmod proxy_fcgi setenvif headers ssl expires rewrite security2 remoteip filter substitute
a2enconf php8.2-fpm
a2dismod mpm_prefork || true
a2enmod mpm_event
echo "ServerName localhost" > /etc/apache2/conf-available/servername.conf
a2enconf servername
systemctl start php8.2-fpm
echo "ServerTokens Prod" >> /etc/apache2/conf-available/security.conf
echo "ServerSignature Off" >> /etc/apache2/conf-available/security.conf

a2enconf security
systemctl restart apache2

#-----------------------------------------------------------------------------
# 05. HEADERS E REGRAS CLOUDFLARE (APACHE)
#-----------------------------------------------------------------------------
echo "| 🛡️ Configurando Headers de Segurança..."

CF_IPV4=$(curl -s https://www.cloudflare.com/ips-v4)
CF_IPV6=$(curl -s https://www.cloudflare.com/ips-v6)

REMOTEIP_CONF="/etc/apache2/conf-available/remoteip-cloudflare.conf"
cat > "$REMOTEIP_CONF" <<EOF
RemoteIPHeader CF-Connecting-IP
$(echo "$CF_IPV4 $CF_IPV6" | tr ' ' '\n' | sed 's/^/RemoteIPTrustedProxy /')

Header unset X-Powered-By
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "1; mode=block"

KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 60
EOF
a2enconf remoteip-cloudflare

#-----------------------------------------------------------------------------
# 06. MODSECURITY (WAF)
#-----------------------------------------------------------------------------
CRS_EXAMPLE=$(find /usr/share/ -name "crs-setup.conf.example" | head -n 1)
[ -n "$CRS_EXAMPLE" ] && cp "$CRS_EXAMPLE" /etc/modsecurity/crs/crs-setup.conf
MODSEC_CONF="/etc/modsecurity/modsecurity.conf"
cp /etc/modsecurity/modsecurity.conf-recommended "$MODSEC_CONF" || true
sed -i 's/^SecRuleEngine.*/SecRuleEngine DetectionOnly/' "$MODSEC_CONF"
echo "SecRule REQUEST_BASENAME \"\.(?i:ico|gif|jpg|jpeg|png|js|css)$\" \"id:1001,phase:1,nolog,allow,ctl:ruleEngine=Off\"" >> "$MODSEC_CONF"

#-----------------------------------------------------------------------------
# 07. FAIL2BAN (INTEGRAÇÃO API CLOUDFLARE)
#-----------------------------------------------------------------------------
CF_ACTION="/etc/fail2ban/action.d/cloudflare-apiv4.conf"
cat > "$CF_ACTION" <<EOF
[Definition]
actionban = curl -s -X POST "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules" \\
            -H "X-Auth-Email: $CF_EMAIL" \\
            -H "X-Auth-Key: $CF_API_KEY" \\
            -H "Content-Type: application/json" \\
            --data '{"mode":"block","configuration":{"target":"ip","value":"<ip>"},"notes":"Fail2Ban <name>"}'
EOF

cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 $CF_IPV4 $CF_IPV6
[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
action = ufw[name=SSH, port=$SSH_PORT, protocol=tcp]
EOF
systemctl restart fail2ban

#-----------------------------------------------------------------------------
# 08. VHOST SSL INICIAL (CEGANDO O ANTIVÍRUS)
#-----------------------------------------------------------------------------
PEM_FILE="/etc/ssl/certs/cloudflare.pem"
KEY_FILE="/etc/ssl/private/cloudflare.key"
mkdir -p /etc/ssl/certs /etc/ssl/private

openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout "$KEY_FILE" -out "$PEM_FILE" \
    -subj "/CN=$TARGET_DOMAIN"
chmod 600 "$KEY_FILE"

# O AJUSTE DE OURO: Configuração agressiva do Substitute sem quebrar o Apache
cat > /etc/apache2/sites-available/000-default-le-ssl.conf <<EOF
<VirtualHost *:443>
    ServerName $TARGET_DOMAIN
    ServerAlias www.$TARGET_DOMAIN
    DocumentRoot /var/www/html

    SSLEngine on
    SSLCertificateFile $PEM_FILE
    SSLCertificateKeyFile $KEY_FILE

    <Directory /var/www/html>
        AllowOverride All
        Require all granted
    </Directory>

    <IfModule mod_headers.c>
        # Força o navegador a não aceitar compressão para o Substitute ler o HTML
        RequestHeader unset Accept-Encoding
        Header set X-XSS-Protection "0"
        Header always set Access-Control-Allow-Origin "*"
    </IfModule>

    <IfModule mod_substitute.c>
        AddOutputFilterByType SUBSTITUTE text/html
        # Remove as injeções da Cloudflare que o antivírus bloqueia
        Substitute "s|<script[^>]*static\.cloudflareinsights\.com[^>]*>.*</script>||ni"
        Substitute "s|<script[^>]*cloudflareinsights\.com[^>]*>.*</script>||ni"
        Substitute "s|<script[^>]*beacon\.min\.js[^>]*>.*</script>||ni"
        Substitute "s|<script[^>]*email-decode\.min\.js[^>]*></script>||ni"
    </IfModule>


	Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"

    SetEnv no-gzip 1
    ErrorLog \${APACHE_LOG_DIR}/error.log
    CustomLog \${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
EOF

# Aplica configurações do Apache de forma segura
a2dismod deflate -f || true
a2enmod filter headers substitute ssl rewrite
a2ensite 000-default-le-ssl
apache2ctl -t && systemctl restart apache2

#-----------------------------------------------------------------------------
# 09. FERRAMENTAS DEV
#-----------------------------------------------------------------------------
curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
npm install -g pm2

#-----------------------------------------------------------------------------
# 10. GERAÇÃO SSL REAL (15 ANOS ORIGIN CA)
#-----------------------------------------------------------------------------
openssl genrsa -out $KEY_FILE 2048
openssl req -new -key $KEY_FILE -subj "/CN=$TARGET_DOMAIN" -out /tmp/server.csr

CSR_JSON=$(cat /tmp/server.csr | sed ':a;N;$!ba;s/\n/\\n/g')

RESPONSE=$(curl -s -X POST "https://api.cloudflare.com/client/v4/certificates" \
    -H "X-Auth-User-Service-Key: $ORIGIN_CA_KEY" -H "Content-Type: application/json" \
    --data "{\"hostnames\":[\"$TARGET_DOMAIN\"],\"requested_validity\":5475,\"request_type\":\"origin-rsa\",\"csr\":\"$CSR_JSON\"}")

if echo "$RESPONSE" | jq -e '.result.certificate' > /dev/null; then
    echo "$RESPONSE" | jq -r '.result.certificate' > $PEM_FILE
    systemctl restart apache2
    echo "| ✅ SSL REAL INSTALADO PARA $TARGET_DOMAIN!"
fi

echo "export DO_TOKEN='$DO_TOKEN'" >> /etc/apache2/envvars
echo "export CF_EMAIL='$CF_EMAIL'" >> /etc/apache2/envvars
echo "export CF_API_KEY='$CF_API_KEY'" >> /etc/apache2/envvars
echo "export CF_ORIGIN_CA_KEY='$ORIGIN_CA_KEY'" >> /etc/apache2/envvars
systemctl restart apache2

#-----------------------------------------------------------------------------
# 11. FINALIZAÇÃO DE ARQUIVOS (CORRIGIDO)
#-----------------------------------------------------------------------------
echo '<?php die("PHP RODANDO!"); ?>' > /var/www/html/index.php
rm -f /var/www/html/index.html
chown -R www-data:www-data /var/www/html
chmod -R 755 /var/www/html

#-----------------------------------------------------------------------------
# 12. FIREWALL E SSH (VERSÃO FINAL ANTI-TRAVAMENTO)
#-----------------------------------------------------------------------------
echo "| 🛡️ Finalizando blindagem do servidor na porta $SSH_PORT..."

systemctl stop ssh.socket || true
systemctl disable ssh.socket || true
systemctl mask ssh.socket || true

sed -i '/^Port /d' /etc/ssh/sshd_config
echo "Port $SSH_PORT" >> /etc/ssh/sshd_config

systemctl reset-failed ssh.service || true

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow "$SSH_PORT"/tcp

for ip in $CF_IPV4 $CF_IPV6; do
    ufw allow from "$ip" to any port 80 proto tcp
    ufw allow from "$ip" to any port 443 proto tcp
done

systemctl daemon-reload
systemctl unmask ssh
systemctl enable ssh
systemctl start ssh
ufw --force enable

#-----------------------------------------------------------------------------
# 05. SCRIPT DE NOTIFICAÇÃO (MANTIDO CONFORME ORIGINAL)
#-----------------------------------------------------------------------------
if [ -n "$TELEGRAM_TOKEN" ]; then
    echo -e "\n\n\n|----------------------------------------------"
    echo "| 🤖 Iniciando módulo de Alertas..."
    
    if [ -z "$TELEGRAM_CHAT_ID" ]; then
        OFFSET=0
        START_TIME=$(date +%s)
        echo "| 📡 AGUARDANDO REGISTRO: Vá ao grupo e digite /registrar"

        until [ -n "$TELEGRAM_CHAT_ID" ]; do
            RESPONSE=$(curl -s "https://api.telegram.org/bot$TELEGRAM_TOKEN/getUpdates?offset=$OFFSET&timeout=20")
            UPD_ID=$(echo "$RESPONSE" | grep -oP '(?<="update_id":)\d+' | tail -n 1)
            [ -n "$UPD_ID" ] && OFFSET=$((UPD_ID + 1))
            MSG_TEXT=$(echo "$RESPONSE" | grep -oP '(?<="text":")[^"]+' | tail -n 1)
            MSG_DATE=$(echo "$RESPONSE" | grep -oP '(?<="date":)\d+' | tail -n 1)

            if [[ "$MSG_TEXT" == "/registrar" ]] && [ "$MSG_DATE" -ge "$START_TIME" ]; then
                TELEGRAM_CHAT_ID=$(echo "$RESPONSE" | grep -oP '(?<="chat":\{"id":)-?\d+' | tail -n 1)
                if [ -n "$TELEGRAM_CHAT_ID" ]; then
                    curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_TOKEN/sendMessage" \
                        -d "chat_id=$TELEGRAM_CHAT_ID" \
                        -d "text=✅ *Servidor Vinculado!*%0A🖥️ Host: $TARGET_DOMAIN" \
                        -d "parse_mode=Markdown" > /dev/null
                    break 
                fi
            fi
            printf "."
            sleep 1
        done
    fi

    cat <<EOF > /usr/local/bin/bunker-notify
#!/bin/bash
TOKEN="$TELEGRAM_TOKEN"
CHAT_ID="$TELEGRAM_CHAT_ID"
IP=\$1
JAIL=\$2
PROJETO="$NOME_PROJETO"
MENSAGEM="🛡️ *Bunker Defense [\$PROJETO]*%0A🚫 *IP BANIDO:* \$IP%0A🌍 *Servidor:* $TARGET_DOMAIN"
curl -s -X POST "https://api.telegram.org/bot\$TOKEN/sendMessage" -d "chat_id=\$CHAT_ID" -d "text=\$MENSAGEM" -d "parse_mode=Markdown" > /dev/null
EOF
    chmod +x /usr/local/bin/bunker-notify

    touch /var/www/html/blacklisted_ips.txt
    chmod 666 /var/www/html/blacklisted_ips.txt

    cat <<'EOF' > /etc/fail2ban/action.d/telegram-alert.conf
[Definition]
actionban = /usr/local/bin/bunker-notify "<ip>" "<name>" && echo "<ip>" >> /var/www/html/blacklisted_ips.txt
actionunban = sed -i '/<ip>/d' /var/www/html/blacklisted_ips.txt
EOF

    cat <<EOF > /etc/fail2ban/jail.local
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
bantime  = 24h
findtime = 5m
maxretry = 3
backend  = systemd
action   = ufw[name=SSH, port="$SSH_PORT", protocol=tcp, insert=1, blocktype=reject]
           telegram-alert

[sshd]
enabled = true
port    = $SSH_PORT
filter  = sshd
maxretry = 3
EOF

    systemctl stop fail2ban
    rm -f /var/run/fail2ban/fail2ban.sock
    rm -f /var/lib/fail2ban/fail2ban.sqlite3
    systemctl start fail2ban
    systemctl enable fail2ban
fi

# Reinício final para garantir que tudo (Apache e SSH) está operando nas portas certas
systemctl restart apache2
echo "| ✅ CONFIGURAÇÃO CONCLUÍDA!"