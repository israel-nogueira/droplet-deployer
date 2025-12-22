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
a2enmod proxy_fcgi setenvif headers ssl expires rewrite security2 remoteip
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
# 08. VHOST SSL INICIAL
#-----------------------------------------------------------------------------
PEM_FILE="/etc/ssl/certs/cloudflare.pem"
KEY_FILE="/etc/ssl/private/cloudflare.key"
mkdir -p /etc/ssl/certs /etc/ssl/private

openssl req -x509 -nodes -days 1 -newkey rsa:2048 -keyout "$KEY_FILE" -out "$PEM_FILE" -subj "/CN=localhost"
chmod 600 "$KEY_FILE"

cat > /etc/apache2/sites-available/000-default-le-ssl.conf <<EOF
<VirtualHost *:443>
    DocumentRoot /var/www/html
    SSLEngine on
    SSLCertificateFile $PEM_FILE
    SSLCertificateKeyFile $KEY_FILE
    <Directory /var/www/html>
        AllowOverride All
        Require all granted
    </Directory>
    <FilesMatch \.php$>
        SetHandler "proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost/"
    </FilesMatch>
</VirtualHost>
EOF

a2ensite 000-default-le-ssl
systemctl restart apache2

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
    --data "{\"hostnames\":[\"$TARGET_DOMAIN\",\"*.$TARGET_DOMAIN\"],\"requested_validity\":5475,\"request_type\":\"origin-rsa\",\"csr\":\"$CSR_JSON\"}")

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
# 11. FINALIZAÇÃO DE ARQUIVOS
#-----------------------------------------------------------------------------
echo "<?php phpinfo(); ?>" > /var/www/html/index.php
rm /var/www/html/index.html || true

#-----------------------------------------------------------------------------
# 12. FIREWALL E SSH (VERSÃO FINAL ANTI-TRAVAMENTO)
#-----------------------------------------------------------------------------
echo "| 🛡️ Finalizando blindagem do servidor na porta $SSH_PORT..."

# 1. Mata o socket ANTES de mexer no config (Evita o erro de Masked)
systemctl stop ssh.socket || true
systemctl disable ssh.socket || true
systemctl mask ssh.socket || true

# 2. Agora sim, ajusta a porta no SSH config
sed -i '/^Port /d' /etc/ssh/sshd_config
echo "Port $SSH_PORT" >> /etc/ssh/sshd_config

# 3. Limpa o estado de falha do sistema para permitir o novo start
systemctl reset-failed ssh.service || true

# 4. Configura UFW (Reset e Regras)
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow "$SSH_PORT"/tcp

for ip in $CF_IPV4 $CF_IPV6; do
    ufw allow from "$ip" to any port 80 proto tcp
    ufw allow from "$ip" to any port 443 proto tcp
done

# 5. Ativação Atômica
systemctl daemon-reload
systemctl unmask ssh
systemctl enable ssh
ufw --force enable



#-----------------------------------------------------------------------------
# 05. SCRIPT DE NOTIFICAÇÃO (O SEGREDO ANTI-ERRO)
#-----------------------------------------------------------------------------
if [ -n "$TELEGRAM_TOKEN" ]; then
    echo "| 🤖 Iniciando módulo de Alertas..."
    
    # Só entra em modo de espera se o CHAT_ID não tiver sido passado pelo index.sh
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
                CHAT_TITLE=$(echo "$RESPONSE" | grep -oP '(?<="title":")[^"]+' | tail -n 1)

                if [ -n "$TELEGRAM_CHAT_ID" ]; then
                    echo -e "\n------------------------------------------------"
                    echo "✅ CAPTURADO COM SUCESSO!"
                    echo "Grupo: $CHAT_TITLE"
                    echo "ID: $TELEGRAM_CHAT_ID"
                    echo "------------------------------------------------"
                    
                    # Confirmação imediata no grupo
                    curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_TOKEN/sendMessage" \
                        -d "chat_id=$TELEGRAM_CHAT_ID" \
                        -d "text=✅ *Servidor Vinculado!*%0A🖥️ Host: $TARGET_DOMAIN%0A🛡️ Finalizando blindagem..." \
                        -d "parse_mode=Markdown" > /dev/null
                    break 
                fi
            fi
            printf "."
            sleep 1
        done
    else
        echo "| ✅ Chat ID já fornecido: $TELEGRAM_CHAT_ID"
    fi

    # Geração do script de notificação
    cat <<EOF > /usr/local/bin/bunker-notify
#!/bin/bash
TOKEN="$TELEGRAM_TOKEN"
CHAT_ID="$TELEGRAM_CHAT_ID"
IP=\$1
JAIL=\$2
PROJETO="$NOME_PROJETO"

MENSAGEM="🛡️ *Bunker Defense [\$PROJETO]*%0A🚫 *IP BANIDO:* \$IP%0A⛓️ *Jail:* \$JAIL%0A🌍 *Servidor:* $TARGET_DOMAIN"

curl -s -X POST "https://api.telegram.org/bot\$TOKEN/sendMessage" \
    -d "chat_id=\$CHAT_ID" \
    -d "text=\$MENSAGEM" \
    -d "parse_mode=Markdown" > /dev/null
EOF
    chmod +x /usr/local/bin/bunker-notify

    #-----------------------------------------------------------------------------
    # 06. FAIL2BAN & BLACKLIST TXT
    #-----------------------------------------------------------------------------
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

    # Reinicialização limpa do Fail2Ban
    systemctl stop fail2ban
    rm -f /var/run/fail2ban/fail2ban.sock
    rm -f /var/lib/fail2ban/fail2ban.sqlite3
    systemctl start fail2ban
    systemctl enable fail2ban

    echo "|------------------------------------------------------------"
    echo "| Para testar agora o fail2ban:"
    echo "| fail2ban-client ping && ufw status | grep $SSH_PORT"
    echo "| "
    echo "| PRECISA RETORNAR:"
    echo "| "
    echo "| Server replied: pong"
    echo "| $SSH_PORT/tcp                   ALLOW       Anywhere"
    echo "|------------------------------------------------------------"
fi
# 6. O PULO DO GATO: Start direto no serviço puro
systemctl start ssh