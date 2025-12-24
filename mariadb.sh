#!/bin/bash
set -e

#-----------------------------------------------------------------------------
# 01. PREPARO, REPOSITÓRIOS E TRAVAS DE APT
#-----------------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then echo "Erro: root necessário"; exit 1; fi
timedatectl set-timezone America/Sao_Paulo

wait_for_apt() {
    while fuser /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock >/dev/null 2>&1 ; do
        echo "| ⏳ Aguardando APT liberar as travas do sistema..."
        sleep 5
    done
}

export DEBIAN_FRONTEND=noninteractive
wait_for_apt

add-apt-repository universe -y
LC_ALL=C.UTF-8 add-apt-repository ppa:ondrej/php -y
wait_for_apt
apt-get update


#-----------------------------------------------------------------------------
# 02. INSTALAÇÃO DOS PACOTES (FORÇANDO ESTABILIDADE PHP 8.2)
#-----------------------------------------------------------------------------
echo "| 📦 Instalando pacotes do sistema e PHP 8.2..."

# Adicionado php8.2-intl explicitamente e o composer
apt-get install -y apache2 mariadb-server mariadb-client \
php8.2 php8.2-fpm php8.2-mysql php8.2-curl php8.2-xml \
php8.2-mbstring php8.2-zip php8.2-gd php8.2-intl php8.2-bcmath \
fail2ban ufw jq wget composer \
libjs-jquery libjs-jquery-ui libjs-codemirror

# MÁGICA: Define o PHP 8.2 como o padrão do sistema para evitar conflitos com o 8.4
update-alternatives --set php /usr/bin/php8.2
update-alternatives --set phar /usr/bin/phar8.2
update-alternatives --set phar.phar /usr/bin/phar.phar8.2

# Garante que o Apache use o FPM do 8.2 e não tente carregar versões novas
a2enmod proxy_fcgi setenvif
a2enconf php8.2-fpm
systemctl restart apache2



#-----------------------------------------------------------------------------
# 03. CONFIGURAÇÃO DO MARIADB (PORTA CUSTOMIZADA)
#-----------------------------------------------------------------------------
echo "| 🚪 Alterando porta do MariaDB para $DB_PORT..."
sed -i "s/.*port.*/port = $DB_PORT/g" /etc/mysql/mariadb.conf.d/50-server.cnf
systemctl restart mariadb

#-----------------------------------------------------------------------------
# 04. INSTALAÇÃO E SEGURANÇA DO PHPMYADMIN (BUNKER)
#-----------------------------------------------------------------------------
echo "| 🗄️ Instalando e blindando phpMyAdmin..."
echo "phpmyadmin phpmyadmin/dbconfig-install boolean true" | debconf-set-selections
echo "phpmyadmin phpmyadmin/reconfigure-webconfig multiselect apache2" | debconf-set-selections
apt-get install -y phpmyadmin


BLOWFISH_SECRET=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 32)
cat <<EOF > /etc/phpmyadmin/config.inc.php
<?php
\$i = 0; \$i++;
\$cfg['blowfish_secret'] = '$BLOWFISH_SECRET'; 
\$cfg['Servers'][\$i]['auth_type'] = 'cookie';
\$cfg['Servers'][\$i]['host'] = '127.0.0.1';
\$cfg['Servers'][\$i]['port'] = '$DB_PORT';
\$cfg['Servers'][\$i]['connect_type'] = 'tcp';
\$cfg['Servers'][\$i]['AllowNoPassword'] = false;

/* Configurações de Armazenamento - RESOLVE O TYPEERROR */
\$cfg['Servers'][\$i]['pmadb'] = 'phpmyadmin';
\$cfg['Servers'][\$i]['bookmarktable'] = 'pma__bookmark';
\$cfg['Servers'][\$i]['relation'] = 'pma__relation';
\$cfg['Servers'][\$i]['table_info'] = 'pma__table_info';
\$cfg['Servers'][\$i]['table_coords'] = 'pma__table_coords';
\$cfg['Servers'][\$i]['pdf_pages'] = 'pma__pdf_pages';
\$cfg['Servers'][\$i]['column_info'] = 'pma__column_info';
\$cfg['Servers'][\$i]['history'] = 'pma__history';
\$cfg['Servers'][\$i]['table_uiprefs'] = 'pma__table_uiprefs';
\$cfg['Servers'][\$i]['tracking'] = 'pma__tracking';
\$cfg['Servers'][\$i]['userconfig'] = 'pma__userconfig';
\$cfg['Servers'][\$i]['recent'] = 'pma__recent';
\$cfg['Servers'][\$i]['favorite'] = 'pma__favorite';
\$cfg['Servers'][\$i]['users'] = 'pma__users';
\$cfg['Servers'][\$i]['usergroups'] = 'pma__usergroups';
\$cfg['Servers'][\$i]['navigationhiding'] = 'pma__navigationhiding';
\$cfg['Servers'][\$i]['savedsearches'] = 'pma__savedsearches';
\$cfg['Servers'][\$i]['central_columns'] = 'pma__central_columns';
\$cfg['Servers'][\$i]['designer_settings'] = 'pma__designer_settings';
\$cfg['Servers'][\$i]['export_templates'] = 'pma__export_templates';
\$cfg['Servers'][\$i]['2fa'] = 'pma__twofactor';
\$cfg['UploadDir'] = '';
\$cfg['SaveDir'] = '';
EOF

#-----------------------------------------------------------------------------
# 05. CORREÇÃO FÍSICA DE ASSETS (SOLUÇÃO ERRO 499 / ANTIVÍRUS)
#-----------------------------------------------------------------------------
echo "| ⚙️ Aplicando Correção Física de Assets (JS e Imagens)..."

PMA_VENDOR="/usr/share/phpmyadmin/js/vendor/jquery"
mkdir -p "$PMA_VENDOR"

# Copia bibliotecas existentes e descarrega as ausentes no repositório do Noble
cp -r /usr/share/javascript/jquery/* "$PMA_VENDOR/" 2>/dev/null || true
cp -r /usr/share/javascript/jquery-ui/* "$PMA_VENDOR/" 2>/dev/null || true

wget -qO "$PMA_VENDOR/jquery-migrate.min.js" https://code.jquery.com/jquery-migrate-3.3.2.min.js
wget -qO "$PMA_VENDOR/jquery.validate.min.js" https://cdnjs.cloudflare.com/ajax/libs/jquery-validate/1.19.3/jquery.validate.min.js
wget -qO "$PMA_VENDOR/jquery.debounce-1.0.6.js" https://raw.githubusercontent.com/cowboy/jquery-throttle-debounce/v1.1/jquery.ba-throttle-debounce.min.js

#-----------------------------------------------------------------------------
# 06. GERAÇÃO SSL (ORIGIN CA) E VIRTUALHOST (PORTA 443)
#-----------------------------------------------------------------------------
echo "| 🔐 Gerando Certificado de Origem Cloudflare para $URL_DB..."

PEM_FILE="/etc/ssl/certs/cloudflare.pem"
KEY_FILE="/etc/ssl/private/cloudflare.key"
mkdir -p /etc/ssl/certs /etc/ssl/private

openssl genrsa -out "$KEY_FILE" 2048
openssl req -new -key "$KEY_FILE" -subj "/CN=$URL_DB" -out /tmp/mariadb.csr
CSR_JSON=$(cat /tmp/mariadb.csr | sed ':a;N;$!ba;s/\n/\\n/g')

RESPONSE=$(curl -s -X POST "https://api.cloudflare.com/client/v4/certificates" \
    -H "X-Auth-User-Service-Key: $ORIGIN_CA_KEY" \
    -H "Content-Type: application/json" \
    --data "{\"hostnames\":[\"$URL_DB\"],\"requested_validity\":5475,\"request_type\":\"origin-rsa\",\"csr\":\"$CSR_JSON\"}")

if echo "$RESPONSE" | jq -e '.result.certificate' > /dev/null; then
    echo "$RESPONSE" | jq -r '.result.certificate' > "$PEM_FILE"
    echo "| ✅ SSL Real instalado com sucesso!"
else
    echo "| ❌ Falha ao gerar SSL. O Cloudflare retornou erro."
fi

echo "| ⚙️ Configurando VirtualHost SSL e removendo restrições..."
a2enmod ssl headers proxy_fcgi setenvif rewrite

cat <<EOF > /etc/apache2/sites-available/db-subdomain.conf
<VirtualHost *:80>
    ServerName $URL_DB
    RewriteEngine On
    RewriteCond %{HTTPS} off
    RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
</VirtualHost>

<VirtualHost *:443>
    ServerName $URL_DB
    DocumentRoot /usr/share/phpmyadmin

    SSLEngine on
    SSLCertificateFile $PEM_FILE
    SSLCertificateKeyFile $KEY_FILE

    # HSTS: Essencial para o Antivírus confiar no site
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"

    <Directory /usr/share/phpmyadmin>
        Options +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    <FilesMatch \.php$>
        SetHandler "proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost"
    </FilesMatch>

    <IfModule mod_headers.c>
        Header always unset Content-Security-Policy
        Header always unset X-Content-Security-Policy
        Header always unset X-WebKit-CSP
        Header always unset X-Frame-Options
        Header set Access-Control-Allow-Origin "*"
    </IfModule>

    SetEnv no-gzip 1
</VirtualHost>
EOF

chown -R www-data:www-data /usr/share/phpmyadmin
chmod -R 755 /usr/share/phpmyadmin
a2dissite 000-default.conf || true
a2disconf phpmyadmin || true
a2ensite db-subdomain.conf
systemctl restart apache2 php8.2-fpm

#-----------------------------------------------------------------------------
# 08. SEGURANÇA MARIADB E USUÁRIOS
#-----------------------------------------------------------------------------
echo "| 🔐 Configurando privilégios de usuários..."

# Detecta se o comando é 'mariadb' ou 'mysql'
SQL_BIN=$(command -v mariadb || command -v mysql)

# 1. Garante que o root use a senha gerada
$SQL_BIN -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED VIA mysql_native_password USING PASSWORD('$DB_ROOT_PASSWORD');" || true

# 2. Criação de usuários e permissões
$SQL_BIN -u root -p"$DB_ROOT_PASSWORD" <<EOF
CREATE DATABASE IF NOT EXISTS phpmyadmin;
CREATE USER IF NOT EXISTS 'webmaster'@'localhost' IDENTIFIED BY '$DB_ROOT_PASSWORD';
GRANT ALL PRIVILEGES ON *.* TO 'webmaster'@'localhost' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON phpmyadmin.* TO 'webmaster'@'localhost';
DROP USER IF EXISTS 'system'@'localhost';
CREATE USER 'system'@'localhost' IDENTIFIED BY '$DB_SYSTEM_PASSWORD';
GRANT SELECT, INSERT, UPDATE, DELETE ON *.* TO 'system'@'localhost';
FLUSH PRIVILEGES;
EOF

# 3. Importa as tabelas estruturais (Busca o caminho dinamicamente)
SQL_TABLES=$(find /usr/share/phpmyadmin -name "create_tables.sql" | head -n 1)
$SQL_BIN -u root -p"$DB_ROOT_PASSWORD" phpmyadmin < "$SQL_TABLES"

#-----------------------------------------------------------------------------
# 09. BLINDAGEM DE REDE (FIREWALL E SSH)
#-----------------------------------------------------------------------------
echo "| 🛡️ Ajustando SSH para porta $SSH_PORT e ativando UFW..."

# 1. Configura a porta no arquivo do SSH primeiro
sed -i "/^Port /d" /etc/ssh/sshd_config
echo "Port $SSH_PORT" >> /etc/ssh/sshd_config

# 2. Abre as portas no Firewall ANTES de ativar ou reiniciar o SSH
ufw --force reset
ufw default deny incoming
ufw allow "$SSH_PORT"/tcp
ufw allow 80/tcp
ufw allow 443/tcp
echo "y" | ufw enable

# 3. Lida com o sistema de sockets do Ubuntu 24.04 (Essencial para mudar a porta)
systemctl stop ssh.socket || true
systemctl disable ssh.socket || true
systemctl mask ssh.socket || true

# 4. Reinicia o serviço SSH tradicional
systemctl daemon-reload
systemctl restart ssh

echo "|---------------------------------------------------------------"
echo "| 🔐 Instalando dependências para 2FA no phpMyAdmin..."
echo "|---------------------------------------------------------------"

# Garante que as extensões do PHP necessárias para o QR Code estejam presentes
apt-get install -y php8.2-imagick php-google2fa-qrcode php-bacon-qr-code || true

echo "| 🔐 Instalando bibliotecas 2FA via Composer..."
cd /usr/share/phpmyadmin
# O comando composer precisa estar na mesma linha que a variável de ambiente
COMPOSER_ALLOW_SUPERUSER=1 composer require pragmarx/google2fa-qrcode bacon/bacon-qr-code --with-all-dependencies

chown -R www-data:www-data /usr/share/phpmyadmin/vendor

#-----------------------------------------------------------------------------
# 10. FINALIZAÇÃO E LOGS
#-----------------------------------------------------------------------------
# Captura o IP Público para exibição
SERVER_IP=$(curl -s icanhazip.com)

echo -e "\n\n\n|------------------------------------------------------------"
echo "|"
echo "| ✅ SERVIDOR TOTALMENTE CONFIGURADO!"
echo "|"
echo "| 🌐 ACESSO:		https://$URL_DB"
echo "| 🔗 SSH:		ssh root@$SERVER_IP -p $SSH_PORT"
echo "| 🔑 WEBMASTER:		webmaster > $DB_ROOT_PASSWORD"
echo "| 🔑 SYSTEM:		system > $DB_SYSTEM_PASSWORD"
echo "| 🛠️ SSH PORT:		$SSH_PORT"
echo "| 🗂️ DB PORT:		$DB_PORT"
echo "|"
echo "|------------------------------------------------------------"
echo "| ⚠️	Verifique se o subdominio  '$URL_DB'"
echo "| 	Está apontando para $SERVER_IP"
echo "|------------------------------------------------------------"
echo -e "\n\n\n"
