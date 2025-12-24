#!/bin/bash
set +H

echo "|----------------------------------------------------"
echo "| 🚀 GESTOR DE PROJETOS & VPS"
echo "|----------------------------------------------------"

# 1. Busca arquivos .env locais
ENVS=($(ls *.env 2>/dev/null))
COUNT=${#ENVS[@]}
NOVO_PROJETO=false

if [ $COUNT -gt 0 ]; then
    echo "| 📂 Projetos salvos encontrados:"
    for i in "${!ENVS[@]}"; do
        echo "| [$((i+1))] ${ENVS[$i]}"
    done
    echo "| [$((COUNT+1))] ➕ Criar novas credenciais (Novo Projeto)"
    echo "|----------------------------------------------------"
    read -p "| 📌 Escolha uma opção: " OPT
    
    if [ "$OPT" -le "$COUNT" ]; then
        ENV_ESCOLHIDO="${ENVS[$((OPT-1))]}"
        echo "| 🔄 Carregando $ENV_ESCOLHIDO..."
        source "./$ENV_ESCOLHIDO"
    else
        NOVO_PROJETO=true
    fi
else
    NOVO_PROJETO=true
fi

# 2. SE FOR NOVO PROJETO, PEDE OS DADOS (CURSOR NA LINHA DE BAIXO)
if [ "$NOVO_PROJETO" = true ]; then
    echo -e "\n🏷️ Nome do Projeto (Sem espaços):"
    read NOME_PROJETO

    echo -e "\n🔑 Token DigitalOcean:"
    read DO_TOKEN

    echo -e "\n📧 Email Cloudflare:"
    read CF_EMAIL

    echo -e "\n🔑 Global API Key Cloudflare:"
    read CF_API_KEY

    echo -e "\n🗝️ Origin CA Key Cloudflare:"
    read ORIGIN_CA_KEY

    echo -e "\n🚪 Porta SSH (Ex: 2202):"
    read SSH_PORT

    echo -e "\n🚪 Porta MARIADB(Ex: 3307):"
    read DB_PORT

    echo -e "\n🤖 Telegram Bot Token:"
    read TELEGRAM_TOKEN




DROPLET_NAME="${NOME_PROJETO}"

MINHA_SENHA=$(cat /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 64)




echo "|----------------------------------------------------"
echo "| 🔐 Senha Root gerada automaticamente: $MINHA_SENHA"
echo -e "|----------------------------------------------------\n\n\n"

# -----------------------------------------------------------------------------
# 01b. SELECIONAR DOMÍNIO NO CLOUDFLARE
# -----------------------------------------------------------------------------
CF_DOMAINS_DATA=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones" \
     -H "X-Auth-Email: $CF_EMAIL" \
     -H "X-Auth-Key: $CF_API_KEY" \
     -H "Content-Type: application/json")

CF_MAP_NAMES=($(echo "$CF_DOMAINS_DATA" | jq -r '.result[].name'))
CF_MAP_IDS=($(echo "$CF_DOMAINS_DATA" | jq -r '.result[].id'))

echo "|----------------------------------------------------"
echo "| 🌐 Escolha o domínio para esta VPS:"
echo "|----------------------------------------------------"
echo "$CF_DOMAINS_DATA" | jq -r '.result | to_entries[] | "| [\(.key + 1)]\t\(.value.name)"'
read -p "| 📌 Opção: " CF_CHOICE

REAL_CF_INDEX=$((CF_CHOICE - 1))
TARGET_DOMAIN=${CF_MAP_NAMES[$REAL_CF_INDEX]}
ZONE_ID_ESCOLHIDA=${CF_MAP_IDS[$REAL_CF_INDEX]}

echo "|----------------------------------------------------"
echo "| ✅ Selecionado: $TARGET_DOMAIN"
echo -e "|----------------------------------------------------\n\n"

# -----------------------------------------------------------------------------
# 01. SELECIONAR PROJETO
# -----------------------------------------------------------------------------
echo "|----------------------------------------------------"
echo "| 🌐 Agora escolha um projeto para esse droplet:"
echo "|----------------------------------------------------"

PROJECTS_DATA=$(curl -s -H "Authorization: Bearer $DO_TOKEN" "https://api.digitalocean.com/v2/projects")
MAP_IDS=($(echo "$PROJECTS_DATA" | jq -r '.projects[].id'))
MAP_NAMES=($(echo "$PROJECTS_DATA" | jq -r '.projects[].name'))

echo "$PROJECTS_DATA" | jq -r '.projects | to_entries[] | "| [\(.key + 1)]\t\(.value.name)"'
read -p "| 📌 Escolha o projeto: " INDEX_CHOICE

REAL_INDEX=$((INDEX_CHOICE - 1))
PROJECT_ID=${MAP_IDS[$REAL_INDEX]}

echo "|----------------------------------------------------"
echo "| ✅ Selecionado: ${MAP_NAMES[$REAL_INDEX]}"
echo -e "|----------------------------------------------------"



DB_ROOT_PASSWORD=$MINHA_SENHA
DB_SYSTEM_PASSWORD=$(cat /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 64)
DOMAIN_CLEAN=$(echo "$TARGET_DOMAIN" | tr -d '[:space:]')
ZONE_ID_CLEAN=$(echo "$ZONE_ID_ESCOLHIDA" | tr -d '[:space:]')

URL_DB="mariadb.$DOMAIN_CLEAN"


cat <<EOF > "${NOME_PROJETO}.env"
DO_TOKEN="$DO_TOKEN"
CF_EMAIL="$CF_EMAIL"
CF_API_KEY="$CF_API_KEY"
ORIGIN_CA_KEY="$ORIGIN_CA_KEY"
NOME_PROJETO="$NOME_PROJETO"
TELEGRAM_TOKEN="$TELEGRAM_TOKEN"
TELEGRAM_CHAT_ID="$TELEGRAM_CHAT_ID"
TARGET_DOMAIN="$DOMAIN_CLEAN"
ZONE_ID_ESCOLHIDA="$ZONE_ID_CLEAN"
SSH_PORT="$SSH_PORT"
DB_PORT="$DB_PORT"
URL_DB="$URL_DB"
DB_ROOT_PASSWORD="$DB_ROOT_PASSWORD"
MINHA_SENHA="$DB_ROOT_PASSWORD"
DB_SYSTEM_PASSWORD="$DB_SYSTEM_PASSWORD"
EOF
    echo -e "\n| ✅ Credenciais salvas em ${NOME_PROJETO}.env"
fi


# 02. USER_DATA
# 02. USER_DATA (Garantindo que a senha seja inserida corretamente)
# Usamos aspas simples para proteger o conteúdo e deixamos o bash expandir apenas o necessário
USER_DATA_CONTENT="#!/bin/bash
sed -i 's/.*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/.*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
echo \"root:$MINHA_SENHA\" | chpasswd
systemctl restart ssh
( if [ ! -f /swapfile ]; then fallocate -l 2G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048; chmod 600 /swapfile; mkswap /swapfile; swapon /swapfile; echo \"/swapfile none swap sw 0 0\" >> /etc/fstab; fi ) &"

# 03. CRIAR DROPLET
echo -e "\n\n|----------------------------------------------------"
echo "| 🌊 Criando Droplet..."

# REMOVIDO: o campo "password" do JSON (a API da DigitalOcean não aceita esse campo na raiz)
# ALTERADO: região para "nyc3" (Atlanta/atl1 costuma dar erro de disponibilidade para AMD)
JSON_PAYLOAD=$(jq -n \
  --arg name "$NOME_PROJETO" \
  --arg ud "$USER_DATA_CONTENT" \
  '{
    name: $name, 
    region: "nyc3", 
    size: "s-2vcpu-4gb-amd", 
    image: "ubuntu-24-04-x64", 
    ipv6: true, 
    user_data: $ud
  }')

DROPLET_RES=$(curl -s -X POST "https://api.digitalocean.com/v2/droplets" \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer $DO_TOKEN" \
     -d "$JSON_PAYLOAD")

# Extração segura do ID
DROPLET_ID=$(echo "$DROPLET_RES" | jq -r '.droplet.id // empty')

# VERIFICAÇÃO DE ERRO: Se não criou o droplet, para o script aqui para evitar o loop infinito do JQ
if [ -z "$DROPLET_ID" ] || [ "$DROPLET_ID" == "null" ]; then
    echo "| ❌ ERRO AO CRIAR DROPLET!"
    echo "| Resposta da API: $DROPLET_RES"
    exit 1
fi

# Adiciona ao projeto
curl -s -X POST "https://api.digitalocean.com/v2/projects/$PROJECT_ID/resources" \
     -H "Authorization: Bearer $DO_TOKEN" \
     -H "Content-Type: application/json" \
     -d "{\"resources\": [\"do:droplet:$DROPLET_ID\"]}" > /dev/null

MY_IP=""
echo "| ⏳ Aguardando IP público (isso pode levar 30-60 segundos)..."
while [ -z "$MY_IP" ] || [ "$MY_IP" == "null" ]; do
    sleep 8
    # O sinal '?' em .v4[]? evita que o jq quebre se o campo ainda não existir
    MY_IP=$(curl -s -X GET "https://api.digitalocean.com/v2/droplets/$DROPLET_ID" \
         -H "Authorization: Bearer $DO_TOKEN" | jq -r '.droplet.networks.v4[]? | select(.type=="public") | .ip_address' | head -n 1)
done

echo "| ✅ IP Obtido: $MY_IP"


# -----------------------------------------------------------------------------
# 03b. NOVO: CRIAR DROPLET DO BANCO DE DADOS (MARIADB)
# -----------------------------------------------------------------------------
echo -e "\n|----------------------------------------------------"
echo "| 🗄️ Criando Droplet do MariaDB..."
DB_DROPLET_NAME="${NOME_PROJETO}-DB"

# 1. Payload Ajustado: Removido 'password' e trocado região para 'nyc3' (mais estável)
DB_PAYLOAD=$(jq -n \
  --arg name "$DB_DROPLET_NAME" \
  --arg ud "$USER_DATA_CONTENT" \
  '{
    name: $name, 
    region: "nyc3", 
    size: "s-1vcpu-2gb-amd", 
    image: "ubuntu-24-04-x64", 
    ipv6: true, 
    user_data: $ud
  }')

DB_RES=$(curl -s -X POST "https://api.digitalocean.com/v2/droplets" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $DO_TOKEN" \
  -d "$DB_PAYLOAD")

# 2. Extração segura do ID
DB_DROPLET_ID=$(echo "$DB_RES" | jq -r '.droplet.id // empty')

# Validação de erro imediata
if [ -z "$DB_DROPLET_ID" ] || [ "$DB_DROPLET_ID" == "null" ]; then
    echo "| ❌ ERRO AO CRIAR DROPLET DO BANCO!"
    echo "| Resposta da API: $DB_RES"
    exit 1
fi

# 3. Adiciona ao projeto DO
curl -s -X POST "https://api.digitalocean.com/v2/projects/$PROJECT_ID/resources" \
  -H "Authorization: Bearer $DO_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"resources\": [\"do:droplet:$DB_DROPLET_ID\"]}" > /dev/null

# 4. Loop de obtenção de IP com proteção contra erro do JQ
IP_MARIADB_NOVO=""
echo "| ⏳ Aguardando IP do MariaDB..."
while [ -z "$IP_MARIADB_NOVO" ] || [ "$IP_MARIADB_NOVO" == "null" ]; do
    sleep 5
    # O uso do '?' em .v4[]? impede o erro se a rede ainda não existir
    IP_MARIADB_NOVO=$(curl -s -X GET "https://api.digitalocean.com/v2/droplets/$DB_DROPLET_ID" \
      -H "Authorization: Bearer $DO_TOKEN" | jq -r '.droplet.networks.v4[]? | select(.type=="public") | .ip_address' | head -n 1)
done

echo "| ✅ IP MariaDB Obtido: $IP_MARIADB_NOVO"

#-----------------------------------------------------------------------------
# 04. APONTAMENTO DNS (CLOUDFLARE)
#-----------------------------------------------------------------------------
ZONE_ID_CLEAN=$(echo "$ZONE_ID_ESCOLHIDA" | tr -d '[:space:]')
DOMAIN_CLEAN=$(echo "$TARGET_DOMAIN" | tr -d '[:space:]')


echo "|----------------------------------------------------"
echo "| 📡 Verificando e Apontando DNS"
echo "|----------------------------------------------------"

# Lista de registros para apontar: [NOME_DO_REGISTRO]:[IP_DESTINO]
# Adicionamos o subdomínio mariadb à lista
REGISTROS=(
    "$DOMAIN_CLEAN:$MY_IP"
    "www.$DOMAIN_CLEAN:$MY_IP"
    "mariadb.$DOMAIN_CLEAN:$IP_MARIADB_NOVO"
)

for item in "${REGISTROS[@]}"; do
    NOME=$(echo $item | cut -d: -f1)
    IP=$(echo $item | cut -d: -f2)

    # 1. Busca o ID do registro específico
    EXISTING_RECORD_DATA=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID_CLEAN/dns_records?name=$NOME&type=A" \
        -H "X-Auth-Email: $CF_EMAIL" \
        -H "X-Auth-Key: $CF_API_KEY" \
        -H "Content-Type: application/json")

    RECORD_ID=$(echo "$EXISTING_RECORD_DATA" | jq -r '.result[0].id // empty')

    if [ -n "$RECORD_ID" ] && [ "$RECORD_ID" != "null" ]; then
        echo "| 🔄 Atualizando: $NOME -> $IP (ID: $RECORD_ID)"
        curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$ZONE_ID_CLEAN/dns_records/$RECORD_ID" \
            -H "X-Auth-Email: $CF_EMAIL" \
            -H "X-Auth-Key: $CF_API_KEY" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"A\",\"name\":\"$NOME\",\"content\":\"$IP\",\"ttl\":1,\"proxied\":true}" > /dev/null
    else
        echo "| ✨ Criando novo: $NOME -> $IP"
        curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID_CLEAN/dns_records" \
            -H "X-Auth-Email: $CF_EMAIL" \
            -H "X-Auth-Key: $CF_API_KEY" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"A\",\"name\":\"$NOME\",\"content\":\"$IP\",\"ttl\":1,\"proxied\":true}" > /dev/null
    fi
done


echo -e "\n\n\n|----------------------------------------------------"
echo "| 🛡️ 1. Desativar Proteção de E-mail (Email Obfuscation)"
echo "|----------------------------------------------------"

curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$ZONE_ID_CLEAN/settings/email_obfuscation" \
     -H "X-Auth-Email: $CF_EMAIL" \
     -H "X-Auth-Key: $CF_API_KEY" \
     -H "Content-Type: application/json" \
     --data '{"value":"off"}'

echo -e "\n\n\n|----------------------------------------------------"
echo "| 🛡️ 2. Alterar Modo SSL para 'Flexible'"
echo "|----------------------------------------------------"

curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$ZONE_ID_CLEAN/settings/ssl" \
     -H "X-Auth-Email: $CF_EMAIL" \
     -H "X-Auth-Key: $CF_API_KEY" \
     -H "Content-Type: application/json" \
     --data '{"value":"full"}'
    #  --data '{"value":"flexible"}'

echo -e "\n\n\n|----------------------------------------------------"
echo "| 🛡️ 3. Desativar Rocket Loader"
echo "|----------------------------------------------------"

curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$ZONE_ID_CLEAN/settings/rocket_loader" \
     -H "X-Auth-Email: $CF_EMAIL" \
     -H "X-Auth-Key: $CF_API_KEY" \
     -H "Content-Type: application/json" \
     --data '{"value":"off"}'

echo -e "\n|----------------------------------------------------"
echo "| 🛡️ 4. Desativar Web Analytics (RUM)"
echo "|----------------------------------------------------"

curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$ZONE_ID_CLEAN/settings/rum" \
     -H "X-Auth-Email: $CF_EMAIL" \
     -H "X-Auth-Key: $CF_API_KEY" \
     -H "Content-Type: application/json" \
     --data '{"value":"off"}'

echo -e "\n\n\n|----------------------------------------------------"
echo "| 🛡️ 5. Limpa todo cache do CloudFlare"
echo "|----------------------------------------------------"

# Limpa todo o cache da Cloudflare para forçar a remoção do script
curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID_CLEAN/purge_cache" \
     -H "X-Auth-Email: $CF_EMAIL" \
     -H "X-Auth-Key: $CF_API_KEY" \
     -H "Content-Type: application/json" \
     --data '{"purge_everything":true}'



ARQUIVO_LOG="./$NOME_PROJETO.txt"
echo "|----------------------------------------------------" > "$ARQUIVO_LOG"
echo "| ✅ PROCESSO FINALIZADO">> "$ARQUIVO_LOG"
echo "| 📎 IP:   $MY_IP" >> "$ARQUIVO_LOG"
echo "| 🚪 SSH_PORT: $SSH_PORT" >> "$ARQUIVO_LOG"
echo "| 🌐 ZONE_ID: $ZONE_ID_ESCOLHIDA">> "$ARQUIVO_LOG"
echo "| 🌐 DOMINIO: $TARGET_DOMAIN">> "$ARQUIVO_LOG"
echo "| 🔑 ACESSO SSH: ssh root@$MY_IP -p $SSH_PORT" >> "$ARQUIVO_LOG"
echo "|"
echo "| 🔑 SENHA (DB + SERVER): $MINHA_SENHA" >> "$ARQUIVO_LOG"
echo "|"
echo "| 📎 IP-DB:   $IP_MARIADB_NOVO" >> "$ARQUIVO_LOG"
echo "| 🌐 DB: $URL_DB">> "$ARQUIVO_LOG"
echo "| 🔑 ACESSO SSH: ssh root@$IP_MARIADB_NOVO -p $SSH_PORT" >> "$ARQUIVO_LOG"
echo "| 🔑 USER ADMIN:	webmaster > $DB_ROOT_PASSWORD" >> "$ARQUIVO_LOG"
echo "| 🔑 USER SYSTEM: system > $DB_SYSTEM_PASSWORD" >> "$ARQUIVO_LOG"
echo "| 🔑 CONEXÃO: $IP_MARIADB_NOVO:$DB_PORT" >> "$ARQUIVO_LOG"
echo "| 🔑 SENHA-CONEXÃO: $DB_SYSTEM_PASSWORD" >> "$ARQUIVO_LOG"
echo "|----------------------------------------------------" >> "$ARQUIVO_LOG"



#-----------------------------------------------------------------------------
# 04b. CONFIGURAÇÃO DE WAF (PAÍSES + RATE LIMIT)
#-----------------------------------------------------------------------------
echo -e "\n\n\n|----------------------------------------------------"
echo "| 🛡️ CONFIGURANDO SEGURANÇA (MODO COMPATIBILIDADE)"
echo "|----------------------------------------------------"

# 1. BUSCAR IDs DOS RULESETS (Necessário para o WAF Moderno)
RULESETS_RAW=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID_CLEAN/rulesets" \
     -H "X-Auth-Email: $CF_EMAIL" -H "X-Auth-Key: $CF_API_KEY")

RULESET_WAF_ID=$(echo "$RULESETS_RAW" | jq -r '.result[] | select(.phase=="http_request_firewall_custom") | .id')
RULESET_RATE_ID=$(echo "$RULESETS_RAW" | jq -r '.result[] | select(.phase=="http_ratelimit") | .id')

# --- WAF: BLOQUEIO DE PAÍSES (POST para evitar erro de substituição) ---
echo "| 🛰️ Criando Regra de Países..."
curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID_CLEAN/rulesets/$RULESET_WAF_ID/rules" \
     -H "X-Auth-Email: $CF_EMAIL" -H "X-Auth-Key: $CF_API_KEY" -H "Content-Type: application/json" \
     --data '{
      "action": "block",
      "expression": "(ip.geoip.country in {\"CN\" \"RU\" \"KP\" \"IN\"})",
      "description": "Blacklist Paises"
    }' > /dev/null


# 05. ESPERA SSH
echo "| ⏳ Aguardando a rede do servidor (Porta 22)..."
ssh-keygen -R "$MY_IP" 2>/dev/null >/dev/null
while ! (timeout 2 bash -c "</dev/tcp/$MY_IP/22") >/dev/null 2>&1; do
    echo -ne "| 🔄 Aguarde, servidor ligando...\r"
    sleep 5
done
echo -e "| ✅ Rede detectada! Aguardando 10s para estabilização..."
sleep 10


# 06. TRANSFERÊNCIA E EXECUÇÃO
echo -e "\n\n|----------------------------------------------------"
echo "| 🔑 SENHA PARA COPIAR: $MINHA_SENHA"
echo "|----------------------------------------------------"
echo "|"
echo "| 📤 Upload setup.sh"
echo "| Insira a senha, se não der certo, aguarde 1 minuto e tente novamente"
echo "|"
echo "|----------------------------------------------------"
until scp -o StrictHostKeyChecking=no ./setup.sh root@$MY_IP:/root/setup.sh; do
    echo -e "\n\n|----------------------------------------------------"
    echo "| ⚠️  SSH ainda não aceitou a senha. Re-tentando em 15s..."
    echo -e "|---------------------------------------------------- \n\n"
    sleep 15
done

echo -e "\n\n|----------------------------------------------------"
echo "| ✅ Upload feito com sucesso!"
echo "| 🔑 Agora insira novamente a senha para executar o script!"
echo -e "|----------------------------------------------------"
#-----------------------------------------------------------------------------
# 06. EXECUÇÃO REMOTA (EXPANDINDO VARIÁVEIS CORRETAMENTE)
#-----------------------------------------------------------------------------
echo -e "\n| 🚀 Iniciando configuração remota..."

# SEM aspas no BUNKER para que o seu PC substitua os valores antes de enviar
ssh -t -o StrictHostKeyChecking=no root@$MY_IP <<BUNKER
    export CF_EMAIL='$CF_EMAIL'
    export CF_API_KEY='$CF_API_KEY'
    export ORIGIN_CA_KEY='$ORIGIN_CA_KEY'
    export SSH_PORT='$SSH_PORT'
    export NOME_PROJETO='$NOME_PROJETO'
    export TELEGRAM_TOKEN='$TELEGRAM_TOKEN'
    export TELEGRAM_CHAT_ID='$TELEGRAM_CHAT_ID'
    export IP_MARIADB='$IP_MARIADB_NOVO'
    export TARGET_DOMAIN='$DOMAIN_CLEAN'
    export ZONE_ID='$ZONE_ID_CLEAN'
    # Remove caracteres do Windows e executa no servidor
    sed -i 's/\r$//' /root/setup.sh
    chmod +x /root/setup.sh
    /bin/bash /root/setup.sh
BUNKER


# Versão correta e limpa:
until scp -o StrictHostKeyChecking=no ./mariadb.sh root@$IP_MARIADB_NOVO:/root/mariadb.sh; do
    echo "| ⚠️  SSH ainda não aceitou a senha. Re-tentando em 10s..."
    sleep 10
done


ssh -t -o StrictHostKeyChecking=no root@$IP_MARIADB_NOVO <<BUNKER_MARIADB
    export SSH_PORT='$SSH_PORT'
    export DB_PORT='$DB_PORT'
    export URL_DB='$URL_DB'
	export ORIGIN_CA_KEY='$ORIGIN_CA_KEY'
    export DB_ROOT_PASSWORD='$DB_ROOT_PASSWORD'
    export DB_SYSTEM_PASSWORD='$DB_SYSTEM_PASSWORD'
    # Remove caracteres do Windows e executa no servidor
    sed -i 's/\r$//' /root/mariadb.sh
    chmod +x /root/mariadb.sh
    /bin/bash /root/mariadb.sh
BUNKER_MARIADB

echo "|----------------------------------------------------"
echo "| ACESSE: cloudflare > SSL/TLS > Servidor de origem"
echo "| Crie novo certificado e substitua "
echo "|----------------------------------------------------"

# 07. FINALIZAÇÃO
echo -e "\n\n"
cat "$ARQUIVO_LOG"
echo -e "\n"


