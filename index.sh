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

    echo -e "\n🗄️ IP do MariaDB Externo:"
    read IP_MARIADB

    echo -e "\n🚪 Porta SSH (Ex: 2202):"
    read SSH_PORT

    echo -e "\n🤖 Telegram Bot Token:"
    read TELEGRAM_TOKEN

    echo -e "\n🆔 Telegram Chat ID (ou deixe vazio para capturar no servidor):"
    read TELEGRAM_CHAT_ID

    # Salva localmente para a próxima vez
    cat <<EOF > "${NOME_PROJETO}.env"
NOME_PROJETO="$NOME_PROJETO"
DO_TOKEN="$DO_TOKEN"
CF_EMAIL="$CF_EMAIL"
CF_API_KEY="$CF_API_KEY"
ORIGIN_CA_KEY="$ORIGIN_CA_KEY"
IP_MARIADB="$IP_MARIADB"
SSH_PORT="$SSH_PORT"
TELEGRAM_TOKEN="$TELEGRAM_TOKEN"
TELEGRAM_CHAT_ID="$TELEGRAM_CHAT_ID"
EOF
    echo -e "\n| ✅ Credenciais salvas em ${NOME_PROJETO}.env"
fi

DROPLET_NAME="${NOME_PROJETO}"
MINHA_SENHA=$(cat /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 64)
# O restante do index.sh (Cloudflare, Criação do Droplet, etc) continua igual


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
DOMAIN_ESCOLHIDO=${CF_MAP_NAMES[$REAL_CF_INDEX]}
ZONE_ID_ESCOLHIDA=${CF_MAP_IDS[$REAL_CF_INDEX]}

echo "|----------------------------------------------------"
echo "| ✅ Selecionado: $DOMAIN_ESCOLHIDO"
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

# 02. USER_DATA
USER_DATA_CONTENT="#!/bin/bash
sed -i 's/.*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/.*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
echo \"root:$MINHA_SENHA\" | chpasswd
systemctl restart ssh
( if [ ! -f /swapfile ]; then fallocate -l 2G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048; chmod 600 /swapfile; mkswap /swapfile; swapon /swapfile; echo \"/swapfile none swap sw 0 0\" >> /etc/fstab; fi ) &"

# 03. CRIAR DROPLET
echo -e "\n\n|----------------------------------------------------"
echo "| 🌊 Criando Droplet..."
JSON_PAYLOAD=$(jq -n --arg name "$DROPLET_NAME" --arg password "$MINHA_SENHA" --arg user_data "$USER_DATA_CONTENT" '{name: $name, region: "atl1", size: "s-2vcpu-4gb-amd", image: "ubuntu-24-04-x64", password: $password, ipv6: true, user_data: $user_data}')

DROPLET_RES=$(curl -s -X POST "https://api.digitalocean.com/v2/droplets" -H "Content-Type: application/json" -H "Authorization: Bearer $DO_TOKEN" -d "$JSON_PAYLOAD")
DROPLET_ID=$(echo "$DROPLET_RES" | jq -r '.droplet.id // empty')

curl -s -X POST "https://api.digitalocean.com/v2/projects/$PROJECT_ID/resources" -H "Authorization: Bearer $DO_TOKEN" -H "Content-Type: application/json" -d "{\"resources\": [\"do:droplet:$DROPLET_ID\"]}" > /dev/null

MY_IP=""
while [ -z "$MY_IP" ] || [ "$MY_IP" == "null" ]; do
    sleep 5
    MY_IP=$(curl -s -X GET "https://api.digitalocean.com/v2/droplets/$DROPLET_ID" -H "Authorization: Bearer $DO_TOKEN" | jq -r '.droplet.networks.v4[] | select(.type=="public") | .ip_address' | head -n 1)
done
echo "| ✅ IP Obtido: $MY_IP"

#-----------------------------------------------------------------------------
# 04. APONTAMENTO DNS (CLOUDFLARE) - INTELIGENTE (CREATE OU UPDATE)
#-----------------------------------------------------------------------------
ZONE_ID_CLEAN=$(echo "$ZONE_ID_ESCOLHIDA" | tr -d '[:space:]')
DOMAIN_CLEAN=$(echo "$DOMAIN_ESCOLHIDO" | tr -d '[:space:]')

echo "|----------------------------------------------------"
echo "| 📡 Verificando e Apontando DNS para: $MY_IP"
echo "|----------------------------------------------------"

for registro in "$DOMAIN_CLEAN" "www.$DOMAIN_CLEAN"; do
    # 1. Busca se o registro já existe para pegar o ID dele
    EXISTING_RECORD_DATA=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID_CLEAN/dns_records?name=$registro&type=A" \
        -H "X-Auth-Email: $CF_EMAIL" \
        -H "X-Auth-Key: $CF_API_KEY" \
        -H "Content-Type: application/json")

    RECORD_ID=$(echo "$EXISTING_RECORD_DATA" | jq -r '.result[0].id // empty')

    if [ -n "$RECORD_ID" ] && [ "$RECORD_ID" != "null" ]; then
        echo "| 🔄 Atualizando IP do DNS existente: $registro (ID: $RECORD_ID)..."
        # 2. Se existe, dá UPDATE (PATCH)
        curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$ZONE_ID_CLEAN/dns_records/$RECORD_ID" \
            -H "X-Auth-Email: $CF_EMAIL" \
            -H "X-Auth-Key: $CF_API_KEY" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"A\",\"name\":\"$registro\",\"content\":\"$MY_IP\",\"ttl\":1,\"proxied\":true}" > /dev/null
    else
        echo "| ✨ Criando novo registro DNS: $registro ..."
        # 3. Se não existe, cria do zero (POST)
        curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID_CLEAN/dns_records" \
            -H "X-Auth-Email: $CF_EMAIL" \
            -H "X-Auth-Key: $CF_API_KEY" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"A\",\"name\":\"$registro\",\"content\":\"$MY_IP\",\"ttl\":1,\"proxied\":true}" > /dev/null
    fi
done

ARQUIVO_LOG="./$DROPLET_NAME.txt"
echo "|----------------------------------------------------" > "$ARQUIVO_LOG"
echo "| ✅ PROCESSO FINALIZADO">> "$ARQUIVO_LOG"
echo "| 📎 IP:   $MY_IP" >> "$ARQUIVO_LOG"
echo "| 🚪 SSH_PORT: $SSH_PORT" >> "$ARQUIVO_LOG"
echo "| 🌐 ZONE_ID: $ZONE_ID_ESCOLHIDA">> "$ARQUIVO_LOG"
echo "| 🌐 DOMINIO: $DOMAIN_ESCOLHIDO">> "$ARQUIVO_LOG"
echo "| 🔑 ACESSO SSH: ssh root@$MY_IP -p $SSH_PORT" >> "$ARQUIVO_LOG"
echo "| 🔑 PASS: $MINHA_SENHA" >> "$ARQUIVO_LOG"
echo "|----------------------------------------------------" >> "$ARQUIVO_LOG"


#-----------------------------------------------------------------------------
# 04b. CONFIGURAÇÃO DE WAF (PAÍSES + RATE LIMIT)
#-----------------------------------------------------------------------------
echo "|----------------------------------------------------"
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
echo -e "\n| ✅ Rede detectada! Aguardando 10s para estabilização..."
sleep 10


# 06. TRANSFERÊNCIA E EXECUÇÃO
echo -e "\n|----------------------------------------------------"
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
# 06. EXECUÇÃO REMOTA (CORRIGIDA)
#-----------------------------------------------------------------------------
echo -e "\n| 🚀 Iniciando configuração remota..."
ssh -t -o StrictHostKeyChecking=no root@$MY_IP <<BUNKER
 export CF_EMAIL='$CF_EMAIL'
 export CF_API_KEY='$CF_API_KEY'
 export ORIGIN_CA_KEY='$ORIGIN_CA_KEY'
 export SSH_PORT='$SSH_PORT'
 export NOME_PROJETO='$NOME_PROJETO'
 export TELEGRAM_TOKEN='$TELEGRAM_TOKEN'
 export TELEGRAM_CHAT_ID='$TELEGRAM_CHAT_ID'
 export IP_MARIADB='$IP_MARIADB'
 export TARGET_DOMAIN='$DOMAIN_CLEAN'
 export ZONE_ID='$ZONE_ID_CLEAN'
 sed -i 's/\r$//' /root/setup.sh
 chmod +x /root/setup.sh
 /bin/bash /root/setup.sh
BUNKER



# 07. FINALIZAÇÃO
echo "|-------------------------------------"
echo "| ✅ PROCESSO FINALIZADO"
echo "| 📎 IP:   $MY_IP" 
echo "| 🔑 PASS: $MINHA_SENHA" 
echo "| 🚪 SSH_PORT: $SSH_PORT" 
echo "| 🌐 ZONE_ID: $ZONE_ID_ESCOLHIDA"
echo "| 🌐 DOMINIO: $DOMAIN_ESCOLHIDO"
echo "| 🔗 SSH: ssh root@$MY_IP -p $SSH_PORT"
echo "|-------------------------------------"