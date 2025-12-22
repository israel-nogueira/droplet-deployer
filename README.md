# 🛡️ Bunker Droplet Deployer

Este repositório contém um ecossistema de automação em Bash para provisionar, configurar e blindar servidores (Droplets) na **DigitalOcean**, integrando-os nativamente com a **Cloudflare**.

Com um único comando, você transforma um servidor vazio em uma infraestrutura de alta performance com **Apache (MPM Event)**, **PHP 8.2-FPM**, **SSL Origin CA de 15 anos** e um sistema de **notificação de ataques via Telegram**.

## 🚀 Funcionalidades Principal

* **Automação Total**: Criação do Droplet via API v2 da DigitalOcean.
* **DNS Inteligente**: Apontamento automático (ou atualização) de registros A e www na Cloudflare.
* **Segurança Nativa (WAF)**:
* Configuração de regras de Firewall na Cloudflare (Bloqueio de países como CN, RU, KP, IN).
* Instalação de **ModSecurity** com regras OWASP.
* **Fail2Ban** integrado à API da Cloudflare (Bane o IP na borda, não apenas no servidor).

* **Criptografia**: Geração de certificados SSL Origin da Cloudflare com validade de 15 anos.
* **Blindagem SSH**: Alteração de porta padrão e fechamento de portas via UFW (liberando apenas IPs da Cloudflare).
* **Alertas**: Notificações em tempo real via **Telegram Bot** para cada IP banido.

---

## 🛠️ Pré-requisitos

Antes de começar, você precisará das seguintes credenciais:

1. **DigitalOcean**: [Personal Access Token](https://cloud.digitalocean.com/account/api/tokens).
2. **Cloudflare**:
* Global API Key.
* Origin CA Key (para o SSL de 15 anos).
* Email da conta.

3. **Telegram** (Opcional): Token de um Bot criado pelo [@BotFather](https://t.me/botfather).

---

## 📦 Estrutura dos Arquivos

* `index.sh`: O orquestrador local. Ele solicita os dados, cria a máquina na DigitalOcean, configura o DNS e inicia o upload.
* `setup.sh`: O executor remoto. Ele roda dentro da nova VPS para instalar o stack LAMP/LEMP, configurar o firewall e aplicar as regras de segurança.

---

## 📖 Como Usar

### 1. Clonar o repositório

```bash
git clone https://github.com/israel-nogueira/droplet-deployer.git
cd droplet-deployer
chmod +x index.sh setup.sh

```

### 2. Iniciar o Provisionamento

```bash
./index.sh

```

### 3. Fluxo de Instalação

1. **Perfil**: O script perguntará se deseja usar um perfil `.env` salvo ou criar um novo.
2. **Dados**: Insira suas chaves de API quando solicitado.
3. **Seleção**: O script buscará em tempo real seus **Domínios na Cloudflare** e seus **Projetos na DigitalOcean** para você escolher via menu numérico.
4. **Aguarde**: O script criará a máquina, aguardará o SSH ficar disponível e fará o deploy automático.
5. **Telegram**: Se você não forneceu um Chat ID, o script pausará e pedirá para você digitar `/registrar` no seu grupo de Telegram para capturar o ID automaticamente.

---

## 🛡️ Stack Técnica Instalada

| Componente | Versão / Configuração |
| --- | --- |
| **OS** | Ubuntu 24.04 LTS |
| **Web Server** | Apache 2.4 (MPM Event + Proxy FastCGI) |
| **Linguagem** | PHP 8.2-FPM & Node.js 20.x |
| **SSL** | Cloudflare Origin CA (RSA 2048) |
| **Firewall** | UFW (Whitelisted Cloudflare IPs Only) |
| **Segurança** | ModSecurity + Fail2Ban + Fail2Ban Cloudflare Action |

---

## ⚠️ Observações Importantes

* **Porta SSH**: O script altera a porta SSH padrão. Certifique-se de anotar a porta escolhida para acessos futuros.
* **Log de Acesso**: Ao final da execução, um arquivo chamado `NOME_DO_PROJETO.txt` será criado na pasta local contendo todas as credenciais, IPs e senhas da nova máquina. **Proteja este arquivo!**
* **Troca de Senha**: A senha do root é gerada aleatoriamente com 64 caracteres para garantir segurança máxima durante o provisionamento.

---

## 🤝 Contribuição

Sinta-se à vontade para abrir *Issues* ou enviar *Pull Requests*. Para mudanças maiores, abra uma discussão primeiro para explicar o que gostaria de alterar.
