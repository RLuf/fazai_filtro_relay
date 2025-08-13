# SMTP Relay Modular - Guia de Instalação
## Sistema Avançado de Filtragem para o Andarilho dos Véus

### 🎯 Características Principais

- **Filtragem Modular**: SPF, DKIM, RBL, Antivírus, IA anti-spam, YARA rules
- **Interface Web**: Dashboard em tempo real com estatísticas
- **SOCKS/Pipes**: Integração flexível com spamd e outros sistemas  
- **Análise por IA**: Claude integrado para detecção avançada de spam
- **Quarentena Inteligente**: Sistema de revisão e liberação manual
- **Logs Detalhados**: Auditoria completa de todas as decisões
- **Alta Performance**: Processamento assíncrono e cache Redis

### 📋 Pré-requisitos

```bash
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install -y \
    python3.11 python3-pip python3-venv \
    postgresql postgresql-contrib \
    redis-server \
    clamav clamav-daemon \
    yara \
    build-essential \
    git

# CentOS/RHEL
sudo dnf install -y \
    python3.11 python3-pip \
    postgresql postgresql-server postgresql-contrib \
    redis \
    clamav clamav-update \
    yara \
    gcc gcc-c++ make \
    git
```

### 🚀 Instalação Rápida

#### 1. Criação do Ambiente

```bash
# Cria usuário dedicado
sudo useradd -r -m -s /bin/bash smtp-relay
sudo mkdir -p /opt/smtp-relay
sudo chown smtp-relay:smtp-relay /opt/smtp-relay

# Muda para o usuário
sudo su - smtp-relay

# Cria ambiente virtual
cd /opt/smtp-relay
python3 -m venv venv
source venv/bin/activate

# Instala dependências
pip install --upgrade pip
cat > requirements.txt << 'EOF'
aiosmtpd==1.4.4.post2
aiohttp==3.9.1
asyncpg==0.29.0
redis==5.0.1
cryptography==41.0.8
yara-python==4.3.1
dnspython==2.4.2
py3dns==3.2.1
pyspf==2.0.14
dkimpy==1.1.5
flask==3.0.0
python-dateutil==2.8.2
psutil==5.9.6
EOF

pip install -r requirements.txt
```

#### 2. Configuração do Banco de Dados

```bash
# Volta para root
exit

# Inicializa PostgreSQL (se necessário)
sudo postgresql-setup --initdb  # CentOS/RHEL apenas
sudo systemctl enable postgresql
sudo systemctl start postgresql

# Configura banco
sudo -u postgres psql << 'EOF'
CREATE USER smtp_relay WITH PASSWORD 'SuaS3nh4Ult4S3cur4!';
CREATE DATABASE smtp_relay OWNER smtp_relay;
GRANT ALL PRIVILEGES ON DATABASE smtp_relay TO smtp_relay;
\q
EOF

# Aplica schema
sudo -u smtp-relay psql -h localhost -U smtp_relay -d smtp_relay << 'EOF'
-- Schema do banco (copiar do arquivo principal)
CREATE TABLE IF NOT EXISTS filter_log (
    id SERIAL PRIMARY KEY,
    message_id VARCHAR(255) NOT NULL,
    sender VARCHAR(255) NOT NULL,
    action VARCHAR(50) NOT NULL,
    score FLOAT NOT NULL,
    filter_results JSONB,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
-- Adicionar outras tabelas conforme o schema
EOF
```

#### 3. Configuração do Redis

```bash
# Inicia Redis
sudo systemctl enable redis
sudo systemctl start redis

# Testa conectividade
redis-cli ping  # Deve retornar PONG
```

#### 4. Configuração do ClamAV

```bash
# Configura ClamAV
sudo systemctl enable clamav-daemon
sudo systemctl enable clamav-freshclam

# Atualiza signatures
sudo freshclam

# Inicia serviços
sudo systemctl start clamav-freshclam
sudo systemctl start clamav-daemon

# Testa funcionamento
clamdscan --version
```

#### 5. Deploy do Sistema

```bash
# Volta para usuário smtp-relay
sudo su - smtp-relay
cd /opt/smtp-relay

# Cria configuração inicial
python3 -c "
import json
config = {
    'listen_host': '0.0.0.0',
    'listen_port': 2525,
    'security_level': 2,
    'score_threshold': 5.0,
    'redis': {'host': 'localhost', 'port': 6379, 'db': 0},
    'database': {
        'host': 'localhost', 'port': 5432,
        'user': 'smtp_relay', 'password': 'SuaS3nh4Ult4S3cur4!',
        'database': 'smtp_relay'
    },
    'filters': {
        'spf': {'enabled': True, 'weight': 1.0},
        'dkim': {'enabled': True, 'weight': 1.0},
        'blacklist': {'enabled': True, 'weight': 2.0},
        'virus': {'enabled': True, 'weight': 3.0},
        'ai_spam': {'enabled': True, 'weight': 2.0},
        'content': {'enabled': True, 'weight': 1.5}
    }
}
with open('config.json', 'w') as f:
    json.dump(config, f, indent=2)
"

# Cria diretórios necessários
mkdir -p templates rules logs

# Cria regras YARA básicas
cat > rules/email_rules.yar << 'EOF'
rule PhishingKeywords {
    strings:
        $a = "urgent action required" nocase
        $b = "verify your account" nocase
        $c = "click here immediately" nocase
        $d = "suspended account" nocase
        $e = "confirm identity" nocase
        $f = "update payment method" nocase
    condition:
        any of them
}

rule SuspiciousAttachments {
    strings:
        $exe = ".exe" nocase
        $scr = ".scr" nocase
        $pif = ".pif" nocase
        $bat = ".bat" nocase
        $cmd = ".cmd" nocase
        $com = ".com" nocase
    condition:
        any of them
}

rule BrazilianScams {
    strings:
        $a = "pix" nocase
        $b = "transferencia" nocase
        $c = "cpf" nocase
        $d = "documentos pendentes" nocase
        $e = "receita federal" nocase
        $f = "banco central" nocase
    condition:
        2 of them
}
EOF
```

### 🔧 Configuração Avançada

#### Integração SOCKS/Pipes

```bash
# Para integração com spamd via SOCKS
cat >> config.json << 'EOF'
{
  "socks_proxy": {
    "enabled": true,
    "host": "127.0.0.1",
    "port": 1080,
    "upstream_spamd": "127.0.0.1:783"
  },
  "pipe_integration": {
    "enabled": true,
    "spamd_path": "/usr/bin/spamc",
    "timeout": 30
  }
}
EOF
```

#### IA Anti-Spam (Claude)

```bash
# Adiciona configuração de IA
cat >> config.json << 'EOF'
{
  "filters": {
    "ai_spam": {
      "enabled": true,
      "weight": 2.0,
      "api_endpoint": "https://api.anthropic.com/v1/messages",
      "model": "claude-3-sonnet-20240229",
      "spam_threshold": 0.7,
      "analyze_headers": true,
      "analyze_attachments": true,
      "max_content_length": 2000
    }
  }
}
EOF
```

### 🛠 Configuração do Systemd

```bash
# Sai do usuário smtp-relay
exit

# Cria service file
sudo tee /etc/systemd/system/smtp-relay.service << 'EOF'
[Unit]
Description=SMTP Relay Modular - Andarilho dos Véus
After=network.target postgresql.service redis.service clamav-daemon.service
Wants=postgresql.service redis.service clamav-daemon.service

[Service]
Type=simple
User=smtp-relay
Group=smtp-relay
WorkingDirectory=/opt/smtp-relay
ExecStart=/opt/smtp-relay/venv/bin/python smtp_relay.py --config config.json --web-port 8080
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
Environment=PYTHONPATH=/opt/smtp-relay
Environment=PYTHONUNBUFFERED=1
LimitNOFILE=65536
MemoryMax=2G

[Install]
WantedBy=multi-user.target
EOF

# Habilita e inicia o serviço
sudo systemctl daemon-reload
sudo systemctl enable smtp-relay
sudo systemctl start smtp-relay

# Verifica status
sudo systemctl status smtp-relay
```

### 🔍 Monitoramento

#### Script de Monitoramento

```bash
# Cria script de monitoramento
sudo tee /opt/smtp-relay/monitor.sh << 'EOF'
#!/bin/bash
LOG_FILE="/var/log/smtp-relay-monitor.log"
SERVICE_NAME="smtp-relay"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> $LOG_FILE
}

# Verifica serviço
if ! systemctl is-active --quiet $SERVICE_NAME; then
    log_message "ERROR: SMTP Relay service is not running"
    systemctl start $SERVICE_NAME
fi

# Verifica dependências
if ! pg_isready -h localhost -p 5432 -U smtp_relay >/dev/null 2>&1; then
    log_message "WARNING: PostgreSQL connection failed"
fi

if ! redis-cli ping >/dev/null 2>&1; then
    log_message "WARNING: Redis connection failed"
fi

if ! clamdscan --version >/dev/null 2>&1; then
    log_message "WARNING: ClamAV not responding"
fi

log_message "Health check completed"
EOF

sudo chmod +x /opt/smtp-relay/monitor.sh

# Adiciona ao