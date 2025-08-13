for i in {1..100}; do
    (echo "EHLO test$i.local"; echo "QUIT") | nc localhost 2525 >/dev/null 2>&1 &
done
wait
echo "   Flood test concluído"

# Teste 2: Email com conteúdo malicioso
echo "2. Testando detecção de conteúdo malicioso..."
cat > /tmp/malicious_email.eml << 'MALEOF'
From: attacker@evil.com
To: victim@localhost
Subject: URGENT: Your account will be suspended!!!

Dear Customer,

Your account will be SUSPENDED in 24 hours unless you CLICK HERE IMMEDIATELY:
http://phishing-site.evil/steal-credentials

This is your FINAL WARNING! Act now or lose access forever!

Best regards,
Fake Bank Security Team
MALEOF

# Envia email malicioso
(
    echo "EHLO evil.local"
    echo "MAIL FROM:<attacker@evil.com>"
    echo "RCPT TO:<victim@localhost>"
    echo "DATA"
    cat /tmp/malicious_email.eml
    echo "."
    echo "QUIT"
) | nc localhost 2525

rm /tmp/malicious_email.eml

# Teste 3: Anexo EICAR (teste de vírus)
echo "3. Testando detecção de vírus..."
cat > /tmp/virus_email.eml << 'VIRUSEOF'
From: virus@test.com
To: target@localhost
Subject: Teste de Vírus
Content-Type: multipart/mixed; boundary="boundary123"

--boundary123
Content-Type: text/plain

Este email contém um anexo de teste EICAR.

--boundary123
Content-Type: application/octet-stream; name="test.txt"
Content-Disposition: attachment; filename="test.txt"

X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
--boundary123--
VIRUSEOF

(
    echo "EHLO virus-test.local"  
    echo "MAIL FROM:<virus@test.com>"
    echo "RCPT TO:<target@localhost>"
    echo "DATA"
    cat /tmp/virus_email.eml
    echo "."
    echo "QUIT"
) | nc localhost 2525

rm /tmp/virus_email.eml

echo "=== Testes concluídos. Verifique logs e quarentena ==="
EOF

chmod +x /opt/smtp-relay/pentest.sh
```

### 10. Configuração Multi-Instância (Load Balancing)

```bash
# Configuração para múltiplas instâncias
cat > /opt/smtp-relay/deploy-cluster.sh << 'EOF'
#!/bin/bash

# Configurações do cluster
INSTANCES=3
BASE_PORT=2525
BASE_WEB_PORT=8080
LOAD_BALANCER_PORT=25

# Cria configurações para cada instância
for i in $(seq 1 $INSTANCES); do
    SMTP_PORT=$((BASE_PORT + i - 1))
    WEB_PORT=$((BASE_WEB_PORT + i - 1))
    
    # Cria diretório da instância
    mkdir -p /opt/smtp-relay/instance-$i
    
    # Copia configuração base e ajusta portas
    jq --arg sport "$SMTP_PORT" --arg wport "$WEB_PORT" \
       '.server.listen_port = ($sport | tonumber) | 
        .web_interface.port = ($wport | tonumber) |
        .redis.db = '$i' |
        .logging.file = "/var/log/smtp-relay/instance-'$i'.log"' \
       /opt/smtp-relay/config.json > /opt/smtp-relay/instance-$i/config.json
    
    # Cria service file
    sudo tee /etc/systemd/system/smtp-relay-$i.service << SERVICEEOF
[Unit]
Description=SMTP Relay Instance $i - Andarilho dos Véus
After=network.target postgresql.service redis.service

[Service]
Type=simple
User=smtp-relay
Group=smtp-relay
WorkingDirectory=/opt/smtp-relay/instance-$i
ExecStart=/opt/smtp-relay/venv/bin/python /opt/smtp-relay/smtp_relay.py --config config.json
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICEEOF
    
    # Habilita serviço
    sudo systemctl enable smtp-relay-$i
    echo "Instância $i configurada (SMTP: $SMTP_PORT, Web: $WEB_PORT)"
done

# Configura HAProxy para load balancing
sudo tee /etc/haproxy/haproxy.cfg << 'HAPROXYEOF'
global
    daemon
    maxconn 4096

defaults
    mode tcp
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms

frontend smtp_frontend
    bind *:25
    default_backend smtp_backend

backend smtp_backend
    balance roundrobin
    server smtp1 127.0.0.1:2525 check
    server smtp2 127.0.0.1:2526 check
    server smtp3 127.0.0.1:2527 check

frontend web_frontend
    bind *:80
    mode http
    default_backend web_backend

backend web_backend
    mode http
    balance roundrobin
    server web1 127.0.0.1:8080 check
    server web2 127.0.0.1:8081 check
    server web3 127.0.0.1:8082 check
HAPROXYEOF

sudo systemctl enable haproxy
echo "Cluster configurado! Inicie com: sudo systemctl start smtp-relay-{1..3} haproxy"
EOF

chmod +x /opt/smtp-relay/deploy-cluster.sh
```

### 11. Automação com Ansible

```yaml
# ansible/playbook.yml
---
- name: Deploy SMTP Relay - Andarilho dos Véus
  hosts: mail_servers
  become: yes
  vars:
    smtp_relay_version: "1.0.0"
    smtp_relay_user: "smtp-relay"
    
  tasks:
    - name: Cria usuário do sistema
      user:
        name: "{{ smtp_relay_user }}"
        system: yes
        shell: /bin/bash
        home: /opt/smtp-relay
        # Exemplos Práticos - SMTP Relay do Andarilho dos Véus

## 🎯 Cenários de Uso Real

### 1. Configuração Inicial Completa

```bash
# 1. Download e instalação
wget https://github.com/seu-repo/smtp-relay/archive/main.zip
unzip main.zip && cd smtp-relay-main

# 2. Executa instalação automática
sudo ./install.sh --full-install

# 3. Configura com wizard interativo
sudo ./configure.sh --wizard

# 4. Testa instalação
./manage.sh test-system
```

### 2. Integração com Postfix Existente

```bash
# Backup da configuração atual
sudo cp /etc/postfix/main.cf /etc/postfix/main.cf.backup

# Configura Postfix para usar o relay
sudo tee -a /etc/postfix/main.cf << 'EOF'
# SMTP Relay Integration - Andarilho dos Véus
content_filter = smtp-amavis:[127.0.0.1]:2525

# Configurações específicas
smtp_always_send_ehlo = yes
smtp_connection_cache_on_demand = no
smtp_connection_reuse_time_limit = 300s

# Fallback se relay estiver offline
relay_domains = 
transport_maps = hash:/etc/postfix/transport

# Configurações de timeout
smtp_connect_timeout = 30s
smtp_helo_timeout = 300s
smtp_mail_timeout = 300s
smtp_data_timeout = 1800s
smtp_quit_timeout = 300s
EOF

# Configura transporte
echo "seu-dominio.com smtp:[127.0.0.1]:2525" | sudo tee -a /etc/postfix/transport
sudo postmap /etc/postfix/transport

# Reinicia Postfix
sudo systemctl restart postfix
```

### 3. Configuração de Filtros por Nível de Segurança

```json
// Configuração BAIXA (desenvolvimento/teste)
{
  "security_level": 1,
  "score_threshold": 8.0,
  "filters": {
    "spf": {"enabled": true, "weight": 0.5},
    "dkim": {"enabled": false},
    "blacklist": {"enabled": true, "weight": 1.0},
    "virus": {"enabled": true, "weight": 2.0},
    "ai_spam": {"enabled": false},
    "content": {"enabled": false}
  }
}

// Configuração MÉDIA (produção normal)
{
  "security_level": 2,
  "score_threshold": 5.0,
  "filters": {
    "spf": {"enabled": true, "weight": 1.0},
    "dkim": {"enabled": true, "weight": 1.0},
    "blacklist": {"enabled": true, "weight": 2.0},
    "virus": {"enabled": true, "weight": 3.0},
    "ai_spam": {"enabled": true, "weight": 1.5},
    "content": {"enabled": true, "weight": 1.0}
  }
}

// Configuração ALTA (ambiente crítico)
{
  "security_level": 3,
  "score_threshold": 3.0,
  "filters": {
    "spf": {"enabled": true, "weight": 2.0},
    "dkim": {"enabled": true, "weight": 2.0},
    "blacklist": {"enabled": true, "weight": 3.0},
    "virus": {"enabled": true, "weight": 5.0},
    "ai_spam": {"enabled": true, "weight": 3.0},
    "content": {"enabled": true, "weight": 2.0},
    "greylisting": {"enabled": true}
  }
}
```

### 4. Comandos do Dia-a-Dia

```bash
# Verifica status completo
./manage.sh status

# Mostra estatísticas de hoje
./manage.sh stats-today

# Lista mensagens em quarentena
./manage.sh quarantine-list

# Adiciona IP à blacklist
./manage.sh blacklist-add 192.168.100.50 "Fonte de spam identificada"

# Libera mensagem específica
./manage.sh quarantine-release 123

# Atualiza assinaturas antivírus
./manage.sh update-signatures

# Executa limpeza de rotina
./manage.sh cleanup-quarantine 30

# Backup completo
./manage.sh backup

# Monitora logs em tempo real
./manage.sh logs
```

### 5. Cenário: Ataque de Spam Massivo

```bash
# 1. Detecta aumento súbito de mensagens
./manage.sh stats-today
# Output mostra: 50.000 mensagens processadas (normal: 5.000)

# 2. Verifica top remetentes
./manage.sh top-senders
# Identifica: spammer@domain.com com 15.000 tentativas

# 3. Adiciona à blacklist imediatamente
./manage.sh blacklist-add spammer@domain.com "Spam massivo detectado"
./manage.sh blacklist-add domain.com "Domínio de spam"

# 4. Ativa modo paranóico temporariamente
jq '.security_level = 4 | .score_threshold = 2.0' config.json > config.tmp
mv config.tmp config.json
./manage.sh restart

# 5. Monitora resultado
watch -n 30 './manage.sh stats-today'

# 6. Volta ao normal após ataque
jq '.security_level = 2 | .score_threshold = 5.0' config.json > config.tmp  
mv config.tmp config.json
./manage.sh restart
```

### 6. Configuração de Alertas Personalizados

```bash
# Cria script de alerta personalizado
cat > /opt/smtp-relay/custom_alerts.sh << 'EOF'
#!/bin/bash

# Configurações
TELEGRAM_TOKEN="seu_bot_token"
TELEGRAM_CHAT_ID="seu_chat_id"
THRESHOLD_QUARANTINE=100
THRESHOLD_VIRUS=5

# Função de envio
send_alert() {
    local message="🚨 SMTP RELAY ALERT 🚨\n\n$1"
    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" \
        -d chat_id="${TELEGRAM_CHAT_ID}" \
        -d text="${message}" \
        -d parse_mode="HTML"
}

# Verifica quarentena
QUARANTINE_COUNT=$(psql -h localhost -U smtp_relay -d smtp_relay -t -c \
    "SELECT COUNT(*) FROM quarantine WHERE reviewed=false;" | xargs)

if [ "${QUARANTINE_COUNT:-0}" -gt $THRESHOLD_QUARANTINE ]; then
    send_alert "⚠️ <b>Alta quarentena:</b> $QUARANTINE_COUNT mensagens precisam de revisão"
fi

# Verifica vírus na última hora  
VIRUS_COUNT=$(psql -h localhost -U smtp_relay -d smtp_relay -t -c \
    "SELECT COUNT(*) FROM filter_log WHERE filter_results::text LIKE '%virus%' 
     AND timestamp > NOW() - INTERVAL '1 hour';" | xargs)

if [ "${VIRUS_COUNT:-0}" -gt $THRESHOLD_VIRUS ]; then
    send_alert "🦠 <b>Vírus detectados:</b> $VIRUS_COUNT na última hora"
fi

# Verifica uso de recursos
MEMORY_USAGE=$(ps -o rss= -p $(pgrep -f smtp_relay.py) | awk '{print $1/1024}')
if (( $(echo "$MEMORY_USAGE > 1500" | bc -l) )); then
    send_alert "💾 <b>Alto uso de memória:</b> ${MEMORY_USAGE}MB"
fi
EOF

chmod +x /opt/smtp-relay/custom_alerts.sh

# Agendar verificação a cada 15 minutos
(crontab -l 2>/dev/null; echo "*/15 * * * * /opt/smtp-relay/custom_alerts.sh") | crontab -
```

### 7. Integração com Fail2Ban

```bash
# Cria filtro fail2ban
sudo tee /etc/fail2ban/filter.d/smtp-relay.conf << 'EOF'
[Definition]
failregex = ^.*SMTP Relay.*reject.*from.*<HOST>.*$
            ^.*Blacklist.*IP.*<HOST>.*listed.*$
ignoreregex =

[Init]
datepattern = ^%%Y-%%m-%%d %%H:%%M:%%S
EOF

# Configura jail
sudo tee /etc/fail2ban/jail.d/smtp-relay.conf << 'EOF'
[smtp-relay]
enabled = true
port = smtp,2525
filter = smtp-relay
logpath = /var/log/smtp-relay/smtp-relay.log
maxretry = 5
findtime = 600
bantime = 3600
action = iptables-multiport[name=smtp-relay, port="smtp,2525", protocol=tcp]
EOF

sudo systemctl restart fail2ban
```

### 8. Dashboard Personalizado com Grafana

```bash
# Instala Grafana
sudo apt-get install -y software-properties-common
sudo add-apt-repository "deb https://packages.grafana.com/oss/deb stable main"
wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -
sudo apt-get update && sudo apt-get install grafana

# Configura fonte de dados PostgreSQL
sudo tee /etc/grafana/provisioning/datasources/smtp-relay.yaml << 'EOF'
apiVersion: 1
datasources:
  - name: SMTP-Relay-DB
    type: postgres
    url: localhost:5432
    database: smtp_relay
    user: smtp_relay
    password: SuaS3nh4Ult4S3cur4!
    sslmode: disable
EOF

# Dashboard básico em JSON
cat > /tmp/smtp-relay-dashboard.json << 'EOF'
{
  "dashboard": {
    "title": "SMTP Relay - Andarilho dos Véus",
    "panels": [
      {
        "title": "Mensagens por Hora",
        "type": "graph",
        "targets": [
          {
            "rawSql": "SELECT $__timeGroup(timestamp,'1h'), count(*) as mensagens FROM filter_log WHERE $__timeFilter(timestamp) GROUP BY 1 ORDER BY 1",
            "refId": "A"
          }
        ]
      },
      {
        "title": "Ações por Tipo",
        "type": "piechart", 
        "targets": [
          {
            "rawSql": "SELECT action, count(*) FROM filter_log WHERE timestamp > now() - interval '24 hours' GROUP BY action",
            "refId": "B"
          }
        ]
      }
    ]
  }
}
EOF

sudo systemctl enable grafana-server
sudo systemctl start grafana-server

echo "Grafana disponível em: http://localhost:3000 (admin/admin)"
```

### 9. Testes de Penetração e Validação

```bash
# Script de teste de penetração
cat > /opt/smtp-relay/pentest.sh << 'EOF'
#!/bin/bash
echo "=== Teste de Penetração SMTP Relay ==="

# Teste 1: Flood de conexões
echo "1. Testando flood de conexões..."
for i in {1..100};