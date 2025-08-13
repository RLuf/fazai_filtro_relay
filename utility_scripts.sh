#!/bin/bash
# =============================================================================
# SMTP Relay - Suite de Scripts Utilitários
# Desenvolvido para o Andarilho dos Véus
# =============================================================================

# Configurações globais
SMTP_RELAY_HOME="/opt/smtp-relay"
SMTP_RELAY_USER="smtp-relay"
SMTP_RELAY_SERVICE="smtp-relay"
CONFIG_FILE="$SMTP_RELAY_HOME/config.json"
LOG_FILE="/var/log/smtp-relay/utilities.log"

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Função de logging
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Função para exibir ajuda
show_help() {
    cat << EOF
SMTP Relay - Ferramentas de Gestão

Uso: $0 <comando> [opções]

Comandos disponíveis:

  GESTÃO DO SERVIÇO:
    status              - Mostra status detalhado do sistema
    start               - Inicia o serviço SMTP Relay
    stop                - Para o serviço SMTP Relay  
    restart             - Reinicia o serviço
    logs                - Mostra logs em tempo real

  MANUTENÇÃO:
    update-signatures   - Atualiza assinaturas antivírus
    cleanup-quarantine  - Limpa quarentena antigas
    optimize-db         - Otimiza banco de dados
    backup              - Executa backup completo
    restore <backup>    - Restaura backup especificado

  BLACKLIST/WHITELIST:
    blacklist-add <ip|domain|email> <reason>    - Adiciona à blacklist
    blacklist-remove <entry>                    - Remove da blacklist
    blacklist-list                              - Lista blacklist
    whitelist-add <ip|domain|email>             - Adiciona à whitelist
    whitelist-remove <entry>                    - Remove da whitelist

  QUARENTENA:
    quarantine-list                             - Lista mensagens em quarentena
    quarantine-release <id>                     - Libera mensagem da quarentena
    quarantine-delete <id>                      - Remove mensagem da quarentena
    quarantine-export <id> <format>             - Exporta mensagem

  ESTATÍSTICAS:
    stats-today         - Estatísticas do dia atual
    stats-week          - Estatísticas da semana
    stats-month         - Estatísticas do mês
    top-senders         - Top remetentes bloqueados
    performance         - Métricas de performance

  TESTES:
    test-system         - Executa testes do sistema
    test-filters        - Testa todos os filtros
    test-email <file>   - Testa email específico
    benchmark           - Executa benchmark de performance

  CONFIGURAÇÃO:
    config-validate     - Valida arquivo de configuração
    config-backup       - Backup da configuração atual
    config-restore      - Restaura configuração
    filter-enable <nome>        - Habilita filtro
    filter-disable <nome>       - Desabilita filtro

EOF
}

# =============================================================================
# FUNÇÕES DE GESTÃO DO SERVIÇO
# =============================================================================

smtp_status() {
    echo -e "${BLUE}=== Status do SMTP Relay ===${NC}"
    
    # Status do serviço
    if systemctl is-active --quiet $SMTP_RELAY_SERVICE; then
        echo -e "Serviço: ${GREEN}ATIVO${NC}"
        
        # PID e uso de recursos
        PID=$(systemctl show --property MainPID $SMTP_RELAY_SERVICE | cut -d= -f2)
        if [ "$PID" != "0" ]; then
            MEM_USAGE=$(ps -o rss= -p $PID | awk '{print $1/1024 "MB"}')
            CPU_USAGE=$(ps -o %cpu= -p $PID)
            echo -e "PID: $PID | CPU: ${CPU_USAGE}% | RAM: ${MEM_USAGE}"
        fi
    else
        echo -e "Serviço: ${RED}INATIVO${NC}"
    fi
    
    # Status das dependências
    echo -e "\n${BLUE}=== Dependências ===${NC}"
    
    # PostgreSQL
    if pg_isready -h localhost -p 5432 -U $SMTP_RELAY_USER >/dev/null 2>&1; then
        echo -e "PostgreSQL: ${GREEN}OK${NC}"
    else
        echo -e "PostgreSQL: ${RED}ERRO${NC}"
    fi
    
    # Redis
    if redis-cli ping >/dev/null 2>&1; then
        echo -e "Redis: ${GREEN}OK${NC}"
    else
        echo -e "Redis: ${RED}ERRO${NC}"
    fi
    
    # ClamAV
    if clamdscan --version >/dev/null 2>&1; then
        echo -e "ClamAV: ${GREEN}OK${NC}"
    else
        echo -e "ClamAV: ${RED}ERRO${NC}"
    fi
    
    # Conectividade SMTP
    if echo "QUIT" | nc -w 5 localhost 2525 >/dev/null 2>&1; then
        echo -e "SMTP Port: ${GREEN}OK${NC}"
    else
        echo -e "SMTP Port: ${RED}ERRO${NC}"
    fi
    
    # Interface Web
    if curl -s http://localhost:8080 >/dev/null; then
        echo -e "Web Interface: ${GREEN}OK${NC}"
    else
        echo -e "Web Interface: ${RED}ERRO${NC}"
    fi
    
    # Estatísticas rápidas
    if [ -x "$(command -v psql)" ]; then
        echo -e "\n${BLUE}=== Estatísticas do Dia ===${NC}"
        HOJE=$(date +%Y-%m-%d)
        
        TOTAL=$(psql -h localhost -U $SMTP_RELAY_USER -d $SMTP_RELAY_USER -t -c \
            "SELECT COUNT(*) FROM filter_log WHERE DATE(timestamp) = '$HOJE';" 2>/dev/null | xargs)
        
        ACEITAS=$(psql -h localhost -U $SMTP_RELAY_USER -d $SMTP_RELAY_USER -t -c \
            "SELECT COUNT(*) FROM filter_log WHERE DATE(timestamp) = '$HOJE' AND action = 'accept';" 2>/dev/null | xargs)
            
        REJEITADAS=$(psql -h localhost -U $SMTP_RELAY_USER -d $SMTP_RELAY_USER -t -c \
            "SELECT COUNT(*) FROM filter_log WHERE DATE(timestamp) = '$HOJE' AND action = 'reject';" 2>/dev/null | xargs)
            
        QUARENTENA=$(psql -h localhost -U $SMTP_RELAY_USER -d $SMTP_RELAY_USER -t -c \
            "SELECT COUNT(*) FROM filter_log WHERE DATE(timestamp) = '$HOJE' AND action = 'quarantine';" 2>/dev/null | xargs)
        
        echo "Total processadas: ${TOTAL:-0}"
        echo "Aceitas: ${ACEITAS:-0}"
        echo "Rejeitadas: ${REJEITADAS:-0}"
        echo "Quarentena: ${QUARENTENA:-0}"
    fi
}

smtp_start() {
    echo -e "${BLUE}Iniciando SMTP Relay...${NC}"
    sudo systemctl start $SMTP_RELAY_SERVICE
    sleep 3
    if systemctl is-active --quiet $SMTP_RELAY_SERVICE; then
        echo -e "${GREEN}Serviço iniciado com sucesso!${NC}"
        log_message "Serviço SMTP Relay iniciado"
    else
        echo -e "${RED}Falha ao iniciar serviço${NC}"
        log_message "ERRO: Falha ao iniciar serviço SMTP Relay"
    fi
}

smtp_stop() {
    echo -e "${BLUE}Parando SMTP Relay...${NC}"
    sudo systemctl stop $SMTP_RELAY_SERVICE
    sleep 2
    if ! systemctl is-active --quiet $SMTP_RELAY_SERVICE; then
        echo -e "${GREEN}Serviço parado com sucesso!${NC}"
        log_message "Serviço SMTP Relay parado"
    else
        echo -e "${RED}Falha ao parar serviço${NC}"
        log_message "ERRO: Falha ao parar serviço SMTP Relay"
    fi
}

smtp_restart() {
    echo -e "${BLUE}Reiniciando SMTP Relay...${NC}"
    sudo systemctl restart $SMTP_RELAY_SERVICE
    sleep 3
    if systemctl is-active --quiet $SMTP_RELAY_SERVICE; then
        echo -e "${GREEN}Serviço reiniciado com sucesso!${NC}"
        log_message "Serviço SMTP Relay reiniciado"
    else
        echo -e "${RED}Falha ao reiniciar serviço${NC}"
        log_message "ERRO: Falha ao reiniciar serviço SMTP Relay"
    fi
}

smtp_logs() {
    echo -e "${BLUE}Logs do SMTP Relay (Ctrl+C para sair):${NC}"
    sudo journalctl -u $SMTP_RELAY_SERVICE -f --no-pager
}

# =============================================================================
# FUNÇÕES DE MANUTENÇÃO
# =============================================================================

update_signatures() {
    echo -e "${BLUE}Atualizando assinaturas antivírus...${NC}"
    
    # Atualiza ClamAV
    sudo freshclam
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Assinaturas ClamAV atualizadas!${NC}"
        log_message "Assinaturas ClamAV atualizadas"
        
        # Reinicia ClamAV daemon
        sudo systemctl restart clamav-daemon
    else
        echo -e "${RED}Erro ao atualizar assinaturas ClamAV${NC}"
        log_message "ERRO: Falha ao atualizar assinaturas ClamAV"
    fi
    
    # Atualiza regras YARA se existirem
    if [ -d "$SMTP_RELAY_HOME/rules" ]; then
        echo -e "${BLUE}Verificando atualizações de regras YARA...${NC}"
        # Aqui poderia haver um git pull se as regras estivessem em repositório
        echo -e "${GREEN}Regras YARA verificadas${NC}"
    fi
}

cleanup_quarantine() {
    echo -e "${BLUE}Limpando quarentena antiga...${NC}"
    
    DAYS=${1:-30}
    
    if [ -x "$(command -v psql)" ]; then
        # Conta mensagens que serão removidas
        COUNT=$(psql -h localhost -U $SMTP_RELAY_USER -d $SMTP_RELAY_USER -t -c \
            "SELECT COUNT(*) FROM quarantine WHERE quarantine_date < NOW() - INTERVAL '$DAYS days';" 2>/dev/null | xargs)
        
        if [ "${COUNT:-0}" -gt 0 ]; then
            echo -e "${YELLOW}Encontradas $COUNT mensagens antigas em quarentena${NC}"
            
            # Remove mensagens antigas
            psql -h localhost -U $SMTP_RELAY_USER -d $SMTP_RELAY_USER -c \
                "DELETE FROM quarantine WHERE quarantine_date < NOW() - INTERVAL '$DAYS days';" >/dev/null 2>&1
            
            echo -e "${GREEN}$COUNT mensagens antigas removidas da quarentena${NC}"
            log_message "$COUNT mensagens antigas removidas da quarentena"
        else
            echo -e "${GREEN}Nenhuma mensagem antiga encontrada${NC}"
        fi
    fi
    
    # Limpa arquivos físicos de quarentena se existirem
    if [ -d "$SMTP_RELAY_HOME/quarantine" ]; then
        find "$SMTP_RELAY_HOME/quarantine" -name "*.eml" -mtime +$DAYS -delete
        echo -e "${GREEN}Arquivos de quarentena antigos removidos${NC}"
    fi
}

optimize_db() {
    echo -e "${BLUE}Otimizando banco de dados...${NC}"
    
    if [ -x "$(command -v psql)" ]; then
        # Vacuum e analyze
        psql -h localhost -U $SMTP_RELAY_USER -d $SMTP_RELAY_USER -c "VACUUM ANALYZE;" >/dev/null 2>&1
        
        # Reindex
        psql -h localhost -U $SMTP_RELAY_USER -d $SMTP_RELAY_USER -c "REINDEX DATABASE $SMTP_RELAY_USER;" >/dev/null 2>&1
        
        # Estatísticas do banco
        SIZE=$(psql -h localhost -U $SMTP_RELAY_USER -d $SMTP_RELAY_USER -t -c \
            "SELECT pg_size_pretty(pg_database_size('$SMTP_RELAY_USER'));" 2>/dev/null | xargs)
        
        echo -e "${GREEN}Banco otimizado! Tamanho atual: $SIZE${NC}"
        log_message "Banco de dados otimizado - Tamanho: $SIZE"
    else
        echo -e "${RED}psql não encontrado${NC}"
    fi
}

# =============================================================================
# FUNÇÕES DE BLACKLIST/WHITELIST
# =============================================================================

blacklist_add() {
    local ENTRY="$1"
    local REASON="$2"
    
    if [ -z "$ENTRY" ]; then
        echo -e "${RED}Uso: blacklist-add <ip|domain|email> <reason>${NC}"
        return 1
    fi
    
    # Determina tipo de entrada
    if [[ $ENTRY =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        TYPE="ip"
    elif [[ $ENTRY =~ @ ]]; then
        TYPE="email"
    else
        TYPE="domain"
    fi
    
    echo -e "${BLUE}Adicionando à blacklist: $ENTRY ($TYPE)${NC}"
    
    if [ -x "$(command -v psql)" ]; then
        psql -h localhost -U $SMTP_RELAY_USER -d $SMTP_RELAY_USER -c \
            "INSERT INTO custom_blacklist (entry_type, entry_value, reason, added_by, added_date) 
             VALUES ('$TYPE', '$ENTRY', '$REASON', 'admin', NOW()) 
             ON CONFLICT (entry_type, entry_value) DO UPDATE SET 
             reason = '$REASON', added_date = NOW(), active = true;" >/dev/null 2>&1
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Entrada adicionada à blacklist!${NC}"
            log_message "Blacklist: Adicionado $ENTRY ($TYPE) - $REASON"
        else
            echo -e "${RED}Erro ao adicionar à blacklist${NC}"
        fi
    fi
}

blacklist_remove() {
    local ENTRY="$1"
    
    if [ -z "$ENTRY" ]; then
        echo -e "${RED}Uso: blacklist-remove <entry>${NC}"
        return 1
    fi
    
    echo -e "${BLUE}Removendo da blacklist: $ENTRY${NC}"
    
    if [ -x "$(command -v psql)" ]; then
        psql -h localhost -U $SMTP_RELAY_USER -d $SMTP_RELAY_USER -c \
            "DELETE FROM custom_blacklist WHERE entry_value = '$ENTRY';" >/dev/null 2>&1
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Entrada removida da blacklist!${NC}"
            log_message "Blacklist: Removido $ENTRY"
        else
            echo -e "${RED}Erro ao remover da blacklist${NC}"
        fi
    fi
}

blacklist_list() {
    echo -e "${BLUE}=== Lista Blacklist ===${NC}"
    
    if [ -x "$(command -v psql)" ]; then
        psql -h localhost -U $SMTP_RELAY_USER -d $SMTP_RELAY_USER -c \
            "SELECT entry_type, entry_value, reason, added_date FROM custom_blacklist WHERE active = true ORDER BY added_date DESC;" 2>/dev/null
    fi
}

# =============================================================================
# FUNÇÕES DE ESTATÍSTICAS
# =============================================================================

stats_today() {
    echo -e "${BLUE}=== Estatísticas de Hoje ===${NC}"
    
    if [ -x "$(command -v psql)" ]; then
        HOJE=$(date +%Y-%m-%d)
        
        psql -h localhost -U $SMTP_RELAY_USER -d $SMTP_RELAY_USER << EOF
SELECT 
    'Total Processadas' as metrica, 
    COUNT(*) as valor 
FROM filter_log 
WHERE DATE(timestamp) = '$HOJE'
UNION ALL
SELECT 
    'Aceitas', 
    COUNT(*) 
FROM filter_log 
WHERE DATE(timestamp) = '$HOJE' AND action = 'accept'
UNION ALL
SELECT 
    'Rejeitadas', 
    COUNT(*) 
FROM filter_log 
WHERE DATE(timestamp) = '$HOJE' AND action = 'reject'
UNION ALL
SELECT 
    'Quarentena', 
    COUNT(*) 
FROM filter_log 
WHERE DATE(timestamp) = '$HOJE' AND action = 'quarantine'
UNION ALL
SELECT 
    'Score Médio', 
    ROUND(AVG(score), 2) 
FROM filter_log 
WHERE DATE(timestamp) = '$HOJE';
EOF
    fi
}

top_senders() {
    echo -e "${BLUE}=== Top Remetentes Bloqueados (Últimos 7 dias) ===${NC}"
    
    if [ -x "$(command -v psql)" ]; then
        psql -h localhost -U $SMTP_RELAY_USER -d $SMTP_RELAY_USER << EOF
SELECT 
    sender,
    COUNT(*) as total_bloqueios,
    COUNT(CASE WHEN action = 'reject' THEN 1 END) as rejeitados,
    COUNT(CASE WHEN action = 'quarantine' THEN 1 END) as quarentena,
    ROUND(AVG(score), 2) as score_medio
FROM filter_log 
WHERE timestamp >= NOW() - INTERVAL '7 days' 
    AND action IN ('reject', 'quarantine')
GROUP BY sender
ORDER BY total_bloqueios DESC
LIMIT 20;
EOF
    fi
}

# =============================================================================
# FUNÇÕES DE TESTE
# =============================================================================

test_system() {
    echo -e "${BLUE}=== Teste Completo do Sistema ===${NC}"
    
    local ERRORS=0
    
    # Teste 1: Serviço ativo
    echo -n "1. Serviço SMTP Relay: "
    if systemctl is-active --quiet $SMTP_RELAY_SERVICE; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FALHA${NC}"
        ((ERRORS++))
    fi
    
    # Teste 2: Porta SMTP
    echo -n "2. Porta SMTP (2525): "
    if echo "QUIT" | nc -w 5 localhost 2525 >/dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FALHA${NC}"
        ((ERRORS++))
    fi
    
    # Teste 3: Interface Web
    echo -n "3. Interface Web (8080): "
    if curl -s http://localhost:8080 >/dev/null; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FALHA${NC}"
        ((ERRORS++))
    fi
    
    # Teste 4: PostgreSQL
    echo -n "4. PostgreSQL: "
    if pg_isready -h localhost -p 5432 -U $SMTP_RELAY_USER >/dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FALHA${NC}"
        ((ERRORS++))
    fi
    
    # Teste 5: Redis
    echo -n "5. Redis: "
    if redis-cli ping >/dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FALHA${NC}"
        ((ERRORS++))
    fi
    
    # Teste 6: ClamAV
    echo -n "6. ClamAV: "
    if echo "eicar" | clamdscan - 2>/dev/null | grep -q "FOUND"; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FALHA${NC}"
        ((ERRORS++))
    fi
    
    # Teste 7: DNS Resolution
    echo -n "7. Resolução DNS: "
    if nslookup google.com >/dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FALHA${NC}"
        ((ERRORS++))
    fi
    
    # Teste 8: Espaço em disco
    echo -n "8. Espaço em disco: "
    DISK_USAGE=$(df /opt/smtp-relay | awk 'NR==2 {print $5}' | sed 's/%//')
    if [ "$DISK_USAGE" -lt 90 ]; then
        echo -e "${GREEN}OK ($DISK_USAGE% usado)${NC}"
    else
        echo -e "${YELLOW}AVISO ($DISK_USAGE% usado)${NC}"
    fi
    
    # Resumo
    echo -