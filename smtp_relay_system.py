#!/usr/bin/env python3
"""
Sistema SMTP Relay Modular com Filtragem Avançada
Desenvolvido para o Andarilho dos Véus
"""

import asyncio
import logging
import json
import re
import hashlib
import socket
import ssl
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum
import email
from email import policy
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import aiosmtpd.smtp
from aiosmtpd.controller import Controller
import aiohttp
import asyncpg
import redis.asyncio as redis
from cryptography.fernet import Fernet
import yara
import dns.resolver
import spf
import dkim
import subprocess
import tempfile
import os

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class FilterAction(Enum):
    ACCEPT = "accept"
    REJECT = "reject" 
    QUARANTINE = "quarantine"
    MODIFY = "modify"
    HOLD = "hold"

class SecurityLevel(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    PARANOID = 4

@dataclass
class FilterResult:
    action: FilterAction
    score: float
    reason: str
    details: Dict[str, Any]
    module: str

@dataclass
class EmailMessage:
    message_id: str
    sender: str
    recipients: List[str]
    subject: str
    body: str
    headers: Dict[str, str]
    raw_data: bytes
    timestamp: datetime
    size: int
    attachments: List[Dict[str, Any]]

class BaseFilter:
    """Classe base para todos os filtros modulares"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get('enabled', True)
        self.weight = config.get('weight', 1.0)
        self.name = self.__class__.__name__
        
    async def initialize(self):
        """Inicialização assíncrona do filtro"""
        pass
        
    async def filter(self, message: EmailMessage) -> FilterResult:
        """Método principal de filtragem - deve ser implementado"""
        raise NotImplementedError
        
    async def cleanup(self):
        """Limpeza de recursos"""
        pass

class SPFFilter(BaseFilter):
    """Filtro SPF para validação de remetente"""
    
    async def filter(self, message: EmailMessage) -> FilterResult:
        try:
            sender_domain = message.sender.split('@')[1]
            sender_ip = message.headers.get('X-Originating-IP', '127.0.0.1')
            
            result = spf.check2(sender_ip, message.sender, sender_domain)
            
            if result[0] == 'pass':
                return FilterResult(
                    FilterAction.ACCEPT, 0.0, "SPF validation passed",
                    {"spf_result": result}, self.name
                )
            elif result[0] in ['fail', 'softfail']:
                score = 5.0 if result[0] == 'fail' else 2.0
                return FilterResult(
                    FilterAction.REJECT if result[0] == 'fail' else FilterAction.HOLD,
                    score, f"SPF validation failed: {result[1]}",
                    {"spf_result": result}, self.name
                )
            else:
                return FilterResult(
                    FilterAction.ACCEPT, 1.0, f"SPF neutral: {result[1]}",
                    {"spf_result": result}, self.name
                )
                
        except Exception as e:
            logger.error(f"SPF Filter error: {e}")
            return FilterResult(
                FilterAction.ACCEPT, 0.5, f"SPF check failed: {str(e)}",
                {"error": str(e)}, self.name
            )

class DKIMFilter(BaseFilter):
    """Filtro DKIM para validação de assinatura"""
    
    async def filter(self, message: EmailMessage) -> FilterResult:
        try:
            # Verificação DKIM usando python-dkim
            result = dkim.verify(message.raw_data)
            
            if result:
                return FilterResult(
                    FilterAction.ACCEPT, -1.0, "DKIM signature valid",
                    {"dkim_valid": True}, self.name
                )
            else:
                return FilterResult(
                    FilterAction.HOLD, 2.0, "DKIM signature invalid or missing",
                    {"dkim_valid": False}, self.name
                )
                
        except Exception as e:
            logger.error(f"DKIM Filter error: {e}")
            return FilterResult(
                FilterAction.ACCEPT, 0.5, f"DKIM check failed: {str(e)}",
                {"error": str(e)}, self.name
            )

class BlacklistFilter(BaseFilter):
    """Filtro de blacklists DNS (RBL) e personalizadas"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.dns_blacklists = config.get('dns_blacklists', [
            'zen.spamhaus.org',
            'bl.spamcop.net',
            'cbl.abuseat.org',
            'psbl.surriel.com'
        ])
        self.custom_blacklist = set(config.get('custom_blacklist', []))
        
    async def check_dns_blacklist(self, ip: str) -> List[str]:
        """Verifica IP em blacklists DNS"""
        hits = []
        reversed_ip = '.'.join(ip.split('.')[::-1])
        
        for bl in self.dns_blacklists:
            try:
                query = f"{reversed_ip}.{bl}"
                result = await asyncio.get_event_loop().run_in_executor(
                    None, dns.resolver.resolve, query, 'A'
                )
                hits.append(bl)
            except:
                continue
                
        return hits
        
    async def filter(self, message: EmailMessage) -> FilterResult:
        try:
            sender_ip = message.headers.get('X-Originating-IP', '127.0.0.1')
            sender_domain = message.sender.split('@')[1]
            
            # Verifica blacklist customizada
            if sender_ip in self.custom_blacklist or sender_domain in self.custom_blacklist:
                return FilterResult(
                    FilterAction.REJECT, 10.0, "Sender in custom blacklist",
                    {"blacklist_type": "custom"}, self.name
                )
            
            # Verifica blacklists DNS
            dns_hits = await self.check_dns_blacklist(sender_ip)
            if dns_hits:
                return FilterResult(
                    FilterAction.REJECT, 8.0, f"IP in DNS blacklist: {', '.join(dns_hits)}",
                    {"blacklist_hits": dns_hits}, self.name
                )
                
            return FilterResult(
                FilterAction.ACCEPT, 0.0, "No blacklist matches",
                {}, self.name
            )
            
        except Exception as e:
            logger.error(f"Blacklist Filter error: {e}")
            return FilterResult(
                FilterAction.ACCEPT, 0.0, f"Blacklist check failed: {str(e)}",
                {"error": str(e)}, self.name
            )

class VirusFilter(BaseFilter):
    """Filtro antivírus usando ClamAV"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.clamd_socket = config.get('clamd_socket', '/var/run/clamav/clamd.ctl')
        
    async def scan_with_clamav(self, data: bytes) -> Tuple[bool, str]:
        """Escaneia dados com ClamAV"""
        try:
            # Salva temporariamente para escaneamento
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp.write(data)
                tmp_path = tmp.name
                
            # Executa clamdscan
            result = subprocess.run(
                ['clamdscan', '--no-summary', tmp_path],
                capture_output=True, text=True
            )
            
            # Remove arquivo temporário
            os.unlink(tmp_path)
            
            if result.returncode == 0:
                return False, "Clean"
            elif result.returncode == 1:
                return True, result.stdout.strip()
            else:
                return False, f"Scan error: {result.stderr}"
                
        except Exception as e:
            return False, f"Scanner unavailable: {str(e)}"
    
    async def filter(self, message: EmailMessage) -> FilterResult:
        try:
            # Escaneia a mensagem completa
            infected, details = await self.scan_with_clamav(message.raw_data)
            
            if infected:
                return FilterResult(
                    FilterAction.QUARANTINE, 15.0, f"Virus detected: {details}",
                    {"virus_details": details}, self.name
                )
            else:
                return FilterResult(
                    FilterAction.ACCEPT, 0.0, "No virus detected",
                    {"scan_result": details}, self.name
                )
                
        except Exception as e:
            logger.error(f"Virus Filter error: {e}")
            return FilterResult(
                FilterAction.ACCEPT, 1.0, f"Virus scan failed: {str(e)}",
                {"error": str(e)}, self.name
            )

class AISpamFilter(BaseFilter):
    """Filtro de spam baseado em IA"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.api_endpoint = config.get('ai_endpoint', 'https://api.anthropic.com/v1/messages')
        self.model = config.get('model', 'claude-3-sonnet-20240229')
        self.threshold = config.get('spam_threshold', 0.7)
        
    async def analyze_with_ai(self, message: EmailMessage) -> Tuple[float, str]:
        """Análise de spam usando IA"""
        try:
            # Prepara contexto para análise
            context = f"""
            Analyze this email for spam characteristics:
            
            From: {message.sender}
            Subject: {message.subject}
            Body: {message.body[:1000]}...
            
            Rate spam probability from 0.0 (definitely not spam) to 1.0 (definitely spam).
            Provide brief reasoning.
            
            Respond in JSON format:
            {{"spam_score": 0.0-1.0, "reason": "brief explanation"}}
            """
            
            async with aiohttp.ClientSession() as session:
                payload = {
                    "model": self.model,
                    "max_tokens": 200,
                    "messages": [{"role": "user", "content": context}]
                }
                
                async with session.post(
                    self.api_endpoint,
                    headers={"Content-Type": "application/json"},
                    json=payload
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        content = data['content'][0]['text']
                        
                        # Parse resposta JSON
                        import json
                        result = json.loads(content)
                        return result['spam_score'], result['reason']
                    else:
                        return 0.5, "AI analysis unavailable"
                        
        except Exception as e:
            logger.error(f"AI analysis error: {e}")
            return 0.5, f"Analysis failed: {str(e)}"
    
    async def filter(self, message: EmailMessage) -> FilterResult:
        try:
            spam_score, reason = await self.analyze_with_ai(message)
            
            if spam_score >= self.threshold:
                action = FilterAction.QUARANTINE if spam_score >= 0.9 else FilterAction.HOLD
                return FilterResult(
                    action, spam_score * 10, f"AI detected spam: {reason}",
                    {"ai_spam_score": spam_score, "ai_reason": reason}, self.name
                )
            else:
                return FilterResult(
                    FilterAction.ACCEPT, spam_score * -2, f"AI analysis clean: {reason}",
                    {"ai_spam_score": spam_score, "ai_reason": reason}, self.name
                )
                
        except Exception as e:
            logger.error(f"AI Spam Filter error: {e}")
            return FilterResult(
                FilterAction.ACCEPT, 0.0, f"AI filter failed: {str(e)}",
                {"error": str(e)}, self.name
            )

class ContentFilter(BaseFilter):
    """Filtro de conteúdo baseado em regras YARA"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.yara_rules_path = config.get('yara_rules_path', 'rules/')
        self.rules = None
        
    async def initialize(self):
        """Carrega regras YARA"""
        try:
            rules_file = Path(self.yara_rules_path) / 'email_rules.yar'
            if rules_file.exists():
                self.rules = yara.compile(filepath=str(rules_file))
            else:
                # Cria regras básicas se não existirem
                basic_rules = '''
                rule PhishingKeywords {
                    strings:
                        $a = "urgent action required" nocase
                        $b = "verify your account" nocase
                        $c = "click here immediately" nocase
                        $d = "suspended account" nocase
                    condition:
                        any of them
                }
                
                rule SuspiciousAttachments {
                    strings:
                        $exe = ".exe" nocase
                        $scr = ".scr" nocase
                        $pif = ".pif" nocase
                        $bat = ".bat" nocase
                    condition:
                        any of them
                }
                '''
                self.rules = yara.compile(source=basic_rules)
                
        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")
            self.rules = None
    
    async def filter(self, message: EmailMessage) -> FilterResult:
        if not self.rules:
            return FilterResult(
                FilterAction.ACCEPT, 0.0, "YARA rules not loaded",
                {}, self.name
            )
            
        try:
            # Combina subject e body para análise
            content = f"{message.subject}\n{message.body}"
            
            matches = self.rules.match(data=content.encode('utf-8', errors='ignore'))
            
            if matches:
                rule_names = [match.rule for match in matches]
                return FilterResult(
                    FilterAction.HOLD, 4.0, f"Content rules matched: {', '.join(rule_names)}",
                    {"yara_matches": rule_names}, self.name
                )
            else:
                return FilterResult(
                    FilterAction.ACCEPT, 0.0, "No content rules matched",
                    {}, self.name
                )
                
        except Exception as e:
            logger.error(f"Content Filter error: {e}")
            return FilterResult(
                FilterAction.ACCEPT, 0.0, f"Content analysis failed: {str(e)}",
                {"error": str(e)}, self.name
            )

class FilterEngine:
    """Motor principal de filtragem"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.filters: List[BaseFilter] = []
        self.security_level = SecurityLevel(config.get('security_level', 2))
        self.score_threshold = config.get('score_threshold', 5.0)
        self.redis_client = None
        self.db_pool = None
        
    async def initialize(self):
        """Inicializa o motor de filtragem"""
        # Inicializa Redis
        redis_config = self.config.get('redis', {})
        self.redis_client = redis.Redis(
            host=redis_config.get('host', 'localhost'),
            port=redis_config.get('port', 6379),
            db=redis_config.get('db', 0)
        )
        
        # Inicializa PostgreSQL
        db_config = self.config.get('database', {})
        self.db_pool = await asyncpg.create_pool(
            host=db_config.get('host', 'localhost'),
            port=db_config.get('port', 5432),
            user=db_config.get('user', 'smtp_relay'),
            password=db_config.get('password', ''),
            database=db_config.get('database', 'smtp_relay'),
            min_size=1, max_size=10
        )
        
        # Carrega filtros configurados
        await self.load_filters()
        
    async def load_filters(self):
        """Carrega e inicializa filtros modulares"""
        filter_configs = self.config.get('filters', {})
        
        # Mapeamento de filtros disponíveis
        available_filters = {
            'spf': SPFFilter,
            'dkim': DKIMFilter,
            'blacklist': BlacklistFilter,
            'virus': VirusFilter,
            'ai_spam': AISpamFilter,
            'content': ContentFilter
        }
        
        for filter_name, filter_config in filter_configs.items():
            if filter_name in available_filters and filter_config.get('enabled', True):
                try:
                    filter_instance = available_filters[filter_name](filter_config)
                    await filter_instance.initialize()
                    self.filters.append(filter_instance)
                    logger.info(f"Loaded filter: {filter_name}")
                except Exception as e:
                    logger.error(f"Failed to load filter {filter_name}: {e}")
    
    async def process_message(self, message: EmailMessage) -> Tuple[FilterAction, List[FilterResult]]:
        """Processa mensagem através de todos os filtros"""
        results = []
        total_score = 0.0
        
        # Cache key para resultados
        cache_key = f"filter:{hashlib.md5(message.raw_data).hexdigest()}"
        
        # Verifica cache
        if self.redis_client:
            cached = await self.redis_client.get(cache_key)
            if cached:
                return json.loads(cached)
        
        # Executa filtros em paralelo
        tasks = []
        for filter_obj in self.filters:
            if filter_obj.enabled:
                tasks.append(filter_obj.filter(message))
        
        filter_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Processa resultados
        for result in filter_results:
            if isinstance(result, Exception):
                logger.error(f"Filter error: {result}")
                continue
                
            if isinstance(result, FilterResult):
                results.append(result)
                # Aplica peso do filtro
                weighted_score = result.score * result.module
                total_score += weighted_score
        
        # Determina ação final
        final_action = self.determine_final_action(total_score, results)
        
        # Cache resultado
        if self.redis_client:
            cache_data = {"action": final_action.value, "results": [asdict(r) for r in results]}
            await self.redis_client.setex(cache_key, 3600, json.dumps(cache_data))
        
        # Log de auditoria
        await self.log_decision(message, final_action, results, total_score)
        
        return final_action, results
    
    def determine_final_action(self, total_score: float, results: List[FilterResult]) -> FilterAction:
        """Determina ação final baseada na pontuação e resultados"""
        
        # Verifica se algum filtro retornou REJECT
        for result in results:
            if result.action == FilterAction.REJECT:
                return FilterAction.REJECT
        
        # Verifica se algum filtro retornou QUARANTINE
        for result in results:
            if result.action == FilterAction.QUARANTINE:
                return FilterAction.QUARANTINE
        
        # Baseado na pontuação total
        if total_score >= self.score_threshold * 2:
            return FilterAction.QUARANTINE
        elif total_score >= self.score_threshold:
            return FilterAction.HOLD
        elif any(r.action == FilterAction.HOLD for r in results):
            return FilterAction.HOLD
        else:
            return FilterAction.ACCEPT
    
    async def log_decision(self, message: EmailMessage, action: FilterAction, 
                          results: List[FilterResult], score: float):
        """Registra decisão para auditoria"""
        if self.db_pool:
            try:
                async with self.db_pool.acquire() as conn:
                    await conn.execute('''
                        INSERT INTO filter_log (
                            message_id, sender, action, score, 
                            filter_results, timestamp
                        ) VALUES ($1, $2, $3, $4, $5, $6)
                    ''', 
                    message.message_id, message.sender, action.value, 
                    score, json.dumps([asdict(r) for r in results]), 
                    datetime.utcnow()
                    )
            except Exception as e:
                logger.error(f"Failed to log decision: {e}")

class SMTPRelay:
    """Servidor SMTP Relay principal"""
    
    def __init__(self, config_file: str = 'config.json'):
        with open(config_file) as f:
            self.config = json.load(f)
            
        self.filter_engine = FilterEngine(self.config)
        self.controller = None
        
    async def initialize(self):
        """Inicializa o servidor SMTP"""
        await self.filter_engine.initialize()
        
        # Configura handler SMTP
        handler = SMTPHandler(self.filter_engine)
        
        # Configura controller
        self.controller = Controller(
            handler,
            hostname=self.config.get('listen_host', '0.0.0.0'),
            port=self.config.get('listen_port', 2525)
        )
        
    def start(self):
        """Inicia o servidor"""
        self.controller.start()
        logger.info(f"SMTP Relay started on {self.config.get('listen_host')}:{self.config.get('listen_port')}")
        
    def stop(self):
        """Para o servidor"""
        if self.controller:
            self.controller.stop()

class SMTPHandler:
    """Handler para conexões SMTP"""
    
    def __init__(self, filter_engine: FilterEngine):
        self.filter_engine = filter_engine
        
    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        """Valida destinatário"""
        # Implementar validação de destinatário se necessário
        return '250 OK'
        
    async def handle_DATA(self, server, session, envelope):
        """Processa dados da mensagem"""
        try:
            # Parse da mensagem
            raw_message = email.message_from_bytes(envelope.content, policy=policy.default)
            
            # Cria objeto EmailMessage
            message = EmailMessage(
                message_id=raw_message.get('Message-ID', ''),
                sender=envelope.mail_from,
                recipients=envelope.rcpt_tos,
                subject=raw_message.get('Subject', ''),
                body=self.extract_body(raw_message),
                headers=dict(raw_message.items()),
                raw_data=envelope.content,
                timestamp=datetime.utcnow(),
                size=len(envelope.content),
                attachments=self.extract_attachments(raw_message)
            )
            
            # Processa através do filter engine
            action, results = await self.filter_engine.process_message(message)
            
            # Executa ação determinada
            if action == FilterAction.ACCEPT:
                await self.relay_message(envelope)
                return '250 Message accepted for delivery'
            elif action == FilterAction.HOLD:
                await self.hold_message(message, results)
                return '250 Message accepted for review'
            elif action == FilterAction.QUARANTINE:
                await self.quarantine_message(message, results)
                return '250 Message quarantined'
            else:  # REJECT
                reason = next((r.reason for r in results if r.action == FilterAction.REJECT), 'Message rejected')
                return f'550 {reason}'
                
        except Exception as e:
            logger.error(f"Handler error: {e}")
            return '451 Temporary failure'
    
    def extract_body(self, message) -> str:
        """Extrai corpo da mensagem"""
        if message.is_multipart():
            for part in message.walk():
                if part.get_content_type() == "text/plain":
                    return part.get_payload(decode=True).decode('utf-8', errors='ignore')
        else:
            return message.get_payload(decode=True).decode('utf-8', errors='ignore')
        return ""
    
    def extract_attachments(self, message) -> List[Dict[str, Any]]:
        """Extrai informações dos anexos"""
        attachments = []
        if message.is_multipart():
            for part in message.walk():
                if part.get_content_disposition() == 'attachment':
                    filename = part.get_filename()
                    if filename:
                        attachments.append({
                            'filename': filename,
                            'size': len(part.get_payload(decode=True) or b''),
                            'content_type': part.get_content_type()
                        })
        return attachments
    
    async def relay_message(self, envelope):
        """Retransmite mensagem aceita"""
        # Implementar lógica de retransmissão
        pass
        
    async def hold_message(self, message: EmailMessage, results: List[FilterResult]):
        """Retém mensagem para revisão"""
        # Implementar armazenamento para revisão manual
        pass
        
    async def quarantine_message(self, message: EmailMessage, results: List[FilterResult]):
        """Quarentena mensagem suspeita"""
        # Implementar quarentena
        pass

# Interface Web para Administração
class WebInterface:
    """Interface web para administração do relay"""
    
    def __init__(self, smtp_relay: SMTPRelay):
        self.smtp_relay = smtp_relay
        self.app = self.create_app()
        
    def create_app(self):
        """Cria aplicação web"""
        from flask import Flask, render_template, request, jsonify
        
        app = Flask(__name__)
        
        @app.route('/')
        def dashboard():
            return render_template('dashboard.html')
            
        @app.route('/api/stats')
        def get_stats():
            # Implementar estatísticas
            return jsonify({})
            
        @app.route('/api/quarantine')
        def quarantine():
            # Implementar listagem de quarentena
            return jsonify({})
            
        return app
    
    def run(self, host='0.0.0.0', port=8080):
        """Executa interface web"""
        self.app.run(host=host, port=port)

# Configuração de exemplo
def create_example_config():
    """Cria arquivo de configuração de exemplo"""
    config = {
        "listen_host": "0.0.0.0",
        "listen_port": 2525,
        "security_level": 2,
        "score_threshold": 5.0,
        "redis": {
            "host": "localhost",
            "port": 6379,
            "db": 0
        },
        "database": {
            "host": "localhost",
            "port": 5432,
            "user": "smtp_relay",
            "password": "secure_password",
            "database": "smtp_relay"
        },
        "filters": {
            "spf": {
                "enabled": True,
                "weight": 1.0
            },
            "dkim": {
                "enabled": True,
                "weight": 1.0
            },
            "blacklist": {
                "enabled": True,
                "weight": 2.0,
                "dns_blacklists": [
                    "zen.spamhaus.org",
                    "bl.spamcop.net",
                    "cbl.abuseat.org"
                ],
                "custom_blacklist": []
            },
            "virus": {
                "enabled": True,
                "weight": 3.0,
                "clamd_socket": "/var/run/clamav/clamd.ctl"
            },
            "ai_spam": {
                "enabled": True,
                "weight": 2.0,
                "ai_endpoint": "https://api.anthropic.com/v1/messages",
                "model": "claude-3-sonnet-20240229",
                "spam_threshold": 0.7
            },
            "content": {
                "enabled": True,
                "weight": 1.5,
                "yara_rules_path": "rules/"
            }
        }
    }
    
    with open('config.json', 'w') as f:
        json.dump(config, f, indent=2)

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='SMTP Relay Modular')
    parser.add_argument('--config', default='config.json', help='Arquivo de configuração')
    parser.add_argument('--create-config', action='store_true', help='Cria configuração de exemplo')
    parser.add_argument('--web-port', type=int, default=8080, help='Porta da interface web')
    
    args = parser.parse_args()
    
    if args.create_config:
        create_example_config()
        print("Arquivo config.json criado!")
        exit(0)
    
    async def main():
        # Inicializa relay
        relay = SMTPRelay(args.config)
        await relay.initialize()
        
        # Inicia servidor SMTP
        relay.start()
        
        # Inicia interface web em thread separada
        import threading
        web_interface = WebInterface(relay)
        web_thread = threading.Thread(
            target=web_interface.run, 
            args=('0.0.0.0', args.web_port),
            daemon=True
        )
        web_thread.start()
        
        logger.info(f"Web interface started on port {args.web_port}")
        
        try:
            # Mantém o servidor rodando
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down...")
            relay.stop()
    
    # Executa o servidor
    asyncio.run(main())


# Script de instalação de dependências
"""
INSTALAÇÃO E CONFIGURAÇÃO:

1. Instale as dependências Python:
pip install aiosmtpd aiohttp asyncpg redis cryptography yara-python dnspython py3dns pyspf dkimpy flask

2. Instale dependências do sistema:
sudo apt-get update
sudo apt-get install -y clamav clamav-daemon postgresql redis-server yara

3. Configure PostgreSQL:
sudo -u postgres createuser smtp_relay
sudo -u postgres createdb smtp_relay
sudo -u postgres psql -c "ALTER USER smtp_relay WITH PASSWORD 'secure_password';"

4. Crie as tabelas do banco:
"""

# Schema do banco de dados
DATABASE_SCHEMA = '''
-- Tabela para log de filtros
CREATE TABLE IF NOT EXISTS filter_log (
    id SERIAL PRIMARY KEY,
    message_id VARCHAR(255) NOT NULL,
    sender VARCHAR(255) NOT NULL,
    action VARCHAR(50) NOT NULL,
    score FLOAT NOT NULL,
    filter_results JSONB,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX(message_id),
    INDEX(sender),
    INDEX(timestamp)
);

-- Tabela para mensagens em quarentena
CREATE TABLE IF NOT EXISTS quarantine (
    id SERIAL PRIMARY KEY,
    message_id VARCHAR(255) UNIQUE NOT NULL,
    sender VARCHAR(255) NOT NULL,
    recipients TEXT[] NOT NULL,
    subject TEXT,
    raw_message BYTEA NOT NULL,
    reason TEXT,
    quarantine_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reviewed BOOLEAN DEFAULT FALSE,
    reviewer VARCHAR(255),
    review_date TIMESTAMP,
    action_taken VARCHAR(50),
    INDEX(sender),
    INDEX(quarantine_date),
    INDEX(reviewed)
);

-- Tabela para mensagens em hold
CREATE TABLE IF NOT EXISTS held_messages (
    id SERIAL PRIMARY KEY,
    message_id VARCHAR(255) UNIQUE NOT NULL,
    sender VARCHAR(255) NOT NULL,
    recipients TEXT[] NOT NULL,
    subject TEXT,
    raw_message BYTEA NOT NULL,
    reason TEXT,
    hold_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    processed BOOLEAN DEFAULT FALSE,
    processor VARCHAR(255),
    process_date TIMESTAMP,
    final_action VARCHAR(50),
    INDEX(sender),
    INDEX(hold_date),
    INDEX(processed)
);

-- Tabela para blacklist customizada
CREATE TABLE IF NOT EXISTS custom_blacklist (
    id SERIAL PRIMARY KEY,
    entry_type VARCHAR(20) NOT NULL, -- 'ip', 'domain', 'email'
    entry_value VARCHAR(255) NOT NULL,
    reason TEXT,
    added_by VARCHAR(255),
    added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_date TIMESTAMP,
    active BOOLEAN DEFAULT TRUE,
    UNIQUE(entry_type, entry_value),
    INDEX(entry_type),
    INDEX(entry_value),
    INDEX(active)
);

-- Tabela para whitelist
CREATE TABLE IF NOT EXISTS whitelist (
    id SERIAL PRIMARY KEY,
    entry_type VARCHAR(20) NOT NULL,
    entry_value VARCHAR(255) NOT NULL,
    reason TEXT,
    added_by VARCHAR(255),
    added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN DEFAULT TRUE,
    UNIQUE(entry_type, entry_value),
    INDEX(entry_type),
    INDEX(entry_value),
    INDEX(active)
);

-- Tabela para estatísticas
CREATE TABLE IF NOT EXISTS statistics (
    id SERIAL PRIMARY KEY,
    date DATE NOT NULL,
    messages_processed INTEGER DEFAULT 0,
    messages_accepted INTEGER DEFAULT 0,
    messages_rejected INTEGER DEFAULT 0,
    messages_quarantined INTEGER DEFAULT 0,
    messages_held INTEGER DEFAULT 0,
    spam_detected INTEGER DEFAULT 0,
    viruses_detected INTEGER DEFAULT 0,
    UNIQUE(date),
    INDEX(date)
);

-- View para relatórios
CREATE OR REPLACE VIEW daily_stats AS
SELECT 
    DATE(timestamp) as date,
    COUNT(*) as total_messages,
    COUNT(CASE WHEN action = 'accept' THEN 1 END) as accepted,
    COUNT(CASE WHEN action = 'reject' THEN 1 END) as rejected,
    COUNT(CASE WHEN action = 'quarantine' THEN 1 END) as quarantined,
    COUNT(CASE WHEN action = 'hold' THEN 1 END) as held,
    AVG(score) as avg_score
FROM filter_log 
GROUP BY DATE(timestamp)
ORDER BY date DESC;
'''

# Templates HTML para interface web
HTML_TEMPLATES = {
    'base.html': '''
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}SMTP Relay Admin{% endblock %}</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/tailwindcss/2.2.19/tailwind.min.css" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
</head>
<body class="bg-gray-100">
    <nav class="bg-blue-800 text-white p-4">
        <div class="container mx-auto flex justify-between items-center">
            <h1 class="text-xl font-bold">SMTP Relay - Andarilho dos Véus</h1>
            <div class="space-x-4">
                <a href="/" class="hover:underline">Dashboard</a>
                <a href="/quarantine" class="hover:underline">Quarentena</a>
                <a href="/held" class="hover:underline">Em Espera</a>
                <a href="/blacklist" class="hover:underline">Blacklist</a>
                <a href="/config" class="hover:underline">Configuração</a>
            </div>
        </div>
    </nav>
    
    <main class="container mx-auto p-4">
        {% block content %}{% endblock %}
    </main>
</body>
</html>
    ''',
    
    'dashboard.html': '''
{% extends "base.html" %}
{% block title %}Dashboard - SMTP Relay{% endblock %}

{% block content %}
<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
    <div class="bg-white p-6 rounded-lg shadow">
        <h3 class="text-lg font-semibold mb-2">Mensagens Hoje</h3>
        <p class="text-3xl font-bold text-blue-600" id="messages-today">0</p>
    </div>
    <div class="bg-white p-6 rounded-lg shadow">
        <h3 class="text-lg font-semibold mb-2">Spam Bloqueado</h3>
        <p class="text-3xl font-bold text-red-600" id="spam-blocked">0</p>
    </div>
    <div class="bg-white p-6 rounded-lg shadow">
        <h3 class="text-lg font-semibold mb-2">Vírus Detectados</h3>
        <p class="text-3xl font-bold text-yellow-600" id="viruses-detected">0</p>
    </div>
    <div class="bg-white p-6 rounded-lg shadow">
        <h3 class="text-lg font-semibold mb-2">Em Quarentena</h3>
        <p class="text-3xl font-bold text-purple-600" id="quarantined">0</p>
    </div>
</div>

<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <div class="bg-white p-6 rounded-lg shadow">
        <h3 class="text-lg font-semibold mb-4">Atividade nos Últimos 7 Dias</h3>
        <canvas id="activity-chart"></canvas>
    </div>
    
    <div class="bg-white p-6 rounded-lg shadow">
        <h3 class="text-lg font-semibold mb-4">Top Filtros Ativos</h3>
        <div id="top-filters">
            <!-- Carregado via JavaScript -->
        </div>
    </div>
</div>

<div class="mt-6 bg-white p-6 rounded-lg shadow">
    <h3 class="text-lg font-semibold mb-4">Log Recente</h3>
    <div class="overflow-x-auto">
        <table class="min-w-full table-auto">
            <thead class="bg-gray-50">
                <tr>
                    <th class="px-4 py-2 text-left">Timestamp</th>
                    <th class="px-4 py-2 text-left">Remetente</th>
                    <th class="px-4 py-2 text-left">Ação</th>
                    <th class="px-4 py-2 text-left">Score</th>
                    <th class="px-4 py-2 text-left">Motivo</th>
                </tr>
            </thead>
            <tbody id="recent-log">
                <!-- Carregado via JavaScript -->
            </tbody>
        </table>
    </div>
</div>

<script>
// Atualiza estatísticas em tempo real
async function updateStats() {
    try {
        const response = await fetch('/api/stats');
        const data = await response.json();
        
        document.getElementById('messages-today').textContent = data.messages_today || 0;
        document.getElementById('spam-blocked').textContent = data.spam_blocked || 0;
        document.getElementById('viruses-detected').textContent = data.viruses_detected || 0;
        document.getElementById('quarantined').textContent = data.quarantined || 0;
        
        updateActivityChart(data.activity_chart || []);
        updateRecentLog(data.recent_log || []);
    } catch (error) {
        console.error('Erro ao carregar estatísticas:', error);
    }
}

// Gráfico de atividade
let activityChart;
function updateActivityChart(data) {
    const ctx = document.getElementById('activity-chart').getContext('2d');
    
    if (activityChart) {
        activityChart.destroy();
    }
    
    activityChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.map(d => d.date),
            datasets: [{
                label: 'Mensagens Processadas',
                data: data.map(d => d.total),
                borderColor: 'rgb(59, 130, 246)',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                tension: 0.1
            }, {
                label: 'Spam Bloqueado',
                data: data.map(d => d.spam),
                borderColor: 'rgb(239, 68, 68)',
                backgroundColor: 'rgba(239, 68, 68, 0.1)',
                tension: 0.1
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

// Log recente
function updateRecentLog(logs) {
    const tbody = document.getElementById('recent-log');
    tbody.innerHTML = logs.map(log => `
        <tr class="${getRowClass(log.action)}">
            <td class="px-4 py-2">${new Date(log.timestamp).toLocaleString()}</td>
            <td class="px-4 py-2">${log.sender}</td>
            <td class="px-4 py-2">
                <span class="px-2 py-1 rounded text-sm ${getActionClass(log.action)}">
                    ${log.action.toUpperCase()}
                </span>
            </td>
            <td class="px-4 py-2">${log.score.toFixed(2)}</td>
            <td class="px-4 py-2">${log.reason}</td>
        </tr>
    `).join('');
}

function getRowClass(action) {
    switch(action) {
        case 'reject': return 'bg-red-50';
        case 'quarantine': return 'bg-yellow-50';
        case 'hold': return 'bg-blue-50';
        default: return '';
    }
}

function getActionClass(action) {
    switch(action) {
        case 'accept': return 'bg-green-100 text-green-800';
        case 'reject': return 'bg-red-100 text-red-800';
        case 'quarantine': return 'bg-yellow-100 text-yellow-800';
        case 'hold': return 'bg-blue-100 text-blue-800';
        default: return 'bg-gray-100 text-gray-800';
    }
}

// Atualiza a cada 5 segundos
setInterval(updateStats, 5000);
updateStats(); // Carrega inicial
</script>
{% endblock %}
    '''
}

# Systemd service para execução como daemon
SYSTEMD_SERVICE = '''
[Unit]
Description=SMTP Relay Modular - Andarilho dos Véus
After=network.target postgresql.service redis.service clamav-daemon.service
Wants=postgresql.service redis.service clamav-daemon.service

[Service]
Type=simple
User=smtp-relay
Group=smtp-relay
WorkingDirectory=/opt/smtp-relay
ExecStart=/opt/smtp-relay/venv/bin/python /opt/smtp-relay/smtp_relay.py --config /opt/smtp-relay/config.json
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Variáveis de ambiente
Environment=PYTHONPATH=/opt/smtp-relay
Environment=PYTHONUNBUFFERED=1

# Limites de recursos
LimitNOFILE=65536
MemoryMax=2G

[Install]
WantedBy=multi-user.target
'''

# Script de monitoramento
MONITORING_SCRIPT = '''#!/bin/bash
# Script de monitoramento do SMTP Relay
# Para uso com cron: */5 * * * * /opt/smtp-relay/monitor.sh

LOG_FILE="/var/log/smtp-relay-monitor.log"
PID_FILE="/var/run/smtp-relay.pid"
SERVICE_NAME="smtp-relay"

# Função de log
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> $LOG_FILE
}

# Verifica se o serviço está rodando
check_service() {
    if systemctl is-active --quiet $SERVICE_NAME; then
        return 0
    else
        return 1
    fi
}

# Verifica conectividade com PostgreSQL
check_database() {
    pg_isready -h localhost -p 5432 -U smtp_relay -d smtp_relay >/dev/null 2>&1
    return $?
}

# Verifica conectividade com Redis
check_redis() {
    redis-cli ping >/dev/null 2>&1
    return $?
}

# Verifica ClamAV
check_clamav() {
    clamdscan --version >/dev/null 2>&1
    return $?
}

# Verifica uso de memória
check_memory() {
    local mem_usage=$(ps -o pid,rss -p $(pgrep -f smtp_relay.py) | awk 'NR==2{print $2}')
    local mem_limit=2097152  # 2GB em KB
    
    if [ "$mem_usage" -gt "$mem_limit" ]; then
        log_message "ALERT: High memory usage: ${mem_usage}KB"
        return 1
    fi
    return 0
}

# Função principal de monitoramento
main() {
    log_message "Starting health check..."
    
    local errors=0
    
    # Verifica serviço principal
    if ! check_service; then
        log_message "ERROR: SMTP Relay service is not running"
        systemctl start $SERVICE_NAME
        ((errors++))
    fi
    
    # Verifica dependências
    if ! check_database; then
        log_message "WARNING: PostgreSQL connection failed"
        ((errors++))
    fi
    
    if ! check_redis; then
        log_message "WARNING: Redis connection failed" 
        ((errors++))
    fi
    
    if ! check_clamav; then
        log_message "WARNING: ClamAV not responding"
        ((errors++))
    fi
    
    # Verifica recursos
    if ! check_memory; then
        log_message "WARNING: High memory usage detected"
        ((errors++))
    fi
    
    if [ $errors -eq 0 ]; then
        log_message "Health check completed successfully"
    else
        log_message "Health check completed with $errors warnings/errors"
    fi
    
    # Rotaciona logs se muito grandes
    if [ -f $LOG_FILE ] && [ $(stat -f%z $LOG_FILE 2>/dev/null || stat -c%s $LOG_FILE) -gt 10485760 ]; then
        mv $LOG_FILE ${LOG_FILE}.old
        touch $LOG_FILE
    fi
}

main "$@"
'''

# Dockerfile para containerização
DOCKERFILE = '''
FROM python:3.11-slim

# Instala dependências do sistema
RUN apt-get update && apt-get install -y \\
    clamav clamav-daemon \\
    postgresql-client \\
    redis-tools \\
    yara \\
    build-essential \\
    && rm -rf /var/lib/apt/lists/*

# Cria usuário para o serviço
RUN useradd -r -s /bin/false smtp-relay

# Define diretório de trabalho
WORKDIR /app

# Copia requirements
COPY requirements.txt .

# Instala dependências Python
RUN pip install --no-cache-dir -r requirements.txt

# Copia código fonte
COPY smtp_relay.py .
COPY config.json.example config.json
COPY templates/ templates/

# Define permissões
RUN chown -R smtp-relay:smtp-relay /app

# Expõe portas
EXPOSE 2525 8080

# Usuário para execução
USER smtp-relay

# Comando padrão
CMD ["python", "smtp_relay.py", "--config", "config.json"]
'''

# Requirements.txt
REQUIREMENTS = '''
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
'''
        