#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║  CYMAG AutoScanner v2.0                                              ║
║  Diagnóstico Automatizado de Segurança — Phase 2: AI Investigation  ║
║  SENAI — Projeto Integrador Interdisciplinar I — 2026               ║
╚══════════════════════════════════════════════════════════════════════╝

ARQUITETURA (duas fases):
  Phase 1 — Varredura multi-camada:
      Socket TCP  → confirma quais portas estão abertas (sem root)
      Nmap -Pn    → identifica serviços e versões (ignora ICMP)
      CME         → valida SMB signing e domínio AD (se 445 ativo)
      Merge       → une os resultados das três camadas

  Phase 2 — Loop de investigação guiado por IA:
      Python envia achados → IA decide próxima ação → Python executa
      Repete até a IA chamar "done" ou atingir o limite de iterações
      (Circuit Breaker: max 8 ações por host, sem repetição de chamadas)

USO:
  python3 cymag_v2.py 10.10.100.0/24
  python3 cymag_v2.py 10.10.100.100 --debug
  GROQ_API_KEY=gsk_xxx python3 cymag_v2.py 10.10.100.100

DEPENDÊNCIAS:
  pip install python-nmap paho-mqtt requests groq reportlab --break-system-packages
"""

# ─── Imports Padrão ───────────────────────────────────────────────────────────
import sys
import os
import json
import socket
import subprocess
import re
import time
import math
import warnings
import ipaddress
import concurrent.futures
import datetime
from pathlib import Path

warnings.filterwarnings("ignore")  # Suprime avisos de SSL/TLS não verificado

# ─── Imports Opcionais (verificados em runtime) ───────────────────────────────
MISSING = []
try:
    import nmap
except ImportError:
    MISSING.append("python-nmap")

try:
    import requests
    requests.packages.urllib3.disable_warnings()  # Suprime aviso de certificado auto-assinado
except ImportError:
    MISSING.append("requests")

try:
    import paho.mqtt.client as mqtt_lib
except ImportError:
    MISSING.append("paho-mqtt")

try:
    from groq import Groq
except ImportError:
    MISSING.append("groq")

try:
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer,
        Table, TableStyle, HRFlowable
    )
    from reportlab.lib import colors
    from reportlab.lib.units import cm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
except ImportError:
    MISSING.append("reportlab")

if MISSING:
    print(f"\n[!] Dependências faltando. Execute:\n"
          f"    pip install {' '.join(MISSING)} --break-system-packages\n")
    sys.exit(1)

# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTES E CONFIGURAÇÕES GLOBAIS
# ═══════════════════════════════════════════════════════════════════════════════

VERSION = "2.0.0"

BANNER = f"""
╔══════════════════════════════════════════════════════════════════════╗
║  CYMAG AutoScanner v{VERSION}  —  Phase 2: AI Investigation Loop       ║
╚══════════════════════════════════════════════════════════════════════╝"""

# Ordem de severidade para ordenação (maior = mais grave)
SEVERITY_ORDER = {"CRÍTICO": 4, "ALTO": 3, "MÉDIO": 2, "BAIXO": 1, "INFO": 0}

# Cores HTML para relatório (mapa severidade → hex)
SEVERITY_COLOR = {
    "CRÍTICO": "#c0392b",
    "ALTO":    "#e67e22",
    "MÉDIO":   "#f39c12",
    "BAIXO":   "#27ae60",
    "INFO":    "#95a5a6",
}

SEVERITY_ICON = {
    "CRÍTICO": "🔴", "ALTO": "🟠", "MÉDIO": "🟡", "BAIXO": "🟢", "INFO": "⚪"
}

# Portas alvo divididas em dois grupos para controle fino
PORTS_COMMON = [
    21, 22, 23, 25, 53, 80, 443, 445,
    1433, 1880, 1883, 3306, 3307, 3389,
    5040, 5432, 6379, 8080, 8443, 8883,
    9200, 27017
]
PORTS_WINDOWS_AD = [
    135, 137, 139, 389, 445, 464, 636,
    3268, 3269, 5985, 5986, 49152
]
ALL_PORTS = sorted(set(PORTS_COMMON + PORTS_WINDOWS_AD))

# Timeouts por camada (em segundos)
SOCKET_TIMEOUT = 1.5   # Por porta no scan de socket
NMAP_TIMEOUT   = "90s" # Timeout total do nmap por host

# Limite de iterações do loop de IA por host (Circuit Breaker)
MAX_AI_ITERATIONS = 8


# ═══════════════════════════════════════════════════════════════════════════════
# MODELOS DE DADOS
# ═══════════════════════════════════════════════════════════════════════════════

class Finding:
    """
    Representa um único achado de segurança.

    Atributos:
        host        : IP do alvo
        service     : Nome do serviço afetado (ex: "SMB", "HTTP")
        port        : Porta TCP/UDP
        title       : Título curto do achado
        description : Explicação técnica detalhada
        severity    : CRÍTICO / ALTO / MÉDIO / BAIXO / INFO
        cvss        : Score CVSS v3.1 (0.0 a 10.0)
        evidence    : Evidência técnica coletada (output de comando, resposta HTTP, etc.)
        source      : Origem do achado: "phase1" (scanner) ou "phase2" (IA)
    """

    def __init__(self, host, service, port, title,
                 description, severity, cvss, evidence="", source="phase1"):
        self.host        = host
        self.service     = service
        self.port        = port
        self.title       = title
        self.description = description
        self.severity    = severity
        self.cvss        = cvss
        self.evidence    = evidence
        self.source      = source   # "phase1" ou "phase2"


# ═══════════════════════════════════════════════════════════════════════════════
# SYSTEM PROMPT DA IA — O "CÉREBRO" DO AGENTE
# ═══════════════════════════════════════════════════════════════════════════════

SYSTEM_PROMPT = """
Você é um Analista de Segurança Ofensiva especializado em diagnóstico de
infraestruturas corporativas (Active Directory, serviços web, IoT).

═══════════════════════════════════════════════════════════
BLOCO 1 — PAPEL E RESTRIÇÕES ABSOLUTAS
═══════════════════════════════════════════════════════════
• Você receberá um JSON com achados de segurança já coletados.
• Sua tarefa é decidir QUAL FUNÇÃO executar a seguir para aprofundar a análise.
• Você DEVE responder EXCLUSIVAMENTE com um objeto JSON válido.
• NUNCA responda com texto livre, markdown, blocos de código ou explicações fora do JSON.
• NUNCA invente funções fora do catálogo abaixo.
• Se o input for inválido, responda: {"reasoning":"input inválido","function_name":"done","params":{"host":"?","summary":"input inválido"}}

═══════════════════════════════════════════════════════════
BLOCO 2 — CATÁLOGO DE FUNÇÕES (ÚNICO CONJUNTO PERMITIDO)
═══════════════════════════════════════════════════════════
Você SÓ pode chamar funções desta lista. Qualquer nome fora dela será descartado.

{
  "enum_smb": {
    "descricao": "Enumera compartilhamentos SMB, null session, versão do protocolo e dados do domínio AD.",
    "quando_usar": "Porta 445 ou 139 encontrada aberta.",
    "params": {"host": "string (IP obrigatório)", "port": "integer (padrão: 445)"}
  },
  "enum_http": {
    "descricao": "Testa endpoint HTTP: headers de segurança ausentes, paths sensíveis (/admin, /api, /.env), disclosure de versão.",
    "quando_usar": "Porta 80, 443, 8080, 8443 aberta.",
    "params": {"host": "string", "port": "integer (padrão: 80)", "path": "string (padrão: /)"}
  },
  "test_sqli": {
    "descricao": "Testa SQL injection em parâmetro de URL. Envia payloads simples e verifica erros SQL na resposta.",
    "quando_usar": "Endpoint da API encontrado com parâmetro de busca (ex: ?name=, ?id=, ?q=).",
    "params": {"host": "string", "port": "integer", "path": "string (ex: /api/collaborators)", "param": "string (ex: name)"}
  },
  "check_nodered": {
    "descricao": "Testa acesso sem autenticação ao painel Node-RED. Verifica /settings, /flows e functionExternalModules.",
    "quando_usar": "Porta 1880 encontrada aberta.",
    "params": {"host": "string", "port": "integer (padrão: 1880)"}
  },
  "check_mqtt": {
    "descricao": "Testa se broker MQTT aceita conexão anônima e captura mensagens por 5 segundos.",
    "quando_usar": "Porta 1883 ou 8883 encontrada aberta.",
    "params": {"host": "string", "port": "integer (padrão: 1883)"}
  },
  "check_mysql": {
    "descricao": "Testa conectividade com MySQL, coleta versão e verifica se aceita login sem senha.",
    "quando_usar": "Porta 3306 ou 3307 encontrada aberta.",
    "params": {"host": "string", "port": "integer (padrão: 3306)"}
  },
  "check_auth_token": {
    "descricao": "Testa se a aplicação aceita token de sessão forjado em Base64 (padrão usuario:role:contexto).",
    "quando_usar": "Aplicação web usa token Base64 sem assinatura criptográfica.",
    "params": {"host": "string", "port": "integer", "endpoint": "string (ex: /admin)", "token": "string (Base64 forjado)"}
  },
  "enum_rpc": {
    "descricao": "Lista endpoints RPC registrados na porta 135 usando impacket-rpcdump.",
    "quando_usar": "Porta 135 encontrada aberta (ambientes Windows/AD).",
    "params": {"host": "string", "port": "integer (padrão: 135)"}
  },
  "done": {
    "descricao": "Sinaliza que a investigação deste host está concluída. DEVE ser chamada ao fim.",
    "quando_usar": "Não há mais ações úteis a executar, ou limite de iterações atingido.",
    "params": {"host": "string", "summary": "string (resumo executivo dos achados)"}
  }
}

═══════════════════════════════════════════════════════════
BLOCO 3 — CIRCUIT BREAKER (PREVENÇÃO DE LOOPS)
═══════════════════════════════════════════════════════════
REGRAS OBRIGATÓRIAS — violá-las produz output inválido:

1. ANTI-REPETIÇÃO: O campo "called" no input lista chamadas já executadas.
   Você JAMAIS pode repetir uma combinação idêntica de {function_name + params}.

2. LIMITE HARD: Se "iteration" >= 8, sua ÚNICA resposta permitida é chamar "done".

3. ESGOTAMENTO LÓGICO: Se não houver nenhuma função nova e útil a chamar,
   chame "done" imediatamente. Não force ações desnecessárias.

4. PRIORIDADE: Investigue achados na ordem: CRÍTICO > ALTO > MÉDIO > BAIXO.

5. EFICIÊNCIA: Prefira funções que podem revelar novos achados encadeados.
   Exemplo: check_nodered revela flows → flows podem conter credenciais MQTT.

═══════════════════════════════════════════════════════════
BLOCO 4 — FORMATO DE SAÍDA (OBRIGATÓRIO)
═══════════════════════════════════════════════════════════
Responda SEMPRE com este JSON e NADA MAIS:

{
  "reasoning": "Explicação em 1-3 frases do PORQUÊ desta ação, baseada nos achados.",
  "function_name": "nome_da_funcao_do_catalogo",
  "params": {
    "chave": "valor conforme definido no catálogo"
  },
  "priority": "CRÍTICO|ALTO|MÉDIO|BAIXO",
  "confidence": 0-10
}

EXEMPLO DE SAÍDA VÁLIDA:
{
  "reasoning": "Node-RED na porta 1880 foi detectado na varredura. É necessário verificar se o painel está acessível sem autenticação, o que permitiria acesso total aos fluxos de automação industrial.",
  "function_name": "check_nodered",
  "params": {"host": "10.10.100.100", "port": 1880},
  "priority": "CRÍTICO",
  "confidence": 9
}

EXEMPLO DE SAÍDA INVÁLIDA (NUNCA FAÇA ISSO):
Vou verificar o Node-RED: {"function_name": ...}
```json
{"function_name": ...}
```
""".strip()


# ═══════════════════════════════════════════════════════════════════════════════
# CATÁLOGO DE FUNÇÕES — IMPLEMENTAÇÕES PYTHON DAS AÇÕES DA IA
# ═══════════════════════════════════════════════════════════════════════════════

class FunctionCatalog:
    """
    Mapeia nomes de função (vindos da IA) para implementações Python reais.

    A IA nunca executa código diretamente — ela declara intenção.
    Esta classe valida e executa com segurança.

    Uso:
        catalog = FunctionCatalog()
        resultado = catalog.execute("enum_smb", {"host": "10.0.0.1", "port": 445})
    """

    # Nomes permitidos — qualquer outro nome vindo da IA é descartado
    ALLOWED = {
        "enum_smb", "enum_http", "test_sqli",
        "check_nodered", "check_mqtt", "check_mysql",
        "check_auth_token", "enum_rpc", "done"
    }

    def execute(self, function_name: str, params: dict) -> dict:
        """
        Valida o nome da função e executa.
        Retorna dict com 'output' (texto) e 'findings' (lista de Finding).
        """
        if function_name not in self.ALLOWED:
            return {
                "output": f"[ERRO] Função '{function_name}' não existe no catálogo.",
                "findings": []
            }

        # Despacha para o método correspondente
        method = getattr(self, f"_fn_{function_name}", None)
        if not method:
            return {"output": "[ERRO] Método não implementado.", "findings": []}

        try:
            return method(**params)
        except TypeError as e:
            # Parâmetros incorretos enviados pela IA
            return {"output": f"[ERRO] Parâmetros inválidos: {e}", "findings": []}
        except Exception as e:
            return {"output": f"[ERRO] Exceção: {e}", "findings": []}

    # ── Implementações das funções ─────────────────────────────────────────────

    def _fn_enum_smb(self, host: str, port: int = 445) -> dict:
        """Enumera compartilhamentos SMB e verifica null session."""
        output_lines = []
        findings = []

        # Tenta smbclient com null session
        try:
            r = subprocess.run(
                ["smbclient", "-L", f"//{host}", "-N", "--no-pass"],
                capture_output=True, text=True, timeout=10
            )
            out = r.stdout + r.stderr
            output_lines.append(f"smbclient -L //{host} -N:\n{out[:600]}")

            if "Sharename" in out or "Disk" in out:
                findings.append(Finding(
                    host=host, service="SMB", port=port,
                    title="SMB Null Session Aceita — Shares Expostos",
                    description=(
                        "O servidor aceita conexões SMB sem credenciais (null session). "
                        "Isso permite enumerar compartilhamentos, usuários e políticas "
                        "do domínio sem autenticação."
                    ),
                    severity="ALTO", cvss=7.5,
                    evidence=f"smbclient -L //{host} -N → lista de shares retornada",
                    source="phase2"
                ))
        except Exception as e:
            output_lines.append(f"smbclient erro: {e}")

        # crackmapexec para dados do AD
        cme_path = _which("crackmapexec") or _which("cme")
        if cme_path:
            try:
                r2 = subprocess.run(
                    [cme_path, "smb", host],
                    capture_output=True, text=True, timeout=20
                )
                out2 = r2.stdout + r2.stderr
                output_lines.append(f"\ncrackmapexec smb {host}:\n{out2[:400]}")

                # Detecta SMB Signing desabilitado
                if "signing:False" in out2 or "signing: False" in out2:
                    findings.append(Finding(
                        host=host, service="SMB", port=port,
                        title="SMB Message Signing Desabilitado",
                        description=(
                            "Sem assinatura de mensagens SMB, ataques NTLM Relay são viáveis. "
                            "Um atacante na rede pode interceptar hashes de autenticação e "
                            "redirecioná-los para outros servidores, comprometendo o domínio."
                        ),
                        severity="CRÍTICO", cvss=9.0,
                        evidence=out2[:300],
                        source="phase2"
                    ))
            except Exception as e:
                output_lines.append(f"crackmapexec erro: {e}")

        return {"output": "\n".join(output_lines), "findings": findings}

    def _fn_enum_http(self, host: str, port: int = 80, path: str = "/") -> dict:
        """Verifica headers de segurança, divulgação de versão e paths sensíveis."""
        findings = []
        output_lines = []
        proto = "https" if port in [443, 8443] else "http"
        base = f"{proto}://{host}:{port}"

        try:
            r = requests.get(f"{base}{path}", timeout=6, verify=False)
            output_lines.append(f"GET {base}{path} → HTTP {r.status_code}")
            output_lines.append(f"Headers: {dict(r.headers)}")

            # Headers de segurança ausentes (OWASP recomendados)
            required_headers = [
                "X-Content-Type-Options",
                "X-Frame-Options",
                "Content-Security-Policy",
            ]
            missing = [h for h in required_headers if h not in r.headers]
            if missing:
                findings.append(Finding(
                    host=host, service="HTTP", port=port,
                    title="Headers de Segurança HTTP Ausentes",
                    description=(
                        "A aplicação não implementa headers de segurança HTTP recomendados "
                        "pelo OWASP, expondo usuários a ataques como clickjacking e XSS."
                    ),
                    severity="MÉDIO", cvss=5.3,
                    evidence=f"Ausentes: {', '.join(missing)}",
                    source="phase2"
                ))

            # Divulgação de versão do servidor
            server = r.headers.get("Server", "")
            if server and any(v in server.lower() for v in ["nginx/", "apache/", "iis/"]):
                findings.append(Finding(
                    host=host, service="HTTP", port=port,
                    title="Divulgação de Versão do Servidor Web",
                    description=(
                        "O header 'Server' expõe a versão exata do servidor web, "
                        "facilitando ataques direcionados a CVEs conhecidas."
                    ),
                    severity="BAIXO", cvss=3.1,
                    evidence=f"Server: {server}",
                    source="phase2"
                ))

        except Exception as e:
            output_lines.append(f"Erro HTTP: {e}")

        return {"output": "\n".join(output_lines), "findings": findings}

    def _fn_test_sqli(self, host: str, port: int = 80,
                      path: str = "/", param: str = "id") -> dict:
        """Testa SQL injection com payload básico e verifica erros na resposta."""
        findings = []
        output_lines = []
        proto = "https" if port in [443, 8443] else "http"

        # Payloads simples que causam erro SQL se não houver sanitização
        payloads = ["'", "' OR '1'='1", "1' AND SLEEP(2)--"]
        sql_errors = [
            "sql", "mysql", "syntax error", "ora-", "pg_", "sqlite",
            "ER_PARSE_ERROR", "warning: mysql", "you have an error in your sql"
        ]

        for payload in payloads:
            url = f"{proto}://{host}:{port}{path}?{param}={payload}"
            try:
                r = requests.get(url, timeout=5, verify=False)
                body_lower = r.text.lower()
                output_lines.append(f"GET {url} → HTTP {r.status_code}")

                if any(err in body_lower for err in sql_errors):
                    findings.append(Finding(
                        host=host, service="HTTP", port=port,
                        title=f"SQL Injection Confirmada — {path}?{param}",
                        description=(
                            f"O parâmetro '{param}' não sanitiza entrada do usuário. "
                            f"O servidor retornou erro SQL ao receber o payload: {payload!r}. "
                            "Isso permite extração completa do banco de dados."
                        ),
                        severity="CRÍTICO", cvss=9.8,
                        evidence=f"Payload: {payload!r} → erro SQL na resposta (HTTP {r.status_code})",
                        source="phase2"
                    ))
                    break  # Um achado confirmatório é suficiente
            except Exception as e:
                output_lines.append(f"Erro em {url}: {e}")

        return {"output": "\n".join(output_lines), "findings": findings}

    def _fn_check_nodered(self, host: str, port: int = 1880) -> dict:
        """Verifica acesso sem autenticação ao painel Node-RED."""
        findings = []
        output_lines = []
        base = f"http://{host}:{port}"

        # /settings expõe versão e configurações (incluindo functionExternalModules)
        try:
            r_settings = requests.get(f"{base}/settings", timeout=5)
            output_lines.append(f"GET /settings → HTTP {r_settings.status_code}")

            if r_settings.status_code == 200:
                data = r_settings.json()
                version = data.get("version", "?")
                ext_modules = data.get("functionExternalModules", False)

                findings.append(Finding(
                    host=host, service="Node-RED", port=port,
                    title="Node-RED Admin Panel Acessível Sem Autenticação",
                    description=(
                        f"O painel administrativo Node-RED v{version} está acessível "
                        "sem credenciais. Permite visualizar, modificar e criar fluxos "
                        "de automação industrial (OT/IoT) livremente."
                    ),
                    severity="CRÍTICO", cvss=9.8,
                    evidence=f"GET /settings → 200 | versão: {version} | funcExtModules: {ext_modules}",
                    source="phase2"
                ))

                # functionExternalModules = true permite RCE via child_process
                if ext_modules:
                    findings.append(Finding(
                        host=host, service="Node-RED", port=port,
                        title="Node-RED — RCE Potencial via functionExternalModules",
                        description=(
                            "A flag 'functionExternalModules: true' permite que nós Function "
                            "importem módulos Node.js como child_process, viabilizando "
                            "execução de comandos arbitrários no sistema operacional do servidor."
                        ),
                        severity="CRÍTICO", cvss=9.1,
                        evidence="settings.functionExternalModules = true",
                        source="phase2"
                    ))
        except Exception as e:
            output_lines.append(f"Erro /settings: {e}")

        # /flows expõe o código-fonte completo da automação
        try:
            r_flows = requests.get(f"{base}/flows", timeout=5)
            output_lines.append(f"GET /flows → HTTP {r_flows.status_code}")

            if r_flows.status_code == 200:
                flows = r_flows.json()
                flow_text = json.dumps(flows).lower()
                n_nodes = len(flows)

                # Verifica se os flows contêm referências a sistemas industriais
                industrial_keywords = ["pump", "fuel", "sensor", "plc", "scada",
                                       "modbus", "mqtt", "temperature", "pressure"]
                ot_found = [kw for kw in industrial_keywords if kw in flow_text]

                ev = f"GET /flows → 200 | {n_nodes} nós exportados sem autenticação"
                if ot_found:
                    ev += f" | palavras-chave industriais: {', '.join(ot_found)}"

                findings.append(Finding(
                    host=host, service="Node-RED", port=port,
                    title="Código-Fonte de Automação OT/IoT Exposto",
                    description=(
                        f"{n_nodes} nós de automação acessíveis sem autenticação via /flows. "
                        "Um atacante pode ler, modificar ou injetar lógica maliciosa nos "
                        "fluxos de controle industrial."
                    ),
                    severity="CRÍTICO", cvss=8.6,
                    evidence=ev,
                    source="phase2"
                ))

        except Exception as e:
            output_lines.append(f"Erro /flows: {e}")

        return {"output": "\n".join(output_lines), "findings": findings}

    def _fn_check_mqtt(self, host: str, port: int = 1883) -> dict:
        """Tenta conectar ao broker MQTT sem credenciais e captura mensagens."""
        findings = []
        output_lines = []
        connected = [False]
        messages = []

        def on_connect(client, ud, flags, rc, props=None):
            if rc == 0:
                connected[0] = True
                client.subscribe("#")  # "#" = assina TODOS os tópicos

        def on_message(client, ud, msg):
            try:
                payload = msg.payload.decode("utf-8", errors="ignore")
                messages.append(f"{msg.topic}: {payload[:100]}")
            except Exception:
                pass

        try:
            c = mqtt_lib.Client(mqtt_lib.CallbackAPIVersion.VERSION2)
            c.on_connect = on_connect
            c.on_message = on_message
            c.connect(host, port, keepalive=5)
            c.loop_start()
            time.sleep(4)   # Aguarda mensagens chegarem
            c.loop_stop()
            try:
                c.disconnect()
            except Exception:
                pass

            if connected[0]:
                output_lines.append(f"Broker MQTT {host}:{port} aceitou conexão anônima")
                if messages:
                    output_lines.append(f"Mensagens capturadas ({len(messages)}):")
                    for m in messages[:5]:
                        output_lines.append(f"  {m}")

                ev = f"Conexão anônima aceita | {len(messages)} msg(s) capturada(s)"
                if messages:
                    ev += f" | ex: {messages[0][:80]}"

                findings.append(Finding(
                    host=host, service="MQTT", port=port,
                    title="Broker MQTT Sem Autenticação e Sem TLS",
                    description=(
                        "O broker MQTT aceita conexões anônimas na porta "
                        f"{port}/tcp sem criptografia. Qualquer dispositivo "
                        "na rede pode publicar ou assinar qualquer tópico, "
                        "incluindo telemetria industrial."
                    ),
                    severity="CRÍTICO", cvss=9.3,
                    evidence=ev,
                    source="phase2"
                ))
            else:
                output_lines.append("Broker MQTT recusou conexão anônima (autenticação ativa).")

        except Exception as e:
            output_lines.append(f"Erro MQTT: {e}")

        return {"output": "\n".join(output_lines), "findings": findings}

    def _fn_check_mysql(self, host: str, port: int = 3306) -> dict:
        """Verifica conectividade MySQL e detecta versões EOL."""
        findings = []
        output_lines = []

        # Usa nmap para fingerprint do MySQL (não precisa de credenciais)
        try:
            r = subprocess.run(
                ["nmap", "-Pn", "-sT", "-p", str(port),
                 "--script", "mysql-info,mysql-empty-password",
                 host, "-oN", "-"],
                capture_output=True, text=True, timeout=20
            )
            out = r.stdout
            output_lines.append(f"nmap mysql-info {host}:{port}:\n{out[:500]}")

            # Detecta versões MySQL com EOL
            eol_versions = {
                "5.0": "2012", "5.1": "2013",
                "5.5": "2018", "5.6": "2021",
                "5.7": "2023"
            }
            for ver, year in eol_versions.items():
                if f"MySQL {ver}" in out or f"mysql/{ver}" in out.lower():
                    findings.append(Finding(
                        host=host, service="MySQL", port=port,
                        title=f"MySQL {ver}.x — EOL Sem Patches Desde {year}",
                        description=(
                            f"MySQL {ver}.x atingiu End-of-Life em {year}. "
                            "Múltiplas CVEs críticas sem patch disponível, incluindo "
                            "vulnerabilidades de execução remota de código."
                        ),
                        severity="CRÍTICO", cvss=9.8,
                        evidence=f"Versão MySQL {ver}.x detectada na porta {port}/tcp",
                        source="phase2"
                    ))
                    break

            # Verifica acesso sem senha (empty password)
            if "empty-password" in out.lower() or "root account has no password" in out.lower():
                findings.append(Finding(
                    host=host, service="MySQL", port=port,
                    title="MySQL Aceita Login Sem Senha (root)",
                    description=(
                        "O usuário root do MySQL não possui senha definida. "
                        "Acesso total ao banco de dados sem credenciais."
                    ),
                    severity="CRÍTICO", cvss=10.0,
                    evidence="mysql-empty-password: conta root sem senha",
                    source="phase2"
                ))

        except Exception as e:
            output_lines.append(f"Erro nmap mysql: {e}")

        return {"output": "\n".join(output_lines), "findings": findings}

    def _fn_check_auth_token(self, host: str, port: int = 80,
                              endpoint: str = "/admin", token: str = "") -> dict:
        """Testa se a aplicação aceita token de sessão forjado em Base64."""
        import base64
        findings = []
        output_lines = []
        proto = "https" if port in [443, 8443] else "http"

        # Se nenhum token foi fornecido, tenta os padrões comuns do ambiente CYMAG
        if not token:
            candidates = [
                base64.b64encode(b"admin:admin:homologacao").decode(),
                base64.b64encode(b"admin:admin:producao").decode(),
                base64.b64encode(b"suporte.n1:support:homologacao").decode(),
            ]
        else:
            candidates = [token]

        for tok in candidates:
            decoded = base64.b64decode(tok).decode("utf-8", errors="ignore")
            output_lines.append(f"\nTestando token: {tok[:30]}... ({decoded})")

            # Testa com header Authorization Bearer
            for header_fmt in [
                {"Authorization": f"Bearer {tok}"},
                {"X-Auth-Token": tok},
                {"x-auth-token": tok},
            ]:
                try:
                    r = requests.get(
                        f"{proto}://{host}:{port}{endpoint}",
                        headers=header_fmt,
                        timeout=5, verify=False
                    )
                    output_lines.append(
                        f"  {list(header_fmt.keys())[0]}: {tok[:20]}... → HTTP {r.status_code}"
                    )

                    if r.status_code == 200:
                        findings.append(Finding(
                            host=host, service="HTTP", port=port,
                            title="Broken Authentication — Token Base64 Forjável Aceito",
                            description=(
                                "A aplicação aceita tokens de sessão forjados codificados "
                                f"em Base64 sem validação criptográfica. Token '{decoded}' "
                                f"concedeu acesso HTTP 200 a {endpoint}."
                            ),
                            severity="CRÍTICO", cvss=9.1,
                            evidence=(
                                f"Token forjado: {tok[:30]}... "
                                f"(= {decoded!r}) → {endpoint} HTTP 200"
                            ),
                            source="phase2"
                        ))
                        return {"output": "\n".join(output_lines), "findings": findings}
                except Exception as e:
                    output_lines.append(f"  Erro: {e}")

        return {"output": "\n".join(output_lines), "findings": findings}

    def _fn_enum_rpc(self, host: str, port: int = 135) -> dict:
        """Enumera endpoints RPC registrados usando impacket-rpcdump."""
        findings = []
        output_lines = []

        # Verifica se impacket está disponível
        rpc_path = _which("impacket-rpcdump")
        if not rpc_path:
            output_lines.append("[!] impacket-rpcdump não encontrado. Pulando enumeração RPC.")
            return {"output": "\n".join(output_lines), "findings": findings}

        try:
            r = subprocess.run(
                [rpc_path, host],
                capture_output=True, text=True, timeout=25
            )
            out = r.stdout
            output_lines.append(f"impacket-rpcdump {host}:\n{out[:800]}")

            if r.returncode == 0 and out:
                # Conta quantos endpoints foram expostos
                endpoints = re.findall(r"Protocol:\s+(.+)", out)
                n_endpoints = len(endpoints)

                if n_endpoints > 0:
                    findings.append(Finding(
                        host=host, service="RPC", port=port,
                        title=f"RPC Endpoint Mapper — {n_endpoints} Serviços Enumerados",
                        description=(
                            f"A porta 135 (RPC Endpoint Mapper) expõe {n_endpoints} serviços "
                            "registrados sem autenticação. Pode revelar serviços internos, "
                            "versões de componentes e vetores de movimentação lateral."
                        ),
                        severity="MÉDIO", cvss=5.3,
                        evidence=f"rpcdump retornou {n_endpoints} endpoints | exemplos: {', '.join(endpoints[:3])}",
                        source="phase2"
                    ))
        except Exception as e:
            output_lines.append(f"Erro rpcdump: {e}")

        return {"output": "\n".join(output_lines), "findings": findings}

    def _fn_done(self, host: str, summary: str) -> dict:
        """Sinaliza fim da investigação (sem ação real — apenas encerra o loop)."""
        return {
            "output": f"[done] Investigação de {host} concluída.\nResumo IA: {summary}",
            "findings": [],
            "__done__": True   # Flag interna para o loop detectar o fim
        }


# ═══════════════════════════════════════════════════════════════════════════════
# AGENTE DE IA — COMUNICAÇÃO COM GROQ/LLAMA
# ═══════════════════════════════════════════════════════════════════════════════

class AIAgent:
    """
    Encapsula a comunicação com a API Groq (LLM).

    Responsabilidades:
        - Enviar o estado atual (achados + histórico) ao LLM
        - Receber e validar o JSON de resposta
        - Garantir que a resposta respeite o catálogo de funções
        - Implementar retry em caso de JSON inválido
    """

    def __init__(self, api_key: str, model: str = "llama-3.3-70b-versatile"):
        self.client = Groq(api_key=api_key)
        self.model  = model

    def decide(self, host: str, findings: list, called: list, iteration: int) -> dict:
        """
        Envia o contexto ao LLM e retorna a próxima ação como dict.

        Args:
            host      : IP do host em investigação
            findings  : Lista de Finding já coletados
            called    : Lista de {function_name, params} já executados
            iteration : Número da iteração atual (para o circuit breaker)

        Returns:
            dict com: reasoning, function_name, params, priority, confidence
        """
        # Serializa achados para o prompt (sem sobrecarregar o contexto)
        findings_json = [
            {
                "title":    f.title,
                "service":  f.service,
                "port":     f.port,
                "severity": f.severity,
                "cvss":     f.cvss,
                "evidence": f.evidence[:150]
            }
            for f in findings
        ]

        # Payload enviado à IA
        user_payload = {
            "host":         host,
            "iteration":    iteration,
            "max_iterations": MAX_AI_ITERATIONS,
            "findings":     findings_json,
            "called":       called,
            "instruction":  (
                f"Iteração {iteration}/{MAX_AI_ITERATIONS}. "
                "Analise os achados acima e decida a próxima ação de investigação. "
                "Retorne APENAS JSON válido conforme o formato especificado."
            )
        }

        # Tenta até 2 vezes (para caso a IA retorne JSON inválido na primeira)
        for attempt in range(2):
            try:
                resp = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system",  "content": SYSTEM_PROMPT},
                        {"role": "user",    "content": json.dumps(user_payload, ensure_ascii=False)}
                    ],
                    max_tokens=512,
                    temperature=0.2  # Baixa temperatura = respostas mais determinísticas
                )

                raw = resp.choices[0].message.content.strip()

                # Extrai JSON mesmo se a IA colocou texto em volta
                match = re.search(r"\{.*\}", raw, re.DOTALL)
                if not match:
                    raise ValueError(f"Nenhum JSON encontrado na resposta: {raw[:200]}")

                decision = json.loads(match.group())

                # Valida campos obrigatórios
                required = ["reasoning", "function_name", "params"]
                for field in required:
                    if field not in decision:
                        raise ValueError(f"Campo obrigatório ausente: '{field}'")

                # Garante que function_name está no catálogo
                if decision["function_name"] not in FunctionCatalog.ALLOWED:
                    raise ValueError(
                        f"Função '{decision['function_name']}' não está no catálogo"
                    )

                return decision

            except (json.JSONDecodeError, ValueError) as e:
                if attempt == 0:
                    print(f"      [!] IA retornou JSON inválido, tentando novamente... ({e})")
                else:
                    print(f"      [!] Falha definitiva no JSON da IA. Encerrando host.")
                    # Fallback: encerra investigação deste host
                    return {
                        "reasoning": f"Falha ao parsear resposta da IA: {e}",
                        "function_name": "done",
                        "params": {"host": host, "summary": "Investigação encerrada por erro de parsing."},
                        "priority": "INFO",
                        "confidence": 0
                    }

        # Nunca deve chegar aqui, mas garante retorno
        return {
            "reasoning": "Erro inesperado",
            "function_name": "done",
            "params": {"host": host, "summary": "Erro inesperado no agente."},
            "priority": "INFO", "confidence": 0
        }


# ═══════════════════════════════════════════════════════════════════════════════
# LOOP DE INVESTIGAÇÃO (PHASE 2)
# ═══════════════════════════════════════════════════════════════════════════════

class InvestigationLoop:
    """
    Orquestra o loop Python ↔ IA para um único host.

    Fluxo:
      1. Recebe achados iniciais da Phase 1
      2. Envia contexto ao AIAgent
      3. AIAgent retorna {function_name, params}
      4. FunctionCatalog executa a função
      5. Novos achados são adicionados à lista
      6. Repete até "done" ou MAX_AI_ITERATIONS
    """

    def __init__(self, agent: AIAgent, catalog: FunctionCatalog):
        self.agent   = agent
        self.catalog = catalog

    def run(self, host: str, initial_findings: list) -> list:
        """
        Executa o loop de investigação para um host.

        Args:
            host             : IP do alvo
            initial_findings : Achados já coletados na Phase 1

        Returns:
            Lista de Finding adicionais gerados na Phase 2
        """
        print(f"\n  [Phase 2] Loop de investigação IA → {host}")

        findings  = list(initial_findings)   # Cópia local para não modificar o original
        new_finds = []                        # Achados gerados na Phase 2
        called    = []                        # Histórico de chamadas para o circuit breaker

        for iteration in range(1, MAX_AI_ITERATIONS + 1):
            print(f"    [{iteration}/{MAX_AI_ITERATIONS}] Consultando IA...")

            # Pergunta à IA o que fazer
            decision = self.agent.decide(host, findings, called, iteration)

            fn_name  = decision.get("function_name", "done")
            params   = decision.get("params", {})
            reason   = decision.get("reasoning", "")
            priority = decision.get("priority", "?")

            print(f"      Raciocínio: {reason[:120]}")
            print(f"      → {fn_name}({params}) [prioridade: {priority}]")

            # Registra no histórico para o circuit breaker
            call_record = {"function_name": fn_name, "params": params}
            called.append(call_record)

            # Executa a função via catálogo
            result = self.catalog.execute(fn_name, params)

            # Verifica se é sinal de encerramento
            if result.get("__done__") or fn_name == "done":
                print(f"      [✓] Investigação encerrada pela IA.")
                break

            # Adiciona novos achados
            phase2_findings = result.get("findings", [])
            if phase2_findings:
                print(f"      [+] {len(phase2_findings)} novo(s) achado(s) encontrado(s):")
                for f in phase2_findings:
                    icon = SEVERITY_ICON.get(f.severity, "⚪")
                    print(f"          {icon} [{f.severity}] {f.title}")
                new_finds.extend(phase2_findings)
                findings.extend(phase2_findings)
            else:
                print(f"      [ ] Nenhum achado novo nesta iteração.")

        print(f"  [Phase 2] Concluído: {len(new_finds)} achado(s) adicionais.")
        return new_finds


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1 — SCANNER MULTI-CAMADA
# ═══════════════════════════════════════════════════════════════════════════════

class Scanner:
    """
    Realiza a varredura de segurança em três camadas:
      Camada 1: Socket TCP — confirma portas abertas sem precisar de root
      Camada 2: Nmap -Pn -sT — identifica serviços e versões
      Camada 3: Merge + enriquecimento (CME para SMB, testes HTTP, etc.)
    """

    # Base de conhecimento: porta → informações de risco padrão
    PORT_RISK_DB = {
        445:  {"service": "SMB",      "severity": "CRÍTICO", "cvss": 9.0,
               "desc": "SMB ativo — vetor primário de ransomware (EternalBlue, NTLM Relay)"},
        139:  {"service": "NetBIOS",  "severity": "MÉDIO",   "cvss": 5.3,
               "desc": "NetBIOS Session Service — pode permitir null session"},
        135:  {"service": "RPC",      "severity": "MÉDIO",   "cvss": 5.3,
               "desc": "RPC Endpoint Mapper — enumeração de serviços Windows"},
        1880: {"service": "Node-RED", "severity": "CRÍTICO", "cvss": 9.8,
               "desc": "Node-RED IoT platform — sem autenticação por padrão"},
        1883: {"service": "MQTT",     "severity": "CRÍTICO", "cvss": 9.3,
               "desc": "MQTT Broker — sem autenticação/TLS por padrão"},
        3307: {"service": "MySQL",    "severity": "CRÍTICO", "cvss": 9.8,
               "desc": "MySQL em porta não padrão — verificar versão e acesso"},
        3306: {"service": "MySQL",    "severity": "ALTO",    "cvss": 7.5,
               "desc": "MySQL exposto — verificar autenticação e versão"},
        3389: {"service": "RDP",      "severity": "ALTO",    "cvss": 7.0,
               "desc": "RDP exposto — vetor de brute-force e ransomware"},
        389:  {"service": "LDAP",     "severity": "MÉDIO",   "cvss": 5.3,
               "desc": "LDAP — pode permitir enumeração de usuários AD"},
        88:   {"service": "Kerberos", "severity": "MÉDIO",   "cvss": 5.3,
               "desc": "Kerberos KDC — AS-REP Roasting se mal configurado"},
        22:   {"service": "SSH",      "severity": "BAIXO",   "cvss": 3.1,
               "desc": "SSH exposto — verificar versão e autenticação"},
        80:   {"service": "HTTP",     "severity": "MÉDIO",   "cvss": 5.3,
               "desc": "HTTP sem TLS — verificar endpoints e headers"},
        5985: {"service": "WinRM",    "severity": "ALTO",    "cvss": 7.5,
               "desc": "WinRM — gerenciamento remoto Windows exposto"},
        21:   {"service": "FTP",      "severity": "ALTO",    "cvss": 7.5,
               "desc": "FTP sem criptografia — credenciais em texto claro"},
        23:   {"service": "Telnet",   "severity": "CRÍTICO", "cvss": 9.8,
               "desc": "Telnet — protocolo sem criptografia, EOL"},
    }

    def __init__(self, debug: bool = False):
        self.debug    = debug
        self.scan_log = {}   # Log interno para debug

    def dbg(self, msg: str):
        """Imprime mensagem de debug se modo debug ativo."""
        if self.debug:
            print(f"    [DBG] {msg}")

    def discover_hosts(self, target: str) -> list:
        """
        Descobre hosts ativos em três etapas progressivas:
          1. Ping sweep (nmap -sn)
          2. Fallback -Pn (para Windows que bloqueia ICMP)
          3. Usa o IP diretamente (para alvo único)
        """
        print(f"[1/4] Descoberta de hosts em {target}...")
        hosts = []

        # Etapa 1: ping sweep padrão
        self.dbg("Etapa 1: nmap ping sweep")
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=target, arguments="-sn --host-timeout 10s")
            hosts = [h for h in nm.all_hosts() if nm[h].state() == "up"]
            self.dbg(f"Ping sweep: {hosts}")
        except Exception as e:
            self.dbg(f"Ping sweep erro: {e}")

        # Etapa 2: fallback -Pn (hosts Windows que bloqueiam ICMP)
        if not hosts:
            self.dbg("Etapa 2: fallback -Pn")
            try:
                nm2 = nmap.PortScanner()
                nm2.scan(hosts=target,
                         arguments="-Pn -sT --open -p 80,135,443,445 --host-timeout 15s -T3")
                hosts = list(nm2.all_hosts())
                self.dbg(f"Fallback -Pn: {hosts}")
            except Exception as e:
                self.dbg(f"Fallback -Pn erro: {e}")

        # Etapa 3: usa o target diretamente se for IP único
        if not hosts:
            self.dbg("Etapa 3: usando target diretamente")
            try:
                ipaddress.ip_address(target)
                hosts = [target]
            except ValueError:
                try:
                    net   = ipaddress.ip_network(target, strict=False)
                    hosts = [str(list(net.hosts())[0])]
                except Exception:
                    hosts = [target.split("/")[0]]

        print(f"    Hosts ativos: {', '.join(hosts) if hosts else 'nenhum'}")
        return hosts

    def scan_host(self, host: str) -> list:
        """
        Executa as três camadas de scan em um host e retorna lista de Finding.

        Camada 1: Socket scan (paralelo, sem root)
        Camada 2: Nmap -Pn -sT -sV (detecção de serviço)
        Camada 3: Merge + CME para SMB + testes específicos
        """
        log = {}
        findings = []

        # ── Camada 1: Socket scan ────────────────────────────────────────────
        print(f"    [1/3] Socket scan...")
        socket_ports = self._socket_scan(host)
        log["socket"] = sorted(socket_ports.keys())
        if socket_ports:
            print(f"    Portas abertas (socket): {sorted(socket_ports.keys())}")
        else:
            print(f"    Nenhuma porta aberta detectada pelo socket.")

        # ── Camada 2: Nmap -Pn focado nas portas descobertas ─────────────────
        print(f"    [2/3] Nmap -Pn -sT (identificação de serviços)...")
        hints = list(socket_ports.keys()) if socket_ports else None
        nmap_services = self._nmap_scan(host, hints)
        log["nmap"] = sorted(nmap_services.keys())
        if nmap_services:
            print(f"    Serviços identificados (nmap): {sorted(nmap_services.keys())}")

        # ── Camada 3: Merge ───────────────────────────────────────────────────
        print(f"    [3/3] Merge e análise de riscos...")
        services = self._merge(socket_ports, nmap_services)
        log["merged"] = sorted(services.keys())

        # Para cada serviço encontrado, gera Finding baseado no PORT_RISK_DB
        for port, svc in services.items():
            risk = self.PORT_RISK_DB.get(port)
            if risk:
                name    = risk["service"]
                product = svc.get("product", "")
                version = svc.get("version", "")
                ev_parts = [f"porta {port}/tcp aberta"]
                if product:
                    ev_parts.append(f"serviço: {product} {version}".strip())
                if svc.get("source") == "socket":
                    ev_parts.append("detectado via socket (nmap não identificou serviço)")

                findings.append(Finding(
                    host=host,
                    service=name,
                    port=port,
                    title=f"{name} Exposto na Porta {port}",
                    description=risk["desc"],
                    severity=risk["severity"],
                    cvss=risk["cvss"],
                    evidence=" | ".join(ev_parts),
                    source="phase1"
                ))

        # CME para validação SMB (achado já pode estar na lista, isso enriquece)
        if 445 in services or 139 in services:
            print(f"    [+] SMB detectado — validando com crackmapexec...")
            cme_data = self._cme_smb(host)
            log["cme"] = cme_data
            if cme_data.get("signing") is False:
                # Atualiza o achado SMB existente com evidência do CME
                for f in findings:
                    if f.service == "SMB" and f.port in [445, 139]:
                        f.title       = "SMB Signing Desabilitado — NTLM Relay Viável"
                        f.severity    = "CRÍTICO"
                        f.cvss        = 9.0
                        f.evidence   += f" | CME: signing=False, SMBv1={cme_data.get('smbv1','?')}"
                        f.description = (
                            "SMB sem assinatura de mensagens permite ataques NTLM Relay. "
                            "Um atacante na rede pode interceptar hashes de autenticação "
                            "e comprometer o domínio Active Directory."
                        )
                        break

        self.scan_log[host] = log
        return findings

    # ── Implementações internas ────────────────────────────────────────────────

    def _socket_scan(self, host: str) -> dict:
        """
        Scan TCP connect em paralelo em todas as portas alvo.
        Não precisa de root. Funciona em qualquer host que responda TCP.
        """
        open_ports = {}

        def check_port(port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(SOCKET_TIMEOUT)
                result = s.connect_ex((host, port))
                s.close()
                return port, result == 0
            except Exception:
                return port, False

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
            futures = [pool.submit(check_port, p) for p in ALL_PORTS]
            for future in concurrent.futures.as_completed(futures):
                port, is_open = future.result()
                if is_open:
                    open_ports[port] = True
                    self.dbg(f"Socket aberto: {port}/tcp")

        return open_ports

    def _nmap_scan(self, host: str, ports_hint: list = None) -> dict:
        """
        Roda nmap com:
          -Pn  → não testa ICMP (funciona em Windows Server que bloqueia ping)
          -sT  → TCP connect scan (sem root, mais confiável em VMs)
          -sV  → detecção de serviço e versão
          -T3  → timing moderado (menos impacto nos outros hosts da rede)
        """
        port_list = ",".join(str(p) for p in (ports_hint or ALL_PORTS))
        args = f"-Pn -sT -sV --open -T3 --host-timeout {NMAP_TIMEOUT} -p {port_list}"

        services = {}
        try:
            nm = nmap.PortScanner()
            nm.scan(host, arguments=args)
            if host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    for p in nm[host][proto]:
                        info = nm[host][proto][p]
                        if info["state"] == "open":
                            services[p] = {
                                "name":      info.get("name", ""),
                                "product":   info.get("product", ""),
                                "version":   info.get("version", ""),
                                "extrainfo": info.get("extrainfo", ""),
                                "source":    "nmap",
                            }
                            self.dbg(f"Nmap: {p}/tcp {info.get('name','')} "
                                     f"{info.get('product','')} {info.get('version','')}")
        except Exception as e:
            self.dbg(f"Nmap erro: {e}")

        return services

    def _merge(self, socket_ports: dict, nmap_services: dict) -> dict:
        """
        Une resultados do socket scan com os do nmap.
        Portas vistas pelo socket mas não pelo nmap são adicionadas com info mínima.
        Isso garante que o DC Windows não suma dos resultados.
        """
        merged = dict(nmap_services)

        socket_only = set(socket_ports.keys()) - set(nmap_services.keys())
        if socket_only:
            self.dbg(f"Portas só no socket (não no nmap): {sorted(socket_only)}")

        for port in socket_only:
            name = _port_name(port)
            merged[port] = {
                "name":      name,
                "product":   "",
                "version":   "",
                "extrainfo": "detectado via socket — nmap não identificou serviço",
                "source":    "socket",
            }

        return merged

    def _cme_smb(self, host: str) -> dict:
        """
        Usa crackmapexec para validar SMB: signing, SMBv1, domínio e hostname.
        Retorna dict vazio se CME não estiver instalado.
        """
        cme_path = _which("crackmapexec") or _which("cme")
        if not cme_path:
            self.dbg("crackmapexec não encontrado")
            return {}

        try:
            r = subprocess.run(
                [cme_path, "smb", host],
                capture_output=True, text=True, timeout=20
            )
            out = r.stdout + r.stderr
            data = {"raw": out.strip()[:400]}

            # Extrai informações do output do CME
            data["signing"] = False if ("signing:False" in out or "signing: False" in out) else \
                              True  if ("signing:True"  in out or "signing: True"  in out) else None
            data["smbv1"]   = True  if ("SMBv1:True"   in out or "SMBv1: True"    in out) else \
                              False if ("SMBv1:False"   in out or "SMBv1: False"   in out) else None

            m = re.search(r"SMB\s+\S+\s+445\s+(\S+)", out)
            if m:
                data["hostname"] = m.group(1)

            m2 = re.search(r"domain:(\S+)", out)
            if m2:
                data["domain"] = m2.group(1).rstrip(")")

            return data
        except Exception as e:
            self.dbg(f"CME erro: {e}")
            return {}


# ═══════════════════════════════════════════════════════════════════════════════
# CÁLCULO DE SCORE DE RISCO (LOCAL — SEM IA)
# ═══════════════════════════════════════════════════════════════════════════════

def calculate_risk_score(findings: list) -> int:
    """
    Calcula o Score de Risco da infraestrutura sem depender de API externa.

    Fórmula:
        Cada achado CRÍTICO contribui com 20 pontos.
        Cada ALTO contribui com 10 pontos.
        Cada MÉDIO contribui com 5 pontos.
        Cada BAIXO contribui com 2 pontos.
        O total é limitado (cap) em 100.

    Exemplos:
        5 CRÍTICO = 100 (score máximo)
        3 CRÍTICO + 2 ALTO = 80
        2 CRÍTICO + 3 ALTO + 4 MÉDIO = 90
    """
    weights = {"CRÍTICO": 20, "ALTO": 10, "MÉDIO": 5, "BAIXO": 2, "INFO": 0}
    raw_score = sum(weights.get(f.severity, 0) for f in findings)
    return min(100, raw_score)


# ═══════════════════════════════════════════════════════════════════════════════
# GERAÇÃO DE RELATÓRIOS
# ═══════════════════════════════════════════════════════════════════════════════

def gen_txt(findings: list, target: str, scan_time: datetime.datetime,
            risk_score: int) -> str:
    """Gera relatório em texto simples (.txt)."""
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    lines = [
        "=" * 64,
        "  CYMAG AutoScanner v2.0 — Relatório de Segurança",
        "=" * 64,
        f"  Alvo    : {target}",
        f"  Data    : {scan_time.strftime('%d/%m/%Y %H:%M')}",
        f"  Achados : {len(findings)}",
        f"  Score   : {risk_score}/100",
        "",
        "  DISTRIBUIÇÃO POR SEVERIDADE:",
    ]
    for sev in ["CRÍTICO", "ALTO", "MÉDIO", "BAIXO", "INFO"]:
        if sev in counts:
            lines.append(f"    {sev}: {counts[sev]}")

    lines.append("\n" + "-" * 64)

    # Lista todos os achados ordenados por severidade
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 0), reverse=True):
        src = "[P2]" if f.source == "phase2" else "[P1]"
        lines += [
            "",
            f"  {src} [{f.severity}] {f.title}",
            f"  Host: {f.host}:{f.port} | Serviço: {f.service} | CVSS: {f.cvss}",
            f"  {f.description}",
        ]
        if f.evidence:
            lines.append(f"  Evidência: {f.evidence[:150]}")

    lines += [
        "",
        "=" * 64,
        "  [P1] = Phase 1 (scanner)  |  [P2] = Phase 2 (IA)",
        "  AVISO: Relatório gerado automaticamente. Revisão por",
        "  especialista é necessária antes de qualquer decisão.",
        "=" * 64,
    ]
    return "\n".join(lines)


def gen_html(findings: list, target: str, scan_time: datetime.datetime,
             risk_score: int) -> str:
    """
    Gera dashboard HTML interativo com:
      - Score de risco calculado localmente
      - Gráfico donut dos achados por severidade
      - Cards filtráveis por severidade
      - Badge [P1]/[P2] indicando fase de descoberta
      - Checkbox "marcar como revisado"
    """
    total  = len(findings)
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    # Cor do score baseada no valor
    if risk_score >= 70:
        rc_color = "#c0392b"
        rc_label = "CRÍTICO"
    elif risk_score >= 40:
        rc_color = "#e67e22"
        rc_label = "ALTO"
    elif risk_score >= 20:
        rc_color = "#f39c12"
        rc_label = "MÉDIO"
    else:
        rc_color = "#27ae60"
        rc_label = "BAIXO"

    # ── Gráfico donut (SVG puro) ───────────────────────────────────────────────
    cx, cy, ro, ri = 60, 60, 52, 30
    seg_html = ""
    cum = 0.0
    sev_order = ["CRÍTICO", "ALTO", "MÉDIO", "BAIXO", "INFO"]

    for sev in sev_order:
        cnt = counts.get(sev, 0)
        if cnt == 0 or total == 0:
            continue
        pct = cnt / total
        a0, a1 = cum * 360, (cum + pct) * 360
        cum += pct
        r0, r1 = math.radians(a0 - 90), math.radians(a1 - 90)
        # Coordenadas do arco externo e interno
        x1o, y1o = cx + ro * math.cos(r0), cy + ro * math.sin(r0)
        x2o, y2o = cx + ro * math.cos(r1), cy + ro * math.sin(r1)
        x1i, y1i = cx + ri * math.cos(r1), cy + ri * math.sin(r1)
        x2i, y2i = cx + ri * math.cos(r0), cy + ri * math.sin(r0)
        la  = 1 if (a1 - a0) > 180 else 0
        d   = (f"M {x1o:.1f} {y1o:.1f} A {ro} {ro} 0 {la} 1 {x2o:.1f} {y2o:.1f} "
               f"L {x1i:.1f} {y1i:.1f} A {ri} {ri} 0 {la} 0 {x2i:.1f} {y2i:.1f} Z")
        seg_html += f'<path d="{d}" fill="{SEVERITY_COLOR.get(sev,"#999")}" title="{sev}: {cnt}"/>\n'

    # ── Legenda do donut ───────────────────────────────────────────────────────
    legend_html = ""
    for sev in sev_order:
        c = counts.get(sev, 0)
        if c:
            sc = sev.lower().replace("í","i").replace("é","e")
            legend_html += (
                f'<div class="li">'
                f'<span class="ld ld-{sc}"></span>'
                f'{SEVERITY_ICON.get(sev,"")} {sev}: <b>{c}</b>'
                f'</div>'
            )

    # ── Botões de filtro ───────────────────────────────────────────────────────
    filters_html = (
        f'<button class="fb active" data-f="ALL" onclick="flt(this)">'
        f'Todos <span class="cnt">{total}</span></button>'
    )
    for sev in sev_order:
        c = counts.get(sev, 0)
        if c:
            sc = sev.lower().replace("í","i").replace("é","e")
            filters_html += (
                f'<button class="fb fb-{sc}" data-f="{sev}" onclick="flt(this)">'
                f'{SEVERITY_ICON.get(sev,"")} {sev} <span class="cnt">{c}</span></button>'
            )

    # ── Cards de achados ────────────────────────────────────────────────────────
    cards_html = ""
    sorted_f = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 0), reverse=True)

    for i, f in enumerate(sorted_f):
        sc    = f.severity.lower().replace("í","i").replace("é","e")
        phase = "🔵 Phase 2 (IA)" if f.source == "phase2" else "⚙️ Phase 1 (Scanner)"
        ev_html = (
            f'<div class="ev"><code>{f.evidence[:400]}</code></div>'
            if f.evidence else ""
        )
        # Cards CRÍTICO começam expandidos
        open_cls = "open" if f.severity == "CRÍTICO" else ""
        disp_cb  = "block" if f.severity == "CRÍTICO" else "none"

        cards_html += f"""
<div class="card sev-{sc}" data-severity="{f.severity}" id="c{i}">
  <div class="ch" onclick="tog(this)">
    <div class="r1">
      <span class="bg bg-{sc}">{f.severity}</span>
      <span class="phase-badge">{phase}</span>
      <span class="ct">{f.title}</span>
      <span class="cv">CVSS {f.cvss}</span>
    </div>
    <div class="r2">🖥 {f.host}:{f.port} &nbsp; ⚙ {f.service}</div>
    <span class="chv {open_cls}">▼</span>
  </div>
  <div class="cb" style="display:{disp_cb}">
    <p class="desc">{f.description}</p>
    {ev_html}
    <label class="ck">
      <input type="checkbox" onchange="markDone(this,'c{i}')"> Marcar como revisado
    </label>
  </div>
</div>"""

    # ── HTML final ─────────────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CYMAG AutoScanner v2.0 — {target}</title>
<style>
* {{ box-sizing:border-box; margin:0; padding:0 }}
body {{ font-family:'Segoe UI',Arial,sans-serif; background:#f0f2f5; color:#222; font-size:14px }}

/* Header */
.hdr {{ background:#1a1a2e; color:#fff; padding:18px 32px;
        display:flex; justify-content:space-between; align-items:center }}
.hdr h1 {{ font-size:20px; font-weight:700; letter-spacing:1px }}
.hdr .meta {{ font-size:11px; color:#aaa; text-align:right; line-height:2 }}

/* Layout */
.wrap {{ max-width:1080px; margin:0 auto; padding:22px 14px }}

/* Dashboard (score + donut) */
.dash {{ display:grid; grid-template-columns:160px 1fr; gap:14px; margin-bottom:20px }}
.score-card {{ background:#fff; border-radius:8px; padding:18px;
               box-shadow:0 1px 4px rgba(0,0,0,.07);
               border-left:4px solid {rc_color}; text-align:center }}
.score-label {{ font-size:10px; text-transform:uppercase; letter-spacing:1px;
                color:#777; margin-bottom:6px }}
.score-value {{ font-size:48px; font-weight:700; color:{rc_color} }}
.score-level {{ font-size:11px; color:#888; margin-top:3px }}
.donut-card  {{ background:#fff; border-radius:8px; padding:18px;
               box-shadow:0 1px 4px rgba(0,0,0,.07);
               display:flex; align-items:center; gap:24px }}

/* Legenda */
.li {{ display:flex; align-items:center; gap:7px; font-size:12px; margin-bottom:7px }}
.ld {{ display:inline-block; width:11px; height:11px; border-radius:50% }}
.ld-critico{{background:#c0392b}}.ld-alto{{background:#e67e22}}
.ld-medio{{background:#f39c12}}.ld-baixo{{background:#27ae60}}.ld-info{{background:#95a5a6}}

/* Filtros */
.fts {{ display:flex; flex-wrap:wrap; gap:7px; margin-bottom:14px; align-items:center }}
.flb {{ font-size:11px; color:#666; font-weight:700 }}
.fb  {{ border:none; padding:5px 13px; border-radius:20px; cursor:pointer;
        font-size:11px; font-weight:600; background:#ddd; color:#333; transition:opacity .2s }}
.fb.active {{ outline:2px solid #333 }}
.fb:hover  {{ opacity:.8 }}
.fb-critico{{background:#c0392b;color:#fff}}.fb-alto{{background:#e67e22;color:#fff}}
.fb-medio{{background:#f39c12;color:#fff}}.fb-baixo{{background:#27ae60;color:#fff}}

/* Cards */
.st {{ font-size:15px; font-weight:700; margin-bottom:10px }}
.card {{ background:#fff; border-radius:8px; margin-bottom:9px;
         box-shadow:0 1px 3px rgba(0,0,0,.06);
         border-left:4px solid #ccc; transition:box-shadow .2s }}
.card:hover {{ box-shadow:0 3px 10px rgba(0,0,0,.11) }}
.card.done   {{ opacity:.5; filter:grayscale(60%) }}
.sev-critico{{border-left-color:#c0392b}}.sev-alto{{border-left-color:#e67e22}}
.sev-medio{{border-left-color:#f39c12}}.sev-baixo{{border-left-color:#27ae60}}

.ch {{ padding:13px 14px; cursor:pointer; position:relative; user-select:none }}
.r1 {{ display:flex; align-items:center; gap:9px; flex-wrap:wrap }}
.bg {{ display:inline-block; padding:2px 7px; border-radius:4px;
       font-size:10px; font-weight:700 }}
.bg-critico{{background:#c0392b;color:#fff}}.bg-alto{{background:#e67e22;color:#fff}}
.bg-medio{{background:#f39c12;color:#fff}}.bg-baixo{{background:#27ae60;color:#fff}}
.phase-badge {{ font-size:10px; color:#666; background:#f0f0f0;
                padding:2px 6px; border-radius:4px }}
.ct {{ font-weight:600; font-size:13.5px; flex:1 }}
.cv {{ font-size:11px; color:#888 }}
.r2 {{ margin-top:5px; font-size:11px; color:#888 }}
.chv {{ position:absolute; right:14px; top:14px;
         font-size:11px; color:#aaa; transition:transform .2s }}
.chv.open {{ transform:rotate(180deg) }}

.cb {{ display:none; padding:0 14px 14px; border-top:1px solid #f0f0f0 }}
.desc {{ color:#444; line-height:1.65; margin-top:11px }}
.ev {{ background:#1e1e1e; border-radius:4px; padding:9px 11px; margin:9px 0; overflow-x:auto }}
.ev code {{ color:#d4d4d4; font-size:11px; font-family:Consolas,monospace;
             white-space:pre-wrap; word-break:break-all }}
.ck {{ display:flex; align-items:center; gap:7px; margin-top:10px;
       font-size:12px; color:#666; cursor:pointer }}

/* Footer */
.ftr {{ background:#1a1a2e; color:#666; text-align:center;
         padding:14px; font-size:11px; margin-top:28px }}

@media print {{
  .fts,.fb {{ display:none }}
  .cb {{ display:block!important }}
  body {{ background:#fff }}
}}
</style>
</head>
<body>
<div class="hdr">
  <div>
    <h1>🔍 CYMAG AutoScanner v2.0</h1>
    <div style="font-size:12px;color:#aaa;margin-top:3px">
      Diagnóstico Automatizado — Phase 1 + Phase 2 (IA Loop)
    </div>
  </div>
  <div class="meta">
    Alvo: <b style="color:#fff">{target}</b><br>
    {scan_time.strftime("%d/%m/%Y %H:%M")}<br>
    {total} achados encontrados
  </div>
</div>

<div class="wrap">
  <!-- Dashboard: Score + Donut -->
  <div class="dash">
    <div class="score-card">
      <div class="score-label">Score de Risco</div>
      <div class="score-value">{risk_score}</div>
      <div class="score-level">{rc_label} (0–100)</div>
    </div>
    <div class="donut-card">
      <svg viewBox="0 0 120 120" width="115" height="115" style="flex-shrink:0">
        {seg_html if seg_html else '<circle cx="60" cy="60" r="52" fill="#eee"/>'}
        <text x="60" y="64" text-anchor="middle" font-size="15" font-weight="bold" fill="#333">{total}</text>
        <text x="60" y="76" text-anchor="middle" font-size="8" fill="#999">achados</text>
      </svg>
      <div>{legend_html}</div>
    </div>
  </div>

  <!-- Lista de achados com filtros -->
  <div class="st">Achados de Segurança</div>
  <div class="fts">
    <span class="flb">Filtrar por severidade:</span>
    {filters_html}
  </div>
  <div id="fl">{cards_html}</div>
</div>

<div class="ftr">
  CYMAG AutoScanner v2.0 &nbsp;|&nbsp;
  SENAI — Faculdade de Tecnologia Paulo Antonio Skaf &nbsp;|&nbsp;
  Projeto Integrador I — 2026<br>
  Relatório gerado automaticamente.
  Consulte sempre um especialista em segurança cibernética antes de tomar decisões.
</div>

<script>
// Filtra cards por severidade
function flt(btn) {{
  document.querySelectorAll('.fb').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  const f = btn.dataset.f;
  document.querySelectorAll('.card').forEach(c => {{
    c.style.display = (f === 'ALL' || c.dataset.severity === f) ? '' : 'none';
  }});
}}

// Expande/colapsa card ao clicar no header
function tog(hdr) {{
  const body = hdr.nextElementSibling;
  const chv  = hdr.querySelector('.chv');
  const open = body.style.display === 'block';
  body.style.display = open ? 'none' : 'block';
  chv.classList.toggle('open', !open);
}}

// Marca/desmarca card como revisado (persiste no localStorage)
function markDone(cb, cardId) {{
  const card = document.getElementById(cardId);
  card.classList.toggle('done', cb.checked);
  localStorage.setItem(cardId, cb.checked ? '1' : '');
}}

// Restaura estado de revisão ao carregar a página
window.addEventListener('DOMContentLoaded', () => {{
  document.querySelectorAll('.card').forEach(c => {{
    if (localStorage.getItem(c.id) === '1') {{
      c.classList.add('done');
      const cb = c.querySelector('input[type="checkbox"]');
      if (cb) cb.checked = true;
    }}
  }});
}});
</script>
</body>
</html>"""

    return html


# ═══════════════════════════════════════════════════════════════════════════════
# UTILITÁRIOS
# ═══════════════════════════════════════════════════════════════════════════════

def _which(cmd: str):
    """Equivalente ao comando 'which' do Unix — retorna o caminho do executável."""
    try:
        r = subprocess.run(["which", cmd], capture_output=True, text=True)
        path = r.stdout.strip()
        return path if path else None
    except Exception:
        return None


def _port_name(port: int) -> str:
    """Retorna o nome do serviço dado o número da porta (fallback do scanner)."""
    known = {
        21:"ftp", 22:"ssh", 23:"telnet", 25:"smtp", 53:"dns",
        80:"http", 135:"msrpc", 137:"netbios-ns", 139:"netbios-ssn",
        389:"ldap", 443:"https", 445:"microsoft-ds", 464:"kpasswd",
        636:"ldapssl", 1433:"mssql", 1880:"node-red", 1883:"mqtt",
        3268:"globalcatalog", 3269:"globalcatalogssl", 3306:"mysql",
        3307:"mysql-alt", 3389:"rdp", 5040:"win-svc", 5432:"postgresql",
        5985:"winrm", 5986:"winrm-ssl", 6379:"redis", 8080:"http-alt",
        8443:"https-alt", 8883:"mqtt-ssl", 9200:"elasticsearch",
        27017:"mongodb", 49152:"rpc-dynamic",
    }
    return known.get(port, "unknown")


# ═══════════════════════════════════════════════════════════════════════════════
# FUNÇÃO PRINCIPAL
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    print(BANNER)

    # ── Argumentos ──────────────────────────────────────────────────────────────
    target = sys.argv[1] if len(sys.argv) >= 2 else input("\nAlvo (IP ou CIDR): ").strip()
    if not target:
        print("[ERRO] Alvo é obrigatório.")
        sys.exit(1)

    debug   = "--debug" in sys.argv
    use_ai  = "--no-ai" not in sys.argv   # Por padrão tenta usar IA

    # ── API Key (Groq) ──────────────────────────────────────────────────────────
    api_key = os.environ.get("GROQ_API_KEY", "")
    if not api_key and use_ai:
        api_key = input("Groq API Key (Enter para pular Phase 2): ").strip()

    # ── Formato do relatório ────────────────────────────────────────────────────
    print("\nFormato do relatório:")
    print("  0 — TXT   (texto simples, sem dependências)")
    print("  1 — HTML  (dashboard interativo, recomendado)")
    while True:
        try:
            fmt = int(input("Escolha (0/1): ").strip())
            if fmt in [0, 1]:
                break
        except Exception:
            pass
        print("  Digite 0 ou 1.")

    print()

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 1 — VARREDURA
    # ═══════════════════════════════════════════════════════════════════════════
    scanner   = Scanner(debug=debug)
    hosts_up  = scanner.discover_hosts(target)

    all_findings = []
    scan_time    = datetime.datetime.now()

    print(f"\n[2/4] Escaneando {len(hosts_up)} host(s)...")
    for host in hosts_up:
        print(f"\n  ▶ {host}")
        host_findings = scanner.scan_host(host)
        all_findings.extend(host_findings)
        print(f"  → {len(host_findings)} achado(s) na Phase 1")

    print(f"\n[3/4] Phase 1 concluída: {len(all_findings)} achado(s) total.")

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 2 — LOOP DE INVESTIGAÇÃO IA (se API key disponível)
    # ═══════════════════════════════════════════════════════════════════════════
    if api_key:
        print(f"\n[3/4] Phase 2 — Loop de investigação IA...")
        agent   = AIAgent(api_key=api_key)
        catalog = FunctionCatalog()
        loop    = InvestigationLoop(agent, catalog)

        for host in hosts_up:
            # Filtra apenas os achados deste host para passar ao loop
            host_findings = [f for f in all_findings if f.host == host]
            if not host_findings:
                continue   # Host sem achados Phase 1 — pula

            new_findings = loop.run(host, host_findings)
            all_findings.extend(new_findings)

        print(f"\n[3/4] Phase 2 concluída. Total de achados: {len(all_findings)}")
    else:
        print("\n[3/4] Phase 2 pulada (sem API Key).")
        print("       Para habilitar: GROQ_API_KEY=gsk_xxx python3 cymag_v2.py <alvo>")

    # ═══════════════════════════════════════════════════════════════════════════
    # SCORE DE RISCO E RELATÓRIO
    # ═══════════════════════════════════════════════════════════════════════════
    print("\n[4/4] Calculando score e gerando relatório...")

    # Score calculado localmente — não depende da IA para ser diferente de zero
    risk_score = calculate_risk_score(all_findings)

    # Nome do arquivo de saída
    ts  = scan_time.strftime("%Y%m%d_%H%M")
    tag = target.replace("/", "_").replace(".", "-")
    out_name = f"CYMAG_{tag}_{ts}"

    if fmt == 0:
        content = gen_txt(all_findings, target, scan_time, risk_score)
        out_path = f"{out_name}.txt"
        Path(out_path).write_text(content, encoding="utf-8")
    else:
        content  = gen_html(all_findings, target, scan_time, risk_score)
        out_path = f"{out_name}.html"
        Path(out_path).write_text(content, encoding="utf-8")

    # ── Sumário final ───────────────────────────────────────────────────────────
    counts = {}
    for f in all_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print(f"\n{'='*54}")
    print(f"  ✅  {out_path}")
    print(f"{'='*54}")
    for sev in ["CRÍTICO", "ALTO", "MÉDIO", "BAIXO", "INFO"]:
        if sev in counts:
            icon = SEVERITY_ICON.get(sev, "⚪")
            p2   = sum(1 for f in all_findings if f.severity == sev and f.source == "phase2")
            p2s  = f"  (+{p2} Phase 2)" if p2 else ""
            print(f"  {icon}  {sev}: {counts[sev]}{p2s}")
    print(f"  📊  Score de Risco: {risk_score}/100")
    if fmt == 1:
        print(f"\n  🌐  firefox {out_path}")
    print(f"{'='*54}\n")

    # Debug: exibe log interno do scanner
    if debug and scanner.scan_log:
        print("\n[DEBUG] Scan log:")
        print(json.dumps(scanner.scan_log, indent=2, default=str))


if __name__ == "__main__":
    main()
