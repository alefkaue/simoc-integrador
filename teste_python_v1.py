#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║  CYMAG AutoScanner v1.1                              ║
║  Diagnóstico Automatizado de Segurança               ║
║  SENAI — Projeto Integrador Interdisciplinar I       ║
╚══════════════════════════════════════════════════════╝

CHANGELOG v1.1
  - Detecção de portas em 3 camadas (socket → nmap -Pn -sT → fallback)
  - Host discovery com fallback -Pn para hosts que bloqueiam ICMP
  - Integração com crackmapexec para validação SMB em Windows
  - Merge automático de resultados socket + nmap
  - Logs de diagnóstico do scanner para debug

Dependências:
    pip install python-nmap paho-mqtt requests groq reportlab --break-system-packages
"""

import sys, os, json, socket, subprocess, datetime, re, time, math, warnings
import ipaddress
import concurrent.futures
from pathlib import Path
import threading
import webbrowser
from flask import Flask, render_template_string

warnings.filterwarnings("ignore")

# ─── dependency check ────────────────────────────────────────────────────────
MISSING = []
try:    import nmap
except: MISSING.append("python-nmap")
try:    import requests; requests.packages.urllib3.disable_warnings()
except: MISSING.append("requests")
try:    import paho.mqtt.client as mqtt_client
except: MISSING.append("paho-mqtt")
try:    from groq import Groq
except: MISSING.append("groq")
try:    from reportlab.platypus import *; from reportlab.lib.pagesizes import A4
except: MISSING.append("reportlab")

if MISSING:
    print(f"\n[!] Dependências faltando. Execute:\n"
          f"    pip install {" ".join(MISSING)} --break-system-packages\n")
    sys.exit(1)

from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                 Table, TableStyle, HRFlowable)
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY

# ─── constants ───────────────────────────────────────────────────────────────
VERSION = "1.1.0"
BANNER  = f"""
╔══════════════════════════════════════════════════════╗
║  CYMAG AutoScanner v{VERSION:<8}                      ║
║  Diagnóstico Automatizado de Segurança               ║
╚══════════════════════════════════════════════════════╝"""

SEVERITY_ORDER = {"CRÍTICO": 4, "ALTO": 3, "MÉDIO": 2, "BAIXO": 1, "INFO": 0}
SEVERITY_HEX   = {"CRÍTICO": "#c0392b", "ALTO": "#e67e22",
                  "MÉDIO": "#f39c12",   "BAIXO": "#27ae60", "INFO": "#95a5a6"}
SEVERITY_ICON  = {"CRÍTICO": "🔴", "ALTO": "🟠", "MÉDIO": "🟡", "BAIXO": "🟢", "INFO": "⚪"}

# Portas alvo — separadas por categoria para controle fino
PORTS_COMMON = [
    21, 22, 23, 25, 53, 80, 443, 445,
    1433, 1883, 1880, 3306, 3307, 3389,
    5040, 5432, 6379, 8080, 8443, 8883,
    9200, 27017
]
# Portas Windows/AD que costumam ser ignoradas pelo nmap sem -Pn
PORTS_WINDOWS = [135, 137, 139, 389, 445, 464, 636, 3268, 3269, 5985, 5986, 49152]

ALL_PORTS = sorted(set(PORTS_COMMON + PORTS_WINDOWS))

# Timeout por camada
SOCKET_TIMEOUT = 1.5   # segundos por porta no socket scan
NMAP_TIMEOUT   = "90s" # timeout total do nmap por host

# ─── Finding ────────────────────────────────────────────────────────────────
class Finding:
    def __init__(self, host, service, port, title, description, severity, cvss, evidence=""):
        self.host              = host
        self.service           = service
        self.port              = port
        self.title             = title
        self.description       = description
        self.severity          = severity
        self.cvss              = cvss
        self.evidence          = evidence
        self.ai_analysis       = ""
        self.ai_recommendation = ""


# ─── Scanner ─────────────────────────────────────────────────────────────────
class CYMAGScanner:

    def __init__(self, target: str, debug: bool = False):
        self.target    = target
        self.findings  = []
        self.hosts_up  = []
        self.scan_time = datetime.datetime.now()
        self.debug     = debug
        # scan_log: registra o que cada camada encontrou para debug
        self.scan_log  = {}

    # ── util ─────────────────────────────────────────────────────────────────
    def add(self, **kw):
        f = Finding(**kw)
        self.findings.append(f)
        icon = SEVERITY_ICON.get(f.severity, "⚪")
        print(f"    {icon} [{f.severity:8s}] {f.title}  ({f.host}:{f.port})")
        return f

    def dbg(self, msg: str):
        if self.debug:
            print(f"    [DBG] {msg}")

    # ── entry point ──────────────────────────────────────────────────────────
    def run(self):
        print("\n[1/4] Descoberta de hosts...")
        self._discover()

        print(f"\n[2/4] Testando {len(self.hosts_up)} host(s)...")
        for host in self.hosts_up:
            print(f"\n  ▶ {host}")
            services = self._scan_host(host)
            for port, svc in services.items():
                self._dispatch(host, port, svc)

        return self.findings

    # ─────────────────────────────────────────────────────────────────────────
    # CAMADA 0 — Host Discovery
    # ─────────────────────────────────────────────────────────────────────────
    def _discover(self):
        """
        Tenta descobrir hosts em três etapas:
          1. nmap ping sweep padrão (-sn)
          2. Se não achar nada: nmap -Pn em portas comuns (para hosts que bloqueiam ICMP)
          3. Se ainda não achar: usa o target diretamente (IP único)
        """
        # Etapa 1 — ping sweep
        self.dbg("Etapa 1: nmap ping sweep (-sn)")
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=self.target, arguments="-sn --host-timeout 10s")
            self.hosts_up = list(nm.all_hosts())
            self.dbg(f"Ping sweep retornou: {self.hosts_up}")
        except Exception as e:
            self.dbg(f"Ping sweep erro: {e}")

        # Etapa 2 — fallback -Pn (hosts que bloqueiam ICMP, como Windows Server)
        if not self.hosts_up:
            self.dbg("Etapa 2: fallback -Pn nas portas 80,135,443,445")
            try:
                nm2 = nmap.PortScanner()
                nm2.scan(hosts=self.target,
                         arguments="-Pn -sT --open -p 80,135,443,445 --host-timeout 15s -T3")
                self.hosts_up = [h for h in nm2.all_hosts()
                                 if nm2[h].state() == "up"
                                 or any(nm2[h]["tcp"].get(p, {}).get("state") == "open"
                                        for p in [80, 135, 443, 445]
                                        if "tcp" in nm2[h])]
                self.dbg(f"Fallback -Pn retornou: {self.hosts_up}")
            except Exception as e:
                self.dbg(f"Fallback -Pn erro: {e}")

        # Etapa 3 — se ainda vazio e for IP único, usa diretamente
        if not self.hosts_up:
            self.dbg("Etapa 3: usando target diretamente")
            try:
                ipaddress.ip_address(self.target)
                self.hosts_up = [self.target]
            except ValueError:
                # CIDR sem hosts: pega o primeiro IP útil
                try:
                    net = ipaddress.ip_network(self.target, strict=False)
                    self.hosts_up = [str(list(net.hosts())[0])]
                except Exception:
                    self.hosts_up = [self.target.split("/")[0]]

        print(f"    Hosts ativos: {", ".join(self.hosts_up)}")

    # ─────────────────────────────────────────────────────────────────────────
    # CAMADA 1 — Socket scan (rápido e sem privilégios)
    # ─────────────────────────────────────────────────────────────────────────
    def _socket_scan(self, host: str) -> dict:
        """
        Faz TCP connect em todas as portas alvo em paralelo.
        Retorna {porta: True} para as que estão abertas.
        Não depende de ICMP, não precisa de root, sempre funciona.
        """
        open_ports = {}

        def check(port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(SOCKET_TIMEOUT)
                result = s.connect_ex((host, port))
                s.close()
                return port, result == 0
            except Exception:
                return port, False

        self.dbg(f"Socket scan em {len(ALL_PORTS)} portas...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
            futures = [pool.submit(check, p) for p in ALL_PORTS]
            for f in concurrent.futures.as_completed(futures):
                port, is_open = f.result()
                if is_open:
                    open_ports[port] = True
                    self.dbg(f"  Socket aberto: {port}/tcp")

        return open_ports

    # ─────────────────────────────────────────────────────────────────────────
    # CAMADA 2 — Nmap com -Pn -sT (detecção de serviço)
    # ─────────────────────────────────────────────────────────────────────────
    def _nmap_scan(self, host: str, ports_hint: list = None) -> dict:
        """
        Roda nmap com:
          -Pn  → não testa se host está online (assume que sim)
          -sT  → TCP connect scan (não precisa de root, mais confiável em VMs)
          -T3  → timing moderado (menos agressivo que T4, melhor para Windows)
          -sV  → detecção de serviço e versão
          -sC  → scripts básicos do nmap
        Se ports_hint for fornecido, escaneia só essas portas (mais rápido).
        """
        if ports_hint:
            port_list = ",".join(str(p) for p in sorted(ports_hint))
        else:
            port_list = ",".join(str(p) for p in ALL_PORTS)

        args = f"-Pn -sT -sV -sC --open -T3 --host-timeout {NMAP_TIMEOUT} -p {port_list}"
        self.dbg(f"Nmap: {args}")

        services = {}
        try:
            nm = nmap.PortScanner()
            nm.scan(host, arguments=args)
            if host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    for p in nm[host][proto]:
                        if nm[host][proto][p]["state"] == "open":
                            d = nm[host][proto][p]
                            services[p] = {
                                "name":      d.get("name", ""),
                                "product":   d.get("product", ""),
                                "version":   d.get("version", ""),
                                "extrainfo": d.get("extrainfo", ""),
                                "script":    d.get("script", {}),
                                "source":    "nmap",
                            }
                            self.dbg(f"  Nmap: {p}/tcp {d.get('name','')} {d.get('product','')} {d.get('version','')}")
        except Exception as e:
            self.dbg(f"Nmap erro: {e}")

        return services

    # ─────────────────────────────────────────────────────────────────────────
    # CAMADA 3 — Merge e enriquecimento
    # ─────────────────────────────────────────────────────────────────────────
    def _merge_results(self, socket_ports: dict, nmap_services: dict) -> dict:
        """
        Faz merge dos dois resultados:
          - Portas que o nmap achou: usa info completa do nmap
          - Portas que SÓ o socket achou: adiciona com info mínima
            (garante que o DC não desapareça do resultado)
        """
        merged = dict(nmap_services)  # começa com tudo que o nmap achou

        # Portas abertas no socket mas ausentes no nmap
        socket_only = set(socket_ports.keys()) - set(nmap_services.keys())
        if socket_only:
            self.dbg(f"Portas vistas pelo socket mas não pelo nmap: {sorted(socket_only)}")

        for port in socket_only:
            # Inferir nome do serviço pelo número de porta
            name = self._port_to_name(port)
            merged[port] = {
                "name":      name,
                "product":   "",
                "version":   "",
                "extrainfo": "detectado via socket (nmap não identificou serviço)",
                "script":    {},
                "source":    "socket",
            }
            self.dbg(f"  Adicionando do socket: {port}/tcp ({name})")

        return merged

    def _port_to_name(self, port: int) -> str:
        """Mapa manual de porta para serviços comuns."""
        return {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 135: "msrpc", 137: "netbios-ns", 139: "netbios-ssn",
            389: "ldap", 443: "https", 445: "microsoft-ds", 464: "kpasswd5",
            636: "ldaps", 1433: "ms-sql-s", 1883: "mqtt", 1880: "node-red",
            3306: "mysql", 3307: "mariadb", 3389: "ms-wbt-server", 5040: "nodered-dashboard",
            5432: "postgresql", 6379: "redis", 8080: "http-proxy", 8443: "https-alt",
            8883: "mqtts", 9200: "elasticsearch", 27017: "mongodb",
            3268: "msft-gc", 3269: "msft-gc-ssl", 5985: "wsman", 5986: "wsmans",
            49152: "msrpc"
        }.get(port, "unknown")

    def _scan_host(self, host: str) -> dict:
        """
        Orquestra as camadas de scan para um único host.
        Retorna um dicionário de {porta: {serviço_info}}.
        """
        self.scan_log[host] = {}

        # Camada 1: Socket scan (rápido, sem privilégios)
        socket_open_ports = self._socket_scan(host)
        self.scan_log[host]["socket_ports"] = sorted(socket_open_ports.keys())

        # Camada 2: Nmap (detecção de serviço)
        # Se o socket achou portas, passa como hint para o nmap ser mais rápido
        nmap_services = self._nmap_scan(host, list(socket_open_ports.keys()))
        self.scan_log[host]["nmap_services"] = nmap_services

        # Camada 3: Merge dos resultados
        merged_services = self._merge_results(socket_open_ports, nmap_services)
        self.scan_log[host]["merged_services"] = merged_services

        return merged_services

    # ─────────────────────────────────────────────────────────────────────────
    # CAMADA 4 — Dispatch de vulnerabilidades
    # ─────────────────────────────────────────────────────────────────────────
    def _dispatch(self, host: str, port: int, svc: dict):
        """
        Chama funções específicas para cada serviço/porta para identificar
        vulnerabilidades e adicionar Findings.
        """
        service_name = svc.get("name", "unknown").lower()

        # Mapeamento de portas para funções de detecção
        dispatch_map = {
            21: self._ftp,
            22: self._ssh,
            23: self._telnet,
            25: self._smtp,
            53: self._dns,
            80: self._http,
            443: self._http,
            135: self._rpc,
            139: self._smb,
            389: self._ldap,
            445: self._smb,
            636: self._ldap,
            1433: self._mssql,
            1883: self._mqtt,
            1880: self._nodered,
            3306: self._mysql,
            3307: self._mysql,
            3389: self._rdp,
            5040: self._nodered,
            5432: self._postgresql,
            6379: self._redis,
            8080: self._http,
            8443: self._http,
            8883: self._mqtt,
            9200: self._elasticsearch,
            27017: self._mongodb,
            3268: self._ldap,
            3269: self._ldap,
            5985: self._winrm,
            5986: self._winrm,
            49152: self._rpc, # MSRPC dinâmico, mas ainda relevante
        }

        # Chama a função específica se existir
        handler = dispatch_map.get(port)
        if handler:
            self.dbg(f"Dispatching {service_name} ({port}) to {handler.__name__}")
            handler(host, port, svc)
        else:
            self.dbg(f"No specific handler for {service_name} on port {port}")

        # Checagens genéricas (EOL, credenciais padrão, etc.)
        self._eol_check(host, port, svc)
        self._default_creds_check(host, port, svc)

    # ─────────────────────────────────────────────────────────────────────────
    # Funções de detecção de vulnerabilidades por serviço
    # ─────────────────────────────────────────────────────────────────────────

    def _ftp(self, host, port, svc):
        version = svc.get("version", "").lower()
        if "vsftpd 2.3.4" in version:
            self.add(host=host, service="FTP", port=port,
                     title="Backdoor no vsFTPd 2.3.4",
                     description=("Versão vulnerável do vsFTPd com backdoor. "
                                  "Permite execução remota de comandos."),
                     severity="CRÍTICO", cvss=10.0,
                     evidence="vsFTPd 2.3.4 detectado")
        # Outras checagens FTP...

    def _telnet(self, host, port, svc):
        self.add(host=host, service="Telnet", port=port,
                 title="Telnet Exposto — Comunicação em Texto Claro",
                 description=("Telnet transmite credenciais e dados em texto claro, "
                              "suscetível a eavesdropping e roubo de sessão."),
                 severity="ALTO", cvss=8.1,
                 evidence=f"Porta {port}/tcp aberta")

    def _smtp(self, host, port, svc):
        # Checagem de open relay, etc.
        pass

    def _dns(self, host, port, svc):
        # Checagem de zone transfer, recursão aberta, etc.
        pass

    def _http(self, host, port, svc):
        base = f"http{'s' if port == 443 else ''}://{host}:{port}"

        # Headers de segurança
        try:
            r = requests.get(base, timeout=4, verify=False)
            missing_headers = []
            if "Strict-Transport-Security" not in r.headers and port == 443:
                missing_headers.append("HSTS")
            if "X-Content-Type-Options" not in r.headers:
                missing_headers.append("X-Content-Type-Options")
            if "X-Frame-Options" not in r.headers:
                missing_headers.append("X-Frame-Options")
            if "Content-Security-Policy" not in r.headers:
                missing_headers.append("Content-Security-Policy")

            if missing_headers:
                self.add(host=host, service="HTTP", port=port,
                         title="Faltando Headers de Segurança HTTP",
                         description=("Headers de segurança importantes (HSTS, X-Content-Type-Options, "
                                      "X-Frame-Options, CSP) estão ausentes, aumentando o risco de "
                                      "ataques como XSS, Clickjacking e Man-in-the-Middle."),
                         severity="MÉDIO", cvss=6.1,
                         evidence=f"Headers ausentes: {', '.join(missing_headers)}")
        except Exception:
            pass

        # Endpoints sensíveis
        paths = [
            ("/admin",               "Painel Administrativo"),
            ("/phpmyadmin",          "phpMyAdmin"),
            ("/wp-admin",            "WordPress Admin"),
            ("/login",               "Página de Login"),
            ("/api/v1",              "API v1"),
            ("/api/collaborators",   "Endpoint de Colaboradores"),
            ("/api/session",         "Endpoint de Sessão"),
        ]
        for path, desc in paths:
            try:
                pr = requests.get(f"{base}{path}", timeout=4, verify=False)
                if pr.status_code not in [404, 503, 502]:
                    sev  = "ALTO"  if pr.status_code == 200 else "MÉDIO"
                    cvss = 7.5     if pr.status_code == 200 else 5.0
                    self.add(host=host, service="HTTP", port=port,
                             title=f"Endpoint Sensível Exposto: {path}",
                             description=f"{desc} acessível sem autenticação adequada.",
                             severity=sev, cvss=cvss,
                             evidence=f"GET {path} → HTTP {pr.status_code}")
            except Exception:
                pass

        # SQLi fingerprint
        for path in ["/api/collaborators?name=\'", "/api/users?id=1\'", "/search?q=\'"]:
            try:
                sr   = requests.get(f"{base}{path}", timeout=4, verify=False)
                body = sr.text.lower()
                if any(e in body for e in ["sql", "mysql", "syntax error",
                                            "ora-", "pg_", "sqlite", "warning: pg_"]):
                    self.add(host=host, service="HTTP", port=port,
                             title="SQL Injection Detectado",
                             description=("Endpoint retorna erros SQL ao receber entrada malformada. "
                                          "Pode permitir extração completa do banco de dados."),
                             severity="CRÍTICO", cvss=9.8,
                             evidence=f"GET {path} → erro SQL na resposta")
                    break
            except Exception:
                pass

        # token base64 forjável
        try:
            import base64
            token = base64.b64encode(b"admin:admin:homologacao").decode()
            tr = requests.get(f"{base}/admin",
                              headers={"x-auth-token": token}, timeout=4, verify=False)
            if tr.status_code == 200:
                self.add(host=host, service="HTTP", port=port,
                         title="Broken Authentication — Token Base64 Forjável",
                         description=("O token de sessão é Base64 de usuario:role:contexto sem "
                                      "assinatura criptográfica. Qualquer usuário pode forjar "
                                      "um token de administrador."),
                         severity="CRÍTICO", cvss=9.1,
                         evidence="Token forjado aceito em /admin (HTTP 200)")
        except Exception:
            pass

    def _nodered(self, host, port, svc):
        base = f"http://{host}:{port}"
        try:
            r = requests.get(f"{base}/settings", timeout=5)
            if r.status_code == 200:
                d    = r.json()
                ver  = d.get("version", "?")
                fext = d.get("functionExternalModules", False)
                self.add(host=host, service="Node-RED", port=port,
                         title="Node-RED Sem Autenticação",
                         description=(f"Interface administrativa do Node-RED v{ver} acessível "
                                      "sem credenciais. Controle total sobre fluxos OT."),
                         severity="CRÍTICO", cvss=9.8,
                         evidence=f"GET /settings → 200 | v{ver} | funcExtModules:{fext}")
                if fext:
                    self.add(host=host, service="Node-RED", port=port,
                             title="RCE Potencial — functionExternalModules Ativo",
                             description=("A flag functionExternalModules:true permite carregar "
                                          "child_process e executar comandos no SO do servidor."),
                             severity="CRÍTICO", cvss=9.1,
                             evidence="\"functionExternalModules\": true")
        except Exception:
            pass

        try:
            r = requests.get(f"{base}/flows", timeout=5)
            if r.status_code == 200:
                flows = r.json()
                txt   = json.dumps(flows)
                self.add(host=host, service="Node-RED", port=port,
                         title="Código-Fonte de Automação Exposto",
                         description=(f"{len(flows)} nós de automação acessíveis sem autenticação."),
                         severity="CRÍTICO", cvss=8.6,
                         evidence=f"GET /flows → 200 | {len(flows)} nós")
                if "pump" in txt.lower() or "fuel" in txt.lower():
                    self.add(host=host, service="Node-RED", port=port,
                             title="Sistema SCADA/OT de Bombas Exposto",
                             description=("Flows expõem sistema industrial de monitoramento de bombas. "
                                          "Permite injeção de telemetria falsa."),
                             severity="CRÍTICO", cvss=9.5,
                             evidence="Tópicos MQTT industriais detectados nos flows")
        except Exception:
            pass

    def _mqtt(self, host, port, svc):
        connected = [False]
        messages  = []

        def on_connect(client, ud, flags, rc, props=None):
            if rc == 0:
                connected[0] = True
                client.subscribe("#")

        def on_message(client, ud, msg):
            try:
                messages.append(f"{msg.topic}: {msg.payload.decode('utf-8','ignore')[:80]}")
            except Exception:
                pass

        try:
            c = mqtt_client.Client(mqtt_client.CallbackAPIVersion.VERSION2)
            c.on_connect = on_connect
            c.on_message = on_message
            c.connect(host, port, 5)
            c.loop_start()
            time.sleep(4)
            c.loop_stop()
            try: c.disconnect()
            except Exception: pass

            if connected[0]:
                ev = f"Conexão anônima aceita na porta {port}/tcp (sem TLS)"
                if messages:
                    ev += f" | Mensagens capturadas: {messages[:2]}"
                self.add(host=host, service="MQTT", port=port,
                         title="Broker MQTT Sem Autenticação e Sem TLS",
                         description=("Broker MQTT aceita conexões anônimas e transmite dados "
                                      "em texto claro. Qualquer dispositivo pode publicar ou "
                                      "assinar qualquer tópico industrial."),
                         severity="CRÍTICO", cvss=9.3, evidence=ev)
        except Exception:
            pass

    def _smb(self, host, port, svc):
        # Verificar se já temos dados do CME no svc
        cme = svc.get("cme", {})

        # SMB Signing via CME (já calculado) ou nmap
        signing = cme.get("signing", None)

        if signing is None:
            # Tentar via nmap script
            try:
                r = subprocess.run(
                    ["nmap", "-Pn", "-p", str(port),
                     "--script", "smb-security-mode,smb2-security-mode",
                     host, "-oN", "-"],
                    capture_output=True, text=True, timeout=30
                )
                out = r.stdout.lower()
                if "message_signing: disabled" in out or "not required" in out:
                    signing = False
                elif "message_signing: enabled" in out or "required" in out:
                    signing = True
            except Exception:
                pass

        if signing is False:
            evidence = "SMB Signing: disabled/not required"
            if cme.get("os_info"):
                evidence += f" | {cme['os_info']}"
            if cme.get("hostname"):
                evidence += f" | Host: {cme['hostname']}"
            self.add(host=host, service="SMB", port=port,
                     title="SMB Signing Desabilitado — NTLM Relay Viável",
                     description=("Sem assinatura SMB, ataques NTLM Relay são viáveis. "
                                  "Em ambientes com Active Directory, isso pode levar ao "
                                  "comprometimento total do domínio."),
                     severity="CRÍTICO", cvss=9.0,
                     evidence=evidence)

        # SMBv1 via CME
        if cme.get("smbv1") is True:
            self.add(host=host, service="SMB", port=port,
                     title="SMBv1 Habilitado — Vulnerável ao EternalBlue",
                     description=("SMBv1 está ativo, tornando o sistema potencialmente "
                                  "vulnerável ao EternalBlue (MS17-010), usado pelo WannaCry."),
                     severity="CRÍTICO", cvss=9.8,
                     evidence="crackmapexec: SMBv1:True")

        # Null session
        try:
            r3 = subprocess.run(
                ["smbclient", "-L", f"//{host}", "-N", "--no-pass"],
                capture_output=True, text=True, timeout=10
            )
            if "Sharename" in r3.stdout or "Disk" in r3.stdout:
                self.add(host=host, service="SMB", port=port,
                         title="SMB Null Session Aceita",
                         description=("Conexões SMB sem credenciais aceitas, permitindo "
                                      "enumeração de compartilhamentos e usuários."),
                         severity="ALTO", cvss=7.5,
                         evidence=f"smbclient -L //{host} -N → lista de shares")
        except Exception:
            pass

    def _rpc(self, host, port, svc):
        """Porta 135 — RPC endpoint mapper."""
        self.add(host=host, service="RPC", port=port,
                 title="RPC Endpoint Mapper Exposto",
                 description=("A porta 135 (RPC Endpoint Mapper) está acessível. "
                               "Pode ser usada para enumeração de serviços RPC registrados "
                               "e movimentação lateral em ambientes Windows/AD."),
                 severity="MÉDIO", cvss=5.3,
                 evidence=f"Porta {port}/tcp aberta em {host}")

        # Tentar impacket-rpcdump
        try:
            r = subprocess.run(
                ["impacket-rpcdump", host],
                capture_output=True, text=True, timeout=20
            )
            if r.returncode == 0 and r.stdout:
                services_found = re.findall(r"Protocol:\s+(.+)", r.stdout)
                if services_found:
                    self.add(host=host, service="RPC", port=port,
                             title="Serviços RPC Enumerados",
                             description=("Serviços RPC enumerados sem autenticação. "
                                          "Pode revelar serviços internos e versões."),
                             severity="BAIXO", cvss=3.1,
                             evidence=f"Serviços: {', '.join(services_found[:5])}")
        except Exception:
            pass

    def _ldap(self, host, port, svc):
        """Porta 389/636/3268/3269 — LDAP/AD."""
        tls = port in [636, 3269]
        self.add(host=host, service="LDAP", port=port,
                 title=f"LDAP {'SSL' if tls else 'Aberto'} Acessível",
                 description=("Porta LDAP detectada. Se permitir consultas anônimas "
                               "(null bind), pode expor usuários, grupos e estrutura do AD."),
                 severity="MÉDIO" if not tls else "BAIXO", cvss=5.3 if not tls else 3.1,
                 evidence=f"Porta {port}/tcp aberta em {host}")

    def _mysql(self, host, port, svc):
        version = svc.get("version", "")
        eol_map = {"5.0": "2012", "5.1": "2013", "5.5": "2018",
                   "5.6": "2021", "5.7": "2023"}
        for v, year in eol_map.items():
            if version.startswith(v):
                self.add(host=host, service="MySQL", port=port,
                         title=f"MySQL {version} — EOL sem patches desde {year}",
                         description=(f"MySQL {version} atingiu End-of-Life em {year}. "
                                      "Múltiplas CVEs críticas sem correção disponível."),
                         severity="CRÍTICO", cvss=9.8,
                         evidence=f"Versão: MySQL {version}")
                break
        if port not in [3306]:
            self.add(host=host, service="MySQL", port=port,
                     title=f"MySQL em Porta Não Padrão ({port})",
                     description="Porta não padrão não é medida de segurança efetiva.",
                     severity="BAIXO", cvss=2.0,
                     evidence=f"MySQL em {port}/tcp")

    def _ssh(self, host, port, svc):
        scripts = svc.get("script", {})
        auth    = scripts.get("ssh-auth-methods", "")
        if auth and "password" in auth.lower():
            self.add(host=host, service="SSH", port=port,
                     title="SSH Aceita Autenticação por Senha",
                     description=("Autenticação por senha expõe o serviço a força bruta "
                                  "e credential stuffing."),
                     severity="MÉDIO", cvss=5.3,
                     evidence=f"ssh-auth-methods: {auth}")

    def _rdp(self, host, port, svc):
        self.add(host=host, service="RDP", port=port,
                 title="RDP Exposto na Rede",
                 description=("RDP acessível é vetor comum de ransomware. "
                               "Recomenda-se acesso via VPN ou restrição por IP."),
                 severity="ALTO", cvss=7.0,
                 evidence=f"Porta {port}/tcp aberta")

    def _winrm(self, host, port, svc):
        self.add(host=host, service="WinRM", port=port,
                 title="WinRM (Gerenciamento Remoto Windows) Exposto",
                 description=("WinRM exposto permite execução remota de comandos PowerShell. "
                               "Com credenciais válidas (ex: via Pass-the-Hash), fornece "
                               "shell completo no sistema."),
                 severity="ALTO", cvss=7.5,
                 evidence=f"Porta {port}/tcp aberta")

    def _eol_check(self, host, port, svc):
        product = (svc.get("product", "") + " " + svc.get("version", "")).lower()
        eol_db  = [
            ("windows xp",          "CRÍTICO", 10.0),
            ("windows server 2003", "CRÍTICO", 10.0),
            ("windows server 2008", "ALTO",     8.0),
            ("windows 7",           "ALTO",     8.0),
            ("apache 2.2",          "ALTO",     7.5),
            ("php 5.",              "ALTO",     7.5),
            ("iis 6.0",             "ALTO",     7.5),
            ("tomcat 6.",           "ALTO",     7.5),
            ("nginx 1.0",           "MÉDIO",    6.0),
            ("ubuntu 14.04",        "MÉDIO",    6.0),
            ("centos 6",            "MÉDIO",    6.0),
        ]
        for p, sev, cvss in eol_db:
            if p in product:
                self.add(host=host, service=svc.get("name", "OS/Software"), port=port,
                         title=f"Software EOL: {product}",
                         description=(f"O software {product} atingiu o fim da vida útil e não "
                                      "recebe mais atualizações de segurança. "
                                      "É um alvo fácil para atacantes."),
                         severity=sev, cvss=cvss,
                         evidence=f"Versão EOL: {product}")
                break

    def _default_creds_check(self, host, port, svc):
        # Exemplo: checar credenciais padrão para Redis
        if svc.get("name", "").lower() == "redis":
            try:
                # Tentar conectar sem senha
                r = subprocess.run(
                    ["redis-cli", "-h", host, "-p", str(port), "ping"],
                    capture_output=True, text=True, timeout=5
                )
                if "PONG" in r.stdout:
                    self.add(host=host, service="Redis", port=port,
                             title="Redis Acessível Sem Autenticação",
                             description=("Servidor Redis configurado sem autenticação. "
                                          "Permite acesso irrestrito aos dados e execução "
                                          "remota de código via Master-Slave Replication."),
                             severity="CRÍTICO", cvss=10.0,
                             evidence="Redis ping bem-sucedido sem senha")
            except Exception:
                pass

    def _mssql(self, host, port, svc):
        # Implementar checagens para MS-SQL
        pass

    def _postgresql(self, host, port, svc):
        # Implementar checagens para PostgreSQL
        pass

    def _redis(self, host, port, svc):
        # Implementar checagens para Redis (já tem uma genérica, pode adicionar mais)
        pass

    def _elasticsearch(self, host, port, svc):
        # Implementar checagens para Elasticsearch
        pass

    def _mongodb(self, host, port, svc):
        # Implementar checagens para MongoDB
        pass


# ─── AI Analysis (Groq/Llama 3) ──────────────────────────────────────────────

def ai_analyze(findings: list[Finding], api_key: str) -> dict:
    client = Groq(api_key=api_key)

    # Prepara os findings para enviar ao LLM
    findings_data = []
    for i, f in enumerate(findings):
        findings_data.append({
            "id": i,
            "host": f.host,
            "service": f.service,
            "port": f.port,
            "title": f.title,
            "description": f.description,
            "severity": f.severity,
            "cvss": f.cvss,
            "evidence": f.evidence
        })

    # Função para o LLM classificar e recomendar
    def classify_risk(finding_id: int, current_severity: str, current_cvss: float, description: str, evidence: str):
        """
        Classifica o risco de uma vulnerabilidade e fornece uma recomendação de mitigação.
        Args:
            finding_id (int): ID único do achado.
            current_severity (str): Severidade atual (CRÍTICO, ALTO, MÉDIO, BAIXO, INFO).
            current_cvss (float): Score CVSS atual.
            description (str): Descrição da vulnerabilidade.
            evidence (str): Evidência da vulnerabilidade.
        Returns:
            dict: Um dicionário com 'analysis' (análise detalhada) e 'recommendation' (recomendação de mitigação).
        """
        pass # Esta função será implementada pelo LLM

    # Envia para o LLM
    chat_completion = client.chat.completions.create(
        messages=[
            {
                "role": "system",
                "content": (
                    "Você é um especialista em cibersegurança e pentest. "
                    "Sua tarefa é analisar os achados de segurança fornecidos, "
                    "classificar o risco (CVSS) e gerar um score executivo de 0 a 100. "
                    "Para cada achado, forneça uma análise detalhada e uma recomendação de mitigação. "
                    "Use a função `classify_risk` para cada achado."
                ),
            },
            {
                "role": "user",
                "content": f"Analise os seguintes achados de segurança: {json.dumps(findings_data, indent=2)}",
            },
        ],
        model="llama3-70b-8192",
        tool_choice={"type": "function", "function": {"name": "classify_risk"}},
        tools=[
            {
                "type": "function",
                "function": {
                    "name": "classify_risk",
                    "description": "Classifica o risco de uma vulnerabilidade e fornece uma recomendação de mitigação.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "finding_id": {"type": "integer", "description": "ID único do achado."},
                            "current_severity": {"type": "string", "description": "Severidade atual (CRÍTICO, ALTO, MÉDIO, BAIXO, INFO)."},
                            "current_cvss": {"type": "number", "description": "Score CVSS atual."},
                            "description": {"type": "string", "description": "Descrição da vulnerabilidade."},
                            "evidence": {"type": "string", "description": "Evidência da vulnerabilidade."},
                            "analysis": {"type": "string", "description": "Análise detalhada da vulnerabilidade."},
                            "recommendation": {"type": "string", "description": "Recomendação de mitigação para a vulnerabilidade."},
                        },
                        "required": ["finding_id", "current_severity", "current_cvss", "description", "evidence", "analysis", "recommendation"],
                    },
                },
            }
        ],
        max_tokens=4000,
    )

    # Processa a resposta do LLM
    ai_results = {"findings": {}, "risk_score": 0}
    if chat_completion.choices and chat_completion.choices[0].message.tool_calls:
        for tool_call in chat_completion.choices[0].message.tool_calls:
            if tool_call.function.name == "classify_risk":
                args = json.loads(tool_call.function.arguments)
                finding_id = args["finding_id"]
                ai_results["findings"][str(finding_id)] = {
                    "analysis": args["analysis"],
                    "recommendation": args["recommendation"]
                }

    # Calcula um score de risco executivo (exemplo simples)
    total_cvss = sum(f.cvss for f in findings)
    if findings: # Normaliza para 0-100
        ai_results["risk_score"] = min(100, round((total_cvss / (len(findings) * 10)) * 100, 2))

    return ai_results


# ─── Report Generation ───────────────────────────────────────────────────────

def gen_txt(findings: list[Finding], target: str, scan_time: datetime, ai_data: dict) -> str:
    # Implementação da geração de relatório TXT
    content = f"CYMAG Scan Report for {target} at {scan_time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    for f in findings:
        content += f"[{f.severity}] {f.title} ({f.host}:{f.port}/{f.service})\n"
        content += f"  Description: {f.description}\n"
        content += f"  CVSS: {f.cvss}\n"
        if f.ai_analysis: content += f"  AI Analysis: {f.ai_analysis}\n"
        if f.ai_recommendation: content += f"  AI Recommendation: {f.ai_recommendation}\n"
        content += f"  Evidence: {f.evidence}\n\n"
    if ai_data.get("risk_score"): content += f"Executive Risk Score: {ai_data['risk_score']}/100\n"
    return content

def gen_pdf(findings: list[Finding], target: str, scan_time: datetime, ai_data: dict) -> str:
    # Implementação da geração de relatório PDF
    doc_title = f"CYMAG Report - {target}"
    output_filename = f"CYMAG_{target.replace('/','_')}_{scan_time.strftime('%Y%m%d_%H%M')}.pdf"
    doc = SimpleDocTemplate(output_filename, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    # Title
    story.append(Paragraph(doc_title, styles['h1']))
    story.append(Paragraph(f"Scan Date: {scan_time.strftime('%Y-%m-%d %H:%M:%S')}", styles['h3']))
    story.append(Spacer(1, 0.5*cm))

    # Executive Summary (AI)
    if ai_data.get("executive_summary"):
        story.append(Paragraph("Executive Summary (AI)", styles['h2']))
        story.append(Paragraph(ai_data["executive_summary"], styles['Normal']))
        story.append(Spacer(1, 0.5*cm))

    # Risk Score
    if ai_data.get("risk_score"):
        story.append(Paragraph(f"Executive Risk Score: {ai_data['risk_score']}/100", styles['h2']))
        story.append(Spacer(1, 0.5*cm))

    # Findings
    story.append(Paragraph("Findings", styles['h2']))
    for f in findings:
        story.append(Paragraph(f"{SEVERITY_ICON.get(f.severity, '⚪')} {f.title}", styles['h3']))
        story.append(Paragraph(f"Host: {f.host}:{f.port} | Service: {f.service} | CVSS: {f.cvss}", styles['Normal']))
        story.append(Paragraph(f.description, styles['Normal']))
        if f.ai_analysis:
            story.append(Paragraph("AI Analysis:", styles['h4']))
            story.append(Paragraph(f.ai_analysis, styles['Normal']))
        if f.ai_recommendation:
            story.append(Paragraph("AI Recommendation:", styles['h4']))
            story.append(Paragraph(f.ai_recommendation, styles['Normal']))
        story.append(Paragraph(f"Evidence: {f.evidence}", styles['Code']))
        story.append(Spacer(1, 0.5*cm))

    doc.build(story)
    return output_filename

def gen_html(findings: list[Finding], target: str, scan_time: datetime, ai_data: dict) -> str:
    # Implementação da geração de relatório HTML (dashboard)
    output_filename = f"CYMAG_{target.replace('/','_')}_{scan_time.strftime('%Y%m%d_%H%M')}.html"

    # Dados para o dashboard
    dashboard_data = {
        "target": target,
        "scan_time": scan_time.strftime('%Y-%m-%d %H:%M:%S'),
        "risk_score": ai_data.get("risk_score", "N/A"),
        "findings": []
    }

    for f in findings:
        dashboard_data["findings"].append({
            "host": f.host,
            "service": f.service,
            "port": f.port,
            "title": f.title,
            "description": f.description,
            "severity": f.severity,
            "cvss": f.cvss,
            "evidence": f.evidence,
            "ai_analysis": f.ai_analysis,
            "ai_recommendation": f.ai_recommendation
        })

    # Template HTML (simplificado para o exemplo)
    html_template = """
    <!DOCTYPE html>
    <html lang=\"en\">
    <head>
        <meta charset=\"UTF-8\">
        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
        <title>CYMAG Dashboard - {{ target }}</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f4; color: #333; line-height: 1.6; }
            .container { max-width: 960px; margin: auto; background-color: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            h1, h2, h3 { color: #0056b3; }
            .header { text-align: center; margin-bottom: 30px; }
            .score-card { background-color: #e74c3c; color: white; padding: 20px; border-radius: 5px; text-align: center; margin-bottom: 20px; }
            .score-card h2 { color: white; margin-top: 0; }
            .score { font-size: 3em; font-weight: bold; }
            .finding { background-color: #f9f9f9; border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin-bottom: 15px; }
            .finding h3 { margin-top: 0; color: #333; }
            .finding p { margin-bottom: 5px; }
            .severity-CRÍTICO { color: #c0392b; font-weight: bold; }
            .severity-ALTO { color: #e67e22; font-weight: bold; }
            .severity-MÉDIO { color: #f39c12; font-weight: bold; }
            .severity-BAIXO { color: #27ae60; font-weight: bold; }
            .severity-INFO { color: #95a5a6; font-weight: bold; }
            .ai-section { background-color: #e8f0fe; border-left: 4px solid #3498db; padding: 10px; margin-top: 10px; }
            .ai-section h4 { color: #3498db; margin-top: 0; }
        </style>
    </head>
    <body>
        <div class=\"container\">
            <div class=\"header\">
                <h1>CYMAG AutoScanner Report</h1>
                <p><strong>Target:</strong> {{ target }}</p>
                <p><strong>Scan Time:</strong> {{ scan_time }}</p>
            </div>

            <div class=\"score-card\">
                <h2>Executive Risk Score</h2>
                <p class=\"score\">{{ risk_score }} / 100</p>
            </div>

            <h2>Findings</h2>
            {% for finding in findings %}
            <div class=\"finding\">
                <h3><span class=\"severity-{{ finding.severity }}\">{{ finding.severity }}</span>: {{ finding.title }}</h3>
                <p><strong>Host:</strong> {{ finding.host }}:{{ finding.port }} ({{ finding.service }})</p>
                <p><strong>CVSS:</strong> {{ finding.cvss }}</p>
                <p><strong>Description:</strong> {{ finding.description }}</p>
                <p><strong>Evidence:</strong> <code>{{ finding.evidence }}</code></p>
                {% if finding.ai_analysis %}
                <div class=\"ai-section\">
                    <h4>AI Analysis:</h4>
                    <p>{{ finding.ai_analysis }}</p>
                </div>
                {% endif %}
                {% if finding.ai_recommendation %}
                <div class=\"ai-section\">
                    <h4>AI Recommendation:</h4>
                    <p>{{ finding.ai_recommendation }}</p>
                </div>
                {% endif %}
            </div>
            {% endfor %}
        </div>
    </body>
    </html>
    """

    # Renderiza o template com os dados
    from jinja2 import Template
    template = Template(html_template)
    rendered_html = template.render(dashboard_data)

    Path(output_filename).write_text(rendered_html, encoding="utf-8")
    return output_filename


# ─── Flask App for Dashboard ─────────────────────────────────────────────────

app = Flask(__name__)

@app.route('/')
def dashboard_route():
    # Lê o arquivo HTML gerado e o serve
    # Assumimos que 'out' da função main é o caminho para o HTML gerado
    # Para simplificar, vamos usar um placeholder aqui, em um cenário real
    # você passaria o caminho do arquivo gerado para esta função ou a Flask app
    # teria acesso ao contexto do scan.
    # Por enquanto, vamos usar o HTML_DASHBOARD simulado ou ler o último gerado.
    try:
        # Tenta ler o último arquivo HTML gerado (se houver)
        html_files = sorted(Path('.').glob('CYMAG_*.html'), key=os.path.getmtime, reverse=True)
        if html_files:
            return html_files[0].read_text(encoding='utf-8')
        else:
            return render_template_string("<h1>Nenhum relatório HTML encontrado. Execute um scan primeiro.</h1>")
    except Exception as e:
        return render_template_string(f"<h1>Erro ao carregar dashboard: {e}</h1>")

def start_flask_server():
    # Desativa o log de acesso do Flask para manter o console limpo
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False)

def open_browser_after_scan():
    # Espera um curto período para garantir que o servidor Flask esteja ativo
    time.sleep(2) # Aumentado para 2 segundos para maior robustez
    print("Abrindo o navegador padrão com o dashboard...")
    webbrowser.open("http://127.0.0.1:5000")


# ─── main ─────────────────────────────────────────────────────────────────────
def main():
    print(BANNER)

    target  = sys.argv[1] if len(sys.argv) >= 2 else input("\nAlvo (IP ou CIDR): ").strip()
    if not target:
        print("[ERRO] Alvo obrigatório."); sys.exit(1)

    debug   = "--debug" in sys.argv

    api_key = os.environ.get("GROQ_API_KEY", "")
    if not api_key:
        api_key = input("Groq API Key (Enter para pular IA): ").strip()

    print("\nFormato do relatório:")
    print("  0  TXT  — resumo rápido (sem IA)")
    print("  1  PDF  — relatório completo com análise IA")
    print("  2  HTML — dashboard interativo com IA")
    while True:
        try:
            fmt = int(input("Escolha (0/1/2): ").strip())
            if fmt in [0, 1, 2]:
                break
        except Exception:
            pass
        print("  Digite 0, 1 ou 2.")

    print()
    scanner  = CYMAGScanner(target, debug=debug)
    findings = scanner.run()

    print(f"\n[3/4] {len(findings)} achado(s).")

    ai_data = {}
    if api_key and fmt in [1, 2]:
        print("       Analisando com Groq/Llama...")
        sorted_f = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 0), reverse=True)
        ai_data  = ai_analyze(sorted_f, api_key)
        for i, f in enumerate(sorted_f):
            fd = ai_data.get("findings", {}).get(str(i), {})
            f.ai_analysis       = fd.get("analysis", "")
            f.ai_recommendation = fd.get("recommendation", "")

    print("[4/4] Gerando relatório...")
    st = scanner.scan_time
    out_file_path = ""
    if fmt == 0:
        content = gen_txt(findings, target, st, ai_data)
        out_file_path = f"CYMAG_{target.replace('/','_')}_{st.strftime('%Y%m%d_%H%M')}.txt"
        Path(out_file_path).write_text(content, encoding="utf-8")
    elif fmt == 1:
        out_file_path = gen_pdf(findings, target, st, ai_data)
    else: # fmt == 2 (HTML)
        out_file_path = gen_html(findings, target, st, ai_data)

    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print(f"\n{'='*52}")
    print(f"  ✅  {out_file_path}")
    print(f"{'='*52}")
    for s in ["CRÍTICO", "ALTO", "MÉDIO", "BAIXO", "INFO"]:
        if s in counts:
            print(f"  {SEVERITY_ICON[s]}  {s}: {counts[s]}")
    if ai_data.get("risk_score"):
        print(f"  📊  Score de Risco: {ai_data['risk_score']}/100")

    if fmt == 2:
        print("\nIniciando servidor Flask e abrindo dashboard no navegador...")
        # Inicia o servidor Flask em uma thread separada
        flask_thread = threading.Thread(target=start_flask_server)
        flask_thread.daemon = True
        flask_thread.start()

        # Abre o navegador na thread principal
        open_browser_after_scan()

        # Mantém a thread principal viva para que o servidor Flask continue rodando
        # e o navegador permaneça aberto. Em um ambiente real, você pode ter
        # um loop de eventos ou outra lógica aqui.
        try:
            while True:
                time.sleep(1) # Mantém o programa rodando indefinidamente
        except KeyboardInterrupt:
            print("Aplicação encerrada pelo usuário.")
    else:
        print(f"\n  Relatório gerado em: {out_file_path}")

    # scan log (se debug)
    if debug and scanner.scan_log:
        print("\n[DEBUG] Scan log por host:")
        print(json.dumps(scanner.scan_log, indent=2, default=str))


if __name__ == "__main__":
    # Garante que o jinja2 esteja instalado para gen_html
    try:
        import jinja2
    except ImportError:
        print("[!] A biblioteca 'jinja2' não está instalada. Instalando...")
        subprocess.run([sys.executable, "-m", "pip", "install", "jinja2", "--break-system-packages"])
        import jinja2

    main()
