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
          f"    pip install {' '.join(MISSING)} --break-system-packages\n")
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

        print(f"    Hosts ativos: {', '.join(self.hosts_up)}")

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
                            self.dbg(f"  Nmap: {p}/tcp {d.get('name','')} "
                                     f"{d.get('product','')} {d.get('version','')}")
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
        """Mapa manual de portas conhecidas para nome de serviço."""
        known = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 135: "msrpc", 137: "netbios-ns",
            139: "netbios-ssn", 389: "ldap", 443: "https", 445: "microsoft-ds",
            464: "kpasswd", 636: "ldapssl", 1433: "mssql", 1880: "node-red",
            1883: "mqtt", 3268: "globalcatalog", 3269: "globalcatalogssl",
            3306: "mysql", 3307: "mysql", 3389: "rdp", 5040: "unknown-win",
            5432: "postgresql", 5985: "winrm", 5986: "winrm-ssl",
            6379: "redis", 8080: "http-alt", 8443: "https-alt",
            8883: "mqtt-ssl", 9200: "elasticsearch", 27017: "mongodb",
            49152: "rpc-dyn",
        }
        return known.get(port, "unknown")

    # ─────────────────────────────────────────────────────────────────────────
    # Orquestração: descoberta de portas em 3 camadas
    # ─────────────────────────────────────────────────────────────────────────
    def _scan_host(self, host: str) -> dict:
        """
        Orquestra as três camadas para um host:
          1. Socket scan  → acha quais portas estão abertas (rápido)
          2. Nmap -Pn -sT → identifica serviços nas portas abertas (preciso)
          3. Merge        → garante que nenhuma porta caia no vazio
        Além disso: se portas SMB/AD forem detectadas, roda crackmapexec.
        """
        log = {"socket": [], "nmap": [], "merged": [], "cme": None}

        # CAMADA 1 — socket
        print(f"    [1/3] Socket scan...")
        socket_ports = self._socket_scan(host)
        log["socket"] = sorted(socket_ports.keys())
        if socket_ports:
            print(f"    Portas abertas (socket): {sorted(socket_ports.keys())}")
        else:
            print(f"    Nenhuma porta aberta detectada pelo socket.")

        # CAMADA 2 — nmap focado nas portas que o socket achou (mais rápido)
        print(f"    [2/3] Nmap -Pn -sT...")
        hints = list(socket_ports.keys()) if socket_ports else None
        nmap_services = self._nmap_scan(host, ports_hint=hints)
        log["nmap"] = sorted(nmap_services.keys())
        if nmap_services:
            print(f"    Portas com serviço identificado (nmap): {sorted(nmap_services.keys())}")
        else:
            print(f"    Nmap não identificou serviços (usando só dados do socket).")

        # CAMADA 3 — merge
        print(f"    [3/3] Merge de resultados...")
        services = self._merge_results(socket_ports, nmap_services)
        log["merged"] = sorted(services.keys())
        print(f"    Total de portas confirmadas: {sorted(services.keys())}")

        # Validação SMB com crackmapexec (se 445 aparecer)
        if 445 in services or 139 in services:
            print(f"    [+] SMB detectado — validando com crackmapexec...")
            cme_data = self._cme_smb(host)
            log["cme"] = cme_data
            if cme_data:
                # Enriquecer o serviço SMB com dados do CME
                smb_port = 445 if 445 in services else 139
                services[smb_port]["cme"] = cme_data
                self.dbg(f"CME data: {cme_data}")

        # WinRM — relevante se for um DC
        if 5985 in services or 5986 in services:
            print(f"    [+] WinRM detectado ({5985 if 5985 in services else 5986})")

        self.scan_log[host] = log
        return services

    # ─────────────────────────────────────────────────────────────────────────
    # crackmapexec — validação SMB especializada
    # ─────────────────────────────────────────────────────────────────────────
    def _cme_smb(self, host: str) -> dict:
        """
        Roda crackmapexec smb no host e extrai:
          - nome do host, domínio, OS
          - SMB signing habilitado ou não
          - SMBv1 habilitado ou não
        Retorna dicionário com esses dados ou {} se CME não estiver instalado.
        """
        cme_path = self._which("crackmapexec") or self._which("cme")
        if not cme_path:
            self.dbg("crackmapexec não encontrado no PATH — pulando")
            return {}

        try:
            result = subprocess.run(
                [cme_path, "smb", host],
                capture_output=True, text=True, timeout=20
            )
            out = result.stdout + result.stderr
            self.dbg(f"CME output: {out[:300]}")

            data = {"raw": out.strip()[:400]}

            # Parsing da linha de saída do CME
            # Exemplo: SMB  10.10.100.2  445  WIN10101002  [*] Windows 10/Server 2016 x64 ...
            #          (signing:True)  (SMBv1:False)
            if "signing:True" in out or "signing: True" in out:
                data["signing"] = True
            elif "signing:False" in out or "signing: False" in out:
                data["signing"] = False

            if "SMBv1:True" in out or "SMBv1: True" in out:
                data["smbv1"] = True
            elif "SMBv1:False" in out or "SMBv1: False" in out:
                data["smbv1"] = False

            # Extrair nome do host e OS
            m_name = re.search(r"\[\*\]\s+Windows[^\n]+", out)
            if m_name:
                data["os_info"] = m_name.group().strip()

            m_host = re.search(r"SMB\s+\S+\s+445\s+(\S+)", out)
            if m_host:
                data["hostname"] = m_host.group(1)

            return data

        except subprocess.TimeoutExpired:
            self.dbg("CME timeout")
        except Exception as e:
            self.dbg(f"CME erro: {e}")
        return {}

    def _which(self, cmd: str):
        """Equivalente ao which do Unix."""
        try:
            r = subprocess.run(["which", cmd], capture_output=True, text=True)
            path = r.stdout.strip()
            return path if path else None
        except Exception:
            return None

    # ─────────────────────────────────────────────────────────────────────────
    # Dispatcher de testes
    # ─────────────────────────────────────────────────────────────────────────
    def _dispatch(self, host, port, svc):
        name    = svc.get("name", "").lower()
        product = svc.get("product", "").lower()

        if port in [80, 443, 8080, 8443] or "http" in name:
            self._http(host, port, svc)
        if port == 1880 or "node-red" in product or (port == 1880 and "http" in name):
            self._nodered(host, port)
        if port in [1883, 8883] or "mqtt" in name or "mosquitto" in product:
            self._mqtt(host, port)
        if port in [445, 139] or "microsoft-ds" in name or "netbios" in name or "smb" in name:
            self._smb(host, port, svc)
        if port == 135 or "msrpc" in name or "rpc" in name:
            self._rpc(host, port, svc)
        if port in [389, 636, 3268, 3269] or "ldap" in name:
            self._ldap(host, port, svc)
        if port in [3306, 3307] or "mysql" in name or "mariadb" in product:
            self._mysql(host, port, svc)
        if port == 22 or "ssh" in name:
            self._ssh(host, port, svc)
        if port == 3389 or "rdp" in name or "ms-wbt" in name:
            self._rdp(host, port)
        if port in [5985, 5986] or "winrm" in name:
            self._winrm(host, port, svc)
        self._eol_check(host, port, svc)

    # ─────────────────────────────────────────────────────────────────────────
    # Testes por serviço
    # ─────────────────────────────────────────────────────────────────────────
    def _http(self, host, port, svc):
        proto = "https" if port in [443, 8443] else "http"
        base  = f"{proto}://{host}:{port}"
        try:
            r = requests.get(base, timeout=6, verify=False, allow_redirects=True)
        except Exception:
            return

        # headers de segurança ausentes
        sec_hdrs = ["X-Content-Type-Options", "X-Frame-Options",
                    "Content-Security-Policy", "Strict-Transport-Security"]
        missing  = [h for h in sec_hdrs if h not in r.headers]
        if missing:
            self.add(host=host, service="HTTP", port=port,
                     title="Headers de Segurança Ausentes",
                     description=("A aplicação não implementa headers de segurança HTTP "
                                  "recomendados, deixando usuários expostos a ataques como "
                                  "clickjacking e XSS."),
                     severity="MÉDIO", cvss=5.3,
                     evidence=f"Ausentes: {', '.join(missing)}")

        # divulgação de versão
        srv = r.headers.get("Server", "")
        if srv and any(x in srv.lower() for x in ["apache/", "nginx/", "iis/", "express"]):
            self.add(host=host, service="HTTP", port=port,
                     title="Divulgação de Versão do Servidor Web",
                     description="O header Server revela versão exata, facilitando ataques direcionados.",
                     severity="BAIXO", cvss=3.1, evidence=f"Server: {srv}")

        # endpoints sensíveis
        paths = [
            ("/admin",               "Painel Administrativo"),
            ("/api",                 "API"),
            ("/.env",                "Arquivo .env"),
            ("/config",              "Arquivo de Configuração"),
            ("/backup",              "Arquivo de Backup"),
            ("/debug",               "Interface de Debug"),
            ("/phpinfo.php",         "PHP Info"),
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
        for path in ["/api/collaborators?name='", "/api/users?id=1'", "/search?q='"]:
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

    def _nodered(self, host, port):
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

    def _mqtt(self, host, port):
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
                 evidence=f"Porta 135/tcp aberta em {host}")

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

    def _rdp(self, host, port):
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
        ]
        for sig, sev, cvss in eol_db:
            if sig in product:
                self.add(host=host, service=svc.get("name", "?").upper(), port=port,
                         title=f"Software EOL: {svc.get('product','')} {svc.get('version','')}",
                         description="Software sem suporte de segurança ativo.",
                         severity=sev, cvss=cvss,
                         evidence=f"{svc.get('product','')} {svc.get('version','')}")
                break


# ─── AI analyzer ─────────────────────────────────────────────────────────────
def ai_analyze(findings: list, api_key: str) -> dict:
    if not findings or not api_key:
        return {}
    try:
        client  = Groq(api_key=api_key)
        summary = "\n".join(
            f"[{i}] {f.severity} | CVSS {f.cvss} | {f.title} | {f.host}:{f.port}\n"
            f"    {f.description[:180]}\n    Evidência: {f.evidence[:120]}"
            for i, f in enumerate(findings)
        )
        prompt = (
            "Você é um especialista em segurança cibernética.\n"
            "Analise os achados e responda SOMENTE em JSON válido.\n\n"
            f"ACHADOS:\n{summary}\n\n"
            "Estrutura:\n"
            '{"summary":"...","risk_score":0-100,"disclaimer":"...","findings":{'
            '"0":{"analysis":"...","recommendation":"..."},"1":{...}}}\n\n'
            "Recomendações por severidade:\n"
            "CRÍTICO/ALTO: grave, exige especialista imediato.\n"
            "MÉDIO: TI pode resolver, mas valide com especialista.\n"
            "BAIXO: solução simples, ainda assim recomende revisão profissional.\n"
            "Disclaimer: você é IA, pode errar, humano deve revisar."
        )
        r   = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=4096, temperature=0.3
        )
        txt   = r.choices[0].message.content
        match = re.search(r"\{.*\}", txt, re.DOTALL)
        if match:
            return json.loads(match.group())
    except Exception as e:
        print(f"  [!] Groq: {e}")
    return {}


# ─── Reports ─────────────────────────────────────────────────────────────────
def gen_txt(findings, target, scan_time, ai_data):
    lines = ["=" * 62,
             "  CYMAG AutoScanner v1.1 — Relatório de Segurança",
             "=" * 62,
             f"  Alvo   : {target}",
             f"  Data   : {scan_time.strftime('%d/%m/%Y %H:%M')}",
             f"  Achados: {len(findings)}", ""]
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    lines.append("  RESUMO:")
    for s in ["CRÍTICO", "ALTO", "MÉDIO", "BAIXO", "INFO"]:
        if s in counts:
            lines.append(f"    {s}: {counts[s]}")
    if ai_data.get("risk_score"):
        lines.append(f"    Score de Risco: {ai_data['risk_score']}/100")
    if ai_data.get("summary"):
        lines += ["", "  ANÁLISE (IA):", f"  {ai_data['summary']}"]
    lines += ["", "-" * 62]
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 0), reverse=True):
        lines += [f"",
                  f"  [{f.severity}] {f.title}",
                  f"  Host: {f.host}:{f.port} | {f.service} | CVSS {f.cvss}",
                  f"  {f.description}"]
        if f.evidence:
            lines.append(f"  Evidência: {f.evidence[:120]}")
        if f.ai_recommendation:
            lines.append(f"  Recomendação: {f.ai_recommendation}")
    lines += ["", "=" * 62,
              "  AVISO: Relatório gerado automaticamente. Consulte",
              "  um especialista antes de tomar decisões.",
              "=" * 62]
    return "\n".join(lines)


def gen_pdf(findings, target, scan_time, ai_data):
    out  = f"CYMAG_{target.replace('/','_')}_{scan_time.strftime('%Y%m%d_%H%M')}.pdf"
    doc  = SimpleDocTemplate(out, pagesize=A4,
                             rightMargin=2*cm, leftMargin=2*cm,
                             topMargin=2*cm, bottomMargin=2*cm)
    SS   = getSampleStyleSheet()
    DARK = colors.HexColor("#1a1a2e")
    BLUE = colors.HexColor("#0f3460")

    def ps(name, **kw):
        base = kw.pop("parent", SS["Normal"])
        return ParagraphStyle(name, parent=base, **kw)

    TITLE = ps("t",  parent=SS["Title"],   fontSize=20, textColor=DARK, alignment=TA_CENTER)
    H2    = ps("h2", parent=SS["Heading2"],fontSize=13, textColor=BLUE, spaceBefore=10)
    BODY  = ps("b",  fontSize=9.5, leading=14, alignment=TA_JUSTIFY)
    SMALL = ps("s",  fontSize=8, textColor=colors.grey, leading=12)
    SEV_C = {k: colors.HexColor(v) for k, v in SEVERITY_HEX.items()}

    story = [Spacer(1, .8*cm),
             Paragraph("CYMAG AutoScanner v1.1", TITLE),
             Paragraph("Relatório de Diagnóstico de Segurança",
                       ps("sub", fontSize=12, textColor=colors.grey, alignment=TA_CENTER)),
             Spacer(1, .3*cm),
             HRFlowable(width="100%", thickness=1, color=BLUE),
             Spacer(1, .3*cm)]

    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    meta = [["Alvo", target],
            ["Data", scan_time.strftime("%d/%m/%Y %H:%M:%S")],
            ["Achados", str(len(findings))]]
    for s in ["CRÍTICO", "ALTO", "MÉDIO", "BAIXO"]:
        if s in counts:
            meta.append([s, str(counts[s])])

    mt = Table(meta, colWidths=[4*cm, 12.5*cm])
    mt.setStyle(TableStyle([
        ("FONTNAME", (0,0), (-1,-1), "Helvetica"),
        ("FONTNAME", (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [colors.white, colors.HexColor("#f5f5f5")]),
        ("GRID", (0,0), (-1,-1), .3, colors.HexColor("#ddd")),
        ("TOPPADDING", (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
    ]))
    story.append(mt)
    story.append(Spacer(1, .4*cm))

    rs = ai_data.get("risk_score", 0)
    if rs:
        rc = (colors.HexColor("#c0392b") if rs >= 70 else
              colors.HexColor("#e67e22") if rs >= 40 else
              colors.HexColor("#27ae60"))
        story.append(Paragraph(f"<b>Score de Risco: {rs}/100</b>",
                               ps("rk", fontSize=13, textColor=rc, alignment=TA_CENTER)))
        story.append(Spacer(1, .3*cm))

    if ai_data.get("summary"):
        story += [Paragraph("Análise Executiva (IA)", H2),
                  Paragraph(ai_data["summary"], BODY)]
        if ai_data.get("disclaimer"):
            story += [Spacer(1, .15*cm), Paragraph(f"⚠ {ai_data['disclaimer']}", SMALL)]
        story.append(Spacer(1, .4*cm))

    story += [Paragraph("Achados de Segurança", H2),
              HRFlowable(width="100%", thickness=.5, color=colors.HexColor("#ccc"))]

    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 0), reverse=True):
        sc  = SEV_C.get(f.severity, colors.grey)
        hdr = [[Paragraph(f"<b>[{f.severity}]</b>",
                           ps("sh", fontSize=9, textColor=colors.white)),
                Paragraph(f"<b>{f.title}</b>",
                           ps("st", fontSize=9.5, textColor=colors.white)),
                Paragraph(f"CVSS {f.cvss}",
                           ps("sc", fontSize=9, textColor=colors.white, alignment=TA_CENTER))]]
        ht  = Table(hdr, colWidths=[2.5*cm, 11*cm, 3*cm])
        ht.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,-1), sc),
                                ("TOPPADDING", (0,0), (-1,-1), 5),
                                ("BOTTOMPADDING", (0,0), (-1,-1), 5),
                                ("LEFTPADDING", (0,0), (-1,-1), 6)]))
        story += [Spacer(1, .25*cm), ht]
        rows = [
            [Paragraph("<b>Host</b>", SMALL),      Paragraph(f"{f.host}:{f.port} — {f.service}", BODY)],
            [Paragraph("<b>Descrição</b>", SMALL),  Paragraph(f.description, BODY)],
        ]
        if f.evidence:
            rows.append([Paragraph("<b>Evidência</b>", SMALL),  Paragraph(f.evidence[:250], SMALL)])
        if f.ai_analysis:
            rows.append([Paragraph("<b>Análise IA</b>", SMALL), Paragraph(f.ai_analysis, BODY)])
        if f.ai_recommendation:
            rows.append([Paragraph("<b>Recomendação</b>", SMALL), Paragraph(f.ai_recommendation, BODY)])
        dt = Table(rows, colWidths=[3*cm, 13.5*cm])
        dt.setStyle(TableStyle([
            ("FONTSIZE", (0,0), (-1,-1), 9),
            ("ROWBACKGROUNDS", (0,0), (-1,-1), [colors.white, colors.HexColor("#fafafa")]),
            ("GRID", (0,0), (-1,-1), .2, colors.HexColor("#eee")),
            ("TOPPADDING", (0,0), (-1,-1), 4),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ("LEFTPADDING", (0,0), (-1,-1), 6),
            ("VALIGN", (0,0), (-1,-1), "TOP"),
        ]))
        story.append(dt)

    story += [Spacer(1, .8*cm),
              HRFlowable(width="100%", thickness=.5, color=colors.HexColor("#ccc")),
              Paragraph("AVISO LEGAL: Relatório gerado automaticamente. Resultados podem "
                        "conter imprecisões. Revisão por especialista em segurança é obrigatória "
                        "antes de qualquer decisão.", SMALL)]
    doc.build(story)
    return out


def gen_html(findings, target, scan_time, ai_data):
    out     = f"CYMAG_{target.replace('/','_')}_{scan_time.strftime('%Y%m%d_%H%M')}.html"
    total   = len(findings)
    counts  = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    rs       = ai_data.get("risk_score", 0)
    rc_color = "#c0392b" if rs >= 70 else "#e67e22" if rs >= 40 else "#27ae60"
    rc_lbl   = "CRÍTICO" if rs >= 70 else "ALTO" if rs >= 40 else "BAIXO"

    sev_order = ["CRÍTICO", "ALTO", "MÉDIO", "BAIXO", "INFO"]

    # donut SVG
    segs = ""
    cum  = 0.0
    cx, cy, ro, ri = 60, 60, 52, 30
    for sev in sev_order:
        cnt = counts.get(sev, 0)
        if cnt == 0:
            continue
        pct = cnt / total if total else 0
        a0  = cum * 360
        a1  = (cum + pct) * 360
        cum += pct
        r0  = math.radians(a0 - 90)
        r1  = math.radians(a1 - 90)
        x1o = cx + ro * math.cos(r0); y1o = cy + ro * math.sin(r0)
        x2o = cx + ro * math.cos(r1); y2o = cy + ro * math.sin(r1)
        x1i = cx + ri * math.cos(r1); y1i = cy + ri * math.sin(r1)
        x2i = cx + ri * math.cos(r0); y2i = cy + ri * math.sin(r0)
        la  = 1 if (a1 - a0) > 180 else 0
        d   = (f"M {x1o:.1f} {y1o:.1f} A {ro} {ro} 0 {la} 1 {x2o:.1f} {y2o:.1f} "
               f"L {x1i:.1f} {y1i:.1f} A {ri} {ri} 0 {la} 0 {x2i:.1f} {y2i:.1f} Z")
        segs += f'<path d="{d}" fill="{SEVERITY_HEX.get(sev,"#999")}" title="{sev}:{cnt}"/>\n'

    legend = ""
    for s in sev_order:
        c = counts.get(s, 0)
        if c:
            sc = s.lower().replace("í", "i").replace("é", "e")
            legend += (f'<div class="li"><span class="ld sdd-{sc}"></span>'
                       f'{s}: <b>{c}</b></div>')

    filters = (f'<button class="fb active" data-f="ALL" onclick="flt(this)">'
               f'Todos <span class="cnt">{total}</span></button>')
    for s in sev_order:
        c = counts.get(s, 0)
        if c:
            sc = s.lower().replace("í", "i").replace("é", "e")
            filters += (f'<button class="fb fb-{sc}" data-f="{s}" onclick="flt(this)">'
                        f'{s} <span class="cnt">{c}</span></button>')

    cards  = ""
    sorted_f = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 0), reverse=True)
    ai_f   = ai_data.get("findings", {})
    for i, f in enumerate(sorted_f):
        fd = ai_f.get(str(i), {})
        f.ai_analysis       = fd.get("analysis", "")
        f.ai_recommendation = fd.get("recommendation", "")
        sc  = f.severity.lower().replace("í", "i").replace("é", "e")
        evh = (f'<div class="ev"><code>{f.evidence[:400]}</code></div>'
               if f.evidence else "")
        aih = (f'<div class="ab"><div class="al">🤖 Análise IA</div>'
               f'<p>{f.ai_analysis}</p></div>'
               if f.ai_analysis else "")
        rch = (f'<div class="rb"><div class="rl">💡 Recomendação</div>'
               f'<p>{f.ai_recommendation}</p></div>'
               if f.ai_recommendation else "")
        cards += f"""
<div class="card sev-{sc}" data-severity="{f.severity}" id="c{i}">
  <div class="ch" onclick="tog(this)">
    <div class="r1">
      <span class="bg bg-{sc}">{f.severity}</span>
      <span class="ct">{f.title}</span>
      <span class="cv">CVSS&nbsp;{f.cvss}</span>
    </div>
    <div class="r2">🖥 {f.host}:{f.port} &nbsp; ⚙ {f.service}</div>
    <span class="chv">▼</span>
  </div>
  <div class="cb">
    <p class="desc">{f.description}</p>
    {evh}{aih}{rch}
    <label class="ck"><input type="checkbox" onchange="done(this,'c{i}')"> Marcar como revisado</label>
  </div>
</div>"""

    summary_html = f"<p>{ai_data.get('summary','Análise de IA não disponível.')}</p>"
    disclaimer   = ai_data.get("disclaimer",
                                "Esta análise foi gerada por IA e pode conter imprecisões. "
                                "Consulte sempre um especialista em segurança cibernética.")

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CYMAG — {target}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',Arial,sans-serif;background:#f0f2f5;color:#222;font-size:14px}}
.hdr{{background:#1a1a2e;color:#fff;padding:18px 32px;display:flex;justify-content:space-between;align-items:center}}
.hdr h1{{font-size:20px;font-weight:700;letter-spacing:1px}}
.hdr .meta{{font-size:11px;color:#aaa;text-align:right;line-height:2}}
.wrap{{max-width:1080px;margin:0 auto;padding:22px 14px}}
.dash{{display:grid;grid-template-columns:160px 1fr;gap:14px;margin-bottom:20px}}
.sc{{background:#fff;border-radius:8px;padding:18px;box-shadow:0 1px 4px rgba(0,0,0,.07);border-left:4px solid {rc_color};text-align:center}}
.sl{{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#777;margin-bottom:6px}}
.sv{{font-size:42px;font-weight:700;color:{rc_color}}}
.ss{{font-size:11px;color:#888;margin-top:3px}}
.cc{{background:#fff;border-radius:8px;padding:18px;box-shadow:0 1px 4px rgba(0,0,0,.07);display:flex;align-items:center;gap:24px}}
.li{{display:flex;align-items:center;gap:7px;font-size:12px;margin-bottom:6px}}
.ld{{display:inline-block;width:11px;height:11px;border-radius:50%}}
.sdd-critico{{background:#c0392b}}.sdd-alto{{background:#e67e22}}
.sdd-medio{{background:#f39c12}}.sdd-baixo{{background:#27ae60}}.sdd-info{{background:#95a5a6}}
.sb{{background:#fff;border-radius:8px;padding:18px;margin-bottom:20px;
    box-shadow:0 1px 4px rgba(0,0,0,.07);border-left:4px solid #0f3460}}
.sb h2{{font-size:14px;color:#0f3460;margin-bottom:8px}}
.sb p{{line-height:1.7;color:#444}}
.disc{{background:#fff8e1;border-left:3px solid #f39c12;padding:9px 13px;
      margin-top:10px;font-size:11px;color:#666;border-radius:0 4px 4px 0}}
.fts{{display:flex;flex-wrap:wrap;gap:7px;margin-bottom:14px;align-items:center}}
.flb{{font-size:11px;color:#666;font-weight:700}}
.fb{{border:none;padding:5px 13px;border-radius:20px;cursor:pointer;font-size:11px;
    font-weight:600;background:#ddd;color:#333;transition:opacity .2s}}
.fb.active{{outline:2px solid #333}}.fb:hover{{opacity:.8}}
.fb-critico{{background:#c0392b;color:#fff}}.fb-alto{{background:#e67e22;color:#fff}}
.fb-medio{{background:#f39c12;color:#fff}}.fb-baixo{{background:#27ae60;color:#fff}}
.fb-info{{background:#95a5a6;color:#fff}}
.st{{font-size:15px;font-weight:700;margin-bottom:10px}}
.card{{background:#fff;border-radius:8px;margin-bottom:9px;
      box-shadow:0 1px 3px rgba(0,0,0,.06);border-left:4px solid #ccc;transition:box-shadow .2s}}
.card:hover{{box-shadow:0 3px 10px rgba(0,0,0,.11)}}
.sev-critico{{border-left-color:#c0392b}}.sev-alto{{border-left-color:#e67e22}}
.sev-medio{{border-left-color:#f39c12}}.sev-baixo{{border-left-color:#27ae60}}
.sev-info{{border-left-color:#95a5a6}}.card.done{{opacity:.5;filter:grayscale(60%)}}
.ch{{padding:13px 14px;cursor:pointer;position:relative;user-select:none}}
.r1{{display:flex;align-items:center;gap:9px;flex-wrap:wrap}}
.bg{{display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700}}
.bg-critico{{background:#c0392b;color:#fff}}.bg-alto{{background:#e67e22;color:#fff}}
.bg-medio{{background:#f39c12;color:#fff}}.bg-baixo{{background:#27ae60;color:#fff}}
.bg-info{{background:#95a5a6;color:#fff}}
.ct{{font-weight:600;font-size:13.5px;flex:1}}.cv{{font-size:11px;color:#888}}
.r2{{margin-top:5px;font-size:11px;color:#888}}
.chv{{position:absolute;right:14px;top:14px;font-size:11px;color:#aaa;transition:transform .2s}}
.chv.open{{transform:rotate(180deg)}}
.cb{{display:none;padding:0 14px 14px;border-top:1px solid #f0f0f0}}
.desc{{color:#444;line-height:1.65;margin-top:11px}}
.ev{{background:#1e1e1e;border-radius:4px;padding:9px 11px;margin:9px 0;overflow-x:auto}}
.ev code{{color:#d4d4d4;font-size:11px;font-family:Consolas,monospace;white-space:pre-wrap;word-break:break-all}}
.ab{{background:#f0f4ff;border-left:3px solid #3498db;padding:9px 13px;margin:9px 0;border-radius:0 4px 4px 0}}
.al{{font-size:10px;font-weight:700;color:#2980b9;margin-bottom:4px}}
.ab p{{color:#333;line-height:1.6;font-size:13px}}
.rb{{background:#f0fff4;border-left:3px solid #27ae60;padding:9px 13px;margin:9px 0;border-radius:0 4px 4px 0}}
.rl{{font-size:10px;font-weight:700;color:#1e8449;margin-bottom:4px}}
.rb p{{color:#333;line-height:1.6;font-size:13px}}
.ck{{display:flex;align-items:center;gap:7px;margin-top:10px;font-size:12px;color:#666;cursor:pointer}}
.ftr{{background:#1a1a2e;color:#666;text-align:center;padding:14px;font-size:11px;margin-top:28px}}
@media print{{.fts,.fb{{display:none}}.cb{{display:block!important}}body{{background:#fff}}}}
</style>
</head>
<body>
<div class="hdr">
  <div>
    <h1>🔍 CYMAG AutoScanner v1.1</h1>
    <div style="font-size:12px;color:#aaa;margin-top:3px">Relatório de Diagnóstico de Segurança</div>
  </div>
  <div class="meta">Alvo: <b style="color:#fff">{target}</b><br>{scan_time.strftime("%d/%m/%Y %H:%M")}<br>{total} achados</div>
</div>
<div class="wrap">
  <div class="dash">
    <div class="sc"><div class="sl">Score de Risco</div><div class="sv">{rs}</div><div class="ss">{rc_lbl}</div></div>
    <div class="cc">
      <svg viewBox="0 0 120 120" width="115" height="115" style="flex-shrink:0">
        {segs if segs else '<circle cx="60" cy="60" r="52" fill="#eee"/>'}
        <text x="60" y="64" text-anchor="middle" font-size="15" font-weight="bold" fill="#333">{total}</text>
        <text x="60" y="76" text-anchor="middle" font-size="8" fill="#999">achados</text>
      </svg>
      <div>{legend}</div>
    </div>
  </div>
  <div class="sb">
    <h2>🤖 Análise Executiva — Inteligência Artificial</h2>
    {summary_html}
    <div class="disc">⚠ <b>Aviso:</b> {disclaimer}</div>
  </div>
  <div class="st">Achados de Segurança</div>
  <div class="fts"><span class="flb">Filtrar:</span>{filters}</div>
  <div id="fl">{cards}</div>
</div>
<div class="ftr">CYMAG AutoScanner v1.1 &nbsp;|&nbsp; SENAI / Faculdade de Tecnologia Paulo Antonio Skaf &nbsp;|&nbsp; Projeto Integrador I<br>Relatório gerado automaticamente. Consulte sempre um especialista em segurança cibernética.</div>
<script>
function flt(b){{document.querySelectorAll('.fb').forEach(x=>x.classList.remove('active'));b.classList.add('active');const f=b.dataset.f;document.querySelectorAll('.card').forEach(c=>{{c.style.display=(f==='ALL'||c.dataset.severity===f)?'':'none';}});}}
function tog(h){{const b=h.nextElementSibling,c=h.querySelector('.chv'),o=b.style.display==='block';b.style.display=o?'none':'block';c.classList.toggle('open',!o);}}
function done(cb,id){{const c=document.getElementById(id);c.classList.toggle('done',cb.checked);localStorage.setItem(id,cb.checked?'1':'');}}
window.addEventListener('DOMContentLoaded',()=>{{
  document.querySelectorAll('.card').forEach(c=>{{if(localStorage.getItem(c.id)==='1'){{c.classList.add('done');const cb=c.querySelector('input');if(cb)cb.checked=true;}}}});
  document.querySelectorAll('.sev-critico').forEach(c=>{{const b=c.querySelector('.cb'),ch=c.querySelector('.chv');if(b)b.style.display='block';if(ch)ch.classList.add('open');}});
}});
</script>
</body>
</html>"""

    with open(out, "w", encoding="utf-8") as fh:
        fh.write(html)
    return out


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
    if fmt == 0:
        content = gen_txt(findings, target, st, ai_data)
        out = f"CYMAG_{target.replace('/','_')}_{st.strftime('%Y%m%d_%H%M')}.txt"
        Path(out).write_text(content, encoding="utf-8")
    elif fmt == 1:
        out = gen_pdf(findings, target, st, ai_data)
    else:
        out = gen_html(findings, target, st, ai_data)

    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print(f"\n{'='*52}")
    print(f"  ✅  {out}")
    print(f"{'='*52}")
    for s in ["CRÍTICO", "ALTO", "MÉDIO", "BAIXO", "INFO"]:
        if s in counts:
            print(f"  {SEVERITY_ICON[s]}  {s}: {counts[s]}")
    if ai_data.get("risk_score"):
        print(f"  📊  Score de Risco: {ai_data['risk_score']}/100")
    if fmt == 2:
        print(f"\n  🌐  firefox {out}")
    print(f"{'='*52}\n")

    # scan log (se debug)
    if debug and scanner.scan_log:
        print("\n[DEBUG] Scan log por host:")
        print(json.dumps(scanner.scan_log, indent=2, default=str))


if __name__ == "__main__":
    main()
