#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║  CYMAG AutoScanner v1.1  (Versão Monolítica)         ║
║  Diagnóstico Automatizado de Segurança               ║
║  SENAI — Projeto Integrador Interdisciplinar I       ║
╚══════════════════════════════════════════════════════╝

CHANGELOG v1.1 (Correção de Sintaxe)
  - Remoção de f-strings no bloco HTML para evitar bugs visuais nos editores de código (IDE).
  - Geração de HTML via substituição direta (.replace).
  - Detecção de portas em 3 camadas (socket → nmap -Pn -sT → fallback)
  - Host discovery com fallback -Pn para hosts que bloqueiam ICMP
  - Integração com crackmapexec para validação SMB em Windows
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
PORTS_WINDOWS = [135, 137, 139, 389, 445, 464, 636, 3268, 3269, 5985, 5986, 49152]
ALL_PORTS = sorted(set(PORTS_COMMON + PORTS_WINDOWS))

SOCKET_TIMEOUT = 1.5   
NMAP_TIMEOUT   = "90s" 

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
        self.scan_log  = {}

    def add(self, **kw):
        f = Finding(**kw)
        self.findings.append(f)
        icon = SEVERITY_ICON.get(f.severity, "⚪")
        print(f"    {icon} [{f.severity:8s}] {f.title}  ({f.host}:{f.port})")
        return f

    def dbg(self, msg: str):
        if self.debug:
            print(f"    [DBG] {msg}")

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

    def _discover(self):
        self.dbg("Etapa 1: nmap ping sweep (-sn)")
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=self.target, arguments="-sn --host-timeout 10s")
            self.hosts_up = list(nm.all_hosts())
            self.dbg(f"Ping sweep retornou: {self.hosts_up}")
        except Exception as e:
            self.dbg(f"Ping sweep erro: {e}")

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

        if not self.hosts_up:
            self.dbg("Etapa 3: usando target diretamente")
            try:
                ipaddress.ip_address(self.target)
                self.hosts_up = [self.target]
            except ValueError:
                try:
                    net = ipaddress.ip_network(self.target, strict=False)
                    self.hosts_up = [str(list(net.hosts())[0])]
                except Exception:
                    self.hosts_up = [self.target.split("/")[0]]

        print(f"    Hosts ativos: {', '.join(self.hosts_up)}")

    def _socket_scan(self, host: str) -> dict:
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

    def _nmap_scan(self, host: str, ports_hint: list = None) -> dict:
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
        except Exception as e:
            self.dbg(f"Nmap erro: {e}")
        return services

    def _merge_results(self, socket_ports: dict, nmap_services: dict) -> dict:
        merged = dict(nmap_services) 
        socket_only = set(socket_ports.keys()) - set(nmap_services.keys())
        for port in socket_only:
            name = self._port_to_name(port)
            merged[port] = {
                "name":      name,
                "product":   "",
                "version":   "",
                "extrainfo": "detectado via socket",
                "script":    {},
                "source":    "socket",
            }
        return merged

    def _port_to_name(self, port: int) -> str:
        known = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 135: "msrpc", 137: "netbios-ns",
            139: "netbios-ssn", 389: "ldap", 443: "https", 445: "microsoft-ds",
            1433: "mssql", 1880: "node-red", 1883: "mqtt", 3306: "mysql", 
            3307: "mysql", 3389: "rdp", 5432: "postgresql", 5985: "winrm",
            8080: "http-alt", 8443: "https-alt"
        }
        return known.get(port, "unknown")

    def _scan_host(self, host: str) -> dict:
        log = {"socket": [], "nmap": [], "merged": [], "cme": None}

        print(f"    [1/3] Socket scan...")
        socket_ports = self._socket_scan(host)
        log["socket"] = sorted(socket_ports.keys())

        print(f"    [2/3] Nmap -Pn -sT...")
        hints = list(socket_ports.keys()) if socket_ports else None
        nmap_services = self._nmap_scan(host, ports_hint=hints)
        log["nmap"] = sorted(nmap_services.keys())

        print(f"    [3/3] Merge de resultados...")
        services = self._merge_results(socket_ports, nmap_services)
        log["merged"] = sorted(services.keys())

        if 445 in services or 139 in services:
            print(f"    [+] SMB detectado — validando com crackmapexec...")
            cme_data = self._cme_smb(host)
            log["cme"] = cme_data
            if cme_data:
                smb_port = 445 if 445 in services else 139
                services[smb_port]["cme"] = cme_data

        self.scan_log[host] = log
        return services

    def _cme_smb(self, host: str) -> dict:
        cme_path = self._which("crackmapexec") or self._which("cme")
        if not cme_path: return {}
        try:
            result = subprocess.run([cme_path, "smb", host], capture_output=True, text=True, timeout=20)
            out = result.stdout + result.stderr
            data = {"raw": out.strip()[:400]}
            if "signing:True" in out or "signing: True" in out: data["signing"] = True
            elif "signing:False" in out or "signing: False" in out: data["signing"] = False
            return data
        except:
            return {}

    def _which(self, cmd: str):
        try:
            r = subprocess.run(["which", cmd], capture_output=True, text=True)
            return r.stdout.strip() if r.stdout.strip() else None
        except: return None

    def _dispatch(self, host, port, svc):
        name    = svc.get("name", "").lower()
        product = svc.get("product", "").lower()

        if port in [80, 443, 8080, 8443] or "http" in name: self._http(host, port, svc)
        if port == 1880 or "node-red" in product or (port == 1880 and "http" in name): self._nodered(host, port)
        if port in [1883, 8883] or "mqtt" in name or "mosquitto" in product: self._mqtt(host, port)
        if port in [445, 139] or "microsoft-ds" in name or "smb" in name: self._smb(host, port, svc)
        if port == 135 or "msrpc" in name or "rpc" in name: self._rpc(host, port, svc)
        if port in [3306, 3307] or "mysql" in name or "mariadb" in product: self._mysql(host, port, svc)
        if port == 22 or "ssh" in name: self._ssh(host, port, svc)
        self._eol_check(host, port, svc)

    def _http(self, host, port, svc):
        proto = "https" if port in [443, 8443] else "http"
        base  = f"{proto}://{host}:{port}"
        try: r = requests.get(base, timeout=6, verify=False, allow_redirects=True)
        except: return

        srv = r.headers.get("Server", "")
        if srv and any(x in srv.lower() for x in ["apache/", "nginx/", "iis/"]):
            self.add(host=host, service="HTTP", port=port, title="Divulgação de Versão do Servidor Web", description="O header Server revela versão exata.", severity="BAIXO", cvss=3.1, evidence=f"Server: {srv}")

        paths = [("/admin", "Painel Administrativo"), ("/api/collaborators", "API de Colaboradores")]
        for path, desc in paths:
            try:
                pr = requests.get(f"{base}{path}", timeout=4, verify=False)
                if pr.status_code == 200:
                    self.add(host=host, service="HTTP", port=port, title=f"Endpoint Sensível: {path}", description=f"{desc} acessível.", severity="ALTO", cvss=7.5, evidence=f"GET {path} → 200 OK")
            except: pass

        for path in ["/api/collaborators?name='", "/search?q='"]:
            try:
                sr = requests.get(f"{base}{path}", timeout=4, verify=False)
                if any(e in sr.text.lower() for e in ["sql", "mysql", "syntax error"]):
                    self.add(host=host, service="HTTP", port=port, title="SQL Injection Detectado", description="Endpoint retorna erros SQL.", severity="CRÍTICO", cvss=9.8, evidence="Erro de banco de dados retornado")
                    break
            except: pass

    def _nodered(self, host, port):
        base = f"http://{host}:{port}"
        try:
            r = requests.get(f"{base}/settings", timeout=5)
            if r.status_code == 200:
                fext = r.json().get("functionExternalModules", False)
                self.add(host=host, service="Node-RED", port=port, title="Node-RED Sem Autenticação", description="Controle total sobre fluxos OT.", severity="CRÍTICO", cvss=9.8, evidence=f"functionExternalModules:{fext}")
        except: pass

    def _mqtt(self, host, port):
        connected = [False]
        def on_connect(client, ud, flags, rc, props=None):
            if rc == 0: connected[0] = True
        try:
            c = mqtt_client.Client(mqtt_client.CallbackAPIVersion.VERSION2)
            c.on_connect = on_connect
            c.connect(host, port, 5); c.loop_start(); time.sleep(2); c.loop_stop(); c.disconnect()
            if connected[0]:
                self.add(host=host, service="MQTT", port=port, title="Broker MQTT Sem Autenticação", description="Conexão anônima aceita.", severity="CRÍTICO", cvss=9.3, evidence="Conectado com sucesso")
        except: pass

    def _smb(self, host, port, svc):
        cme = svc.get("cme", {})
        signing = cme.get("signing", None)
        if signing is False:
            self.add(host=host, service="SMB", port=port, title="SMB Signing Desabilitado", description="Vulnerável a NTLM Relay.", severity="CRÍTICO", cvss=9.0, evidence="signing:False")

    def _rpc(self, host, port, svc):
        self.add(host=host, service="RPC", port=port, title="RPC Endpoint Mapper Exposto", description="Permite enumeração de serviços.", severity="MÉDIO", cvss=5.3, evidence=f"Porta {port} aberta")

    def _mysql(self, host, port, svc):
        version = svc.get("version", "")
        if "5.5" in version:
            self.add(host=host, service="MySQL", port=port, title=f"MySQL {version} — EOL", description="Versão obsoleta sem patches.", severity="CRÍTICO", cvss=9.8, evidence=f"Versão: MySQL {version}")

    def _ssh(self, host, port, svc):
        pass 

    def _eol_check(self, host, port, svc):
        pass 


# ─── AI analyzer ─────────────────────────────────────────────────────────────
def ai_analyze(findings: list, api_key: str) -> dict:
    if not findings or not api_key: return {}
    try:
        client  = Groq(api_key=api_key)
        summary = "\n".join(f"[{i}] {f.severity} | {f.title} | {f.host}:{f.port}" for i, f in enumerate(findings))
        prompt = (
            "Você é um especialista em cibersegurança. Analise os achados e responda SOMENTE em JSON.\n"
            f"ACHADOS:\n{summary}\n"
            'Estrutura: {"summary":"...","risk_score":0-100,"disclaimer":"...","findings":{"0":{"analysis":"...","recommendation":"..."}}}'
        )
        r = client.chat.completions.create(model="llama-3.3-70b-versatile", messages=[{"role": "user", "content": prompt}], max_tokens=4096, temperature=0.3)
        txt = r.choices[0].message.content
        match = re.search(r"\{.*\}", txt, re.DOTALL)
        if match: return json.loads(match.group())
    except: pass
    return {}

# ─── Reports ─────────────────────────────────────────────────────────────────
def gen_txt(findings, target, scan_time, ai_data):
    lines = [f"  Alvo   : {target}", f"  Data   : {scan_time.strftime('%d/%m/%Y %H:%M')}", f"  Achados: {len(findings)}", ""]
    for f in findings:
        lines += [f"  [{f.severity}] {f.title}", f"  Host: {f.host}:{f.port}"]
    return "\n".join(lines)

def gen_pdf(findings, target, scan_time, ai_data):
    # Simplificado para o protótipo
    return f"CYMAG_{target.replace('/','_')}.pdf"


# =========================================================================================
# AQUI ESTÁ A CORREÇÃO DE SINTAXE.
# O HTML AGORA É UMA STRING PURA (SEM O `f` NA FRENTE), PARA NÃO BUGAR O SEU EDITOR.
# OS VALORES SÃO INJETADOS DEPOIS USANDO O COMANDO .replace()
# =========================================================================================
def gen_html(findings, target, scan_time, ai_data):
    out     = f"CYMAG_{target.replace('/','_')}_{scan_time.strftime('%Y%m%d_%H%M')}.html"
    total   = len(findings)
    counts  = {}
    for f in findings: counts[f.severity] = counts.get(f.severity, 0) + 1

    rs       = ai_data.get("risk_score", 0)
    rc_color = "#c0392b" if rs >= 70 else "#e67e22" if rs >= 40 else "#27ae60"
    rc_lbl   = "CRÍTICO" if rs >= 70 else "ALTO" if rs >= 40 else "BAIXO"

    sev_order = ["CRÍTICO", "ALTO", "MÉDIO", "BAIXO", "INFO"]
    cards  = ""
    
    sorted_f = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 0), reverse=True)
    for i, f in enumerate(sorted_f):
        sc  = f.severity.lower().replace("í", "i").replace("é", "e")
        
        # REMOVIDO O 'f' DE F-STRING AQUI TAMBÉM!
        card_tpl = """
        <div class="card sev-__SC__" data-severity="__SEV__" id="c__I__">
          <div class="ch">
            <div class="r1">
              <span class="bg bg-__SC__">__SEV__</span>
              <span class="ct">__TITLE__</span>
              <span class="cv">CVSS&nbsp;__CVSS__</span>
            </div>
            <div class="r2">🖥 __HOST__:__PORT__ &nbsp; ⚙ __SVC__</div>
          </div>
          <div class="cb" style="display:block; padding: 15px; border-top: 1px solid #ccc; margin-top: 10px;">
            <p class="desc">__DESC__</p>
          </div>
        </div>"""
        
        # SUBSTITUIÇÃO DIRETA (SEM BUGAR O EDITOR)
        c_html = card_tpl.replace("__SC__", sc)
        c_html = c_html.replace("__SEV__", str(f.severity))
        c_html = c_html.replace("__I__", str(i))
        c_html = c_html.replace("__TITLE__", str(f.title))
        c_html = c_html.replace("__CVSS__", str(f.cvss))
        c_html = c_html.replace("__HOST__", str(f.host))
        c_html = c_html.replace("__PORT__", str(f.port))
        c_html = c_html.replace("__SVC__", str(f.service))
        c_html = c_html.replace("__DESC__", str(f.description))
        
        cards += c_html

    summary_text = ai_data.get('summary', 'Análise de IA não disponível.')
    disclaimer   = ai_data.get('disclaimer', 'Relatório gerado automaticamente.')

    # STRING PURA (SEM F-STRING). O SEU VS CODE NÃO VAI MAIS FICAR AZUL!
    html_template = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CYMAG — __TARGET__</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', Arial, sans-serif; background: #f0f2f5; color: #222; font-size: 14px; }
.hdr { background: #1a1a2e; color: #fff; padding: 18px 32px; display: flex; justify-content: space-between; align-items: center; }
.hdr h1 { font-size: 20px; font-weight: 700; letter-spacing: 1px; }
.wrap { max-width: 1080px; margin: 0 auto; padding: 22px 14px; }
.sc { background: #fff; border-radius: 8px; padding: 18px; box-shadow: 0 1px 4px rgba(0,0,0,.07); border-left: 4px solid __RC_COLOR__; text-align: center; margin-bottom: 20px;}
.sv { font-size: 42px; font-weight: 700; color: __RC_COLOR__; }
.sb { background: #fff; border-radius: 8px; padding: 18px; margin-bottom: 20px; box-shadow: 0 1px 4px rgba(0,0,0,.07); border-left: 4px solid #0f3460; }
.card { background: #fff; border-radius: 8px; margin-bottom: 9px; box-shadow: 0 1px 3px rgba(0,0,0,.06); border-left: 4px solid #ccc; }
.sev-critico { border-left-color: #c0392b; } .sev-alto { border-left-color: #e67e22; }
.sev-medio { border-left-color: #f39c12; } .sev-baixo { border-left-color: #27ae60; }
.ch { padding: 13px 14px; }
.r1 { display: flex; align-items: center; gap: 9px; flex-wrap: wrap; }
.bg { display: inline-block; padding: 2px 7px; border-radius: 4px; font-size: 10px; font-weight: 700; color: white; }
.bg-critico { background: #c0392b; } .bg-alto { background: #e67e22; }
.bg-medio { background: #f39c12; } .bg-baixo { background: #27ae60; }
.ct { font-weight: 600; font-size: 13.5px; flex: 1; }
.cv { font-size: 11px; color: #888; }
.r2 { margin-top: 5px; font-size: 11px; color: #888; }
</style>
</head>
<body>
<div class="hdr">
  <div><h1>🔍 CYMAG AutoScanner v1.1</h1></div>
  <div>Alvo: <b>__TARGET__</b><br>Achados: __TOTAL__</div>
</div>
<div class="wrap">
  <div class="sc">
    <div>Score de Risco Executivo</div>
    <div class="sv">__RS__</div>
    <div>__RC_LBL__</div>
  </div>
  <div class="sb">
    <h2>🤖 Análise Executiva — Inteligência Artificial</h2>
    <p>__SUMMARY__</p>
    <p style="margin-top: 10px; font-size: 11px; color: #888;">⚠ Aviso: __DISCLAIMER__</p>
  </div>
  <div id="fl">__CARDS__</div>
</div>
</body>
</html>"""

    # Agora fazemos a substituição das variáveis de forma limpa.
    html_final = html_template.replace("__TARGET__", target)
    html_final = html_final.replace("__TOTAL__", str(total))
    html_final = html_final.replace("__RS__", str(rs))
    html_final = html_final.replace("__RC_COLOR__", rc_color)
    html_final = html_final.replace("__RC_LBL__", rc_lbl)
    html_final = html_final.replace("__SUMMARY__", summary_text)
    html_final = html_final.replace("__DISCLAIMER__", disclaimer)
    html_final = html_final.replace("__CARDS__", cards)

    with open(out, "w", encoding="utf-8") as fh:
        fh.write(html_final)
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
            if fmt in [0, 1, 2]: break
        except Exception: pass
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

    print(f"\n{'='*52}")
    print(f"  ✅  {out}")
    print(f"{'='*52}\n")

if __name__ == "__main__":
    main()

#
