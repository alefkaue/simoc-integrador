#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║  CYMAG AutoScanner v1.0                              ║
║  Diagnóstico Automatizado de Segurança               ║
║  SENAI — Projeto Integrador Interdisciplinar I       ║
╚══════════════════════════════════════════════════════╝
Uso:
    python3 cymag_scanner.py <alvo> [--format 0|1|2]
    python3 cymag_scanner.py 192.168.1.0/24
    python3 cymag_scanner.py 10.10.100.100

Dependências:
    pip install python-nmap paho-mqtt requests groq reportlab --break-system-packages
"""

import sys, os, json, socket, subprocess, datetime, re, time, math, warnings
import ipaddress
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
VERSION = "1.0.0"
BANNER  = f"""
╔══════════════════════════════════════════════════════╗
║  CYMAG AutoScanner v{VERSION:<8}                      ║
║  Diagnóstico Automatizado de Segurança               ║
╚══════════════════════════════════════════════════════╝"""

SEVERITY_ORDER  = {"CRÍTICO": 4, "ALTO": 3, "MÉDIO": 2, "BAIXO": 1, "INFO": 0}
SEVERITY_HEX    = {"CRÍTICO": "#c0392b","ALTO": "#e67e22",
                   "MÉDIO": "#f39c12","BAIXO": "#27ae60","INFO": "#95a5a6"}
SEVERITY_ICON   = {"CRÍTICO": "🔴","ALTO": "🟠","MÉDIO": "🟡","BAIXO": "🟢","INFO": "⚪"}

# ─── Finding dataclass ───────────────────────────────────────────────────────
class Finding:
    def __init__(self, host, service, port, title, description, severity, cvss, evidence=""):
        self.host           = host
        self.service        = service
        self.port           = port
        self.title          = title
        self.description    = description
        self.severity       = severity
        self.cvss           = cvss
        self.evidence       = evidence
        self.ai_analysis    = ""
        self.ai_recommendation = ""

# ─── Scanner ─────────────────────────────────────────────────────────────────
class CYMAGScanner:
    def __init__(self, target: str):
        self.target    = target
        self.findings  = []
        self.hosts_up  = []
        self.scan_time = datetime.datetime.now()

    # ── helpers ──
    def add(self, **kw):
        f = Finding(**kw)
        self.findings.append(f)
        icon = SEVERITY_ICON.get(f.severity, "⚪")
        print(f"    {icon} [{f.severity:8s}] {f.title}  ({f.host}:{f.port})")
        return f

    # ── public entry ──
    def run(self):
        print("\n[1/4] Descoberta de hosts...")
        self._discover()
        print(f"\n[2/4] Testando {len(self.hosts_up)} host(s)...")
        for h in self.hosts_up:
            print(f"\n  ▶ {h}")
            svcs = self._port_scan(h)
            for port, svc in svcs.items():
                self._dispatch(h, port, svc)
        return self.findings

    # ── discovery ──
    def _discover(self):
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=self.target, arguments="-sn --host-timeout 10s")
            self.hosts_up = list(nm.all_hosts())
        except Exception as e:
            print(f"  [!] nmap discover: {e}")
        if not self.hosts_up:
            # single IP fallback
            try:
                ipaddress.ip_address(self.target)
                self.hosts_up = [self.target]
            except:
                # strip CIDR and use base
                self.hosts_up = [self.target.split("/")[0]]
        print(f"    Hosts: {', '.join(self.hosts_up)}")

    # ── port scan ──
    def _port_scan(self, host):
        ports = ("21,22,23,25,53,80,443,445,1433,1883,1880,"
                 "3306,3307,3389,5040,5432,6379,8080,8443,8883,9200,27017")
        svcs = {}
        try:
            nm = nmap.PortScanner()
            nm.scan(host, arguments=f"-sV -sC --open -T4 --host-timeout 60s -p {ports}")
            if host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    for p in nm[host][proto]:
                        if nm[host][proto][p]["state"] == "open":
                            d = nm[host][proto][p]
                            svcs[p] = {
                                "name":      d.get("name",""),
                                "product":   d.get("product",""),
                                "version":   d.get("version",""),
                                "extrainfo": d.get("extrainfo",""),
                                "script":    d.get("script",{}),
                            }
                            print(f"    porta {p}: {d.get('name','')} "
                                  f"{d.get('product','')} {d.get('version','')}")
        except Exception as e:
            print(f"    [!] port scan: {e}")
        return svcs

    # ── dispatcher ──
    def _dispatch(self, host, port, svc):
        name    = svc.get("name","").lower()
        product = svc.get("product","").lower()

        if port in [80,443,8080,8443] or "http" in name:
            self._http(host, port, svc)
        if port == 1880 or "node" in product:
            self._nodered(host, port)
        if port in [1883,8883] or "mqtt" in name or "mosquitto" in product:
            self._mqtt(host, port)
        if port == 445 or "microsoft-ds" in name or "smb" in name:
            self._smb(host, port, svc)
        if port in [3306,3307] or "mysql" in name or "mariadb" in product:
            self._mysql(host, port, svc)
        if port == 22 or "ssh" in name:
            self._ssh(host, port, svc)
        if port == 3389 or "rdp" in name or "ms-wbt" in name:
            self._rdp(host, port)
        self._eol_check(host, port, svc)

    # ── HTTP tests ──
    def _http(self, host, port, svc):
        proto = "https" if port in [443,8443] else "http"
        base  = f"{proto}://{host}:{port}"
        try:
            r = requests.get(base, timeout=6, verify=False, allow_redirects=True)
        except Exception:
            return

        # missing security headers
        sec_hdrs = ["X-Content-Type-Options","X-Frame-Options",
                    "Content-Security-Policy","Strict-Transport-Security"]
        missing  = [h for h in sec_hdrs if h not in r.headers]
        if missing:
            self.add(host=host, service="HTTP", port=port,
                     title="Headers de Segurança Ausentes",
                     description=("A aplicação não implementa headers de segurança HTTP "
                                  "recomendados, deixando usuários expostos a ataques como "
                                  "clickjacking e XSS."),
                     severity="MÉDIO", cvss=5.3,
                     evidence=f"Ausentes: {', '.join(missing)}")

        # server version disclosure
        srv = r.headers.get("Server","")
        if srv and any(x in srv.lower() for x in ["apache/","nginx/","iis/","express"]):
            self.add(host=host, service="HTTP", port=port,
                     title="Divulgação de Versão do Servidor Web",
                     description="O header Server revela versão exata, facilitando ataques direcionados.",
                     severity="BAIXO", cvss=3.1, evidence=f"Server: {srv}")

        # sensitive paths
        paths = [("/admin","Painel admin"),("/api","API"),("/.env","Arquivo .env"),
                 ("/config","Config"),("/backup","Backup"),("/debug","Debug"),
                 ("/phpinfo.php","PHP Info"),("/api/v1","API v1"),
                 ("/api/collaborators","Endpoint colaboradores"),
                 ("/api/session","Endpoint sessão")]
        for path, desc in paths:
            try:
                pr = requests.get(f"{base}{path}", timeout=4, verify=False)
                if pr.status_code not in [404,503,502]:
                    sev  = "ALTO"  if pr.status_code == 200 else "MÉDIO"
                    cvss = 7.5     if pr.status_code == 200 else 5.0
                    self.add(host=host, service="HTTP", port=port,
                             title=f"Endpoint Sensível Exposto: {path}",
                             description=f"{desc} acessível sem autenticação adequada.",
                             severity=sev, cvss=cvss,
                             evidence=f"GET {path} → HTTP {pr.status_code}")
            except:
                pass

        # SQLi fingerprint
        for path in ["/api/collaborators?name='", "/api/users?id=1'", "/search?q='"]:
            try:
                sr = requests.get(f"{base}{path}", timeout=4, verify=False)
                body = sr.text.lower()
                if any(e in body for e in ["sql","mysql","syntax error","ora-","pg_","sqlite","warning: pg_"]):
                    self.add(host=host, service="HTTP", port=port,
                             title="SQL Injection Detectado",
                             description=("Endpoint retorna erros SQL ao receber entrada malformada. "
                                          "Pode permitir extração completa do banco de dados."),
                             severity="CRÍTICO", cvss=9.8,
                             evidence=f"GET {path} → erro SQL na resposta")
                    break
            except:
                pass

        # broken auth — base64 token
        try:
            import base64
            token = base64.b64encode(b"admin:admin:homologacao").decode()
            tr = requests.get(f"{base}/admin",
                              headers={"x-auth-token": token}, timeout=4, verify=False)
            if tr.status_code == 200:
                self.add(host=host, service="HTTP", port=port,
                         title="Broken Authentication — Token Base64 Forjável",
                         description=("O token de sessão é simplesmente Base64 de usuario:role:contexto "
                                      "sem assinatura criptográfica. Qualquer usuário pode forjar um token "
                                      "de administrador sem conhecer a senha."),
                         severity="CRÍTICO", cvss=9.1,
                         evidence=f"Token forjado aceito em /admin (HTTP 200)")
        except:
            pass

    # ── Node-RED tests ──
    def _nodered(self, host, port):
        base = f"http://{host}:{port}"

        # /settings
        try:
            r = requests.get(f"{base}/settings", timeout=5)
            if r.status_code == 200:
                d    = r.json()
                ver  = d.get("version","?")
                fext = d.get("functionExternalModules", False)
                self.add(host=host, service="Node-RED", port=port,
                         title="Node-RED Sem Autenticação",
                         description=(f"A interface administrativa do Node-RED v{ver} está acessível "
                                      "sem credenciais. Qualquer usuário na rede pode visualizar e "
                                      "modificar fluxos de automação industrial (OT)."),
                         severity="CRÍTICO", cvss=9.8,
                         evidence=f"GET /settings → 200 | versão {ver} | funcExtModules: {fext}")
                if fext:
                    self.add(host=host, service="Node-RED", port=port,
                             title="RCE Potencial — functionExternalModules Ativo",
                             description=("A flag functionExternalModules:true permite que funções JS "
                                          "carreguem child_process e executem comandos no SO do servidor."),
                             severity="CRÍTICO", cvss=9.1,
                             evidence="\"functionExternalModules\": true")
        except:
            pass

        # /flows
        try:
            r = requests.get(f"{base}/flows", timeout=5)
            if r.status_code == 200:
                flows = r.json()
                fc    = len(flows)
                txt   = json.dumps(flows)
                self.add(host=host, service="Node-RED", port=port,
                         title="Código-Fonte de Automação Industrial Exposto",
                         description=(f"{fc} nós de automação acessíveis sem autenticação. "
                                      "Expõe lógica de negócio, tópicos MQTT e possíveis credenciais."),
                         severity="CRÍTICO", cvss=8.6,
                         evidence=f"GET /flows → 200 | {fc} nós")
                if "fuel-pump" in txt.lower() or "pump" in txt.lower():
                    self.add(host=host, service="Node-RED", port=port,
                             title="Sistema SCADA/OT de Bombas de Combustível Exposto",
                             description=("Flows expõem sistema de monitoramento e controle de bombas "
                                          "industriais via MQTT. Atacante pode injetar telemetria falsa "
                                          "e manipular ordens de reabastecimento."),
                             severity="CRÍTICO", cvss=9.5,
                             evidence="Tópicos: fuel-pumps/data, fuel-pumps/refill-request")
        except:
            pass

    # ── MQTT tests ──
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
            except:
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
            except: pass

            if connected[0]:
                ev = f"Conexão anônima aceita na porta {port}/tcp (sem TLS)"
                if messages:
                    ev += f" | Mensagens capturadas: {messages[:2]}"
                self.add(host=host, service="MQTT", port=port,
                         title="Broker MQTT Sem Autenticação e Sem TLS",
                         description=("O broker MQTT aceita conexões anônimas e transmite dados em "
                                      "texto claro. Qualquer dispositivo pode publicar ou assinar "
                                      "qualquer tópico, incluindo comandos de controle industrial."),
                         severity="CRÍTICO", cvss=9.3, evidence=ev)
        except:
            pass

    # ── SMB tests ──
    def _smb(self, host, port, svc):
        # nmap signing check
        try:
            r = subprocess.run(
                ["nmap","-p",str(port),"--script",
                 "smb-security-mode,smb2-security-mode", host,"-oN","-"],
                capture_output=True, text=True, timeout=30)
            out = r.stdout.lower()
            if "message_signing: disabled" in out or "signing: false" in out or "not required" in out:
                self.add(host=host, service="SMB", port=port,
                         title="SMB Signing Desabilitado — NTLM Relay Viável",
                         description=("Sem assinatura de pacotes SMB, ataques de NTLM Relay são viáveis. "
                                      "Um atacante pode interceptar credenciais NTLM e reutilizá-las para "
                                      "autenticar em outros servidores sem conhecer a senha. "
                                      "Em ambientes AD isso pode levar ao comprometimento total do domínio."),
                         severity="CRÍTICO", cvss=9.0,
                         evidence="nmap smb-security-mode: message_signing disabled/not required")
        except:
            pass

        # EternalBlue
        try:
            r2 = subprocess.run(
                ["nmap","-p",str(port),"--script","smb-vuln-ms17-010",host,"-oN","-"],
                capture_output=True, text=True, timeout=30)
            if "VULNERABLE" in r2.stdout:
                self.add(host=host, service="SMB", port=port,
                         title="EternalBlue MS17-010 — VULNERÁVEL",
                         description=("Sistema vulnerável ao exploit usado pelo ransomware WannaCry. "
                                      "Permite execução remota de código sem autenticação."),
                         severity="CRÍTICO", cvss=9.8,
                         evidence="nmap smb-vuln-ms17-010: VULNERABLE")
        except:
            pass

        # null session
        try:
            r3 = subprocess.run(
                ["smbclient","-L",f"//{host}","-N","--no-pass"],
                capture_output=True, text=True, timeout=10)
            if "Sharename" in r3.stdout or "Disk" in r3.stdout:
                self.add(host=host, service="SMB", port=port,
                         title="SMB Null Session Aceita",
                         description=("Conexões SMB sem credenciais são aceitas, permitindo enumeração "
                                      "de compartilhamentos, usuários e grupos do domínio."),
                         severity="ALTO", cvss=7.5,
                         evidence=f"smbclient -L //{host} -N → lista de shares")
        except:
            pass

    # ── MySQL tests ──
    def _mysql(self, host, port, svc):
        version = svc.get("version","")
        eol_map = {"5.0":"2012","5.1":"2013","5.5":"2018","5.6":"2021","5.7":"2023"}
        for v, year in eol_map.items():
            if version.startswith(v):
                self.add(host=host, service="MySQL", port=port,
                         title=f"MySQL {version} — Versão EOL (sem patches desde {year})",
                         description=(f"MySQL {version} atingiu End-of-Life em {year} e não recebe mais "
                                      "correções de segurança. Múltiplas CVEs críticas sem patch disponível."),
                         severity="CRÍTICO", cvss=9.8,
                         evidence=f"Versão: MySQL {version} (EOL desde {year})")
                break

        # non-standard port
        if port not in [3306]:
            self.add(host=host, service="MySQL", port=port,
                     title=f"MySQL em Porta Não Padrão ({port})",
                     description=("Uso de porta não padrão pode indicar tentativa de ofuscação. "
                                  "Não é uma medida de segurança efetiva."),
                     severity="BAIXO", cvss=2.0,
                     evidence=f"MySQL respondendo em {port}/tcp")

    # ── SSH tests ──
    def _ssh(self, host, port, svc):
        version = svc.get("version","")
        product = svc.get("product","OpenSSH")
        scripts = svc.get("script",{})
        auth    = scripts.get("ssh-auth-methods","")

        if auth and "password" in auth.lower():
            self.add(host=host, service="SSH", port=port,
                     title="SSH Aceita Autenticação por Senha",
                     description=("Autenticação por senha habilitada torna o serviço suscetível "
                                  "a ataques de força bruta e credential stuffing."),
                     severity="MÉDIO", cvss=5.3,
                     evidence=f"ssh-auth-methods: {auth}")

    # ── RDP tests ──
    def _rdp(self, host, port):
        self.add(host=host, service="RDP", port=port,
                 title="RDP Exposto na Rede",
                 description=("Remote Desktop Protocol acessível é vetor comum de ransomware. "
                               "Recomenda-se restringir por VPN ou limitar acesso por IP."),
                 severity="ALTO", cvss=7.0,
                 evidence=f"Porta {port}/tcp aberta")

    # ── EOL check ──
    def _eol_check(self, host, port, svc):
        product = (svc.get("product","") + " " + svc.get("version","")).lower()
        eol_db  = [
            ("windows xp",        "CRÍTICO", 10.0),
            ("windows server 2003","CRÍTICO",10.0),
            ("windows server 2008","ALTO",    8.0),
            ("windows 7",          "ALTO",    8.0),
            ("apache 2.2",         "ALTO",    7.5),
            ("php 5.",             "ALTO",    7.5),
        ]
        for signature, sev, cvss in eol_db:
            if signature in product:
                self.add(host=host, service=svc.get("name","?").upper(), port=port,
                         title=f"Software EOL: {svc.get('product','')} {svc.get('version','')}",
                         description=("Software sem suporte de segurança ativo. "
                                      "Não recebe patches de segurança."),
                         severity=sev, cvss=cvss,
                         evidence=f"Produto: {svc.get('product','')} {svc.get('version','')}")
                break


# ─── AI analyzer ─────────────────────────────────────────────────────────────
def ai_analyze(findings, api_key):
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
            "Analise os achados abaixo e responda SOMENTE em JSON válido.\n\n"
            f"ACHADOS:\n{summary}\n\n"
            "Estrutura esperada:\n"
            "{\n"
            '  "summary": "Resumo executivo de 3-4 frases",\n'
            '  "risk_score": 0-100,\n'
            '  "disclaimer": "Aviso sobre limitações da IA",\n'
            '  "findings": {\n'
            '    "0": {"analysis": "2-3 frases técnicas", "recommendation": "ação recomendada"},\n'
            '    "1": {"analysis": "...", "recommendation": "..."}\n'
            "  }\n"
            "}\n\n"
            "Para recomendações:\n"
            "- CRÍTICO/ALTO: reforce que é grave, exige especialista imediatamente.\n"
            "- MÉDIO: ação pode ser feita pela TI, mas valide com especialista.\n"
            "- BAIXO: solução simples descrita, ainda assim recomende revisão profissional.\n"
            "Sempre inclua no disclaimer que você é IA, pode errar, e que um humano deve revisar."
        )
        r = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role":"user","content":prompt}],
            max_tokens=4096, temperature=0.3
        )
        txt   = r.choices[0].message.content
        match = re.search(r"\{.*\}", txt, re.DOTALL)
        if match:
            return json.loads(match.group())
    except Exception as e:
        print(f"  [!] Groq: {e}")
    return {}


# ─── TXT report ──────────────────────────────────────────────────────────────
def gen_txt(findings, target, scan_time, ai_data):
    lines = ["=" * 62,
             "  CYMAG AutoScanner — Relatório de Segurança",
             "=" * 62,
             f"  Alvo   : {target}",
             f"  Data   : {scan_time.strftime('%d/%m/%Y %H:%M')}",
             f"  Achados: {len(findings)}",
             ""]
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity,0) + 1
    lines.append("  RESUMO:")
    for s in ["CRÍTICO","ALTO","MÉDIO","BAIXO","INFO"]:
        if s in counts:
            lines.append(f"    {s}: {counts[s]}")
    if ai_data.get("risk_score"):
        lines.append(f"    Score de Risco: {ai_data['risk_score']}/100")
    if ai_data.get("summary"):
        lines += ["", "  ANÁLISE (IA):", f"  {ai_data['summary']}"]
    lines += ["", "-" * 62]
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.severity,0), reverse=True):
        lines += [f"", f"  [{f.severity}] {f.title}",
                  f"  Host: {f.host}:{f.port} | {f.service} | CVSS {f.cvss}",
                  f"  {f.description}"]
        if f.evidence:
            lines.append(f"  Evidência: {f.evidence[:120]}")
        if f.ai_recommendation:
            lines.append(f"  Recomendação: {f.ai_recommendation}")
    lines += ["", "=" * 62,
              "  AVISO: Relatório gerado automaticamente. Consulte um",
              "  especialista em segurança antes de tomar decisões.",
              "=" * 62]
    return "\n".join(lines)


# ─── PDF report ──────────────────────────────────────────────────────────────
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

    TITLE  = ps("t", parent=SS["Title"], fontSize=20, textColor=DARK, alignment=TA_CENTER)
    H2     = ps("h2", parent=SS["Heading2"], fontSize=13, textColor=BLUE, spaceBefore=10)
    BODY   = ps("b", fontSize=9.5, leading=14, alignment=TA_JUSTIFY)
    SMALL  = ps("s", fontSize=8, textColor=colors.grey, leading=12)
    SEV_C  = {k: colors.HexColor(v) for k,v in SEVERITY_HEX.items()}

    story = [Spacer(1,.8*cm),
             Paragraph("CYMAG AutoScanner", TITLE),
             Paragraph("Relatório de Diagnóstico de Segurança",
                       ps("sub", fontSize=12, textColor=colors.grey, alignment=TA_CENTER)),
             Spacer(1,.3*cm),
             HRFlowable(width="100%", thickness=1, color=BLUE),
             Spacer(1,.3*cm)]

    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity,0)+1

    meta = [["Alvo", target],
            ["Data/Hora", scan_time.strftime("%d/%m/%Y %H:%M:%S")],
            ["Total de Achados", str(len(findings))]]
    for s in ["CRÍTICO","ALTO","MÉDIO","BAIXO"]:
        if s in counts:
            meta.append([s, str(counts[s])])

    mt = Table(meta, colWidths=[4*cm, 12.5*cm])
    mt.setStyle(TableStyle([
        ("FONTNAME",(0,0),(-1,-1),"Helvetica"),
        ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),
        ("FONTSIZE",(0,0),(-1,-1),9),
        ("ROWBACKGROUNDS",(0,0),(-1,-1),[colors.white, colors.HexColor("#f5f5f5")]),
        ("GRID",(0,0),(-1,-1),.3,colors.HexColor("#ddd")),
        ("TOPPADDING",(0,0),(-1,-1),4),
        ("BOTTOMPADDING",(0,0),(-1,-1),4),
    ]))
    story.append(mt)
    story.append(Spacer(1,.4*cm))

    rs = ai_data.get("risk_score",0)
    if rs:
        rc = colors.HexColor("#c0392b") if rs>=70 else colors.HexColor("#e67e22") if rs>=40 else colors.HexColor("#27ae60")
        story.append(Paragraph(f"<b>Score de Risco: {rs}/100</b>",
                               ps("rk", fontSize=13, textColor=rc, alignment=TA_CENTER)))
        story.append(Spacer(1,.3*cm))

    if ai_data.get("summary"):
        story += [Paragraph("Análise Executiva (IA)", H2),
                  Paragraph(ai_data["summary"], BODY)]
        if ai_data.get("disclaimer"):
            story.append(Spacer(1,.15*cm))
            story.append(Paragraph(f"⚠ {ai_data['disclaimer']}", SMALL))
        story.append(Spacer(1,.4*cm))

    story += [Paragraph("Achados de Segurança", H2),
              HRFlowable(width="100%", thickness=.5, color=colors.HexColor("#ccc"))]

    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.severity,0), reverse=True):
        sc = SEV_C.get(f.severity, colors.grey)
        hdr = [[Paragraph(f"<b>[{f.severity}]</b>",
                           ps("sh",fontSize=9,textColor=colors.white)),
                Paragraph(f"<b>{f.title}</b>",
                           ps("st",fontSize=9.5,textColor=colors.white)),
                Paragraph(f"CVSS {f.cvss}",
                           ps("sc",fontSize=9,textColor=colors.white,alignment=TA_CENTER))]]
        ht = Table(hdr, colWidths=[2.5*cm,11*cm,3*cm])
        ht.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),sc),
                                ("TOPPADDING",(0,0),(-1,-1),5),
                                ("BOTTOMPADDING",(0,0),(-1,-1),5),
                                ("LEFTPADDING",(0,0),(-1,-1),6)]))
        story += [Spacer(1,.25*cm), ht]

        rows = [
            [Paragraph("<b>Host</b>", SMALL), Paragraph(f"{f.host}:{f.port} — {f.service}", BODY)],
            [Paragraph("<b>Descrição</b>", SMALL), Paragraph(f.description, BODY)],
        ]
        if f.evidence:
            rows.append([Paragraph("<b>Evidência</b>", SMALL),
                         Paragraph(f.evidence[:250], SMALL)])
        if f.ai_analysis:
            rows.append([Paragraph("<b>Análise IA</b>", SMALL),
                         Paragraph(f.ai_analysis, BODY)])
        if f.ai_recommendation:
            rows.append([Paragraph("<b>Recomendação</b>", SMALL),
                         Paragraph(f.ai_recommendation, BODY)])

        dt = Table(rows, colWidths=[3*cm,13.5*cm])
        dt.setStyle(TableStyle([
            ("FONTSIZE",(0,0),(-1,-1),9),
            ("ROWBACKGROUNDS",(0,0),(-1,-1),[colors.white, colors.HexColor("#fafafa")]),
            ("GRID",(0,0),(-1,-1),.2,colors.HexColor("#eee")),
            ("TOPPADDING",(0,0),(-1,-1),4),
            ("BOTTOMPADDING",(0,0),(-1,-1),4),
            ("LEFTPADDING",(0,0),(-1,-1),6),
            ("VALIGN",(0,0),(-1,-1),"TOP"),
        ]))
        story.append(dt)

    story += [Spacer(1,.8*cm),
              HRFlowable(width="100%", thickness=.5, color=colors.HexColor("#ccc")),
              Paragraph(
                  "AVISO LEGAL: Este relatório foi gerado automaticamente pela ferramenta "
                  "CYMAG AutoScanner e pela IA Groq (Llama). Os resultados podem conter "
                  "imprecisões ou falsos positivos. Recomenda-se revisão por profissional "
                  "especializado em segurança cibernética antes de qualquer decisão.", SMALL)]
    doc.build(story)
    return out


# ─── HTML report ─────────────────────────────────────────────────────────────
def gen_html(findings, target, scan_time, ai_data):
    out      = f"CYMAG_{target.replace('/','_')}_{scan_time.strftime('%Y%m%d_%H%M')}.html"
    total    = len(findings)
    counts   = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity,0)+1

    rs       = ai_data.get("risk_score",0)
    rc_cls   = "risk-critical" if rs>=70 else "risk-high" if rs>=40 else "risk-low"
    rc_lbl   = "CRÍTICO" if rs>=70 else "ALTO" if rs>=40 else "BAIXO"
    rc_color = "#c0392b" if rs>=70 else "#e67e22" if rs>=40 else "#27ae60"

    # ── donut SVG ──
    sev_order = ["CRÍTICO","ALTO","MÉDIO","BAIXO","INFO"]
    segs  = ""
    cum   = 0.0
    cx,cy,ro,ri = 60,60,52,30
    for sev in sev_order:
        cnt = counts.get(sev,0)
        if cnt == 0: continue
        pct = cnt/total if total else 0
        a0  = cum*360
        a1  = (cum+pct)*360
        cum += pct
        r0  = math.radians(a0-90)
        r1  = math.radians(a1-90)
        x1o = cx+ro*math.cos(r0); y1o = cy+ro*math.sin(r0)
        x2o = cx+ro*math.cos(r1); y2o = cy+ro*math.sin(r1)
        x1i = cx+ri*math.cos(r1); y1i = cy+ri*math.sin(r1)
        x2i = cx+ri*math.cos(r0); y2i = cy+ri*math.sin(r0)
        la  = 1 if (a1-a0)>180 else 0
        d   = (f"M {x1o:.1f} {y1o:.1f} A {ro} {ro} 0 {la} 1 {x2o:.1f} {y2o:.1f} "
               f"L {x1i:.1f} {y1i:.1f} A {ri} {ri} 0 {la} 0 {x2i:.1f} {y2i:.1f} Z")
        segs += f'<path d="{d}" fill="{SEVERITY_HEX.get(sev,"#999")}" title="{sev}:{cnt}"/>\n'

    # ── legend ──
    legend_html = ""
    for s in sev_order:
        c = counts.get(s,0)
        if c:
            sc = s.lower().replace("í","i").replace("é","e")
            legend_html += (f'<div class="leg-item">'
                            f'<span class="leg-dot sev-dot-{sc}"></span>'
                            f'{s}: <b>{c}</b></div>')

    # ── filter buttons ──
    filters = (f'<button class="fbtn active" data-f="ALL" onclick="doFilter(this)">'
               f'Todos <span class="cnt">{total}</span></button>')
    for s in sev_order:
        c = counts.get(s,0)
        if c:
            sc = s.lower().replace("í","i").replace("é","e")
            filters += (f'<button class="fbtn fbtn-{sc}" data-f="{s}" onclick="doFilter(this)">'
                        f'{s} <span class="cnt">{c}</span></button>')

    # ── finding cards ──
    cards = ""
    sorted_f = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.severity,0), reverse=True)
    ai_f     = ai_data.get("findings",{})
    for i,f in enumerate(sorted_f):
        # inject AI into finding
        fd = ai_f.get(str(i),{})
        f.ai_analysis       = fd.get("analysis","")
        f.ai_recommendation = fd.get("recommendation","")
        sc  = f.severity.lower().replace("í","i").replace("é","e")
        evh = (f'<div class="evidence"><code>{f.evidence[:400]}</code></div>'
               if f.evidence else "")
        aih = (f'<div class="ai-blk"><div class="ai-lbl">🤖 Análise IA</div>'
               f'<p>{f.ai_analysis}</p></div>'
               if f.ai_analysis else "")
        rch = (f'<div class="rec-blk"><div class="rec-lbl">💡 Recomendação</div>'
               f'<p>{f.ai_recommendation}</p></div>'
               if f.ai_recommendation else "")
        cards += f"""
<div class="card sev-{sc}" data-severity="{f.severity}" id="card-{i}">
  <div class="card-hdr" onclick="toggle(this)">
    <div class="row1">
      <span class="badge bdg-{sc}">{f.severity}</span>
      <span class="card-title">{f.title}</span>
      <span class="cvss">CVSS&nbsp;{f.cvss}</span>
    </div>
    <div class="row2">
      <span>🖥 {f.host}:{f.port}</span>&nbsp;&nbsp;
      <span>⚙ {f.service}</span>
    </div>
    <span class="chev">▼</span>
  </div>
  <div class="card-body">
    <p class="desc">{f.description}</p>
    {evh}{aih}{rch}
    <label class="chk">
      <input type="checkbox" onchange="markDone(this,'card-{i}')">
      Marcar como revisado
    </label>
  </div>
</div>"""

    summary_html = f"<p>{ai_data.get('summary','Análise de IA não disponível.')}</p>"
    disclaimer   = ai_data.get("disclaimer",
                                "Esta análise foi gerada por IA e pode conter imprecisões. "
                                "Consulte sempre um especialista em segurança cibernética.")

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CYMAG Scanner — {target}</title>
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',Arial,sans-serif;background:#f0f2f5;color:#222;font-size:14px}}
/* header */
.hdr{{background:#1a1a2e;color:#fff;padding:18px 32px;display:flex;justify-content:space-between;align-items:center}}
.hdr h1{{font-size:20px;font-weight:700;letter-spacing:1px}}
.hdr .meta{{font-size:11px;color:#aaa;text-align:right;line-height:2}}
/* container */
.wrap{{max-width:1080px;margin:0 auto;padding:22px 14px}}
/* dashboard */
.dash{{display:grid;grid-template-columns:160px 1fr;gap:14px;margin-bottom:20px}}
@media(max-width:600px){{.dash{{grid-template-columns:1fr}}}}
.stat-card{{background:#fff;border-radius:8px;padding:18px;box-shadow:0 1px 4px rgba(0,0,0,.07);border-left:4px solid {rc_color};text-align:center}}
.stat-lbl{{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#777;margin-bottom:6px}}
.stat-val{{font-size:42px;font-weight:700;color:{rc_color}}}
.stat-sub{{font-size:11px;color:#888;margin-top:3px}}
.chart-card{{background:#fff;border-radius:8px;padding:18px;box-shadow:0 1px 4px rgba(0,0,0,.07);display:flex;align-items:center;gap:24px}}
.leg-item{{display:flex;align-items:center;gap:7px;font-size:12px;margin-bottom:6px}}
.leg-dot{{display:inline-block;width:11px;height:11px;border-radius:50%}}
/* severity dot colors */
.sev-dot-critico{{background:#c0392b}}.sev-dot-alto{{background:#e67e22}}
.sev-dot-medio{{background:#f39c12}}.sev-dot-baixo{{background:#27ae60}}
.sev-dot-info{{background:#95a5a6}}
/* summary */
.sum-box{{background:#fff;border-radius:8px;padding:18px;margin-bottom:20px;
         box-shadow:0 1px 4px rgba(0,0,0,.07);border-left:4px solid #0f3460}}
.sum-box h2{{font-size:14px;color:#0f3460;margin-bottom:8px}}
.sum-box p{{line-height:1.7;color:#444}}
.disc{{background:#fff8e1;border-left:3px solid #f39c12;padding:9px 13px;
       margin-top:10px;font-size:11px;color:#666;border-radius:0 4px 4px 0}}
/* filters */
.filters{{display:flex;flex-wrap:wrap;gap:7px;margin-bottom:14px;align-items:center}}
.flbl{{font-size:11px;color:#666;font-weight:700}}
.fbtn{{border:none;padding:5px 13px;border-radius:20px;cursor:pointer;font-size:11px;
       font-weight:600;background:#ddd;color:#333;transition:opacity .2s}}
.fbtn.active{{outline:2px solid #333}}
.fbtn:hover{{opacity:.8}}
.fbtn-critico{{background:#c0392b;color:#fff}}
.fbtn-alto{{background:#e67e22;color:#fff}}
.fbtn-medio{{background:#f39c12;color:#fff}}
.fbtn-baixo{{background:#27ae60;color:#fff}}
.fbtn-info{{background:#95a5a6;color:#fff}}
/* cards */
.sec-title{{font-size:15px;font-weight:700;margin-bottom:10px}}
.card{{background:#fff;border-radius:8px;margin-bottom:9px;
      box-shadow:0 1px 3px rgba(0,0,0,.06);border-left:4px solid #ccc;transition:box-shadow .2s}}
.card:hover{{box-shadow:0 3px 10px rgba(0,0,0,.11)}}
.sev-critico{{border-left-color:#c0392b}}.sev-alto{{border-left-color:#e67e22}}
.sev-medio{{border-left-color:#f39c12}}.sev-baixo{{border-left-color:#27ae60}}
.sev-info{{border-left-color:#95a5a6}}.card.done{{opacity:.5;filter:grayscale(60%)}}
.card-hdr{{padding:13px 14px;cursor:pointer;position:relative;user-select:none}}
.row1{{display:flex;align-items:center;gap:9px;flex-wrap:wrap}}
.badge{{display:inline-block;padding:2px 7px;border-radius:4px;
        font-size:10px;font-weight:700;letter-spacing:.4px;flex-shrink:0}}
.bdg-critico{{background:#c0392b;color:#fff}}.bdg-alto{{background:#e67e22;color:#fff}}
.bdg-medio{{background:#f39c12;color:#fff}}.bdg-baixo{{background:#27ae60;color:#fff}}
.bdg-info{{background:#95a5a6;color:#fff}}
.card-title{{font-weight:600;font-size:13.5px;flex:1}}
.cvss{{font-size:11px;color:#888;flex-shrink:0}}
.row2{{margin-top:5px;font-size:11px;color:#888}}
.chev{{position:absolute;right:14px;top:14px;font-size:11px;color:#aaa;transition:transform .2s}}
.chev.open{{transform:rotate(180deg)}}
.card-body{{display:none;padding:0 14px 14px;border-top:1px solid #f0f0f0}}
.desc{{color:#444;line-height:1.65;margin-top:11px}}
.evidence{{background:#1e1e1e;border-radius:4px;padding:9px 11px;margin:9px 0;overflow-x:auto}}
.evidence code{{color:#d4d4d4;font-size:11px;font-family:Consolas,monospace;white-space:pre-wrap;word-break:break-all}}
.ai-blk{{background:#f0f4ff;border-left:3px solid #3498db;padding:9px 13px;margin:9px 0;border-radius:0 4px 4px 0}}
.ai-lbl{{font-size:10px;font-weight:700;color:#2980b9;margin-bottom:4px}}
.ai-blk p{{color:#333;line-height:1.6;font-size:13px}}
.rec-blk{{background:#f0fff4;border-left:3px solid #27ae60;padding:9px 13px;margin:9px 0;border-radius:0 4px 4px 0}}
.rec-lbl{{font-size:10px;font-weight:700;color:#1e8449;margin-bottom:4px}}
.rec-blk p{{color:#333;line-height:1.6;font-size:13px}}
.chk{{display:flex;align-items:center;gap:7px;margin-top:10px;font-size:12px;color:#666;cursor:pointer}}
/* footer */
.ftr{{background:#1a1a2e;color:#666;text-align:center;padding:14px;
     font-size:11px;margin-top:28px}}
/* print */
@media print{{
  .filters,.fbtn{{display:none}}
  .card-body{{display:block!important}}
  body{{background:#fff}}
}}
</style>
</head>
<body>
<div class="hdr">
  <div>
    <h1>🔍 CYMAG AutoScanner</h1>
    <div style="font-size:12px;color:#aaa;margin-top:3px">Relatório de Diagnóstico de Segurança</div>
  </div>
  <div class="meta">
    Alvo: <b style="color:#fff">{target}</b><br>
    {scan_time.strftime("%d/%m/%Y %H:%M")}<br>
    {total} achados
  </div>
</div>

<div class="wrap">

  <div class="dash">
    <div class="stat-card">
      <div class="stat-lbl">Score de Risco</div>
      <div class="stat-val">{rs}</div>
      <div class="stat-sub">{rc_lbl}</div>
    </div>
    <div class="chart-card">
      <svg viewBox="0 0 120 120" width="115" height="115" style="flex-shrink:0">
        {segs if segs else '<circle cx="60" cy="60" r="52" fill="#eee"/>'}
        <text x="60" y="64" text-anchor="middle" font-size="15" font-weight="bold" fill="#333">{total}</text>
        <text x="60" y="76" text-anchor="middle" font-size="8" fill="#999">achados</text>
      </svg>
      <div>{legend_html}</div>
    </div>
  </div>

  <div class="sum-box">
    <h2>🤖 Análise Executiva — Inteligência Artificial</h2>
    {summary_html}
    <div class="disc">⚠ <b>Aviso:</b> {disclaimer}</div>
  </div>

  <div class="sec-title">Achados de Segurança</div>
  <div class="filters">
    <span class="flbl">Filtrar:</span>
    {filters}
  </div>
  <div id="findings">
    {cards}
  </div>

</div>

<div class="ftr">
  CYMAG AutoScanner v1.0 &nbsp;|&nbsp; SENAI / Faculdade de Tecnologia Paulo Antonio Skaf
  &nbsp;|&nbsp; Projeto Integrador Interdisciplinar I<br>
  Relatório gerado automaticamente. Sempre consulte um especialista em segurança cibernética.
</div>

<script>
function doFilter(btn){{
  document.querySelectorAll('.fbtn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  const f=btn.dataset.f;
  document.querySelectorAll('.card').forEach(c=>{{
    c.style.display=(f==='ALL'||c.dataset.severity===f)?'':'none';
  }});
}}
function toggle(hdr){{
  const body=hdr.nextElementSibling;
  const chev=hdr.querySelector('.chev');
  const open=body.style.display==='block';
  body.style.display=open?'none':'block';
  chev.classList.toggle('open',!open);
}}
function markDone(cb,id){{
  const c=document.getElementById(id);
  c.classList.toggle('done',cb.checked);
  localStorage.setItem(id,cb.checked?'1':'');
}}
window.addEventListener('DOMContentLoaded',()=>{{
  // restore checkboxes
  document.querySelectorAll('.card').forEach(c=>{{
    if(localStorage.getItem(c.id)==='1'){{
      c.classList.add('done');
      const cb=c.querySelector('input[type=checkbox]');
      if(cb)cb.checked=true;
    }}
  }});
  // auto-expand critical
  document.querySelectorAll('.sev-critico').forEach(c=>{{
    const b=c.querySelector('.card-body');
    const ch=c.querySelector('.chev');
    if(b)b.style.display='block';
    if(ch)ch.classList.add('open');
  }});
}});
</script>
</body>
</html>"""

    with open(out,"w",encoding="utf-8") as fh:
        fh.write(html)
    return out


# ─── main ─────────────────────────────────────────────────────────────────────
def main():
    print(BANNER)

    # target
    target = sys.argv[1] if len(sys.argv)>=2 else input("\nAlvo (IP ou CIDR, ex: 192.168.1.0/24): ").strip()
    if not target:
        print("[ERRO] Alvo obrigatório."); sys.exit(1)

    # api key
    api_key = os.environ.get("GROQ_API_KEY","")
    if not api_key:
        api_key = input("Groq API Key (Enter para pular IA): ").strip()

    # format
    print("\nFormato do relatório:")
    print("  0  TXT  — resumo rápido (sem IA)")
    print("  1  PDF  — relatório completo com análise IA")
    print("  2  HTML — dashboard interativo com IA (filtros, checklist, gráfico)")
    while True:
        try:
            fmt = int(input("Escolha (0/1/2): ").strip())
            if fmt in [0,1,2]: break
        except: pass
        print("  Digite 0, 1 ou 2.")

    print()

    # scan
    scanner  = CYMAGScanner(target)
    findings = scanner.run()

    print(f"\n[3/4] {len(findings)} achado(s) encontrado(s).")

    # ai
    ai_data = {}
    if api_key and fmt in [1,2]:
        print("       Analisando com IA (Groq/Llama)...")
        sorted_f = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.severity,0), reverse=True)
        ai_data  = ai_analyze(sorted_f, api_key)
        af       = ai_data.get("findings",{})
        for i,f in enumerate(sorted_f):
            fd = af.get(str(i),{})
            f.ai_analysis       = fd.get("analysis","")
            f.ai_recommendation = fd.get("recommendation","")

    # report
    print("[4/4] Gerando relatório...")
    st = scanner.scan_time
    if fmt==0:
        content = gen_txt(findings, target, st, ai_data)
        out = f"CYMAG_{target.replace('/','_')}_{st.strftime('%Y%m%d_%H%M')}.txt"
        Path(out).write_text(content, encoding="utf-8")
    elif fmt==1:
        out = gen_pdf(findings, target, st, ai_data)
    else:
        out = gen_html(findings, target, st, ai_data)

    # summary
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity,0)+1

    print(f"\n{'='*52}")
    print(f"  ✅  Relatório: {out}")
    print(f"{'='*52}")
    for s in ["CRÍTICO","ALTO","MÉDIO","BAIXO","INFO"]:
        if s in counts:
            print(f"  {SEVERITY_ICON[s]}  {s}: {counts[s]}")
    if ai_data.get("risk_score"):
        print(f"  📊  Score de Risco: {ai_data['risk_score']}/100")
    if fmt==2:
        print(f"\n  🌐  firefox {out}")
    print(f"{'='*52}\n")


if __name__ == "__main__":
    main()
