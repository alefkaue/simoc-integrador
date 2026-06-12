#!/usr/bin/env python3
import os
import sys
import json
import subprocess
import threading
import webbrowser
import time
from flask import Flask, render_template_string, send_file
from groq import Groq
from weasyprint import HTML

# =====================================================================
# 1. ENCAPSULAMENTO DE FRONT-END (HTML, CSS e JS embutidos)
# =====================================================================

# ---> HTML DO DASHBOARD SAAS (Renderizado pelo Flask) <---
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>CYMAG — Cybersecurity Intelligence</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<script>
  tailwind.config = {
    theme: {
      extend: {
        fontFamily: { sans: ['Inter', 'system-ui', 'sans-serif'] },
        colors: {
          ink:        '#0B1220',
          panel:      '#111A2E',
          panel2:     '#162038',
          line:       '#1F2A44',
          mute:       '#8A95AD',
          soft:       '#C9D1E2',
          brand:      '#3B82F6',
          ok:         '#10B981',
          warn:       '#F59E0B',
          bad:        '#EF4444',
          crit:       '#B91C1C',
        }
      }
    }
  }
</script>
<style>
  body { font-family: 'Inter', sans-serif; background: #0B1220; color: #E5EAF3; }
  .card { background: #111A2E; border: 1px solid #1F2A44; border-radius: 14px; }
  .hover-row:hover { background: rgba(59,130,246,0.04); }
  .mitigated td { text-decoration: line-through; color: #6B7385 !important; }
  .switch { position: relative; width: 42px; height: 24px; background:#1F2A44; border-radius: 999px; cursor: pointer; transition: background .2s; }
  .switch::after { content:''; position:absolute; top:3px; left:3px; width:18px; height:18px; background:#fff; border-radius:50%; transition: transform .2s; }
  .switch.on { background:#3B82F6; }
  .switch.on::after { transform: translateX(18px); }
  .pill { display:inline-flex; align-items:center; gap:6px; padding: 3px 10px; border-radius: 999px; font-size: 11px; font-weight: 600; letter-spacing: .02em; }
  .pill .dot { width:6px; height:6px; border-radius:50%; }
  .pill-crit { background: rgba(185,28,28,.12); color:#FCA5A5; } .pill-crit .dot { background:#EF4444; }
  .pill-high { background: rgba(245,158,11,.10); color:#FCD34D; } .pill-high .dot { background:#F59E0B; }
  .pill-med  { background: rgba(59,130,246,.10); color:#93C5FD; } .pill-med .dot { background:#3B82F6; }
  .pill-low  { background: rgba(16,185,129,.10); color:#6EE7B7; } .pill-low .dot { background:#10B981; }
  .nav-item { display:flex; align-items:center; gap:10px; padding:10px 12px; border-radius:10px; color:#8A95AD; cursor:pointer; font-size:14px; font-weight:500; }
  .nav-item:hover, .nav-item.active { background:#162038; color:#fff; }
  .nav-item.active { box-shadow: inset 2px 0 0 #3B82F6; }
  .kpi-num { font-variant-numeric: tabular-nums; }
</style>
</head>
<body class="min-h-screen">

<!-- TELA DE LOGIN -->
<section id="login-screen" class="min-h-screen flex items-center justify-center px-6">
  <div class="w-full max-w-md card p-10">
    <div class="flex items-center gap-3 mb-8">
      <div class="w-10 h-10 rounded-lg bg-brand/10 border border-brand/30 flex items-center justify-center">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#3B82F6" stroke-width="2"><path d="M12 2 L4 6 v6 c0 5 3.5 8.5 8 10 c4.5-1.5 8-5 8-10 V6 z"/></svg>
      </div>
      <div>
        <div class="text-lg font-bold tracking-tight">CYMAG</div>
        <div class="text-xs text-mute">Cyber Risk Intelligence Platform</div>
      </div>
    </div>
    <h1 class="text-2xl font-semibold mb-2">Acesso ao Sistema</h1>
    <p class="text-sm text-mute mb-8">Varredura concluída! Selecione o perfil de acesso.</p>
    <div class="space-y-3">
      <button onclick="enterApp('cyber')" class="w-full bg-brand hover:bg-blue-600 transition text-white font-semibold py-3 rounded-lg flex items-center justify-between px-4">
        <span>Entrar como Analista Cyber</span><span class="text-xs opacity-70">/cyber</span>
      </button>
      <button onclick="enterApp('exec')" class="w-full bg-panel2 hover:bg-line transition text-soft border border-line font-semibold py-3 rounded-lg flex items-center justify-between px-4">
        <span>Entrar como Executivo</span><span class="text-xs opacity-70">/board</span>
      </button>
    </div>
  </div>
</section>

<!-- APP SHELL -->
<section id="app-shell" class="hidden min-h-screen flex">
  <aside class="w-64 shrink-0 border-r border-line bg-panel flex flex-col">
    <div class="p-5 border-b border-line flex items-center gap-3">
      <div class="w-9 h-9 rounded-lg bg-brand/10 border border-brand/30 flex items-center justify-center">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#3B82F6" stroke-width="2"><path d="M12 2 L4 6 v6 c0 5 3.5 8.5 8 10 c4.5-1.5 8-5 8-10 V6 z"/></svg>
      </div>
      <div>
        <div class="text-sm font-bold">CYMAG</div><div class="text-[10px] text-mute uppercase tracking-wider">Security Suite</div>
      </div>
    </div>
    <nav class="p-3 space-y-1 flex-1">
      <div class="text-[10px] uppercase tracking-wider text-mute px-3 pt-2 pb-1">Painéis</div>
      <div class="nav-item active" id="nav-cyber" onclick="switchView('cyber')">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 6h16M4 12h16M4 18h10"/></svg> Visão Cyber
      </div>
      <div class="nav-item" id="nav-exec" onclick="switchView('exec')">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 3v18h18"/><path d="M7 14l4-4 4 4 5-6"/></svg> Visão Executiva
      </div>
    </nav>
    <div class="p-3 border-t border-line">
      <div class="p-3 rounded-lg bg-panel2 border border-line">
        <div class="text-xs text-mute mb-1">Sessão Ativa</div>
        <div id="session-role" class="text-sm font-semibold mb-2">Analista</div>
        <button onclick="logout()" class="text-xs text-mute hover:text-soft underline">Encerrar sessão</button>
      </div>
    </div>
  </aside>

  <main class="flex-1 flex flex-col min-w-0">
    <header class="h-16 border-b border-line bg-panel/60 backdrop-blur flex items-center justify-between px-6 sticky top-0 z-20">
      <div>
        <div class="text-[11px] text-mute uppercase tracking-wider" id="crumb">Dashboard / Visão Cyber</div>
        <div class="text-sm font-semibold" id="view-title">Operações de Segurança</div>
      </div>
      <div class="flex items-center gap-3">
        <button onclick="exportPDF()" class="text-xs font-semibold px-4 py-2 rounded-lg bg-brand hover:bg-blue-600 text-white transition flex items-center gap-2">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3v12"/><path d="M7 10l5 5 5-5"/><path d="M5 21h14"/></svg> Exportar Relatório PDF
        </button>
      </div>
    </header>

    <!-- PAINEL CYBER -->
    <div id="view-cyber" class="p-6 space-y-6 overflow-auto">
      <div class="grid grid-cols-4 gap-4">
        <div class="card p-5"><div class="text-xs text-mute uppercase tracking-wider">Vulnerabilidades</div><div class="text-3xl font-bold mt-2 kpi-num" id="kpi-vuln">0</div></div>
        <div class="card p-5"><div class="text-xs text-mute uppercase tracking-wider">Críticas</div><div class="text-3xl font-bold mt-2 kpi-num text-bad" id="kpi-crit">0</div></div>
        <div class="card p-5"><div class="text-xs text-mute uppercase tracking-wider">Hosts Afetados</div><div class="text-3xl font-bold mt-2 kpi-num" id="kpi-hosts">0</div></div>
        <div class="card p-5"><div class="text-xs text-mute uppercase tracking-wider">Mitigadas</div><div class="text-3xl font-bold mt-2 kpi-num text-ok" id="kpi-mit">0</div></div>
      </div>
      <div class="card overflow-hidden">
        <div class="px-5 py-4 border-b border-line"><div class="text-sm font-semibold">Vulnerabilidades técnicas detectadas</div></div>
        <table class="w-full text-sm">
          <thead class="bg-panel2/50 text-mute text-xs uppercase tracking-wider">
            <tr><th class="text-left px-5 py-3 font-medium">Host</th><th class="text-left px-5 py-3 font-medium">CVSS</th><th class="text-left px-5 py-3 font-medium">CVE</th><th class="text-left px-5 py-3 font-medium">Descrição</th><th class="text-right px-5 py-3 font-medium">Ação</th></tr>
          </thead>
          <tbody id="cyber-tbody"></tbody>
        </table>
      </div>
    </div>

    <!-- PAINEL EXECUTIVO -->
    <div id="view-exec" class="p-6 space-y-6 overflow-auto hidden">
      <div class="grid grid-cols-3 gap-4">
        <div class="card p-6">
          <div class="text-xs text-mute uppercase tracking-wider">Risco Global</div>
          <div class="flex items-end gap-2 mt-2"><div class="text-4xl font-bold kpi-num text-bad" id="exec-risk">0</div><div class="text-sm text-mute pb-1">/ 100</div></div>
          <div class="mt-3 h-1.5 bg-panel2 rounded-full overflow-hidden"><div id="exec-risk-bar" class="h-full bg-brand transition-all duration-1000" style="width:0%"></div></div>
        </div>
      </div>
      <div class="grid grid-cols-3 gap-4">
        <div class="card p-5 col-span-1"><div class="text-sm font-semibold mb-1">Distribuição por Severidade</div><canvas id="chartSev" height="220"></canvas></div>
        <div class="card p-5 col-span-2"><div class="text-sm font-semibold mb-1">Evolução do Risco</div><canvas id="chartTrend" height="220"></canvas></div>
      </div>
      <div class="card p-4 flex items-center justify-between">
        <div><div class="text-sm font-semibold">Exibir Detalhes Técnicos</div></div>
        <div class="flex items-center gap-3"><span class="text-xs text-mute" id="tech-state">Desativado</span><div id="tech-switch" class="switch" onclick="toggleTech()"></div></div>
      </div>
      <div class="card overflow-hidden">
        <table class="w-full text-sm">
          <thead class="bg-panel2/50 text-mute text-xs uppercase tracking-wider">
            <tr><th class="text-left px-5 py-3 font-medium">Risco de Negócio</th><th class="text-left px-5 py-3 font-medium">Categoria</th><th class="text-left px-5 py-3 font-medium">Impacto Estimado</th><th class="text-left px-5 py-3 font-medium">Probabilidade</th><th class="text-left px-5 py-3 font-medium tech-col hidden">Detalhes Técnicos</th></tr>
          </thead>
          <tbody id="exec-tbody"></tbody>
        </table>
      </div>
    </div>
  </main>
</section>

<script>
// ==== INJEÇÃO DOS DADOS DO PYTHON DIRETAMENTE NO JAVASCRIPT ====
const VULNS_DATA = {{ cyber_vulns | tojson | safe }};
const EXEC_DATA = {{ exec_risks | tojson | safe }};
const RISK_SCORE = {{ risk_score | safe }};

let mitigatedCount = 0;
let chartSev, chartTrend;

window.onload = () => {
  renderCyberTable();
  renderExecTable();
  document.getElementById('kpi-vuln').textContent = VULNS_DATA.length;
  document.getElementById('kpi-crit').textContent = VULNS_DATA.filter(v => v.sev === 'crit').length;
  document.getElementById('kpi-hosts').textContent = new Set(VULNS_DATA.map(v => v.host.split(':')[0])).size;
  document.getElementById('exec-risk').textContent = RISK_SCORE;
  document.getElementById('exec-risk-bar').style.width = RISK_SCORE + '%';
};

function enterApp(role) {
  document.getElementById('login-screen').classList.add('hidden');
  document.getElementById('app-shell').classList.remove('hidden');
  document.getElementById('session-role').textContent = role === 'cyber' ? 'Analista Cyber' : 'Executivo C-Level';
  switchView(role === 'cyber' ? 'cyber' : 'exec');
  initCharts();
}

function logout() {
  document.getElementById('app-shell').classList.add('hidden');
  document.getElementById('login-screen').classList.remove('hidden');
}

function switchView(view) {
  document.getElementById('view-cyber').classList.toggle('hidden', view !== 'cyber');
  document.getElementById('view-exec').classList.toggle('hidden', view !== 'exec');
  document.getElementById('nav-cyber').classList.toggle('active', view === 'cyber');
  document.getElementById('nav-exec').classList.toggle('active', view === 'exec');
  document.getElementById('crumb').textContent = 'Dashboard / ' + (view === 'cyber' ? 'Visão Cyber' : 'Visão Executiva');
  document.getElementById('view-title').textContent = view === 'cyber' ? 'Operações de Segurança' : 'Resumo Executivo';
}

function initCharts() {
  if (chartSev) return;
  const grid = '#1F2A44', tick = '#8A95AD';
  chartSev = new Chart(document.getElementById('chartSev'), {
    type: 'doughnut',
    data: {
      labels: ['Crítico', 'Alto', 'Médio', 'Baixo'],
      datasets: [{ data: [ VULNS_DATA.filter(v=>v.sev==='crit').length, VULNS_DATA.filter(v=>v.sev==='high').length, VULNS_DATA.filter(v=>v.sev==='med').length, VULNS_DATA.filter(v=>v.sev==='low').length ], backgroundColor: ['#EF4444','#F59E0B','#3B82F6','#10B981'], borderColor:'#111A2E', borderWidth: 3 }]
    },
    options: { cutout: '68%', plugins: { legend: { position:'bottom', labels:{ color: tick, font:{ size:11 } } } } }
  });
  chartTrend = new Chart(document.getElementById('chartTrend'), {
    type: 'line',
    data: { labels: ['Mês 1','Mês 2','Mês 3','Atual'], datasets: [{ label:'Risco Global', data:[40, 55, 60, RISK_SCORE], borderColor:'#3B82F6', backgroundColor:'rgba(59,130,246,0.12)', fill:true, tension:0.4 }] },
    options: { plugins:{ legend:{ display:false } }, scales:{ x:{ grid:{ color: grid }, ticks:{ color: tick } }, y:{ beginAtZero:true, max:100, grid:{ color: grid }, ticks:{ color: tick } } } }
  });
}

function sevPill(s) {
  if (s==='crit') return '<span class="pill pill-crit"><span class="dot"></span>Crítico</span>';
  if (s==='high') return '<span class="pill pill-high"><span class="dot"></span>Alto</span>';
  if (s==='med')  return '<span class="pill pill-med"><span class="dot"></span>Médio</span>';
  return '<span class="pill pill-low"><span class="dot"></span>Baixo</span>';
}

function renderCyberTable() {
  const tbody = document.getElementById('cyber-tbody');
  if(VULNS_DATA.length === 0) { tbody.innerHTML = '<tr><td colspan="5" class="px-5 py-8 text-center text-mute">Sem dados.</td></tr>'; return; }
  tbody.innerHTML = VULNS_DATA.map((v) => `
    <tr class="hover-row border-t border-line">
      <td class="px-5 py-4 font-medium">${v.host}</td>
      <td class="px-5 py-4">${sevPill(v.sev)} <span class="text-mute text-xs ml-2">${v.cvss}</span></td>
      <td class="px-5 py-4 font-mono text-xs text-soft">${v.cve}</td>
      <td class="px-5 py-4 text-mute">${v.desc}</td>
      <td class="px-5 py-4 text-right"><button onclick="mitigate(this)" class="text-xs font-medium px-3 py-1.5 rounded-md bg-panel2 hover:bg-line border border-line">Mitigar</button></td>
    </tr>`).join('');
}

function mitigate(btn) {
  const row = btn.closest('tr');
  if (row.classList.contains('mitigated')) return;
  row.classList.add('mitigated');
  btn.outerHTML = '<span class="text-xs text-ok font-semibold">✓ Resolvido</span>';
  document.getElementById('kpi-mit').textContent = ++mitigatedCount;
}

function renderExecTable() {
  const tbody = document.getElementById('exec-tbody');
  if(EXEC_DATA.length === 0) return;
  tbody.innerHTML = EXEC_DATA.map(r => `
    <tr class="border-t border-line hover-row">
      <td class="px-5 py-4 font-medium">${r.risk}</td>
      <td class="px-5 py-4 text-mute">${r.cat}</td>
      <td class="px-5 py-4 font-semibold text-bad">${r.impact}</td>
      <td class="px-5 py-4">${sevPill(r.prob==='Alta'?'crit':r.prob==='Média'?'high':'med').replace('Crítico','Alta').replace('Alto','Média').replace('Médio','Baixa')}</td>
      <td class="px-5 py-4 tech-col hidden text-xs font-mono text-soft"><div>CVE: ${r.cve}</div><div class="text-mute">Alvo: ${r.ip}:${r.port}</div></td>
    </tr>`).join('');
}

function toggleTech() {
  const sw = document.getElementById('tech-switch');
  sw.classList.toggle('on');
  const on = sw.classList.contains('on');
  document.getElementById('tech-state').textContent = on ? 'Ativado' : 'Desativado';
  document.querySelectorAll('.tech-col').forEach(el => el.classList.toggle('hidden', !on));
}

function exportPDF() {
  alert("Iniciando geração de PDF Automático! Aguarde o download...");
  window.location.href = "/export_pdf";
}
</script>
</body>
</html>
"""

# ---> HTML DO RELATÓRIO PDF EXECUTIVO (Gerado via WeasyPrint) <---
PDF_HTML = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <style>
        @page { size: A4; margin: 3cm 2cm; @bottom-right { content: "Página " counter(page); font-size: 10pt; color: #555; } }
        body { font-family: 'Arial', sans-serif; font-size: 11pt; color: #222; line-height: 1.5; }
        .capa-box { text-align: center; margin-top: 150px; }
        .title { font-size: 28pt; font-weight: bold; margin-bottom: 10px; color: #000; }
        .subtitle { font-size: 14pt; color: #555; margin-bottom: 100px; }
        .score-box { background: #f8d7da; border-left: 5px solid #dc3545; padding: 20px; font-size: 14pt; color: #721c24; margin: 0 auto; width: 60%; font-weight: bold; }
        h1 { font-size: 16pt; color: #111; border-bottom: 2px solid #111; padding-bottom: 5px; margin-top: 40px; page-break-after: avoid; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { border: 1px solid #ccc; padding: 10px; text-align: left; font-size: 10pt; }
        th { background: #222; color: #fff; }
        .crit { color: #dc3545; font-weight: bold; }
    </style>
</head>
<body>

    <div class="capa-box">
        <div style="font-size: 14pt; font-weight: bold; margin-bottom: 20px;">SENAI - Segurança Cibernética</div>
        <div class="title">CYMAG</div>
        <div class="subtitle">Relatório Executivo de Diagnóstico Contínuo (SaaS)</div>
        <div class="score-box">
            Score Global de Risco Cibernético: {{ risk_score }} / 100
        </div>
        <div style="margin-top: 150px; color: #555;">Data da Varredura: Automação em Tempo Real</div>
    </div>

    <div style="page-break-before: always;"></div>

    <h1>1. SUMÁRIO DE NEGÓCIOS (VISÃO EXECUTIVA)</h1>
    <p>A varredura automatizada identificou riscos operacionais que podem resultar em sanções legais e paradas de operação. Abaixo estão os riscos traduzidos para a governança corporativa:</p>
    <table>
        <tr><th>Risco de Negócio</th><th>Categoria</th><th>Impacto Financeiro</th><th>Ativo Afetado</th></tr>
        {% for r in exec_risks %}
        <tr>
            <td class="crit">{{ r.risk }}</td>
            <td>{{ r.cat }}</td>
            <td style="font-weight:bold;">{{ r.impact }}</td>
            <td>{{ r.ip }}:{{ r.port }}</td>
        </tr>
        {% endfor %}
    </table>

    <h1>2. EVIDÊNCIAS TÉCNICAS (VISÃO CYBER)</h1>
    <p>Detalhamento das vulnerabilidades e CVEs identificadas pela Inteligência Artificial durante o processo de Red Teaming:</p>
    <table>
        <tr><th>Host / Serviço</th><th>CVSS</th><th>CVE</th><th>Descrição da Falha</th></tr>
        {% for v in cyber_vulns %}
        <tr>
            <td style="font-weight:bold;">{{ v.host }}</td>
            <td>{{ v.cvss }}</td>
            <td>{{ v.cve }}</td>
            <td>{{ v.desc }}</td>
        </tr>
        {% endfor %}
    </table>

</body>
</html>
"""

# =====================================================================
# 2. CONFIGURAÇÕES GLOBAIS E INICIALIZAÇÃO
# =====================================================================
app = Flask(__name__)

# O banco de dados em memória do SaaS
_DB = {
    "cyber_vulns": [],
    "exec_risks": [],
    "risk_score": 0
}

# Verificação de Chave de API
api_key = os.environ.get("GROQ_API_KEY")
if not api_key:
    print("\n[-] ERRO CRÍTICO: GROQ_API_KEY não foi detectada no terminal.")
    print("[-] Por favor, execute o comando: export GROQ_API_KEY='sua_chave_aqui'")
    sys.exit(1)

client = Groq(api_key=api_key)

# =====================================================================
# 3. MOTOR DE VARREDURA E INTELIGÊNCIA ARTIFICIAL
# =====================================================================
def run_scan(target):
    print(f"\n[*] Iniciando CYMAG AutoScanner no alvo: {target}")
    print("[*] Tentativa 1: Varredura Profunda com extração de CVEs (Nmap Vulners)...")
    
    try:
        # A varredura pesada do Nmap usando o script Vulners
        res = subprocess.run(
            ["nmap", "-sS", "-sV", "--script", "vulners", target],
            capture_output=True, text=True, timeout=180
        )
        if "Nmap done" in res.stdout and "0 hosts up" not in res.stdout:
            print("[+] Escaneamento Profundo concluído!")
            return res.stdout
    except Exception as e:
        print(f"[-] Erro na Tentativa 1: {e}")

    print("[!] FALLBACK ATIVADO: Tentando varredura rápida de serviços...")
    try:
        # A varredura de fallback (se a profunda travar ou bloquear ICMP)
        res = subprocess.run(
            ["nmap", "-Pn", "-F", "-sV", target],
            capture_output=True, text=True, timeout=60
        )
        print("[+] Varredura de Fallback concluída!")
        return res.stdout
    except Exception as e:
        print(f"[-] Falha catastrófica no scanner: {e}")
        return "Nenhum dado pôde ser coletado do alvo."

def analyze_with_ia(nmap_log):
    print("\n[*] Enviando dados brutos do terminal para a IA Cognitiva (Groq/Llama3)...")
    prompt = """
    Analise o output do Nmap. Retorne ESTRITAMENTE um objeto JSON válido. NENHUM texto extra.
    O JSON deve ter 2 listas:
    "cyber_vulns": objetos com "host", "cvss" (numero), "sev" ("crit", "high", "med", "low"), "cve", "desc" (descricao).
    "exec_risks": objetos traduzidos para negócio com "risk", "cat", "impact" (ex: "R$ 1M"), "prob" ("Alta","Média","Baixa"), "cve", "ip", "port".
    Se achar servicos legados EOL ou portas MQTT/Node-RED sem auth, priorize como severidade crítica (crit).
    """

    try:
        chat = client.chat.completions.create(
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": f"Output bruto do Nmap:\n{nmap_log}"}
            ],
            model="llama3-70b-8192",
            temperature=0.1, # Temperatura baixa garante o JSON perfeito
        )
        
        raw_json = chat.choices[0].message.content
        if raw_json.startswith("```json"):
            raw_json = raw_json.replace("```json", "").replace("```", "").strip()
            
        dados = json.loads(raw_json)
        print("[+] Inteligência Artificial processou os dados e gerou os painéis!")
        return dados
    except Exception as e:
        print(f"[-] Erro ao processar o JSON da IA: {e}")
        return {"cyber_vulns": [], "exec_risks": []}

def calc_score(vulns):
    score = 0
    for v in vulns:
        if v.get("sev") == "crit": score += 10
        elif v.get("sev") == "high": score += 5
        elif v.get("sev") == "med": score += 2
        else: score += 1
    return min(score, 100)

# =====================================================================
# 4. ROTAS DO SERVIDOR FLASK (DASHBOARD E GERADOR DE PDF WEASYPRINT)
# =====================================================================
@app.route("/")
def index():
    # Rota que serve o Painel SaaS usando as variáveis do Python no HTML encapsulado
    return render_template_string(
        DASHBOARD_HTML, 
        cyber_vulns=_DB["cyber_vulns"], 
        exec_risks=_DB["exec_risks"], 
        risk_score=_DB["risk_score"]
    )

@app.route("/export_pdf")
def export_pdf():
    print("\n[*] Exportação de Relatório Executivo PDF solicitada pela interface Web...")
    
    # 1. Preenche o template de PDF com os dados reais do Pentest
    html_pronto = render_template_string(
        PDF_HTML, 
        cyber_vulns=_DB["cyber_vulns"], 
        exec_risks=_DB["exec_risks"], 
        risk_score=_DB["risk_score"]
    )
    
    # 2. Chama a biblioteca WeasyPrint nativamente no Python para gerar o PDF em memória
    out_file = "CYMAG_Relatorio_Executivo.pdf"
    HTML(string=html_pronto).write_pdf(out_file)
    print(f"[+] Relatório {out_file} gerado com sucesso!")
    
    # 3. Manda o PDF para o navegador baixar
    return send_file(out_file, as_attachment=True)

# =====================================================================
# 5. ORQUESTRAÇÃO FINAL E ABERTURA AUTOMÁTICA
# =====================================================================
def start_servers_and_browser():
    def open_browser():
        time.sleep(1.5)
        print("\n[+] Abrindo o painel SaaS no navegador padrão...")
        webbrowser.open("[http://127.0.0.1:5000](http://127.0.0.1:5000)")
        
    threading.Thread(target=open_browser, daemon=True).start()
    
    import logging
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    app.run(host="127.0.0.1", port=5000)

if __name__ == "__main__":
    print("\n==========================================================")
    print("        CYMAG - CONTINUOUS AUTOMATED RED TEAMING          ")
    print("==========================================================")
    
    target = input("\n[>] Digite o IP do Alvo (ex: 10.10.100.100) ou Enter para Modo de Demonstração: ").strip()
    
    if target:
        nmap_log = run_scan(target)
    else:
        print("[!] Nenhum IP fornecido. Simulando output do ambiente SIMOC (Modo Demo)...")
        nmap_log = """
        Nmap scan report for 10.10.100.100
        80/tcp open http Nginx 1.24.0 (CVE-2021-23017)
        1880/tcp open Node-RED sem autenticação
        1883/tcp open MQTT Mosquitto sem TLS
        3307/tcp open mysql MySQL 5.5.62
        Nmap scan report for 10.10.100.2
        445/tcp open smb (SMB Signing Desabilitado)
        """

    # Passa o output real para a IA traduzir
    dados = analyze_with_ia(nmap_log)
    
    # Preenche o banco de dados em memória do SaaS
    _DB["cyber_vulns"] = dados.get("cyber_vulns", [])
    _DB["exec_risks"] = dados.get("exec_risks", [])
    _DB["risk_score"] = calc_score(_DB["cyber_vulns"])
    
    print("\n[+] Levantando o Servidor Web Flask Interno...")
    start_servers_and_browser()
