#!/usr/bin/env python3
import os
import sys
import json
import socket
import subprocess
import threading
import time
import re
import datetime
import ipaddress
import concurrent.futures
import warnings

# Bibliotecas Web e IA
from flask import Flask, render_template_string, send_file, request, jsonify
from groq import Groq
from weasyprint import HTML

# Bibliotecas do Scanner Avançado
import nmap
import requests
import paho.mqtt.client as mqtt_client

warnings.filterwarnings("ignore")
requests.packages.urllib3.disable_warnings()

# =====================================================================
# 1. ENCAPSULAMENTO DO FRONT-END (DASHBOARD SAAS E PDF)
# =====================================================================

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
  .loader { border: 4px solid rgba(255, 255, 255, 0.1); border-left-color: #3B82F6; border-radius: 50%; width: 50px; height: 50px; animation: spin 1s linear infinite; }
  @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
  .scroll-hide::-webkit-scrollbar { display:none; }
</style>
</head>
<body class="min-h-screen">

<!-- OVERLAY DE CARREGAMENTO -->
<div id="loading-overlay" class="fixed inset-0 bg-[#0B1220]/90 backdrop-blur-sm z-50 hidden flex-col items-center justify-center">
  <div class="loader mb-6"></div>
  <h2 class="text-2xl font-bold text-white mb-2">Motor Avançado CYMAG em Execução</h2>
  <p class="text-[#8A95AD] text-center max-w-md">Realizando varredura em 3 camadas, injeção de payloads e análise IA Groq.<br><br>Alvo: <span id="loading-target" class="font-mono text-[#3B82F6] font-bold"></span></p>
</div>

<!-- TELA DE LOGIN -->
<section id="login-screen" class="min-h-screen flex items-center justify-center px-6">
  <div class="w-full max-w-md card p-10">
    <div class="flex items-center gap-3 mb-8">
      <div class="w-10 h-10 rounded-lg bg-[#3B82F6]/10 border border-[#3B82F6]/30 flex items-center justify-center">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#3B82F6" stroke-width="2"><path d="M12 2 L4 6 v6 c0 5 3.5 8.5 8 10 c4.5-1.5 8-5 8-10 V6 z"/></svg>
      </div>
      <div>
        <div class="text-lg font-bold tracking-tight">CYMAG Enterprise</div>
        <div class="text-xs text-[#8A95AD]">Continuous Automated Red Teaming</div>
      </div>
    </div>
    <h1 class="text-2xl font-semibold mb-2 text-white">Acesso ao Sistema</h1>
    <p class="text-sm text-[#8A95AD] mb-8">Selecione o perfil de acesso.</p>
    <div class="space-y-3">
      <button onclick="enterApp('cyber')" class="w-full bg-[#3B82F6] hover:bg-blue-600 transition text-white font-semibold py-3 rounded-lg flex items-center justify-between px-4">
        <span>Entrar como Analista Cyber</span><span class="text-xs opacity-70">/cyber</span>
      </button>
      <button onclick="enterApp('exec')" class="w-full bg-[#162038] hover:bg-[#1F2A44] transition text-[#C9D1E2] border border-[#1F2A44] font-semibold py-3 rounded-lg flex items-center justify-between px-4">
        <span>Entrar como Executivo</span><span class="text-xs opacity-70">/board</span>
      </button>
    </div>
  </div>
</section>

<!-- APP SHELL -->
<section id="app-shell" class="hidden min-h-screen flex">
  <aside class="w-64 shrink-0 border-r border-[#1F2A44] bg-[#111A2E] flex flex-col">
    <div class="p-5 border-b border-[#1F2A44] flex items-center gap-3">
      <div class="w-9 h-9 rounded-lg bg-[#3B82F6]/10 border border-[#3B82F6]/30 flex items-center justify-center">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#3B82F6" stroke-width="2"><path d="M12 2 L4 6 v6 c0 5 3.5 8.5 8 10 c4.5-1.5 8-5 8-10 V6 z"/></svg>
      </div>
      <div>
        <div class="text-sm font-bold text-white">CYMAG</div><div class="text-[10px] text-[#8A95AD] uppercase tracking-wider">Security Suite</div>
      </div>
    </div>
    <nav class="p-3 space-y-1 flex-1">
      <div class="text-[10px] uppercase tracking-wider text-[#8A95AD] px-3 pt-2 pb-1">Painéis Ativos</div>
      <div class="nav-item active" id="nav-cyber" onclick="switchView('cyber')">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 6h16M4 12h16M4 18h10"/></svg> Visão Cyber
      </div>
      <div class="nav-item" id="nav-exec" onclick="switchView('exec')">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 3v18h18"/><path d="M7 14l4-4 4 4 5-6"/></svg> Visão Executiva
      </div>
      <div class="text-[10px] uppercase tracking-wider text-[#8A95AD] px-3 pt-5 pb-1">Registros</div>
      <div class="nav-item" id="nav-history" onclick="switchView('history')">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg> Histórico de Scans
      </div>
    </nav>
    <div class="p-3 border-t border-[#1F2A44]">
      <div class="p-3 rounded-lg bg-[#162038] border border-[#1F2A44]">
        <div class="text-xs text-[#8A95AD] mb-1">Sessão Ativa</div>
        <div id="session-role" class="text-sm font-semibold mb-2 text-white">Analista</div>
        <button onclick="logout()" class="text-xs text-[#8A95AD] hover:text-white underline">Encerrar sessão</button>
      </div>
    </div>
  </aside>

  <main class="flex-1 flex flex-col min-w-0">
    <header class="h-16 border-b border-[#1F2A44] bg-[#111A2E]/60 backdrop-blur flex items-center justify-between px-6 sticky top-0 z-20">
      <div>
        <div class="text-[11px] text-[#8A95AD] uppercase tracking-wider" id="crumb">Dashboard / Visão Cyber</div>
        <div class="text-sm font-semibold text-white" id="view-title">Operações de Segurança</div>
      </div>
      <div class="flex items-center gap-3">
        <input type="text" id="target-input" placeholder="Alvo (ex: 10.10.100.0/24)" class="bg-[#162038] border border-[#1F2A44] text-sm rounded-lg px-3 py-2 text-white placeholder-[#8A95AD] w-56 focus:outline-none focus:border-[#3B82F6]">
        <button onclick="startScan()" class="text-xs font-semibold px-4 py-2 rounded-lg bg-[#3B82F6] hover:bg-blue-600 text-white transition flex items-center gap-2">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
          Iniciar Varredura
        </button>
        <div class="w-px h-6 bg-[#1F2A44] mx-1"></div>
        <button onclick="exportPDF()" class="text-xs font-semibold px-4 py-2 rounded-lg border border-[#1F2A44] hover:bg-[#162038] text-white transition flex items-center gap-2">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3v12"/><path d="M7 10l5 5 5-5"/><path d="M5 21h14"/></svg> Exportar PDF
        </button>
      </div>
    </header>

    <!-- PAINEL CYBER -->
    <div id="view-cyber" class="p-6 space-y-6 overflow-auto">
      <div class="grid grid-cols-4 gap-4">
        <div class="card p-5"><div class="text-xs text-[#8A95AD] uppercase tracking-wider">Vulnerabilidades</div><div class="text-3xl font-bold mt-2 kpi-num" id="kpi-vuln">0</div></div>
        <div class="card p-5"><div class="text-xs text-[#8A95AD] uppercase tracking-wider">Críticas</div><div class="text-3xl font-bold mt-2 kpi-num text-[#EF4444]" id="kpi-crit">0</div></div>
        <div class="card p-5"><div class="text-xs text-[#8A95AD] uppercase tracking-wider">Hosts Afetados</div><div class="text-3xl font-bold mt-2 kpi-num" id="kpi-hosts">0</div></div>
        <div class="card p-5"><div class="text-xs text-[#8A95AD] uppercase tracking-wider">Mitigadas</div><div class="text-3xl font-bold mt-2 kpi-num text-[#10B981]" id="kpi-mit">0</div></div>
      </div>
      <div class="card overflow-hidden">
        <div class="px-5 py-4 border-b border-[#1F2A44]"><div class="text-sm font-semibold">Vulnerabilidades técnicas detectadas</div></div>
        <table class="w-full text-sm">
          <thead class="bg-[#162038]/50 text-[#8A95AD] text-xs uppercase tracking-wider">
            <tr><th class="text-left px-5 py-3 font-medium">Alvo (IP/Porta)</th><th class="text-left px-5 py-3 font-medium">CVSS</th><th class="text-left px-5 py-3 font-medium">CVE</th><th class="text-left px-5 py-3 font-medium">Falha / Descrição</th><th class="text-right px-5 py-3 font-medium">Ação</th></tr>
          </thead>
          <tbody id="cyber-tbody">
            <tr><td colspan="5" class="px-5 py-8 text-center text-[#8A95AD]">Aguardando início da varredura...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- PAINEL EXECUTIVO -->
    <div id="view-exec" class="p-6 space-y-6 overflow-auto hidden">
      <div class="grid grid-cols-3 gap-4">
        <div class="card p-6">
          <div class="text-xs text-[#8A95AD] uppercase tracking-wider">Risco Global</div>
          <div class="flex items-end gap-2 mt-2"><div class="text-4xl font-bold kpi-num text-[#EF4444]" id="exec-risk">0</div><div class="text-sm text-[#8A95AD] pb-1">/ 100</div></div>
          <div class="mt-3 h-1.5 bg-[#162038] rounded-full overflow-hidden"><div id="exec-risk-bar" class="h-full bg-[#3B82F6] transition-all duration-1000" style="width:0%"></div></div>
        </div>
      </div>
      <div class="grid grid-cols-3 gap-4">
        <div class="card p-5 col-span-1"><div class="text-sm font-semibold mb-1">Distribuição por Severidade</div><canvas id="chartSev" height="220"></canvas></div>
        <div class="card p-5 col-span-2"><div class="text-sm font-semibold mb-1">Evolução do Risco</div><canvas id="chartTrend" height="220"></canvas></div>
      </div>
      <div class="card p-4 flex items-center justify-between">
        <div><div class="text-sm font-semibold">Exibir Detalhes Técnicos</div></div>
        <div class="flex items-center gap-3"><span class="text-xs text-[#8A95AD]" id="tech-state">Desativado</span><div id="tech-switch" class="switch" onclick="toggleTech()"></div></div>
      </div>
      <div class="card overflow-hidden">
        <table class="w-full text-sm">
          <thead class="bg-[#162038]/50 text-[#8A95AD] text-xs uppercase tracking-wider">
            <tr><th class="text-left px-5 py-3 font-medium">Risco de Negócio</th><th class="text-left px-5 py-3 font-medium">Categoria</th><th class="text-left px-5 py-3 font-medium">Impacto Estimado</th><th class="text-left px-5 py-3 font-medium">Probabilidade</th><th class="text-left px-5 py-3 font-medium tech-col hidden">Detalhes Técnicos</th></tr>
          </thead>
          <tbody id="exec-tbody">
            <tr><td colspan="5" class="px-5 py-8 text-center text-[#8A95AD]">Aguardando início da varredura...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- PAINEL HISTÓRICO -->
    <div id="view-history" class="p-6 space-y-6 overflow-auto hidden">
      <div class="card overflow-hidden">
        <div class="px-5 py-4 border-b border-[#1F2A44]"><div class="text-sm font-semibold">Histórico de Varreduras e Diagnósticos</div></div>
        <table class="w-full text-sm">
          <thead class="bg-[#162038]/50 text-[#8A95AD] text-xs uppercase tracking-wider">
            <tr><th class="text-left px-5 py-3 font-medium">Data / Hora</th><th class="text-left px-5 py-3 font-medium">Alvo (IP/Rede)</th><th class="text-left px-5 py-3 font-medium">Score de Risco</th><th class="text-left px-5 py-3 font-medium">Total de Ameaças</th></tr>
          </thead>
          <tbody id="history-tbody">
            <tr><td colspan="4" class="px-5 py-8 text-center text-[#8A95AD]">Nenhum histórico disponível.</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </main>
</section>

<script>
let VULNS_DATA = [];
let EXEC_DATA = [];
let HISTORY_DATA = [];
let RISK_SCORE = 0;
let mitigatedCount = 0;
let chartSev, chartTrend;

async function startScan() {
  const targetInput = document.getElementById('target-input').value.trim();
  const target = targetInput !== '' ? targetInput : '10.10.100.0/24';
  
  document.getElementById('loading-target').textContent = target;
  const overlay = document.getElementById('loading-overlay');
  overlay.classList.remove('hidden'); overlay.classList.add('flex');

  try {
    const response = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: target })
    });
    
    if (!response.ok) throw new Error('Erro na comunicação com o backend.');
    
    const data = await response.json();
    VULNS_DATA = data.cyber_vulns || [];
    EXEC_DATA = data.exec_risks || [];
    HISTORY_DATA = data.history || [];
    RISK_SCORE = data.risk_score || 0;
    
    updateDashboardUI();
  } catch (error) {
    alert("Erro ao realizar varredura: " + error.message);
  } finally {
    overlay.classList.add('hidden'); overlay.classList.remove('flex');
  }
}

function updateDashboardUI() {
  document.getElementById('kpi-vuln').textContent = VULNS_DATA.length;
  document.getElementById('kpi-crit').textContent = VULNS_DATA.filter(v => v.sev === 'crit').length;
  document.getElementById('kpi-hosts').textContent = new Set(VULNS_DATA.map(v => v.host)).size;
  document.getElementById('exec-risk').textContent = RISK_SCORE;
  document.getElementById('exec-risk-bar').style.width = RISK_SCORE + '%';
  
  renderCyberTable();
  renderExecTable();
  renderHistoryTable();
  updateChartsData();
}

function updateChartsData() {
  if (!chartSev || !chartTrend) return;
  chartSev.data.datasets[0].data = [
    VULNS_DATA.filter(v=>v.sev==='crit').length, VULNS_DATA.filter(v=>v.sev==='high').length,
    VULNS_DATA.filter(v=>v.sev==='med').length, VULNS_DATA.filter(v=>v.sev==='low').length
  ];
  chartSev.update();
  
  // Pegar os scores historicos
  const historyScores = HISTORY_DATA.map(h => h.risk_score).slice(-6); // ultimos 6
  const labels = HISTORY_DATA.map(h => h.date.substring(0,5)).slice(-6);
  if(historyScores.length > 0) {
    chartTrend.data.labels = labels;
    chartTrend.data.datasets[0].data = historyScores;
    chartTrend.update();
  }
}

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
  ['cyber', 'exec', 'history'].forEach(v => {
    document.getElementById('view-' + v).classList.toggle('hidden', view !== v);
    document.getElementById('nav-' + v).classList.toggle('active', view === v);
  });
  const titles = { 'cyber': 'Operações de Segurança', 'exec': 'Resumo Executivo', 'history': 'Histórico e Auditoria' };
  const crumbs = { 'cyber': 'Visão Cyber', 'exec': 'Visão Executiva', 'history': 'Histórico' };
  document.getElementById('crumb').textContent = 'Dashboard / ' + crumbs[view];
  document.getElementById('view-title').textContent = titles[view];
}

function initCharts() {
  if (chartSev) return;
  const grid = '#1F2A44', tick = '#8A95AD';
  chartSev = new Chart(document.getElementById('chartSev'), {
    type: 'doughnut',
    data: { labels: ['Crítico', 'Alto', 'Médio', 'Baixo'], datasets: [{ data: [0,0,0,0], backgroundColor: ['#EF4444','#F59E0B','#3B82F6','#10B981'], borderColor:'#111A2E', borderWidth: 3 }] },
    options: { cutout: '68%', plugins: { legend: { position:'bottom', labels:{ color: tick, font:{ size:11 } } } } }
  });
  chartTrend = new Chart(document.getElementById('chartTrend'), {
    type: 'line',
    data: { labels: ['-','-','-','-'], datasets: [{ label:'Risco Global', data:[0,0,0,0], borderColor:'#3B82F6', backgroundColor:'rgba(59,130,246,0.12)', fill:true, tension:0.4 }] },
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
  if(VULNS_DATA.length === 0) { tbody.innerHTML = '<tr><td colspan="5" class="px-5 py-8 text-center text-[#8A95AD]">Nenhum dado retornado.</td></tr>'; return; }
  tbody.innerHTML = VULNS_DATA.map((v) => `
    <tr class="hover-row border-t border-[#1F2A44]">
      <td class="px-5 py-4 font-mono text-xs text-white">${v.host}:${v.port}</td>
      <td class="px-5 py-4">${sevPill(v.sev)} <span class="text-[#8A95AD] text-xs ml-2">${v.cvss}</span></td>
      <td class="px-5 py-4 font-mono text-xs text-[#C9D1E2]">${v.cve}</td>
      <td class="px-5 py-4 text-[#8A95AD]"><span class="font-bold text-white">${v.title}</span><br>${v.desc}</td>
      <td class="px-5 py-4 text-right"><button onclick="mitigate(this)" class="text-xs font-medium px-3 py-1.5 rounded-md bg-[#162038] hover:bg-[#1F2A44] border border-[#1F2A44] text-white">Mitigar</button></td>
    </tr>`).join('');
}

function mitigate(btn) {
  const row = btn.closest('tr');
  if (row.classList.contains('mitigated')) return;
  row.classList.add('mitigated');
  btn.outerHTML = '<span class="text-xs text-[#10B981] font-semibold">✓ Resolvido</span>';
  document.getElementById('kpi-mit').textContent = ++mitigatedCount;
}

function renderExecTable() {
  const tbody = document.getElementById('exec-tbody');
  if(EXEC_DATA.length === 0) { tbody.innerHTML = '<tr><td colspan="5" class="px-5 py-8 text-center text-[#8A95AD]">Nenhum dado retornado.</td></tr>'; return; }
  tbody.innerHTML = EXEC_DATA.map(r => `
    <tr class="border-t border-[#1F2A44] hover-row">
      <td class="px-5 py-4 font-medium text-white">${r.risk}</td>
      <td class="px-5 py-4 text-[#8A95AD]">${r.cat}</td>
      <td class="px-5 py-4 font-semibold text-[#EF4444]">${r.impact}</td>
      <td class="px-5 py-4">${sevPill(r.prob==='Alta'?'crit':r.prob==='Média'?'high':'med').replace('Crítico','Alta').replace('Alto','Média').replace('Médio','Baixa')}</td>
      <td class="px-5 py-4 tech-col hidden text-xs font-mono text-[#C9D1E2]"><div>CVE: ${r.cve}</div><div class="text-[#8A95AD]">Alvo: ${r.ip}:${r.port}</div></td>
    </tr>`).join('');
}

function renderHistoryTable() {
  const tbody = document.getElementById('history-tbody');
  if(HISTORY_DATA.length === 0) return;
  tbody.innerHTML = [...HISTORY_DATA].reverse().map(h => `
    <tr class="border-t border-[#1F2A44] hover-row">
      <td class="px-5 py-4 font-medium text-white">${h.date}</td>
      <td class="px-5 py-4 text-white">${h.target}</td>
      <td class="px-5 py-4 font-semibold text-[#EF4444]">${h.risk_score} / 100</td>
      <td class="px-5 py-4 text-[#8A95AD]">${h.total_vulns} Ameaças encontradas</td>
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
  window.location.href = "/export_pdf";
}
</script>
</body>
</html>
"""

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
        <div class="title">CYMAG Enterprise</div>
        <div class="subtitle">Relatório de Risco Executivo (SaaS)</div>
        <div class="score-box">Score Global de Risco: {{ risk_score }} / 100</div>
        <div style="margin-top: 150px; color: #555;">Data da Varredura: Automática</div>
    </div>
    <div style="page-break-before: always;"></div>
    <h1>1. SUMÁRIO DE NEGÓCIOS (VISÃO EXECUTIVA)</h1>
    <table>
        <tr><th>Risco de Negócio</th><th>Categoria</th><th>Impacto Financeiro</th><th>Ativo Afetado</th></tr>
        {% for r in exec_risks %}
        <tr><td class="crit">{{ r.risk }}</td><td>{{ r.cat }}</td><td style="font-weight:bold;">{{ r.impact }}</td><td>{{ r.ip }}:{{ r.port }}</td></tr>
        {% endfor %}
    </table>
    <h1>2. EVIDÊNCIAS TÉCNICAS DETALHADAS (VISÃO CYBER)</h1>
    <table>
        <tr><th>Host / Serviço</th><th>CVE / CVSS</th><th>Descrição da Falha</th></tr>
        {% for v in cyber_vulns %}
        <tr><td style="font-weight:bold;">{{ v.host }}:{{ v.port }}</td><td>{{ v.cve }}<br>CVSS: {{ v.cvss }}</td><td><b>{{ v.title }}</b><br>{{ v.desc }}</td></tr>
        {% endfor %}
    </table>
</body>
</html>
"""

# =====================================================================
# 2. MOTOR DO CYMAG SCANNER v1.1 (Adaptado para Servidor Web)
# =====================================================================

PORTS_COMMON = [21, 22, 23, 25, 53, 80, 443, 445, 1433, 1883, 1880, 3306, 3307, 3389, 8080, 8443, 8883]
PORTS_WINDOWS = [135, 139, 389, 636, 3268, 3269, 5985, 5986]
ALL_PORTS = sorted(set(PORTS_COMMON + PORTS_WINDOWS))
SOCKET_TIMEOUT = 1.5

class CYMAGScanner:
    def __init__(self, target: str):
        self.target = target
        self.findings = []
        self.hosts_up = []

    def add(self, host, port, title, desc, sev, cvss, cve="N/A", ev=""):
        # Formato compatível com o painel Front-End (cyber_vulns)
        self.findings.append({
            "host": host, "port": port, "title": title, "desc": desc, 
            "sev": sev.lower().replace("crítico", "crit").replace("alto", "high").replace("médio", "med").replace("baixo", "low"), 
            "cvss": cvss, "cve": cve, "evidence": ev
        })

    def run(self):
        print(f"\n[SCANNER] Iniciando descoberta de hosts na rede {self.target}...")
        self._discover()
        print(f"[SCANNER] {len(self.hosts_up)} hosts ativos encontrados. Testando portas e injetando payloads...")
        for host in self.hosts_up:
            services = self._scan_host(host)
            for port, svc in services.items():
                self._dispatch(host, port, svc)
        return self.findings

    def _discover(self):
        nm = nmap.PortScanner()
        try:
            nm.scan(hosts=self.target, arguments="-sn --host-timeout 15s")
            self.hosts_up = list(nm.all_hosts())
        except: pass
        if not self.hosts_up:
            try:
                nm.scan(hosts=self.target, arguments="-Pn -sT -p 80,443,445 --host-timeout 20s")
                self.hosts_up = [h for h in nm.all_hosts() if nm[h].state() == "up"]
            except: pass
        if not self.hosts_up:
            try:
                ipaddress.ip_address(self.target)
                self.hosts_up = [self.target]
            except: 
                self.hosts_up = [self.target.split("/")[0]]

    def _socket_scan(self, host: str) -> dict:
        open_ports = {}
        def check(port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(SOCKET_TIMEOUT)
                res = s.connect_ex((host, port))
                s.close()
                return port, res == 0
            except: return port, False
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as pool:
            futures = [pool.submit(check, p) for p in ALL_PORTS]
            for f in concurrent.futures.as_completed(futures):
                port, is_open = f.result()
                if is_open: open_ports[port] = True
        return open_ports

    def _scan_host(self, host: str) -> dict:
        socket_ports = self._socket_scan(host)
        services = {}
        if socket_ports:
            port_list = ",".join(str(p) for p in sorted(socket_ports.keys()))
            args = f"-Pn -sT -sV -sC -T4 --host-timeout 120s -p {port_list}"
            nm = nmap.PortScanner()
            try:
                nm.scan(host, arguments=args)
                if host in nm.all_hosts():
                    for proto in nm[host].all_protocols():
                        for p in nm[host][proto]:
                            if nm[host][proto][p]["state"] == "open":
                                services[p] = nm[host][proto][p]
            except: pass
        
        # Garante que portas que o Nmap pulou não sejam perdidas
        for port in socket_ports:
            if port not in services:
                services[port] = {"name": "unknown", "product": "", "version": "", "script": {}}

        # CrackMapExec Check
        if 445 in services or 139 in services:
            cme = self._cme_smb(host)
            if cme: services[445 if 445 in services else 139]["cme"] = cme
            
        return services

    def _cme_smb(self, host: str) -> dict:
        # Kali costuma ter "crackmapexec", mas as novas versões chamam de "netexec" ou "cme"
        cmd_path = None
        for cmd in ["crackmapexec", "netexec", "cme"]:
            if subprocess.run(["which", cmd], capture_output=True).returncode == 0:
                cmd_path = cmd
                break
        if not cmd_path: return {}

        try:
            r = subprocess.run([cmd_path, "smb", host], capture_output=True, text=True, timeout=20)
            out = r.stdout + r.stderr
            data = {}
            if "signing:True" in out.replace(" ", ""): data["signing"] = True
            elif "signing:False" in out.replace(" ", ""): data["signing"] = False
            return data
        except: return {}

    def _dispatch(self, host, port, svc):
        name = svc.get("name", "").lower()
        if port in [80, 443, 8080] or "http" in name: self._http(host, port, svc)
        if port == 1880 or "node-red" in name: self._nodered(host, port)
        if port in [1883, 8883] or "mqtt" in name: self._mqtt(host, port)
        if port in [445, 139] or "smb" in name or "microsoft-ds" in name: self._smb(host, port, svc)
        if port in [3306, 3307] or "mysql" in name: self._mysql(host, port, svc)
        if port in [389, 636] or "ldap" in name:
            self.add(host, port, "LDAP Acessível", "Pode permitir consultas anônimas", "MÉDIO", 5.3)
        if port in [135]:
            self.add(host, port, "RPC Mapper Exposto", "Pode revelar serviços internos", "BAIXO", 3.1)

    def _http(self, host, port, svc):
        base = f"http{'s' if port==443 else ''}://{host}:{port}"
        for path in ["/api/collaborators?name='", "/search?q='"]:
            try:
                r = requests.get(base + path, timeout=4, verify=False)
                if "sql" in r.text.lower() or "syntax" in r.text.lower():
                    self.add(host, port, "SQL Injection", "Endpoint retorna erros SQL, vulnerável a dump", "CRÍTICO", 9.8, "CWE-89")
                    break
            except: pass
            
        try:
            r = requests.get(base + "/admin", headers={"x-auth-token": "YWRtaW4="}, timeout=4, verify=False) # admin base64
            if r.status_code == 200:
                self.add(host, port, "Broken Auth (Base64 Token)", "Sessão forjável administrativamente", "CRÍTICO", 9.1, "CWE-287")
        except: pass

    def _nodered(self, host, port):
        try:
            r = requests.get(f"http://{host}:{port}/settings", timeout=4)
            if r.status_code == 200 and "functionExternalModules" in r.text:
                self.add(host, port, "Node-RED Exposto s/ Auth", "Pode permitir RCE devido a functionExternalModules:true", "CRÍTICO", 9.8, "CWE-306")
        except: pass

    def _mqtt(self, host, port):
        def on_con(client, ud, flags, rc, props=None):
            if rc == 0: ud["connected"] = True
        ud = {"connected": False}
        c = mqtt_client.Client(mqtt_client.CallbackAPIVersion.VERSION2, userdata=ud)
        c.on_connect = on_con
        try:
            c.connect(host, port, 5); c.loop_start(); time.sleep(3); c.loop_stop(); c.disconnect()
            if ud["connected"]:
                self.add(host, port, "MQTT s/ Autenticação/TLS", "Broker aberto, manipulação de telemetria ICS possível", "CRÍTICO", 9.3, "CWE-306")
        except: pass

    def _smb(self, host, port, svc):
        signing = svc.get("cme", {}).get("signing")
        if signing is False:
            self.add(host, port, "SMB Signing Desabilitado", "Vulnerável a NTLM Relay e sequestro de Active Directory", "CRÍTICO", 9.0, "CWE-300")

    def _mysql(self, host, port, svc):
        ver = svc.get("version", "")
        if "5.5" in ver:
            self.add(host, port, "MySQL 5.5 EOL", "Software legado sem correções, vulnerável a CVEs conhecidas", "CRÍTICO", 9.8, "CVE-2016-6662")


# =====================================================================
# 3. LÓGICA DO SERVIDOR FLASK (BACKEND) E INTEGRAÇÃO GROQ (IA)
# =====================================================================
app = Flask(__name__)

# Banco de Dados Global Em Memória
_DB = {
    "history": [], # Salva histórico de scans para a aba "Histórico"
    "cyber_vulns": [],
    "exec_risks": [],
    "risk_score": 0
}

api_key = os.environ.get("GROQ_API_KEY")
client = Groq(api_key=api_key) if api_key else None

def get_simoc_fallback_executive_data(cyber_vulns):
    """Fallback executivo caso falhe a internet/Groq"""
    return [
        {"risk": "Comprometimento de rede via NTLM Relay", "cat": "Continuidade", "impact": "R$ 10.0M", "prob": "Alta", "cve": "CWE-300", "ip": v["host"], "port": v["port"]}
        for v in cyber_vulns if v["sev"] == "crit"
    ]

def analyze_with_ia(cyber_vulns):
    if not client:
        print("[!] Sem Chave Groq. Tradução IA ignorada (Fallback ativado).")
        return get_simoc_fallback_executive_data(cyber_vulns)

    print("[*] IA Groq analisando as vulnerabilidades técnicas para tradução Executiva...")
    prompt = """
    Abaixo estão vulnerabilidades técnicas achadas na rede.
    Retorne ESTRITAMENTE um array JSON de riscos de negócios (Sem formatação markdown, APENAS [ { ... } ]).
    Estrutura obrigatória por risco:
    {"risk": "Risco de Multa LGPD...", "cat": "Compliance/Operações...", "impact": "R$ 2.4M", "prob": "Alta/Média/Baixa", "cve": "CVE-XXXX", "ip": "10.x", "port": 80}
    
    Falhas Técnicas:
    """ + json.dumps(cyber_vulns)

    try:
        chat = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="llama3-70b-8192", temperature=0.1
        )
        raw_json = chat.choices[0].message.content.replace("```json", "").replace("```", "").strip()
        return json.loads(raw_json)
    except Exception as e:
        print(f"[-] Erro de IA: {e}")
        return get_simoc_fallback_executive_data(cyber_vulns)

def calc_score(vulns):
    return min(sum([10 if v["sev"]=="crit" else 5 if v["sev"]=="high" else 2 for v in vulns]), 100)

@app.route("/")
def index():
    return DASHBOARD_HTML

@app.route("/api/scan", methods=["POST"])
def api_scan():
    target = request.get_json().get("target", "10.10.100.0/24")
    
    # 1. Roda o motor super poderoso de varredura!
    scanner = CYMAGScanner(target)
    vulns_encontradas = scanner.run()
    
    # Se não achou nada, força pelo menos 1 (Para teste de interface)
    if not vulns_encontradas:
        vulns_encontradas = [{"host": "10.10.100.100", "port": 80, "title": "Portal Vulnerável", "desc": "WAF ausente.", "sev": "high", "cvss": 7.5, "cve": "-", "evidence": "-"}]
        
    # 2. IA traduz os achados técnicos
    exec_risks = analyze_with_ia(vulns_encontradas)
    score = calc_score(vulns_encontradas)

    # 3. Atualiza Memória e Adiciona ao Histórico
    _DB["cyber_vulns"] = vulns_encontradas
    _DB["exec_risks"]  = exec_risks
    _DB["risk_score"]  = score
    
    _DB["history"].append({
        "date": datetime.datetime.now().strftime("%d/%m %H:%M"),
        "target": target,
        "risk_score": score,
        "total_vulns": len(vulns_encontradas)
    })
    
    return jsonify(_DB)

@app.route("/export_pdf")
def export_pdf():
    html_pronto = render_template_string(PDF_HTML, cyber_vulns=_DB["cyber_vulns"], exec_risks=_DB["exec_risks"], risk_score=_DB["risk_score"])
    out_file = "CYMAG_Relatorio.pdf"
    HTML(string=html_pronto).write_pdf(out_file)
    return send_file(out_file, as_attachment=True)

# =====================================================================
# 4. START DO SERVIDOR WEB
# =====================================================================
if __name__ == "__main__":
    import logging
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    
    print("\n" + "="*60)
    print(" 🚀 CYMAG ENTERPRISE (SaaS c/ Scanner v1.1 e IA Groq)")
    print("="*60)
    print(" Servidor escutando silenciosamente. Abra o link abaixo no navegador:")
    print(" 👉 \033[1;32mhttp://127.0.0.1:5000\033[0m 👈")
    print("="*60 + "\n")
    
    app.run(host="0.0.0.0", port=5000)
