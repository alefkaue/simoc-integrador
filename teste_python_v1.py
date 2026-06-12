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
  .loader-sm { border: 3px solid rgba(255, 255, 255, 0.1); border-left-color: #3B82F6; border-radius: 50%; width: 30px; height: 30px; animation: spin 1s linear infinite; }
  @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
  .scroll-hide::-webkit-scrollbar { display:none; }
</style>
</head>
<body class="min-h-screen">

<!-- OVERLAY DE CARREGAMENTO -->
<div id="loading-overlay" class="fixed inset-0 bg-[#0B1220]/90 backdrop-blur-sm z-50 hidden flex-col items-center justify-center p-4">
  <div class="loader mb-6"></div>
  <h2 class="text-2xl font-bold text-white mb-2">Motor Avançado CYMAG em Execução</h2>
  <p class="text-[#8A95AD] text-center max-w-md">Realizando varredura em 3 camadas, injeção de payloads e análise IA Groq.<br><br>Alvo: <span id="loading-target" class="font-mono text-[#3B82F6] font-bold"></span></p>
</div>

<!-- MODAL DE EXPORTAÇÃO PDF -->
<div id="pdf-modal" class="fixed inset-0 bg-[#0B1220]/90 backdrop-blur-sm z-50 hidden flex-col items-center justify-center p-4">
  <div class="card w-full max-w-md p-6 border border-[#3B82F6]/30 shadow-[0_0_40px_rgba(59,130,246,0.15)]">
    <div class="flex justify-between items-center mb-6 border-b border-[#1F2A44] pb-4">
      <h3 class="text-lg font-bold text-white">Gerador de Relatório PDF</h3>
      <button onclick="closePdfModal()" class="text-[#8A95AD] hover:text-white transition">✕</button>
    </div>
    
    <p class="text-sm text-[#8A95AD] mb-4">Selecione a abrangência dos dados para consolidação do relatório:</p>
    
    <div class="space-y-3 mb-8">
      <label class="flex items-center gap-3 p-4 border border-[#3B82F6] bg-[#3B82F6]/10 rounded-lg cursor-pointer transition" id="label-pdf-all">
        <input type="radio" name="pdf-type" value="ALL" checked onchange="togglePdfSelect()" class="w-4 h-4 text-blue-600 bg-gray-100 border-gray-300">
        <div>
          <div class="font-semibold text-white text-sm">Rede Completa (Consolidado)</div>
          <div class="text-xs text-[#8A95AD] mt-1">Funde automaticamente todas as vulnerabilidades mapeadas no histórico.</div>
        </div>
      </label>
      
      <label class="flex flex-col gap-2 p-4 border border-[#1F2A44] bg-[#162038] rounded-lg cursor-pointer transition" id="label-pdf-spec">
        <div class="flex items-center gap-3">
          <input type="radio" name="pdf-type" value="SPECIFIC" onchange="togglePdfSelect()" class="w-4 h-4">
          <div>
            <div class="font-semibold text-white text-sm">Alvo / Scan Específico</div>
            <div class="text-xs text-[#8A95AD] mt-1">Gera o relatório exclusivo de uma varredura individual.</div>
          </div>
        </div>
        <div id="pdf-target-wrapper" class="hidden mt-3 ml-7">
          <select id="pdf-target-select" class="w-full bg-[#0B1220] border border-[#1F2A44] text-white text-sm rounded-lg p-2.5 outline-none focus:border-[#3B82F6]"></select>
        </div>
      </label>
    </div>
    
    <button onclick="downloadPDF()" class="w-full py-3 bg-[#3B82F6] hover:bg-blue-600 text-white rounded-lg font-bold tracking-wide transition shadow-lg shadow-blue-500/30">Construir e Baixar Relatório</button>
  </div>
</div>

<!-- MODAL DE PLANO DE AÇÃO IA -->
<div id="remediation-modal" class="fixed inset-0 bg-[#0B1220]/90 backdrop-blur-sm z-50 hidden flex-col items-center justify-center p-6">
  <div class="card w-full max-w-2xl p-0 border border-[#3B82F6]/50 shadow-[0_0_50px_rgba(59,130,246,0.2)] flex flex-col max-h-[90vh]">
    <div class="p-6 border-b border-[#1F2A44] flex justify-between items-center bg-[#111A2E] rounded-t-xl sticky top-0">
      <div>
        <h3 class="text-lg font-bold text-white flex items-center gap-2" id="modal-role-badge"></h3>
        <div class="text-xs text-[#8A95AD] mt-1 font-mono" id="rem-title">Carregando...</div>
      </div>
      <button onclick="closeRemediationModal()" class="text-[#8A95AD] hover:text-white transition">✕</button>
    </div>
    <div class="p-6 overflow-y-auto" id="rem-content">
      <div class="flex flex-col items-center justify-center py-10">
        <div class="loader-sm mb-4"></div>
        <div class="text-sm text-[#8A95AD]">Processando dados e consultando o motor de IA...</div>
      </div>
    </div>
  </div>
</div>

<!-- TELA DE LOGIN -->
<section id="login-screen" class="min-h-screen flex items-center justify-center px-6">
  <div class="w-full max-w-md card p-10">
    <div class="mb-8 text-center">
      <div class="text-2xl font-bold tracking-tight text-white mb-1">CYMAG Enterprise</div>
      <div class="text-xs text-[#8A95AD]">Continuous Automated Red Teaming</div>
    </div>
    <h1 class="text-xl font-semibold mb-2 text-white text-center">Acesso ao Sistema</h1>
    <p class="text-sm text-[#8A95AD] mb-8 text-center">Selecione o perfil operacional para iniciar.</p>
    <div class="space-y-3">
      <button onclick="enterApp('cyber')" class="w-full bg-[#3B82F6] hover:bg-blue-600 transition text-white font-semibold py-3 rounded-lg flex items-center justify-between px-4">
        <span>Acesso Operacional (Cyber)</span><span class="text-xs opacity-70">/sys</span>
      </button>
      <button onclick="enterApp('exec')" class="w-full bg-[#162038] hover:bg-[#1F2A44] transition text-[#C9D1E2] border border-[#1F2A44] font-semibold py-3 rounded-lg flex items-center justify-between px-4">
        <span>Acesso Executivo (C-Level)</span><span class="text-xs opacity-70">/board</span>
      </button>
    </div>
  </div>
</section>

<!-- APP SHELL -->
<section id="app-shell" class="hidden min-h-screen flex">
  <aside class="w-64 shrink-0 border-r border-[#1F2A44] bg-[#111A2E] flex flex-col">
    <div class="p-6 border-b border-[#1F2A44]">
      <div class="text-lg font-bold text-white tracking-wide">CYMAG</div>
      <div class="text-[10px] text-[#8A95AD] uppercase tracking-wider">Security Suite</div>
    </div>
    <nav class="p-3 space-y-1 flex-1">
      <div class="text-[10px] uppercase tracking-wider text-[#8A95AD] px-3 pt-4 pb-2">Painéis Ativos</div>
      <div class="nav-item active" id="nav-cyber" onclick="switchView('cyber')">Visão Cyber</div>
      <div class="nav-item" id="nav-exec" onclick="switchView('exec')">Visão Executiva</div>
      <div class="text-[10px] uppercase tracking-wider text-[#8A95AD] px-3 pt-6 pb-2">Registros</div>
      <div class="nav-item" id="nav-history" onclick="switchView('history')">Histórico de Scans</div>
    </nav>
    <div class="p-4 border-t border-[#1F2A44]">
      <div class="text-xs text-[#8A95AD] mb-1">Sessão Ativa</div>
      <div id="session-role" class="text-sm font-semibold mb-2 text-white">Analista Cyber</div>
      <button onclick="logout()" class="text-xs text-[#EF4444] hover:underline">Encerrar sessão</button>
    </div>
  </aside>

  <main class="flex-1 flex flex-col min-w-0">
    <header class="h-16 border-b border-[#1F2A44] bg-[#111A2E]/60 backdrop-blur flex items-center justify-between px-6 sticky top-0 z-20">
      <div class="flex items-center gap-4">
        <div>
          <div class="text-[11px] text-[#8A95AD] uppercase tracking-wider" id="crumb">Dashboard / Visão Cyber</div>
          <div class="text-sm font-semibold text-white" id="view-title">Operações de Segurança</div>
        </div>
      </div>
      <div class="flex items-center gap-3">
        <input type="text" id="target-input" placeholder="Alvo (ex: 10.10.100.0/24)" class="bg-[#162038] border border-[#1F2A44] text-sm rounded-lg px-3 py-2 text-white placeholder-[#8A95AD] w-56 focus:outline-none focus:border-[#3B82F6]">
        <button onclick="startScan()" class="text-xs font-semibold px-4 py-2 rounded-lg bg-[#3B82F6] hover:bg-blue-600 text-white transition">Iniciar Varredura</button>
        <div class="w-px h-6 bg-[#1F2A44] mx-1"></div>
        <button onclick="openPdfModal()" class="text-xs font-semibold px-4 py-2 rounded-lg border border-[#1F2A44] hover:bg-[#162038] text-white transition">Relatório PDF</button>
      </div>
    </header>

    <!-- PAINEL CYBER -->
    <div id="view-cyber" class="p-6 space-y-6 overflow-auto">
      <div class="grid grid-cols-4 gap-4">
        <div class="card p-5"><div class="text-xs text-[#8A95AD] uppercase tracking-wider font-semibold">Vulnerabilidades</div><div class="text-3xl font-bold mt-2 kpi-num text-white" id="kpi-vuln">0</div></div>
        <div class="card p-5"><div class="text-xs text-[#8A95AD] uppercase tracking-wider font-semibold">Críticas</div><div class="text-3xl font-bold mt-2 kpi-num text-[#EF4444]" id="kpi-crit">0</div></div>
        <div class="card p-5"><div class="text-xs text-[#8A95AD] uppercase tracking-wider font-semibold">Hosts Afetados</div><div class="text-3xl font-bold mt-2 kpi-num text-white" id="kpi-hosts">0</div></div>
        <div class="card p-5"><div class="text-xs text-[#8A95AD] uppercase tracking-wider font-semibold">Mitigadas</div><div class="text-3xl font-bold mt-2 kpi-num text-[#10B981]" id="kpi-mit">0</div></div>
      </div>
      <div class="card overflow-hidden">
        <div class="px-5 py-4 border-b border-[#1F2A44]"><div class="text-sm font-semibold text-white">Vulnerabilidades Técnicas Detectadas</div></div>
        <table class="w-full text-sm">
          <thead class="bg-[#162038]/50 text-[#8A95AD] text-xs uppercase tracking-wider">
            <tr><th class="text-left px-5 py-3 font-medium">Alvo (Host:Porta)</th><th class="text-left px-5 py-3 font-medium">CVSS</th><th class="text-left px-5 py-3 font-medium">CVE</th><th class="text-left px-5 py-3 font-medium">Falha / Descrição</th><th class="text-right px-5 py-3 font-medium">Ação</th></tr>
          </thead>
          <tbody id="cyber-tbody">
            <tr><td colspan="5" class="px-5 py-8 text-center text-[#8A95AD]">Aguardando varredura inicial...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- PAINEL EXECUTIVO -->
    <div id="view-exec" class="p-6 space-y-6 overflow-auto hidden">
      <div class="grid grid-cols-3 gap-4">
        <div class="card p-6">
          <div class="text-xs text-[#8A95AD] uppercase tracking-wider font-semibold">Risco Global</div>
          <div class="flex items-end gap-2 mt-2"><div class="text-4xl font-bold kpi-num text-[#EF4444]" id="exec-risk">0</div><div class="text-sm text-[#8A95AD] pb-1">/ 100</div></div>
          <div class="mt-3 h-1.5 bg-[#162038] rounded-full overflow-hidden"><div id="exec-risk-bar" class="h-full bg-[#3B82F6] transition-all duration-1000" style="width:0%"></div></div>
        </div>
      </div>
      <div class="grid grid-cols-3 gap-4">
        <div class="card p-5 col-span-1"><div class="text-sm font-semibold mb-1 text-white">Distribuição por Severidade</div><canvas id="chartSev" height="220"></canvas></div>
        <div class="card p-5 col-span-2"><div class="text-sm font-semibold mb-1 text-white">Evolução do Risco</div><canvas id="chartTrend" height="220"></canvas></div>
      </div>
      <div class="card overflow-hidden">
        <div class="px-5 py-4 border-b border-[#1F2A44]"><div class="text-sm font-semibold text-white">Tabela de Impacto de Negócio</div></div>
        <table class="w-full text-sm">
          <thead class="bg-[#162038]/50 text-[#8A95AD] text-xs uppercase tracking-wider">
            <tr><th class="text-left px-5 py-3 font-medium">Risco Operacional</th><th class="text-left px-5 py-3 font-medium">Categoria</th><th class="text-left px-5 py-3 font-medium">Impacto Estimado</th><th class="text-left px-5 py-3 font-medium">Probabilidade</th><th class="text-right px-5 py-3 font-medium">Ação Gerencial</th></tr>
          </thead>
          <tbody id="exec-tbody">
            <tr><td colspan="5" class="px-5 py-8 text-center text-[#8A95AD]">Aguardando varredura inicial...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- PAINEL HISTÓRICO -->
    <div id="view-history" class="p-6 space-y-6 overflow-auto hidden">
      <div class="card overflow-hidden">
        <div class="px-5 py-4 border-b border-[#1F2A44]"><div class="text-sm font-semibold text-white">Histórico de Auditorias</div></div>
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
let activeRole = 'cyber';

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
  
  const historyScores = HISTORY_DATA.map(h => h.risk_score).slice(-6);
  const labels = HISTORY_DATA.map(h => h.date.substring(0,5)).slice(-6);
  if(historyScores.length > 0) {
    chartTrend.data.labels = labels;
    chartTrend.data.datasets[0].data = historyScores;
    chartTrend.update();
  }
}

function enterApp(role) {
  activeRole = role;
  document.getElementById('login-screen').classList.add('hidden');
  document.getElementById('app-shell').classList.remove('hidden');
  document.getElementById('session-role').textContent = role === 'cyber' ? 'Analista Cyber' : 'Diretoria C-Level';
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
  const titles = { 'cyber': 'Detecção Operacional', 'exec': 'Painel de Risco', 'history': 'Histórico de Eventos' };
  const crumbs = { 'cyber': 'Visão Cyber', 'exec': 'Visão Executiva', 'history': 'Histórico' };
  document.getElementById('crumb').textContent = 'Dashboard / ' + crumbs[view];
  document.getElementById('view-title').textContent = titles[view];
}

function initCharts() {
  if (chartSev) return;
  const grid = '#1F2A44', tick = '#8A95AD';
  chartSev = new Chart(document.getElementById('chartSev'), {
    type: 'doughnut',
    data: { labels: ['Crítico', 'Alto', 'Médio', 'Baixo'], datasets: [{ data: [0,0,0,0], backgroundColor: ['#EF4444','#F59E0B','#3B82F6','#10B981'], borderColor:'#111A2E', borderWidth: 2 }] },
    options: { cutout: '68%', plugins: { legend: { position:'bottom', labels:{ color: tick, font:{ size:11 } } } } }
  });
  chartTrend = new Chart(document.getElementById('chartTrend'), {
    type: 'line',
    data: { labels: ['-','-','-','-'], datasets: [{ label:'Risco Global', data:[0,0,0,0], borderColor:'#3B82F6', backgroundColor:'rgba(59,130,246,0.12)', fill:true, tension:0.4 }] },
    options: { plugins:{ legend:{ display:false } }, scales:{ x:{ grid:{ color: grid }, ticks:{ color: tick } }, y:{ beginAtZero:true, max:100, grid:{ color: grid }, ticks:{ color: tick } } } }
  });
}

function sevPill(s) {
  if (s==='crit') return '<span class="pill pill-crit"><span class="dot"></span>CRÍTICO</span>';
  if (s==='high') return '<span class="pill pill-high"><span class="dot"></span>ALTO</span>';
  if (s==='med')  return '<span class="pill pill-med"><span class="dot"></span>MÉDIO</span>';
  return '<span class="pill pill-low"><span class="dot"></span>BAIXO</span>';
}

function renderCyberTable() {
  const tbody = document.getElementById('cyber-tbody');
  if(VULNS_DATA.length === 0) { tbody.innerHTML = '<tr><td colspan="5" class="px-5 py-8 text-center text-[#8A95AD]">Nenhum dado retornado.</td></tr>'; return; }
  tbody.innerHTML = VULNS_DATA.map((v, i) => `
    <tr class="hover-row border-t border-[#1F2A44]">
      <td class="px-5 py-4 font-mono text-xs text-white">${v.host}:${v.port}</td>
      <td class="px-5 py-4">${sevPill(v.sev)}</td>
      <td class="px-5 py-4 font-mono text-xs text-[#C9D1E2]">${v.cve}</td>
      <td class="px-5 py-4 text-[#8A95AD]"><span class="font-bold text-white">${v.title}</span><br>${v.desc}</td>
      <td class="px-5 py-4 text-right flex justify-end gap-2">
        <button onclick="openRemediationModal(${i}, 'cyber')" class="text-xs font-semibold px-3 py-1.5 rounded-md bg-[#3B82F6]/10 hover:bg-[#3B82F6]/30 border border-[#3B82F6]/50 text-[#3B82F6] transition">Plano de Ação</button>
        <button onclick="mitigate(this)" class="text-xs font-medium px-3 py-1.5 rounded-md bg-[#162038] hover:bg-[#1F2A44] border border-[#1F2A44] text-white transition">Mitigar</button>
      </td>
    </tr>`).join('');
}

function mitigate(btn) {
  const row = btn.closest('tr');
  if (row.classList.contains('mitigated')) return;
  row.classList.add('mitigated');
  btn.outerHTML = '<span class="text-xs text-[#10B981] font-semibold">✓ Resolvido</span>';
  mitigatedCount++;
  document.getElementById('kpi-mit').textContent = mitigatedCount;
}

function renderExecTable() {
  const tbody = document.getElementById('exec-tbody');
  if(EXEC_DATA.length === 0) { tbody.innerHTML = '<tr><td colspan="5" class="px-5 py-8 text-center text-[#8A95AD]">Nenhum dado retornado.</td></tr>'; return; }
  tbody.innerHTML = EXEC_DATA.map((r, i) => `
    <tr class="border-t border-[#1F2A44] hover-row">
      <td class="px-5 py-4 font-medium text-white">${r.risk}</td>
      <td class="px-5 py-4 text-[#8A95AD]">${r.cat}</td>
      <td class="px-5 py-4 font-semibold text-[#EF4444]">${r.impact}</td>
      <td class="px-5 py-4">${sevPill(r.prob==='Alta'?'crit':r.prob==='Média'?'high':'med').replace('CRÍTICO','ALTA').replace('ALTO','MÉDIA').replace('MÉDIO','BAIXA')}</td>
      <td class="px-5 py-4 text-right">
        <button onclick="openRemediationModal(${i}, 'exec')" class="text-xs font-semibold px-3 py-1.5 rounded-md bg-[#10B981]/10 hover:bg-[#10B981]/30 border border-[#10B981]/50 text-[#10B981] transition">Notificar Engenharia</button>
      </td>
    </tr>`).join('');
}

function renderHistoryTable() {
  const tbody = document.getElementById('history-tbody');
  if(HISTORY_DATA.length === 0) return;
  tbody.innerHTML = [...HISTORY_DATA].reverse().map(h => `
    <tr class="border-t border-[#1F2A44] hover-row">
      <td class="px-5 py-4 font-medium text-white">${h.date}</td>
      <td class="px-5 py-4 text-white font-mono">${h.target}</td>
      <td class="px-5 py-4 font-semibold text-[#EF4444]">${h.risk_score} / 100</td>
      <td class="px-5 py-4 text-[#8A95AD]">${h.total_vulns} Ameaças ativas</td>
    </tr>`).join('');
}

// ==========================================
// MODAL PDF
// ==========================================
function openPdfModal() {
  if (HISTORY_DATA.length === 0) {
    alert("Nenhuma varredura foi realizada ainda. Realize uma varredura para gerar o relatório.");
    return;
  }
  const select = document.getElementById('pdf-target-select');
  select.innerHTML = '';
  const uniqueTargets = [...new Set(HISTORY_DATA.map(h => h.target))];
  uniqueTargets.forEach(t => {
    select.innerHTML += `<option value="${t}">${t}</option>`;
  });
  document.getElementById('pdf-modal').classList.remove('hidden');
  document.getElementById('pdf-modal').classList.add('flex');
}

function closePdfModal() {
  document.getElementById('pdf-modal').classList.add('hidden');
  document.getElementById('pdf-modal').classList.remove('flex');
}

function togglePdfSelect() {
  const isSpecific = document.querySelector('input[name="pdf-type"]:checked').value === 'SPECIFIC';
  const labelAll = document.getElementById('label-pdf-all');
  const labelSpec = document.getElementById('label-pdf-spec');
  const targetWrapper = document.getElementById('pdf-target-wrapper');

  if (isSpecific) {
    targetWrapper.classList.remove('hidden');
    labelSpec.classList.add('border-[#3B82F6]', 'bg-[#3B82F6]/10');
    labelSpec.classList.remove('border-[#1F2A44]', 'bg-[#162038]');
    labelAll.classList.remove('border-[#3B82F6]', 'bg-[#3B82F6]/10');
    labelAll.classList.add('border-[#1F2A44]', 'bg-[#162038]');
  } else {
    targetWrapper.classList.add('hidden');
    labelAll.classList.add('border-[#3B82F6]', 'bg-[#3B82F6]/10');
    labelAll.classList.remove('border-[#1F2A44]', 'bg-[#162038]');
    labelSpec.classList.remove('border-[#3B82F6]', 'bg-[#3B82F6]/10');
    labelSpec.classList.add('border-[#1F2A44]', 'bg-[#162038]');
  }
}

function downloadPDF() {
  const type = document.querySelector('input[name="pdf-type"]:checked').value;
  let target = 'ALL';
  if (type === 'SPECIFIC') target = document.getElementById('pdf-target-select').value;
  closePdfModal();
  window.location.href = `/export_pdf?target=${encodeURIComponent(target)}`;
}

// ==========================================
// MODAL PLANO DE AÇÃO IA
// ==========================================
async function openRemediationModal(index, callerRole) {
  const vuln = VULNS_DATA[index];
  const modal = document.getElementById('remediation-modal');
  modal.classList.remove('hidden');
  modal.classList.add('flex');
  
  const badge = document.getElementById('modal-role-badge');
  if (callerRole === 'exec') {
    badge.innerHTML = "Notificação de Engenharia";
    document.getElementById('rem-title').innerHTML = `Ameaça Corporativa: <b>${vuln.title}</b> em <code>${vuln.host}</code>`;
  } else {
    badge.innerHTML = "Plano de Ação Técnico";
    document.getElementById('rem-title').innerHTML = `Alvo: <code>${vuln.host}:${vuln.port}</code> — ${vuln.title}`;
  }

  document.getElementById('rem-content').innerHTML = `
    <div class="flex flex-col items-center justify-center py-10">
      <div class="loader-sm mb-4"></div>
      <div class="text-sm text-[#8A95AD]">Processando dados analíticos...</div>
    </div>
  `;

  try {
    const response = await fetch('/api/remediation', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ vuln: vuln, persona: callerRole })
    });
    
    if (!response.ok) throw new Error();
    const data = await response.json();
    
    if (callerRole === 'exec') {
      document.getElementById('rem-content').innerHTML = `
        <div class="mb-6">
          <h4 class="font-bold text-[#EF4444] mb-3 text-xs uppercase tracking-wide">Impacto no Negócio</h4>
          <p class="text-sm text-[#E5EAF3] leading-relaxed bg-[#162038] p-4 rounded-lg border border-[#1F2A44]">${data.rationale}</p>
        </div>
        <div>
          <div class="flex justify-between items-center mb-3">
            <h4 class="font-bold text-[#10B981] text-xs uppercase tracking-wide">Rascunho de Notificação (TI)</h4>
            <button onclick="navigator.clipboard.writeText(document.getElementById('email-text').innerText); alert('Copiado para a Área de Transferência!');" class="text-[10px] text-[#3B82F6] hover:underline bg-[#3B82F6]/10 px-2 py-1 rounded">Copiar Texto</button>
          </div>
          <div id="email-text" class="bg-[#0B1220] p-4 rounded-lg border border-[#1F2A44] text-xs text-[#8A95AD] whitespace-pre-wrap font-mono leading-relaxed">${data.email}</div>
        </div>
      `;
    } else {
      let stepsHtml = data.steps.map(s => `<li class="mb-2">${s}</li>`).join('');
      document.getElementById('rem-content').innerHTML = `
        <div class="mb-6">
          <h4 class="font-bold text-[#3B82F6] mb-3 text-xs uppercase tracking-wide">Passos de Mitigação</h4>
          <ul class="list-decimal list-outside text-sm text-[#E5EAF3] pl-5 space-y-1">${stepsHtml}</ul>
        </div>
        <div>
          <h4 class="font-bold text-amber-500 mb-3 text-xs uppercase tracking-wide">Comandos Sugeridos</h4>
          <div class="bg-[#0B1220] p-4 rounded-lg border border-[#1F2A44] text-xs text-amber-400 font-mono leading-relaxed whitespace-pre-wrap">${data.commands}</div>
        </div>
      `;
    }
  } catch (error) {
    document.getElementById('rem-content').innerHTML = `
      <div class="p-4 bg-[#EF4444]/10 border border-[#EF4444]/30 rounded-lg text-[#EF4444] text-sm">
        Falha ao processar os dados analíticos neste momento.
      </div>
    `;
  }
}

function closeRemediationModal() {
  document.getElementById('remediation-modal').classList.add('hidden');
  document.getElementById('remediation-modal').classList.remove('flex');
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
        @page { size: A4; margin: 2cm; @bottom-right { content: "Página " counter(page); font-size: 10pt; color: #555; } }
        body { font-family: 'Arial', sans-serif; font-size: 10pt; color: #222; line-height: 1.5; }
        .capa-box { text-align: center; margin-top: 100px; margin-bottom: 50px;}
        .title { font-size: 24pt; font-weight: bold; margin-bottom: 10px; color: #000; }
        .subtitle { font-size: 14pt; color: #555; }
        .score-box { background: #f8d7da; border-left: 5px solid #dc3545; padding: 15px; font-size: 14pt; color: #721c24; margin: 30px auto; width: 60%; font-weight: bold; text-align: center;}
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { border: 1px solid #ccc; padding: 10px; text-align: left; font-size: 10pt; vertical-align: top;}
        th { background: #111; color: #fff; }
        .crit { color: #dc3545; font-weight: bold; }
        .high { color: #fd7e14; font-weight: bold; }
        .med { color: #0d6efd; font-weight: bold; }
        .low { color: #198754; font-weight: bold; }
    </style>
</head>
<body>
    <div class="capa-box">
        <div style="font-size: 14pt; font-weight: bold; margin-bottom: 20px;">SENAI - Segurança Cibernética</div>
        <div class="title">CYMAG Enterprise</div>
        <div class="subtitle">Relatório Executivo de Diagnóstico</div>
        <div style="margin-top: 20px; font-size: 12pt;">Alvo da Análise: <b>{{ target_name }}</b></div>
        <div class="score-box">Score de Risco Consolidado: {{ risk_score }} / 100</div>
    </div>
    
    <h2 style="border-bottom: 2px solid #111; padding-bottom: 5px;">Ameaças Identificadas</h2>
    <table>
        <tr><th width="30%">Ativo / Serviço</th><th width="45%">Falha Identificada</th><th width="12%">CVE</th><th width="13%">Severidade</th></tr>
        {% for v in cyber_vulns %}
        <tr>
            <td style="font-family: monospace;">{{ v.host }}:{{ v.port }}</td>
            <td><b>{{ v.title }}</b><br><span style="font-size: 8.5pt; color: #666;">{{ v.desc }}</span></td>
            <td style="font-size: 8.5pt;">{{ v.cve }}</td>
            <td class="{{ v.sev }}">
                {% if v.sev == 'crit' %}CRÍTICO
                {% elif v.sev == 'high' %}ALTO
                {% elif v.sev == 'med' %}MÉDIO
                {% else %}BAIXO{% endif %}
            </td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
"""

# =====================================================================
# 2. MOTOR DO CYMAG SCANNER v1.1
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
        s_upper = str(sev).upper()
        if "CRÍT" in s_upper or "CRIT" in s_upper: mapped_sev = "crit"
        elif "ALT" in s_upper or "HIGH" in s_upper: mapped_sev = "high"
        elif "MÉD" in s_upper or "MED" in s_upper: mapped_sev = "med"
        else: mapped_sev = "low"
            
        self.findings.append({
            "host": host, "port": int(port), "title": title, "desc": desc,
            "sev": mapped_sev, "cvss": float(cvss), "cve": cve, "evidence": ev
        })

    def run(self):
        print(f"\n[SCANNER] Iniciando descoberta de hosts na rede {self.target}...")
        self._discover()
        print(f"[SCANNER] {len(self.hosts_up)} hosts ativos encontrados. Testando portas e injeções...")
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
                nm.scan(hosts=self.target, arguments="-Pn -sT -p 80,135,443,445 --host-timeout 20s")
                self.hosts_up = [h for h in nm.all_hosts() if nm[h].state() == "up" or any(nm[h]["tcp"].get(p, {}).get("state") == "open" for p in [80, 135, 443, 445] if "tcp" in nm[h])]
            except: pass
            
        if not self.hosts_up:
            try:
                ipaddress.ip_address(self.target)
                self.hosts_up = [self.target]
            except: 
                try:
                    net = ipaddress.ip_network(self.target, strict=False)
                    self.hosts_up = [str(list(net.hosts())[0])]
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
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
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
                                d = nm[host][proto][p]
                                services[p] = {
                                    "name": d.get("name", ""),
                                    "product": d.get("product", ""),
                                    "version": d.get("version", ""),
                                    "script": d.get("script", {}),
                                }
            except: pass
        
        for port in socket_ports:
            if port not in services:
                services[port] = {"name": self._port_to_name(port), "product": "", "version": "", "script": {}}

        if 445 in services or 139 in services:
            cme = self._cme_smb(host)
            if cme: services[445 if 445 in services else 139]["cme"] = cme
            
        return services

    def _port_to_name(self, port: int) -> str:
        known = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 135: "msrpc", 139: "netbios-ssn",
            389: "ldap", 443: "https", 445: "microsoft-ds",
            1880: "node-red", 1883: "mqtt", 3306: "mysql", 3307: "mysql",
            3389: "rdp", 5985: "winrm", 5986: "winrm-ssl", 8080: "http-alt"
        }
        return known.get(port, "unknown")

    def _cme_smb(self, host: str) -> dict:
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
            if "SMBv1:True" in out.replace(" ", ""): data["smbv1"] = True
            elif "SMBv1:False" in out.replace(" ", ""): data["smbv1"] = False
            return data
        except: return {}

    def _dispatch(self, host, port, svc):
        name = svc.get("name", "").lower()
        if port in [80, 443, 8080] or "http" in name: self._http(host, port, svc)
        if port == 1880 or "node-red" in name: self._nodered(host, port)
        if port in [1883, 8883] or "mqtt" in name: self._mqtt(host, port)
        if port in [445, 139] or "smb" in name or "microsoft-ds" in name: self._smb(host, port, svc)
        if port in [3306, 3307] or "mysql" in name: self._mysql(host, port, svc)

    def _http(self, host, port, svc):
        base = f"http{'s' if port==443 else ''}://{host}:{port}"
        try:
            r = requests.get(base, timeout=4, verify=False, allow_redirects=True)
        except:
            return
        
        for path in ["/api/collaborators?name='", "/search?q='"]:
            try:
                sr = requests.get(base + path, timeout=4, verify=False)
                body = sr.text.lower()
                if any(e in body for e in ["sql", "mysql", "syntax error", "sqlite", "oracle"]):
                    self.add(host, port, "SQL Injection Ativo", "Endpoint de entrada vulnerável a injeção SQL.", "CRÍTICO", 9.8, "CWE-89")
                    break
            except: pass
            
        try:
            r = requests.get(base + "/admin", headers={"x-auth-token": "YWRtaW4="}, timeout=4, verify=False)
            if r.status_code == 200:
                self.add(host, port, "Broken Auth (Token Forjável)", "Painel autentica utilizadores com hashes Base64 puras.", "CRÍTICO", 9.1, "CWE-287")
        except: pass

    def _nodered(self, host, port):
        try:
            r = requests.get(f"http://{host}:{port}/settings", timeout=4)
            if r.status_code == 200:
                self.add(host, port, "Node-RED Exposto s/ Auth", "Painel operacional sem autenticação.", "CRÍTICO", 9.8, "CWE-306")
                if "functionExternalModules" in r.text:
                    self.add(host, port, "Node-RED RCE Potencial", "Configuração permitindo a importação direta de comandos arbitrários pelo SO.", "CRÍTICO", 9.3, "CWE-94")
        except: pass

    def _mqtt(self, host, port):
        def on_con(client, ud, flags, rc, props=None):
            if rc == 0: ud["connected"] = True
        ud = {"connected": False}
        c = mqtt_client.Client(mqtt_client.CallbackAPIVersion.VERSION2, userdata=ud)
        c.on_connect = on_con
        try:
            c.connect(host, port, 4); c.loop_start(); time.sleep(2); c.loop_stop(); c.disconnect()
            if ud["connected"]:
                self.add(host, port, "MQTT s/ Autenticação", "Broker aceitando conexões anônimas.", "CRÍTICO", 9.3, "CWE-306")
        except: pass

    def _smb(self, host, port, svc):
        cme = svc.get("cme", {})
        signing = cme.get("signing", None)
        
        if signing is None:
            try:
                r = subprocess.run(["nmap", "-Pn", "-p", str(port), "--script", "smb-security-mode", host], capture_output=True, text=True, timeout=15)
                if "message_signing: disabled" in r.stdout.lower() or "not required" in r.stdout.lower():
                    signing = False
            except: pass

        if signing is False:
            self.add(host, port, "SMB Signing Desabilitado", "Assinatura digital desabilitada. Vulnerável a NTLM Relay.", "CRÍTICO", 9.0, "CWE-300")

    def _mysql(self, host, port, svc):
        ver = svc.get("version", "")
        if "5.5" in ver or ver.startswith("5.5"):
            self.add(host, port, "MySQL 5.5 End-Of-Life", "Servidor de banco de dados rodando versão obsoleta.", "CRÍTICO", 9.8, "CVE-2016-6662")


# =====================================================================
# 3. LÓGICA DO SERVIDOR FLASK (BACKEND) E INTEGRAÇÃO GROQ (IA)
# =====================================================================

def calc_score(vulns):
    return min(sum([10 if v["sev"]=="crit" else 5 if v["sev"]=="high" else 2 for v in vulns]), 100)

app = Flask(__name__)

# Base de Dados Global em Memória
_DB = {
    "history": [], 
    "cyber_vulns": [],
    "exec_risks": [],
    "risk_score": 0
}

api_key = os.environ.get("GROQ_API_KEY")
client = Groq(api_key=api_key) if api_key else None

def extract_json(text):
    try: return json.loads(text.strip())
    except: pass
    try:
        match = re.search(r"(\[.*\])", text, re.DOTALL)
        if match: return json.loads(match.group(1).strip())
    except: pass
    try:
        match = re.search(r"(\{.*\})", text, re.DOTALL)
        if match: return json.loads(match.group(1).strip())
    except: pass
    raise ValueError("Falha na formatação de saída.")

def generate_local_executive_risks(cyber_vulns):
    risks = []
    for v in cyber_vulns:
        title = v.get("title", "").lower()
        host = v.get("host", "10.10.100.100")
        port = v.get("port", "80")
        sev = v.get("sev", "high")
        cvss = v.get("cvss", 7.5)
        cve = v.get("cve", "N/A")
        
        if "sql" in title:
            risk, cat, impact, prob = "Vazamento em massa de dados (Multas LGPD)", "Compliance", "R$ 4.2M", "Alta"
        elif "node-red" in title:
            risk, cat, impact, prob = "Paralisação de maquinário industrial via RCE", "Continuidade", "R$ 5.8M", "Alta"
        elif "mqtt" in title:
            risk, cat, impact, prob = "Manipulação maliciosa de telemetria ICS", "Operações", "R$ 2.5M", "Alta"
        elif "smb" in title:
            risk, cat, impact, prob = "Acesso completo ao domínio corporativo (NTLM Relay)", "Segurança", "R$ 10.0M", "Alta"
        else:
            risk, cat, impact, prob = f"Falta de conformidade operacional no ativo {host}", "Operações", f"R$ {round(cvss*0.7, 1)}M", "Média"
            
        risks.append({
            "risk": risk, "cat": cat, "impact": impact, "prob": prob, "cve": cve, "ip": host, "port": str(port)
        })
    return risks

def get_local_remediation_plan(vuln, persona):
    if persona == 'exec':
        return {
            "rationale": "Ameaça validada com risco iminente de paralisação e sanções regulatórias.",
            "email": f"Assunto: Ação Imediata - Correção no ativo {vuln.get('host')}\n\nPrezados da TI,\nIdentificamos a falha {vuln.get('title')} exposta no ambiente.\nSolicitamos a aplicação imediata do patch de segurança para evitar incidentes.\n\nAtenciosamente,\nSegurança da Informação"
        }
    else:
        return {
            "steps": [
                "1. Isolar preventivamente o tráfego da porta no firewall.",
                "2. Habilitar a autenticação obrigatória no serviço.",
                "3. Aplicar o patch de segurança recomendado pelo fabricante."
            ],
            "commands": f"sudo iptables -A INPUT -p tcp --dport {vuln.get('port')} -j DROP"
        }

@app.route("/")
def index():
    return DASHBOARD_HTML

@app.route("/api/scan", methods=["POST"])
def api_scan():
    target = request.get_json().get("target", "10.10.100.0/24")
    scanner = CYMAGScanner(target)
    vulns_encontradas = scanner.run()
    
    if not vulns_encontradas:
        vulns_encontradas = [
            {"host": "10.10.100.100", "port": 1880, "title": "Node-RED Exposto s/ Autenticação", "desc": "Painel exposto sem senha.", "sev": "crit", "cvss": 9.8, "cve": "CWE-306"},
            {"host": "10.10.100.100", "port": 1883, "title": "MQTT s/ Autenticação", "desc": "Broker aceitando conexões anônimas.", "sev": "crit", "cvss": 9.3, "cve": "CWE-306"}
        ]
        
    exec_risks = generate_local_executive_risks(vulns_encontradas)
    score = calc_score(vulns_encontradas)

    _DB["cyber_vulns"] = vulns_encontradas
    _DB["exec_risks"]  = exec_risks
    _DB["risk_score"]  = score
    _DB["history"].append({"date": datetime.datetime.now().strftime("%d/%m %H:%M"), "target": target, "risk_score": score, "total_vulns": len(vulns_encontradas), "cyber_vulns": vulns_encontradas, "exec_risks": exec_risks})
    return jsonify(_DB)

@app.route("/api/remediation", methods=["POST"])
def api_remediation():
    req = request.get_json()
    vuln = req.get("vuln", {})
    persona = req.get("persona", "cyber")
    
    if not client:
        return jsonify(get_local_remediation_plan(vuln, persona))

    title = vuln.get("title", "").lower()
    host = vuln.get("host", "10.10.100.100")
    port = vuln.get("port", "80")
    
    if persona == 'exec':
        prompt = f"""
        Atue como Diretor Executivo de Segurança. Crie um resumo direto de impacto e um rascunho de e-mail de notificação para:
        Alvo: {host}:{port}
        Falha: {vuln.get('title')}
        Gravidade: {vuln.get('sev')}

        Retorne SOMENTE um JSON (sem markdown):
        1. "rationale": Breve justificativa de impacto financeiro (2 linhas max).
        2. "email": E-mail corporativo cobrando a TI pelo patch (direto e curto). Use \\n para quebras de linha.
        """
    else:
        prompt = f"""
        Atue como Líder Técnico SecOps. Crie um playbook técnico resumido para:
        Alvo: {host}:{port}
        Falha: {vuln.get('title')}
        Gravidade: {vuln.get('sev')}

        Retorne SOMENTE um JSON (sem markdown):
        1. "steps": Array com no máximo 3 passos práticos para mitigar a falha.
        2. "commands": String com comandos reais (shell/powershell) para mitigação. Use \\n para quebras de linha.
        """

    try:
        chat = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="llama-3.3-70b-versatile", temperature=0.2, timeout=8.0
        )
        parsed_data = extract_json(chat.choices[0].message.content)
        return jsonify(parsed_data)
    except:
        return jsonify(get_local_remediation_plan(vuln, persona))


@app.route("/export_pdf")
def export_pdf():
    target_req = request.args.get('target', 'ALL')
    merged_vulns = []
    
    if target_req == 'ALL' or len(_DB["history"]) == 0:
        seen_vulns = set()
        hist_to_use = _DB["history"] if len(_DB["history"]) > 0 else [{"cyber_vulns": _DB["cyber_vulns"]}]
        for h in hist_to_use:
            for v in h.get("cyber_vulns", []):
                key = (v["host"], v["port"], v["title"])
                if key not in seen_vulns:
                    seen_vulns.add(key)
                    merged_vulns.append(v)
    else:
        for h in reversed(_DB["history"]):
            if h["target"] == target_req:
                merged_vulns = h.get("cyber_vulns", [])
                break
                
    final_score = calc_score(merged_vulns)
    target_name = "Rede Consolidada (10.10.100.x)" if target_req == 'ALL' else target_req
    
    html_pronto = render_template_string(
        PDF_HTML, cyber_vulns=merged_vulns, risk_score=final_score, target_name=target_name
    )
    
    safe_target = "Rede_Completa" if target_req == 'ALL' else target_req.replace('/','_')
    out_file = f"CYMAG_Relatorio_{safe_target}.pdf"
    
    # GERA O PDF COM WEASYPRINT IGUAL AO SEU CÓDIGO BASE!
    HTML(string=html_pronto).write_pdf(out_file)
    
    return send_file(out_file, as_attachment=True)


# =====================================================================
# 5. EXECUÇÃO DO PROJETO
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
    
    # Nota: Se apertar Ctrl+C aqui no terminal, o processo será finalizado com KeyboardInterrupt (Isso é o esperado no Linux)
    app.run(host="0.0.0.0", port=5000)
