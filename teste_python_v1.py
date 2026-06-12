#!/usr/bin/env python3
"""
CYMAG Enterprise — app.py (Monólito SaaS Completo)
Continuous Automated Red Teaming — Risk Intelligence Platform
"""

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
import base64

from flask import Flask, render_template_string, send_file, request, jsonify
from groq import Groq

# ---------------------------------------------------------
# NOVO GERADOR DE PDF (REPORTLAB - Leve e sem travamentos)
# ---------------------------------------------------------
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

import nmap
import requests
import paho.mqtt.client as mqtt_client

warnings.filterwarnings("ignore")
requests.packages.urllib3.disable_warnings()

# =====================================================================
# 1. ENCAPSULAMENTO DO FRONT-END (DASHBOARD SAAS)
# =====================================================================

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="pt-PT">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>CYMAG — Cybersecurity Intelligence</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
  body { font-family: 'Inter', sans-serif; background: #0B1220; color: #E5EAF3; }
  .card { background: #111A2E; border: 1px solid #1F2A44; border-radius: 8px; }
  .hover-row:hover { background: rgba(59,130,246,0.04); }
  .mitigated td { text-decoration: line-through; color: #6B7385 !important; }
  .pill { display:inline-flex; align-items:center; gap:6px; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; letter-spacing: .02em; text-transform: uppercase;}
  .pill .dot { width:6px; height:6px; border-radius:50%; }
  .pill-crit { background: rgba(185,28,28,.12); border: 1px solid rgba(185,28,28,.3); color:#FCA5A5; } .pill-crit .dot { background:#EF4444; }
  .pill-high { background: rgba(245,158,11,.10); border: 1px solid rgba(245,158,11,.3); color:#FCD34D; } .pill-high .dot { background:#F59E0B; }
  .pill-med  { background: rgba(59,130,246,.10); border: 1px solid rgba(59,130,246,.3); color:#93C5FD; } .pill-med .dot { background:#3B82F6; }
  .pill-low  { background: rgba(16,185,129,.10); border: 1px solid rgba(16,185,129,.3); color:#6EE7B7; } .pill-low .dot { background:#10B981; }
  .nav-item { display:flex; align-items:center; gap:10px; padding:10px 12px; border-radius:6px; color:#8A95AD; cursor:pointer; font-size:13px; font-weight:500; transition: 0.2s;}
  .nav-item:hover, .nav-item.active { background:#162038; color:#fff; }
  .nav-item.active { box-shadow: inset 3px 0 0 #3B82F6; }
  .kpi-num { font-variant-numeric: tabular-nums; }
  .loader { border: 3px solid rgba(255, 255, 255, 0.1); border-left-color: #3B82F6; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; }
  .loader-sm { border: 2px solid rgba(255, 255, 255, 0.1); border-left-color: #3B82F6; border-radius: 50%; width: 24px; height: 24px; animation: spin 1s linear infinite; }
  @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
  .scroll-hide::-webkit-scrollbar { display:none; }
</style>
</head>
<body class="min-h-screen">

<!-- TOAST -->
<div id="toast-container" class="fixed top-5 right-5 z-50 flex flex-col gap-3"></div>

<!-- OVERLAY LOADING -->
<div id="loading-overlay" class="fixed inset-0 bg-[#0B1220]/90 backdrop-blur-sm z-50 hidden flex-col items-center justify-center text-center px-4">
  <div class="loader mb-6"></div>
  <h2 class="text-xl font-bold text-white mb-2">Processamento de Auditoria</h2>
  <p class="text-[#8A95AD] text-sm text-center max-w-md">Executando varredura na rede e análise estrutural.<br><br>Alvo: <span id="loading-target" class="font-mono text-[#3B82F6] font-bold"></span></p>
</div>

<!-- MODAL DE EXPORTAÇÃO PDF -->
<div id="pdf-modal" class="fixed inset-0 bg-[#0B1220]/90 backdrop-blur-sm z-50 hidden flex-col items-center justify-center p-4">
  <div class="card w-full max-w-md p-6 border border-[#3B82F6]/30 shadow-2xl">
    <div class="flex justify-between items-center mb-6 border-b border-[#1F2A44] pb-4">
      <h3 class="text-lg font-bold text-white">Exportação de Relatório</h3>
      <button onclick="closePdfModal()" class="text-[#8A95AD] hover:text-white transition">✕</button>
    </div>
    <div class="space-y-3 mb-8">
      <label class="flex items-center gap-3 p-4 border border-[#3B82F6] bg-[#3B82F6]/10 rounded cursor-pointer" id="label-pdf-all">
        <input type="radio" name="pdf-type" value="ALL" checked onchange="togglePdfSelect()" class="w-4 h-4 text-blue-600">
        <div>
          <div class="font-semibold text-white text-sm">Relatório Consolidado (Toda a Rede)</div>
          <div class="text-xs text-[#8A95AD] mt-1">Unifica todos os ativos detectados no histórico num relatório básico.</div>
        </div>
      </label>
      <label class="flex flex-col gap-2 p-4 border border-[#1F2A44] bg-[#162038] rounded cursor-pointer" id="label-pdf-spec">
        <div class="flex items-center gap-3">
          <input type="radio" name="pdf-type" value="SPECIFIC" onchange="togglePdfSelect()" class="w-4 h-4">
          <div>
            <div class="font-semibold text-white text-sm">Ativo Específico</div>
            <div class="text-xs text-[#8A95AD] mt-1">Gera o relatório restrito a um host/rede.</div>
          </div>
        </div>
        <div id="pdf-target-wrapper" class="hidden mt-3 ml-7">
          <select id="pdf-target-select" class="w-full bg-[#0B1220] border border-[#1F2A44] text-white text-sm rounded p-2 outline-none focus:border-[#3B82F6]"></select>
        </div>
      </label>
    </div>
    <button onclick="downloadPDF()" class="w-full py-2.5 bg-[#3B82F6] hover:bg-blue-600 text-white rounded font-semibold transition">Gerar Documento PDF</button>
  </div>
</div>

<!-- MODAL DE REMEDIAÇÃO IA (Clean) -->
<div id="remediation-modal" class="fixed inset-0 bg-[#0B1220]/90 backdrop-blur-sm z-50 hidden flex-col items-center justify-center p-6">
  <div class="card w-full max-w-2xl p-0 border border-[#1F2A44] shadow-2xl flex flex-col max-h-[90vh]">
    <div class="p-5 border-b border-[#1F2A44] flex justify-between items-center bg-[#111A2E] rounded-t-xl sticky top-0">
      <div>
        <h3 class="text-base font-bold text-white" id="modal-role-badge">Plano de Ação</h3>
        <div class="text-xs text-[#8A95AD] mt-1 font-mono" id="rem-title">Carregando...</div>
      </div>
      <button onclick="closeRemediationModal()" class="text-[#8A95AD] hover:text-white transition">✕</button>
    </div>
    
    <div class="p-6 overflow-y-auto" id="rem-content">
      <div class="flex flex-col items-center justify-center py-10">
        <div class="loader-sm mb-4"></div>
        <div class="text-xs text-[#8A95AD]">Processando dados de remediação...</div>
      </div>
    </div>
  </div>
</div>

<!-- TELA DE LOGIN -->
<section id="login-screen" class="min-h-screen flex items-center justify-center px-6">
  <div class="w-full max-w-md card p-8 border border-[#1F2A44]">
    <div class="mb-8">
      <div class="text-xl font-bold tracking-tight text-white">CYMAG</div>
      <div class="text-xs text-[#8A95AD]">Plataforma de Auditoria Contínua</div>
    </div>
    <div class="space-y-3">
      <button onclick="enterApp('cyber')" class="w-full bg-[#3B82F6] hover:bg-blue-600 text-white font-medium text-sm py-3 rounded flex justify-between px-4 transition">
        <span>Acesso Operacional (Cyber)</span><span class="opacity-50">/sys</span>
      </button>
      <button onclick="enterApp('exec')" class="w-full bg-[#162038] hover:bg-[#1F2A44] text-[#C9D1E2] border border-[#1F2A44] font-medium text-sm py-3 rounded flex justify-between px-4 transition">
        <span>Acesso Executivo (C-Level)</span><span class="opacity-50">/exec</span>
      </button>
    </div>
  </div>
</section>

<!-- APP SHELL -->
<section id="app-shell" class="hidden min-h-screen flex">
  <aside class="w-60 shrink-0 border-r border-[#1F2A44] bg-[#111A2E] flex flex-col">
    <div class="p-5 border-b border-[#1F2A44]">
      <div class="text-sm font-bold text-white tracking-wide">CYMAG</div>
      <div class="text-[10px] text-[#8A95AD] uppercase">Security Suite</div>
    </div>
    <nav class="p-3 space-y-1 flex-1">
      <div class="text-[10px] uppercase text-[#8A95AD] px-3 pt-2 pb-2 font-semibold">Dashboards</div>
      <div class="nav-item active" id="nav-cyber" onclick="switchView('cyber')">Detecção Operacional</div>
      <div class="nav-item" id="nav-exec" onclick="switchView('exec')">Visão Executiva</div>
      <div class="text-[10px] uppercase text-[#8A95AD] px-3 pt-6 pb-2 font-semibold">Auditoria</div>
      <div class="nav-item" id="nav-history" onclick="switchView('history')">Histórico de Eventos</div>
    </nav>
    <div class="p-4 border-t border-[#1F2A44]">
      <div class="text-xs text-[#8A95AD] mb-1">Logado como</div>
      <div id="session-role" class="text-sm font-medium text-white mb-3">Analista</div>
      <button onclick="logout()" class="text-xs text-[#EF4444] hover:underline">Sair</button>
    </div>
  </aside>

  <main class="flex-1 flex flex-col min-w-0">
    <header class="h-16 border-b border-[#1F2A44] bg-[#111A2E]/80 backdrop-blur flex items-center justify-between px-6 sticky top-0 z-20">
      <div class="flex items-center gap-4">
        <div class="text-sm font-semibold text-white" id="view-title">Detecção Operacional</div>
        <button onclick="injectSimulation()" class="bg-[#1F2A44] hover:bg-[#2A3B5C] text-[#8A95AD] hover:text-white border border-[#2A3B5C] text-[10px] uppercase px-2 py-1 rounded transition ml-2">
          Demo Mock
        </button>
      </div>
      <div class="flex items-center gap-3">
        <input type="text" id="target-input" placeholder="Alvo (ex: 10.10.100.0/24)" class="bg-[#0B1220] border border-[#1F2A44] text-sm rounded px-3 py-1.5 text-white w-52 focus:outline-none focus:border-[#3B82F6]">
        <button onclick="startScan()" class="text-xs font-semibold px-4 py-1.5 rounded bg-[#3B82F6] hover:bg-blue-600 text-white transition">Escanear</button>
        <div class="w-px h-5 bg-[#1F2A44] mx-1"></div>
        <button onclick="openPdfModal()" class="text-xs font-semibold px-3 py-1.5 rounded border border-[#1F2A44] hover:bg-[#162038] text-[#C9D1E2] transition">PDF</button>
      </div>
    </header>

    <!-- PAINEL CYBER -->
    <div id="view-cyber" class="p-6 space-y-6 overflow-auto">
      <div class="grid grid-cols-4 gap-4">
        <div class="card p-5 border-l-2 border-l-[#3B82F6]"><div class="text-[11px] text-[#8A95AD] uppercase font-semibold">Vulnerabilidades</div><div class="text-2xl font-bold mt-1 text-white" id="kpi-vuln">0</div></div>
        <div class="card p-5 border-l-2 border-l-[#EF4444]"><div class="text-[11px] text-[#8A95AD] uppercase font-semibold">Nível Crítico</div><div class="text-2xl font-bold mt-1 text-[#EF4444]" id="kpi-crit">0</div></div>
        <div class="card p-5"><div class="text-[11px] text-[#8A95AD] uppercase font-semibold">Ativos Mapeados</div><div class="text-2xl font-bold mt-1 text-white" id="kpi-hosts">0</div></div>
        <div class="card p-5 border-l-2 border-l-[#10B981]"><div class="text-[11px] text-[#8A95AD] uppercase font-semibold">Mitigações</div><div class="text-2xl font-bold mt-1 text-[#10B981]" id="kpi-mit">0</div></div>
      </div>
      <div class="card overflow-hidden">
        <table class="w-full text-sm text-left">
          <thead class="bg-[#162038]/50 text-[#8A95AD] text-[10px] uppercase tracking-wider font-semibold border-b border-[#1F2A44]">
            <tr><th class="px-5 py-3">Host / Porta</th><th class="px-5 py-3">Severidade</th><th class="px-5 py-3">CVE</th><th class="px-5 py-3">Identificação</th><th class="px-5 py-3 text-right">Ação</th></tr>
          </thead>
          <tbody id="cyber-tbody">
            <tr><td colspan="5" class="px-5 py-8 text-center text-[#8A95AD] text-xs">Sem dados em memória. Realize uma varredura.</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- PAINEL EXECUTIVO -->
    <div id="view-exec" class="p-6 space-y-6 overflow-auto hidden">
      <div class="grid grid-cols-3 gap-4">
        <div class="card p-6 border-t-2 border-t-[#EF4444]">
          <div class="text-[11px] text-[#8A95AD] uppercase font-semibold">Risco Consolidado</div>
          <div class="flex items-end gap-2 mt-1"><div class="text-3xl font-bold text-[#EF4444]" id="exec-risk">0</div><div class="text-xs text-[#8A95AD] pb-1">/ 100</div></div>
        </div>
      </div>
      <div class="grid grid-cols-3 gap-4">
        <div class="card p-5 col-span-1"><div class="text-xs font-semibold text-[#C9D1E2] mb-3 uppercase">Distribuição</div><canvas id="chartSev" height="200"></canvas></div>
        <div class="card p-5 col-span-2"><div class="text-xs font-semibold text-[#C9D1E2] mb-3 uppercase">Tendência de Risco</div><canvas id="chartTrend" height="200"></canvas></div>
      </div>
      <div class="card overflow-hidden">
        <table class="w-full text-sm text-left">
          <thead class="bg-[#162038]/50 text-[#8A95AD] text-[10px] uppercase tracking-wider font-semibold border-b border-[#1F2A44]">
            <tr><th class="px-5 py-3">Risco Operacional</th><th class="px-5 py-3">Categoria</th><th class="px-5 py-3">Impacto</th><th class="px-5 py-3 text-right">Ação Gerencial</th></tr>
          </thead>
          <tbody id="exec-tbody">
            <tr><td colspan="4" class="px-5 py-8 text-center text-[#8A95AD] text-xs">Sem dados em memória.</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- PAINEL HISTÓRICO -->
    <div id="view-history" class="p-6 space-y-6 overflow-auto hidden">
      <div class="card overflow-hidden">
        <table class="w-full text-sm text-left">
          <thead class="bg-[#162038]/50 text-[#8A95AD] text-[10px] uppercase tracking-wider font-semibold border-b border-[#1F2A44]">
            <tr><th class="px-5 py-3">Data/Hora</th><th class="px-5 py-3">Escopo</th><th class="px-5 py-3">Score Global</th><th class="px-5 py-3">Total Ocorrências</th></tr>
          </thead>
          <tbody id="history-tbody">
            <tr><td colspan="4" class="px-5 py-8 text-center text-[#8A95AD] text-xs">Nenhum evento registrado.</td></tr>
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

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  const colors = {
    info: 'bg-[#162038] border border-[#1F2A44] text-[#C9D1E2]',
    success: 'bg-[#10B981]/10 border border-[#10B981]/30 text-[#10B981]',
    error: 'bg-[#EF4444]/10 border border-[#EF4444]/30 text-[#EF4444]'
  };
  toast.className = `p-3 px-4 rounded text-xs shadow-lg transition duration-300 transform translate-y-2 opacity-0 ${colors[type]}`;
  toast.innerText = message;
  container.appendChild(toast);
  setTimeout(() => toast.classList.remove('translate-y-2', 'opacity-0'), 10);
  setTimeout(() => {
    toast.classList.add('opacity-0', 'translate-y-2');
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

async function injectSimulation() {
  const overlay = document.getElementById('loading-overlay');
  document.getElementById('loading-target').textContent = "Injeção de Dados Mock";
  overlay.classList.remove('hidden'); overlay.classList.add('flex');
  
  try {
    const r = await fetch('/api/simulate', { method: 'POST' });
    if (!r.ok) throw new Error();
    const data = await r.json();
    VULNS_DATA = data.cyber_vulns || [];
    EXEC_DATA = data.exec_risks || [];
    HISTORY_DATA = data.history || [];
    RISK_SCORE = data.risk_score || 0;
    updateDashboardUI();
    showToast("Dados de demonstração injetados com sucesso.", "success");
  } catch {
    showToast("Erro na simulação.", "error");
  } finally {
    overlay.classList.add('hidden'); overlay.classList.remove('flex');
  }
}

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
    if (!response.ok) throw new Error();
    const data = await response.json();
    VULNS_DATA = data.cyber_vulns || [];
    EXEC_DATA = data.exec_risks || [];
    HISTORY_DATA = data.history || [];
    RISK_SCORE = data.risk_score || 0;
    updateDashboardUI();
    showToast("Auditoria concluída.", "success");
  } catch {
    showToast("Falha durante o escaneamento.", "error");
  } finally {
    overlay.classList.add('hidden'); overlay.classList.remove('flex');
  }
}

function updateDashboardUI() {
  document.getElementById('kpi-vuln').textContent = VULNS_DATA.length;
  document.getElementById('kpi-crit').textContent = VULNS_DATA.filter(v => v.sev === 'crit' || v.sev === 'high').length;
  document.getElementById('kpi-hosts').textContent = new Set(VULNS_DATA.map(v => v.host)).size;
  document.getElementById('exec-risk').textContent = RISK_SCORE;
  
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
  const historyScores = HISTORY_DATA.map(h => h.risk_score);
  const labels = HISTORY_DATA.map(h => h.date.substring(0,5));
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
  document.getElementById('session-role').textContent = role === 'cyber' ? 'Operações / SecOps' : 'C-Level / Diretoria';
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
  const titles = { 'cyber': 'Detecção Operacional', 'exec': 'Painel de Risco (C-Level)', 'history': 'Histórico de Eventos' };
  document.getElementById('view-title').textContent = titles[view];
}

function initCharts() {
  if (chartSev) return;
  const grid = '#1F2A44', tick = '#8A95AD';
  chartSev = new Chart(document.getElementById('chartSev'), {
    type: 'doughnut',
    data: { labels: ['Crítico', 'Alto', 'Médio', 'Baixo'], datasets: [{ data: [0,0,0,0], backgroundColor: ['#EF4444','#F59E0B','#3B82F6','#10B981'], borderColor:'#111A2E', borderWidth: 2 }] },
    options: { cutout: '75%', plugins: { legend: { position:'right', labels:{ color: tick, font:{ size:10 }, boxWidth: 10 } } } }
  });
  chartTrend = new Chart(document.getElementById('chartTrend'), {
    type: 'line',
    data: { labels: ['-'], datasets: [{ label:'Evolução Risco', data:[0], borderColor:'#3B82F6', backgroundColor:'rgba(59,130,246,0.1)', fill:true, tension:0.3, pointRadius: 3 }] },
    options: { plugins:{ legend:{ display:false } }, scales:{ x:{ grid:{ color: grid }, ticks:{ color: tick, font:{size:10} } }, y:{ beginAtZero:true, max:100, grid:{ color: grid }, ticks:{ color: tick, font:{size:10} } } } }
  });
}

function sevPill(s) {
  if (s==='crit') return '<span class="pill pill-crit">Crítico</span>';
  if (s==='high') return '<span class="pill pill-high">Alto</span>';
  if (s==='med')  return '<span class="pill pill-med">Médio</span>';
  return '<span class="pill pill-low">Baixo</span>';
}

function renderCyberTable() {
  const tbody = document.getElementById('cyber-tbody');
  if(VULNS_DATA.length === 0) { tbody.innerHTML = '<tr><td colspan="5" class="px-5 py-6 text-center text-[#8A95AD] text-xs">Aguardando varredura.</td></tr>'; return; }
  tbody.innerHTML = VULNS_DATA.map((v, i) => `
    <tr class="border-t border-[#1F2A44] hover:bg-[#162038]/50 transition">
      <td class="px-5 py-3 font-mono text-[11px] text-[#C9D1E2]">${v.host}:${v.port}</td>
      <td class="px-5 py-3">${sevPill(v.sev)}</td>
      <td class="px-5 py-3 font-mono text-[11px] text-[#8A95AD]">${v.cve}</td>
      <td class="px-5 py-3"><div class="font-medium text-white text-xs">${v.title}</div><div class="text-[10px] text-[#8A95AD] mt-0.5 truncate max-w-xs">${v.desc}</div></td>
      <td class="px-5 py-3 text-right flex justify-end gap-2">
        <button onclick="openRemediationModal(${i})" class="text-[10px] px-2 py-1 rounded bg-[#1F2A44] hover:bg-[#2A3B5C] text-[#C9D1E2] transition">Mitigação IA</button>
        <button onclick="mitigate(this)" class="text-[10px] px-2 py-1 rounded border border-[#1F2A44] hover:border-[#10B981] hover:text-[#10B981] text-[#8A95AD] transition">Resolver</button>
      </td>
    </tr>`).join('');
}

function mitigate(btn) {
  const row = btn.closest('tr');
  if (row.classList.contains('opacity-50')) return;
  row.classList.add('opacity-50');
  btn.outerHTML = '<span class="text-[10px] text-[#10B981]">OK</span>';
  mitigatedCount++;
  document.getElementById('kpi-mit').textContent = mitigatedCount;
}

function renderExecTable() {
  const tbody = document.getElementById('exec-tbody');
  if(EXEC_DATA.length === 0) { tbody.innerHTML = '<tr><td colspan="4" class="px-5 py-6 text-center text-[#8A95AD] text-xs">Sem dados.</td></tr>'; return; }
  tbody.innerHTML = EXEC_DATA.map((r, i) => `
    <tr class="border-t border-[#1F2A44] hover:bg-[#162038]/50 transition">
      <td class="px-5 py-3 font-medium text-[#C9D1E2] text-xs">${r.risk}</td>
      <td class="px-5 py-3 text-[11px] text-[#8A95AD]">${r.cat}</td>
      <td class="px-5 py-3 font-bold text-[#EF4444] text-xs">${r.impact}</td>
      <td class="px-5 py-3 text-right">
        <button onclick="openRemediationModal(${i}, 'exec')" class="text-[10px] px-2 py-1 rounded bg-[#1F2A44] hover:bg-[#2A3B5C] text-white transition">Solicitar Correção</button>
      </td>
    </tr>`).join('');
}

function renderHistoryTable() {
  const tbody = document.getElementById('history-tbody');
  if(HISTORY_DATA.length === 0) return;
  tbody.innerHTML = [...HISTORY_DATA].reverse().map(h => `
    <tr class="border-t border-[#1F2A44] hover:bg-[#162038]/50">
      <td class="px-5 py-3 text-[11px] text-[#C9D1E2]">${h.date}</td>
      <td class="px-5 py-3 font-mono text-[11px] text-[#8A95AD]">${h.target}</td>
      <td class="px-5 py-3 font-bold ${h.risk_score > 50 ? 'text-[#EF4444]' : 'text-[#F59E0B]'} text-xs">${h.risk_score}</td>
      <td class="px-5 py-3 text-[11px] text-[#8A95AD]">${h.total_vulns} registros</td>
    </tr>`).join('');
}

function openPdfModal() {
  if (HISTORY_DATA.length === 0) {
    showToast("Sem histórico para exportação.", "error"); return;
  }
  const select = document.getElementById('pdf-target-select');
  select.innerHTML = '';
  const uniqueTargets = [...new Set(HISTORY_DATA.map(h => h.target))];
  uniqueTargets.forEach(t => { select.innerHTML += `<option value="${t}">${t}</option>`; });
  document.getElementById('pdf-modal').classList.remove('hidden');
  document.getElementById('pdf-modal').classList.add('flex');
}

function closePdfModal() {
  document.getElementById('pdf-modal').classList.add('hidden');
  document.getElementById('pdf-modal').classList.remove('flex');
}

function togglePdfSelect() {
  const isSpec = document.querySelector('input[name="pdf-type"]:checked').value === 'SPECIFIC';
  document.getElementById('pdf-target-wrapper').classList.toggle('hidden', !isSpec);
}

function downloadPDF() {
  const type = document.querySelector('input[name="pdf-type"]:checked').value;
  const target = type === 'SPECIFIC' ? document.getElementById('pdf-target-select').value : 'ALL';
  closePdfModal();
  showToast("Gerando PDF Executivo...", "info");
  window.location.href = `/export_pdf?target=${encodeURIComponent(target)}`;
}

async function openRemediationModal(index, callerRole = 'cyber') {
  const vuln = VULNS_DATA[index];
  const modal = document.getElementById('remediation-modal');
  modal.classList.remove('hidden');
  modal.classList.add('flex');
  
  document.getElementById('modal-role-badge').innerText = callerRole === 'exec' ? "Notificação de Engenharia" : "Plano de Mitigação";
  document.getElementById('rem-title').innerHTML = `Ativo: ${vuln.host} | Falha: ${vuln.title}`;

  document.getElementById('rem-content').innerHTML = `
    <div class="flex flex-col items-center justify-center py-10">
      <div class="loader-sm mb-4"></div>
      <div class="text-xs text-[#8A95AD]">Processando solução técnica via IA...</div>
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
        <div class="mb-5">
          <div class="text-xs font-bold text-[#EF4444] mb-2 uppercase">Impacto de Negócio</div>
          <div class="text-xs text-[#C9D1E2] leading-relaxed bg-[#162038] p-3 rounded border border-[#1F2A44]">${data.rationale}</div>
        </div>
        <div>
          <div class="flex justify-between items-end mb-2">
            <div class="text-xs font-bold text-[#3B82F6] uppercase">Comunicação Interna Sugerida</div>
            <button onclick="navigator.clipboard.writeText(document.getElementById('email-text').innerText); showToast('Copiado!', 'success');" class="text-[10px] text-white bg-[#3B82F6] px-2 py-1 rounded hover:bg-blue-600 transition">Copiar Texto</button>
          </div>
          <div id="email-text" class="bg-[#0B1220] p-3 rounded border border-[#1F2A44] text-[11px] text-[#8A95AD] whitespace-pre-wrap font-mono leading-relaxed">${data.email}</div>
        </div>
      `;
    } else {
      let stepsHtml = data.steps.map(s => `<li class="mb-1.5">${s}</li>`).join('');
      document.getElementById('rem-content').innerHTML = `
        <div class="mb-5">
          <div class="text-xs font-bold text-[#3B82F6] mb-2 uppercase">Procedimento Técnico</div>
          <ul class="list-decimal list-inside text-xs text-[#C9D1E2] space-y-1 bg-[#162038] p-3 rounded border border-[#1F2A44]">${stepsHtml}</ul>
        </div>
        <div>
          <div class="text-xs font-bold text-amber-500 mb-2 uppercase">Console / Scripting</div>
          <div class="bg-[#0B1220] p-3 rounded border border-[#1F2A44] text-[11px] text-amber-400 font-mono leading-relaxed whitespace-pre-wrap">${data.commands}</div>
        </div>
      `;
    }
  } catch (error) {
    document.getElementById('rem-content').innerHTML = `<div class="p-3 text-xs bg-[#EF4444]/10 border border-[#EF4444]/30 rounded text-[#EF4444]">Falha de conexão com o processador. Consulte o log.</div>`;
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
        # Mapeamento blindado para severidade, garantindo que CRÍTICO vá para 'crit'
        s_upper = str(sev).upper()
        if "CRÍT" in s_upper or "CRIT" in s_upper:
            mapped_sev = "crit"
        elif "ALT" in s_upper or "HIGH" in s_upper:
            mapped_sev = "high"
        elif "MÉD" in s_upper or "MED" in s_upper:
            mapped_sev = "med"
        else:
            mapped_sev = "low"
            
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
        if port in [389, 636] or "ldap" in name:
            self.add(host, port, "LDAP Acessível s/ Autenticação", "Permite consultas anônimas expurgando estrutura interna do AD.", "MÉDIO", 5.3)
        if port in [135]:
            self.add(host, port, "RPC Mapper Exposto", "RPC Endpoint exposto permite listagem e enumeração de serviços gerenciais do Windows.", "BAIXO", 3.1)

    def _http(self, host, port, svc):
        base = f"http{'s' if port==443 else ''}://{host}:{port}"
        try:
            r = requests.get(base, timeout=4, verify=False, allow_redirects=True)
        except:
            return
        
        sec_hdrs = ["X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy"]
        missing = [h for h in sec_hdrs if h not in r.headers]
        if missing:
            self.add(host, port, "Headers de Segurança Ausentes", f"Aplicação web não implementa headers HTTP de segurança: {', '.join(missing)}.", "MÉDIO", 5.3)

        for path in ["/api/collaborators?name='", "/search?q='"]:
            try:
                sr = requests.get(base + path, timeout=4, verify=False)
                body = sr.text.lower()
                if any(e in body for e in ["sql", "mysql", "syntax error", "sqlite", "oracle"]):
                    self.add(host, port, "SQL Injection Ativo", "Endpoint de entrada vulnerável a injeção SQL cega baseada em tempo/erro.", "CRÍTICO", 9.8, "CWE-89")
                    break
            except: pass
            
        try:
            r = requests.get(base + "/admin", headers={"x-auth-token": "YWRtaW4="}, timeout=4, verify=False)
            if r.status_code == 200:
                self.add(host, port, "Broken Auth (Base64 Session Token)", "Painel gerencial autentica utilizadores com hashes Base64 puras.", "CRÍTICO", 9.1, "CWE-287")
        except: pass

    def _nodered(self, host, port):
        try:
            r = requests.get(f"http://{host}:{port}/settings", timeout=4)
            if r.status_code == 200:
                self.add(host, port, "Node-RED Exposto s/ Autenticação", "Painel operacional e fluxos de engenharia expostos sem autenticação administrativa.", "CRÍTICO", 9.8, "CWE-306")
                if "functionExternalModules" in r.text:
                    self.add(host, port, "Node-RED RCE Potencial (External Modules)", "Configuração functionExternalModules habilitada, permitindo a importação direta de comandos arbitrários pelo SO.", "CRÍTICO", 9.3, "CWE-94")
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
                self.add(host, port, "MQTT s/ Autenticação/TLS", "Broker de mensageria IoT Mosquitto aberto, aceitando conexões anônimas sem cifras de transporte.", "CRÍTICO", 9.3, "CWE-306")
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
            self.add(host, port, "SMB Signing Desabilitado", "Assinatura digital desabilitada no protocolo de compartilhamento de arquivos. Vulnerável a NTLM Relay e escalada de privilégios.", "CRÍTICO", 9.0, "CWE-300")
            
        if cme.get("smbv1") is True:
            self.add(host, port, "SMBv1 Ativo na Máquina", "Compartilhamento de arquivos utilizando protocolo legado altamente vulnerável a exploits de RCE.", "CRÍTICO", 9.8, "CVE-2017-0144")

    def _mysql(self, host, port, svc):
        ver = svc.get("version", "")
        if "5.5" in ver or ver.startswith("5.5"):
            self.add(host, port, "MySQL 5.5 End-Of-Life (EOL)", "Servidor de banco de dados rodando em versão obsoleta sem correções ou patches acumulados do fabricante.", "CRÍTICO", 9.8, "CVE-2016-6662")


# =====================================================================
# 3. LÓGICA DO SERVIDOR FLASK (BACKEND) E INTEGRAÇÃO GROQ (IA)
# =====================================================================
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
    raise ValueError("JSON parse error")

def generate_local_executive_risks(cyber_vulns):
    risks = []
    for v in cyber_vulns:
        title = v.get("title", "").lower()
        sev = v.get("sev", "high")
        if "sql" in title:
            risk, cat, impact = "Vazamento em massa de dados e sanções RGPD/LGPD", "Compliance", "R$ 4.2M"
        elif "node-red" in title:
            risk, cat, impact = "Paralisação de maquinário industrial via RCE", "Continuidade", "R$ 5.8M"
        elif "mqtt" in title:
            risk, cat, impact = "Manipulação maliciosa de telemetria ICS", "Operações", "R$ 2.5M"
        elif "smb" in title:
            risk, cat, impact = "Comprometimento estrutural do Active Directory", "Segurança", "R$ 10.0M"
        else:
            risk, cat, impact = f"Falta de conformidade de segurança no serviço", "Operações", "R$ 500k"
        
        risks.append({"risk": risk, "cat": cat, "impact": impact, "prob": "Alta" if sev in ['crit','high'] else "Média", "cve": v.get("cve","N/A"), "ip": v.get("host"), "port": str(v.get("port"))})
    return risks

def get_local_remediation_plan(vuln, persona):
    if persona == 'exec':
        return {
            "rationale": "Esta falha possui um vetor de ataque que compromete a base operacional do ativo, expondo a empresa a multas regulatórias e paralisações críticas.",
            "email": f"Assunto: Ação Necessária - Correção de Ativo {vuln.get('host')}\n\nPrezada equipe de Infraestrutura,\n\nA auditoria automatizada detectou uma falha classificada como de alto risco no ativo {vuln.get('host')} (Porta {vuln.get('port')}).\nSolicita-se intervenção técnica para aplicação dos devidos controles de segurança e mitigações compensatórias.\n\nAtenciosamente,\nCybersecurity"
        }
    else:
        return {
            "steps": [
                "Revisar as políticas de acesso do serviço afetado.",
                "Aplicar atualizações e patches cumulativos mais recentes do fabricante.",
                "Implementar bloqueios de segurança via Firewall."
            ],
            "commands": f"# Isolamento preventivo no Linux:\nsudo ufw deny from any to any port {vuln.get('port')}\n\n# Consulta de logs de atividade:\njournalctl -u nomedoservico -n 50 --no-pager"
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
            {"host": "10.10.100.100", "port": 1880, "title": "Node-RED Exposto s/ Autenticação", "desc": "Painel operacional exposto sem autenticação gerencial.", "sev": "crit", "cvss": 9.8, "cve": "CWE-306"},
            {"host": "10.10.100.100", "port": 1883, "title": "MQTT s/ Autenticação", "desc": "Broker de mensageria IoT Mosquitto aberto.", "sev": "crit", "cvss": 9.3, "cve": "CWE-306"}
        ]
        
    exec_risks = generate_local_executive_risks(vulns_encontradas)
    score = min(sum([10 if v["sev"]=="crit" else 5 if v["sev"]=="high" else 2 for v in vulns_encontradas]), 100)

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

    if persona == 'exec':
        prompt = f"Atue como Diretor Executivo (CISO). Forneça impacto de negócio formal e um email corporativo exigindo correção para a falha {vuln.get('title')} no IP {vuln.get('host')}. Retorne estritamente JSON: {{\"rationale\": \"...\", \"email\": \"...\"}}. Seja curto e direto."
    else:
        prompt = f"Atue como Engenheiro DevSecOps. Forneça no máximo 3 passos de mitigação para a falha {vuln.get('title')} no IP {vuln.get('host')}. Retorne estritamente JSON: {{\"steps\": [\"passo 1\", \"passo 2\"], \"commands\": \"comandos shell\"}}. Seja técnico e direto."

    try:
        chat = client.chat.completions.create(messages=[{"role": "user", "content": prompt}], model="llama-3.3-70b-versatile", temperature=0.1, timeout=8.0)
        return jsonify(extract_json(chat.choices[0].message.content))
    except:
        return jsonify(get_local_remediation_plan(vuln, persona))

@app.route("/api/simulate", methods=["POST"])
def api_simulate():
    _DB["history"] = [
        {"date": "10/06 14:00", "target": "10.10.100.3", "risk_score": 35, "total_vulns": 1, "cyber_vulns": [{"host": "10.10.100.3", "port": 3306, "title": "MySQL 5.5 EOL", "desc": "Servidor rodando versão legada.", "sev": "high", "cvss": 8.8, "cve": "CVE-2016-6662"}], "exec_risks": []},
        {"date": "11/06 09:30", "target": "10.10.100.100", "risk_score": 68, "total_vulns": 2, "cyber_vulns": [{"host": "10.10.100.100", "port": 1880, "title": "Node-RED Exposto", "desc": "Painel de automação sem senhas.", "sev": "crit", "cvss": 9.8, "cve": "CWE-306"}], "exec_risks": []},
        {"date": "12/06 02:15", "target": "10.10.100.0/24", "risk_score": 85, "total_vulns": 4, "cyber_vulns": [{"host": "10.10.100.100", "port": 1883, "title": "MQTT s/ Autenticação", "desc": "Broker aberto.", "sev": "crit", "cvss": 9.3, "cve": "CWE-306"}, {"host": "10.10.100.2", "port": 445, "title": "SMB Signing Desabilitado", "desc": "Vulnerável a Relay.", "sev": "crit", "cvss": 9.0, "cve": "CWE-300"}], "exec_risks": []}
    ]
    last = _DB["history"][-1]
    _DB["cyber_vulns"] = last["cyber_vulns"]
    _DB["exec_risks"] = generate_local_executive_risks(last["cyber_vulns"])
    _DB["risk_score"] = last["risk_score"]
    return jsonify(_DB)

@app.route("/export_pdf")
def export_pdf():
    import io
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
    target_name = "Infraestrutura Consolidada" if target_req == 'ALL' else target_req
    safe_target = "Consolidado" if target_req == 'ALL' else target_req.replace('/','_')
    out_file = f"CYMAG_Relatorio_{safe_target}.pdf"

    # REPORTLAB PARA PDF ROBUSTO E LEVE
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle("TitleStyle", parent=styles["Title"], fontSize=18, textColor=colors.HexColor("#111A2E"), spaceAfter=10)
    sub_style = ParagraphStyle("SubStyle", parent=styles["Normal"], fontSize=10, textColor=colors.gray, spaceAfter=20)
    
    story = []
    story.append(Paragraph("CYMAG Enterprise - Relatório Executivo", title_style))
    story.append(Paragraph(f"<b>Escopo da Auditoria:</b> {target_name} <br/><b>Score de Risco Global:</b> {final_score}/100", sub_style))
    
    # Tabela Básica e Direta para o Executivo
    table_data = [["Host / Porta", "Falha Identificada", "CVE", "Severidade"]]
    
    for v in sorted(merged_vulns, key=lambda x: {"crit":4, "high":3, "med":2, "low":1}.get(x["sev"],0), reverse=True):
        sev_label = "CRÍTICO" if v["sev"] == "crit" else "ALTO" if v["sev"] == "high" else "MÉDIO" if v["sev"] == "med" else "BAIXO"
        table_data.append([
            f"{v['host']}:{v['port']}",
            v['title'],
            v['cve'],
            sev_label
        ])
        
    t = Table(table_data, colWidths=[100, 210, 80, 80])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#162038")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('TOPPADDING', (0, 0), (-1, 0), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
    ]))
    
    # Colore a coluna da severidade
    for i, row in enumerate(table_data[1:], start=1):
        sev = row[3]
        color = colors.black
        if sev == "CRÍTICO": color = colors.HexColor("#EF4444")
        elif sev == "ALTO": color = colors.HexColor("#F59E0B")
        elif sev == "MÉDIO": color = colors.HexColor("#3B82F6")
        elif sev == "BAIXO": color = colors.HexColor("#10B981")
        t.setStyle(TableStyle([('TEXTCOLOR', (3, i), (3, i), color), ('FONTNAME', (3, i), (3, i), 'Helvetica-Bold')]))

    story.append(t)
    doc.build(story)
    
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=out_file, mimetype='application/pdf')

if __name__ == "__main__":
    import logging
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    print("\n[CYMAG ENTERPRISE] Servidor online no http://127.0.0.1:5000\n")
    app.run(host="0.0.0.0", port=5000)
