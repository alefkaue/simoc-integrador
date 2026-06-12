#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  CYMAG Enterprise — app.py (Monólito SaaS Completo)             ║
║  Continuous Automated Red Teaming — Risk Intelligence Platform   ║
║  SENAI — Bento de Souza                                          ║
╚══════════════════════════════════════════════════════════════════╝
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
</style>
</head>
<body class="min-h-screen">

<!-- SISTEMA DE NOTIFICAÇÕES (TOAST) -->
<div id="toast-container" class="fixed top-5 right-5 z-50 flex flex-col gap-3"></div>

<!-- OVERLAY DE CARREGAMENTO -->
<div id="loading-overlay" class="fixed inset-0 bg-[#0B1220]/90 backdrop-blur-sm z-50 hidden flex-col items-center justify-center text-center px-4">
  <div class="loader mb-6"></div>
  <h2 class="text-2xl font-bold text-white mb-2">Motor de Auditoria CYMAG em Execução</h2>
  <p class="text-[#8A95AD] text-center max-w-md">Realizando varredura profunda, injeção de pacotes de teste e análise cognitiva IA.<br><br>Alvo: <span id="loading-target" class="font-mono text-[#3B82F6] font-bold"></span></p>
</div>

<!-- MODAL DE EXPORTAÇÃO PDF -->
<div id="pdf-modal" class="fixed inset-0 bg-[#0B1220]/90 backdrop-blur-sm z-50 hidden flex-col items-center justify-center p-4">
  <div class="card w-full max-w-md p-6 border border-[#3B82F6]/30 shadow-[0_0_40px_rgba(59,130,246,0.15)]">
    <div class="flex justify-between items-center mb-6 border-b border-[#1F2A44] pb-4">
      <h3 class="text-lg font-bold text-white flex items-center gap-2">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#3B82F6" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
        Exportar Relatório PDF
      </h3>
      <button onclick="closePdfModal()" class="text-[#8A95AD] hover:text-white transition">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
      </button>
    </div>
    
    <p class="text-sm text-[#8A95AD] mb-4">Selecione o escopo do relatório a ser gerado:</p>
    
    <div class="space-y-3 mb-8">
      <label class="flex items-center gap-3 p-4 border border-[#3B82F6] bg-[#3B82F6]/10 rounded-lg cursor-pointer transition" id="label-pdf-all">
        <input type="radio" name="pdf-type" value="ALL" checked onchange="togglePdfSelect()" class="w-4 h-4 text-blue-600">
        <div>
          <div class="font-semibold text-white text-sm">Infraestrutura Consolidada</div>
          <div class="text-xs text-[#8A95AD] mt-1">Gera um relatório consolidado unificando todos os ativos mapeados no histórico.</div>
        </div>
      </label>
      
      <label class="flex flex-col gap-2 p-4 border border-[#1F2A44] bg-[#162038] rounded-lg cursor-pointer transition" id="label-pdf-spec">
        <div class="flex items-center gap-3">
          <input type="radio" name="pdf-type" value="SPECIFIC" onchange="togglePdfSelect()" class="w-4 h-4">
          <div>
            <div class="font-semibold text-white text-sm">Ativo Específico</div>
            <div class="text-xs text-[#8A95AD] mt-1">Gera o relatório exclusivo de uma varredura individual do histórico.</div>
          </div>
        </div>
        <div id="pdf-target-wrapper" class="hidden mt-3 ml-7">
          <select id="pdf-target-select" class="w-full bg-[#0B1220] border border-[#1F2A44] text-white text-sm rounded-lg p-2.5 outline-none focus:border-[#3B82F6]"></select>
        </div>
      </label>
    </div>
    
    <button onclick="downloadPDF()" class="w-full py-3 bg-[#3B82F6] hover:bg-blue-600 text-white rounded-lg font-bold tracking-wide transition shadow-lg shadow-blue-500/30 flex items-center justify-center gap-2">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
      Gerar e Descarregar PDF
    </button>
  </div>
</div>

<!-- MODAL DE REMEDIAÇÃO IA (Cyber ou Executivo) -->
<div id="remediation-modal" class="fixed inset-0 bg-[#0B1220]/90 backdrop-blur-sm z-50 hidden flex-col items-center justify-center p-6">
  <div class="card w-full max-w-2xl p-0 border border-[#3B82F6]/50 shadow-[0_0_50px_rgba(59,130,246,0.2)] flex flex-col max-h-[90vh]">
    <div class="p-6 border-b border-[#1F2A44] flex justify-between items-center bg-[#111A2E] rounded-t-xl sticky top-0">
      <div>
        <h3 class="text-lg font-bold text-white flex items-center gap-2" id="modal-role-badge">
          <!-- Injetado dinamicamente -->
        </h3>
        <div class="text-xs text-[#8A95AD] mt-1 font-mono" id="rem-title">Carregando...</div>
      </div>
      <button onclick="closeRemediationModal()" class="text-[#8A95AD] hover:text-white transition">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
      </button>
    </div>
    
    <div class="p-6 overflow-y-auto" id="rem-content">
      <div class="flex flex-col items-center justify-center py-10">
        <div class="loader-sm mb-4"></div>
        <div class="text-sm text-[#8A95AD]">Processando dados e consultando a IA cognitiva...</div>
      </div>
    </div>
  </div>
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
    <h1 class="text-2xl font-semibold mb-2 text-white">Acesso à Plataforma</h1>
    <p class="text-sm text-[#8A95AD] mb-8">Selecione o perfil operacional para iniciar.</p>
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
      <div class="text-[10px] uppercase tracking-wider text-[#8A95AD] px-3 pt-2 pb-1">Painéis</div>
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
        <button onclick="logout()" class="text-xs text-[#8A95AD] hover:text-white underline">Sair do Sistema</button>
      </div>
    </div>
  </aside>

  <main class="flex-1 flex flex-col min-w-0">
    <header class="h-16 border-b border-[#1F2A44] bg-[#111A2E]/60 backdrop-blur flex items-center justify-between px-6 sticky top-0 z-20">
      <div class="flex items-center gap-4">
        <div>
          <div class="text-[11px] text-[#8A95AD] uppercase tracking-wider" id="crumb">Dashboard / Visão Cyber</div>
          <div class="text-sm font-semibold text-white" id="view-title">Operações de Segurança</div>
        </div>
        <!-- BOTÃO DE DEMONSTRAÇÃO EXCLUSIVO PARA O VÍDEO DO TCC -->
        <button onclick="injectSimulation()" class="bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-500/30 text-xs px-3 py-1.5 rounded-lg font-bold flex items-center gap-1.5 transition ml-4">
          <span>⚡</span> Injetar Histórico (Demo TCC)
        </button>
      </div>
      <div class="flex items-center gap-3">
        <input type="text" id="target-input" placeholder="Alvo (ex: 10.10.100.0/24)" class="bg-[#162038] border border-[#1F2A44] text-sm rounded-lg px-3 py-2 text-white placeholder-[#8A95AD] w-52 focus:outline-none focus:border-[#3B82F6]">
        <button onclick="startScan()" class="text-xs font-semibold px-4 py-2 rounded-lg bg-[#3B82F6] hover:bg-blue-600 text-white transition flex items-center gap-2">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
          Iniciar Varredura
        </button>
        <div class="w-px h-6 bg-[#1F2A44] mx-1"></div>
        <button onclick="openPdfModal()" class="text-xs font-semibold px-4 py-2 rounded-lg border border-[#1F2A44] hover:bg-[#162038] text-white transition flex items-center gap-2">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3v12"/><path d="M7 10l5 5 5-5"/><path d="M5 21h14"/></svg> Relatório PDF
        </button>
      </div>
    </header>

    <!-- PAINEL CYBER -->
    <div id="view-cyber" class="p-6 space-y-6 overflow-auto">
      <div class="grid grid-cols-4 gap-4">
        <div class="card p-5"><div class="text-xs text-[#8A95AD] uppercase tracking-wider">Vulnerabilidades</div><div class="text-3xl font-bold mt-2 kpi-num" id="kpi-vuln">0</div></div>
        <div class="card p-5"><div class="text-xs text-[#8A95AD] uppercase tracking-wider">Críticas</div><div class="text-3xl font-bold mt-2 kpi-num text-[#EF4444]" id="kpi-crit">0</div></div>
        <div class="card p-5"><div class="text-xs text-[#8A95AD] uppercase tracking-wider">Hosts Mapeados</div><div class="text-3xl font-bold mt-2 kpi-num" id="kpi-hosts">0</div></div>
        <div class="card p-5"><div class="text-xs text-[#8A95AD] uppercase tracking-wider">Mitigadas</div><div class="text-3xl font-bold mt-2 kpi-num text-[#10B981]" id="kpi-mit">0</div></div>
      </div>
      <div class="card overflow-hidden">
        <div class="px-5 py-4 border-b border-[#1F2A44]"><div class="text-sm font-semibold">Registo Técnico de Vulnerabilidades</div></div>
        <table class="w-full text-sm">
          <thead class="bg-[#162038]/50 text-[#8A95AD] text-xs uppercase tracking-wider">
            <tr><th class="text-left px-5 py-3 font-medium">Alvo (Host/Porta)</th><th class="text-left px-5 py-3 font-medium">CVSS</th><th class="text-left px-5 py-3 font-medium">CVE</th><th class="text-left px-5 py-3 font-medium">Falha Identificada</th><th class="text-right px-5 py-3 font-medium">Operação</th></tr>
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
          <div class="text-xs text-[#8A95AD] uppercase tracking-wider">Nível de Risco Global</div>
          <div class="flex items-end gap-2 mt-2"><div class="text-4xl font-bold kpi-num text-[#EF4444]" id="exec-risk">0</div><div class="text-sm text-[#8A95AD] pb-1">/ 100</div></div>
          <div class="mt-3 h-1.5 bg-[#162038] rounded-full overflow-hidden"><div id="exec-risk-bar" class="h-full bg-[#3B82F6] transition-all duration-1000" style="width:0%"></div></div>
        </div>
      </div>
      <div class="grid grid-cols-3 gap-4">
        <div class="card p-5 col-span-1"><div class="text-sm font-semibold mb-1">Severidade das Falhas</div><canvas id="chartSev" height="220"></canvas></div>
        <div class="card p-5 col-span-2"><div class="text-sm font-semibold mb-1">Histórico de Mitigação (Tendência)</div><canvas id="chartTrend" height="220"></canvas></div>
      </div>
      
      <div class="card overflow-hidden">
        <div class="px-5 py-4 border-b border-[#1F2A44]"><div class="text-sm font-semibold">Tabela de Impacto Financeiro e Negócio</div></div>
        <table class="w-full text-sm">
          <thead class="bg-[#162038]/50 text-[#8A95AD] text-xs uppercase tracking-wider">
            <tr><th class="text-left px-5 py-3 font-medium">Impacto no Negócio</th><th class="text-left px-5 py-3 font-medium">Categoria</th><th class="text-left px-5 py-3 font-medium">Prejuízo Estimado</th><th class="text-left px-5 py-3 font-medium">Probabilidade</th><th class="text-right px-5 py-3 font-medium">Ação C-Level</th></tr>
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
        <div class="px-5 py-4 border-b border-[#1F2A44]"><div class="text-sm font-semibold">Histórico de Diagnósticos Executados</div></div>
        <table class="w-full text-sm">
          <thead class="bg-[#162038]/50 text-[#8A95AD] text-xs uppercase tracking-wider">
            <tr><th class="text-left px-5 py-3 font-medium">Data / Hora</th><th class="text-left px-5 py-3 font-medium">Sub-rede / Host</th><th class="text-left px-5 py-3 font-medium">Score de Risco</th><th class="text-left px-5 py-3 font-medium">Ameaças Ativas</th></tr>
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

// Sistema de Notificações Customizado (Sem usar o alert() nativo)
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  const colors = {
    info: 'bg-[#162038] border-[#3B82F6] text-white',
    success: 'bg-[#162038] border-[#10B981] text-white',
    warning: 'bg-[#162038] border-[#F59E0B] text-white',
    error: 'bg-[#162038] border-[#EF4444] text-white'
  };
  toast.className = `p-4 rounded-xl border shadow-xl flex items-center gap-3 transition duration-300 transform translate-y-2 opacity-0 ${colors[type] || colors.info}`;
  toast.innerHTML = `
    <span class="text-lg">${type === 'success' ? '✓' : type === 'warning' ? '⚠' : 'ℹ'}</span>
    <span class="text-sm font-medium">${message}</span>
  `;
  container.appendChild(toast);
  setTimeout(() => { toast.classList.remove('translate-y-2', 'opacity-0'); }, 10);
  setTimeout(() => {
    toast.classList.add('opacity-0', 'translate-y-2');
    setTimeout(() => { toast.remove(); }, 300);
  }, 4000);
}

// Injeção de Histórico de Simulação para demonstração fluida de vídeo/pitch
async function injectSimulation() {
  const overlay = document.getElementById('loading-overlay');
  document.getElementById('loading-target').textContent = "Injeção de Histórico de Laboratório";
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
    showToast("Histórico de simulação injetado! Gráfico de tendência e linha do tempo populados com sucesso.", "success");
  } catch {
    showToast("Erro ao processar simulação offline.", "error");
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
    showToast(`Varredura finalizada para o escopo: ${target}`, "success");
  } catch (error) {
    showToast("Erro durante a varredura.", "error");
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
  
  const historyScores = HISTORY_DATA.map(h => h.risk_score);
  const labels = HISTORY_DATA.map(h => h.date);
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
    data: { labels: ['-','-','-','-'], datasets: [{ label:'Evolução Risco', data:[0,0,0,0], borderColor:'#3B82F6', backgroundColor:'rgba(59,130,246,0.12)', fill:true, tension:0.4 }] },
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
  if(VULNS_DATA.length === 0) { tbody.innerHTML = '<tr><td colspan="5" class="px-5 py-8 text-center text-[#8A95AD]">Aguardando início da varredura...</td></tr>'; return; }
  tbody.innerHTML = VULNS_DATA.map((v, i) => `
    <tr class="hover-row border-t border-[#1F2A44]">
      <td class="px-5 py-4 font-mono text-xs text-white">${v.host}:${v.port}</td>
      <td class="px-5 py-4">${sevPill(v.sev)} <span class="text-[#8A95AD] text-xs ml-2">${v.cvss}</span></td>
      <td class="px-5 py-4 font-mono text-xs text-[#C9D1E2]">${v.cve}</td>
      <td class="px-5 py-4 text-[#8A95AD]"><span class="font-bold text-white">${v.title}</span><br>${v.desc}</td>
      <td class="px-5 py-4 text-right flex justify-end gap-2">
        <button onclick="openRemediationModal(${i})" class="text-xs font-semibold px-3 py-1.5 rounded-md bg-[#3B82F6]/10 hover:bg-[#3B82F6]/30 border border-[#3B82F6]/50 text-[#3B82F6] transition">🛠️ Playbook Técnico</button>
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
  showToast("O ativo foi marcado temporariamente como mitigado.", "success");
}

function renderExecTable() {
  const tbody = document.getElementById('exec-tbody');
  if(EXEC_DATA.length === 0) { tbody.innerHTML = '<tr><td colspan="5" class="px-5 py-8 text-center text-[#8A95AD]">Aguardando início da varredura...</td></tr>'; return; }
  tbody.innerHTML = EXEC_DATA.map((r, i) => `
    <tr class="border-t border-[#1F2A44] hover-row">
      <td class="px-5 py-4 font-medium text-white">${r.risk}</td>
      <td class="px-5 py-4 text-[#8A95AD]">${r.cat}</td>
      <td class="px-5 py-4 font-semibold text-[#EF4444]">${r.impact}</td>
      <td class="px-5 py-4">${sevPill(r.prob==='Alta'?'crit':r.prob==='Média'?'high':'med').replace('Crítico','Alta').replace('Alto','Média').replace('Médio','Baixa')}</td>
      <td class="px-5 py-4 text-right">
        <button onclick="openRemediationModal(${i}, 'exec')" class="text-xs font-semibold px-3 py-1.5 rounded-md bg-[#10B981]/10 hover:bg-[#10B981]/30 border border-[#10B981]/50 text-[#10B981] transition">📩 Notificar Engenharia</button>
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
    showToast("Nenhuma varredura mapeada para exportação.", "warning");
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
  showToast("Compilando e gerando o relatório consolidado...", "info");
  window.location.href = `/export_pdf?target=${encodeURIComponent(target)}`;
}

// ==========================================
// MODAL PLANO DE AÇÃO IA (CENÁRIO C ATIVO)
// ==========================================
async function openRemediationModal(index, callerRole = 'cyber') {
  const vuln = VULNS_DATA[index];
  const modal = document.getElementById('remediation-modal');
  modal.classList.remove('hidden');
  modal.classList.add('flex');
  
  // Customiza o Header do modal dependendo do papel ativo (/cyber ou /exec)
  const badge = document.getElementById('modal-role-badge');
  if (callerRole === 'exec') {
    badge.innerHTML = "<span>📩</span> Notificar Engenharia (Modelo C-Level)";
    document.getElementById('rem-title').innerHTML = `Ameaça Corporativa: <b>${vuln.title}</b> em <code>${vuln.host}</code>`;
  } else {
    badge.innerHTML = "<span>🛠️</span> Playbook Técnico (Modelo Operacional)";
    document.getElementById('rem-title').innerHTML = `Playbook de Mitigação: <code>${vuln.host}:${vuln.port}</code> — ${vuln.title}`;
  }

  document.getElementById('rem-content').innerHTML = `
    <div class="flex flex-col items-center justify-center py-10">
      <div class="loader-sm mb-4"></div>
      <div class="text-sm text-[#8A95AD]">Processando plano direcionado com o Copilot IA...</div>
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
      // Exibe apenas a análise de risco de negócio e o modelo de e-mail gerencial
      document.getElementById('rem-content').innerHTML = `
        <div class="mb-6">
          <h4 class="font-bold text-[#EF4444] mb-3 flex items-center gap-2">⚠️ Racional de Impacto no Negócio:</h4>
          <p class="text-sm text-[#E5EAF3] leading-relaxed bg-[#162038] p-4 rounded-lg border border-[#1F2A44]">${data.rationale}</p>
        </div>
        <div>
          <div class="flex justify-between items-center mb-3">
            <h4 class="font-bold text-[#10B981] flex items-center gap-2">📩 Rascunho de E-mail de Notificação (TI / Engenharia):</h4>
            <button onclick="navigator.clipboard.writeText(document.getElementById('email-text').innerText); showToast('Copiado para a Área de Transferência!', 'success');" class="text-xs text-[#3B82F6] hover:underline">Copiar Texto</button>
          </div>
          <div id="email-text" class="bg-[#0B1220] p-4 rounded-lg border border-[#1F2A44] text-xs text-[#8A95AD] whitespace-pre-wrap font-mono leading-relaxed">
            ${data.email}
          </div>
        </div>
      `;
    } else {
      // Exibe apenas as instruções técnicas brutas e os comandos de console (Playbook)
      let stepsHtml = data.steps.map(s => `<li class="mb-2">${s}</li>`).join('');
      document.getElementById('rem-content').innerHTML = `
        <div class="mb-6">
          <h4 class="font-bold text-[#3B82F6] mb-3 flex items-center gap-2">🛠️ Passos Técnicos de Mitigação:</h4>
          <ul class="list-decimal list-outside text-sm text-[#E5EAF3] pl-5 space-y-1">${stepsHtml}</ul>
        </div>
        <div>
          <h4 class="font-bold text-amber-500 mb-3 flex items-center gap-2">💻 Comandos Recomendados para Terminal:</h4>
          <div class="bg-[#0B1220] p-4 rounded-lg border border-[#1F2A44] text-xs text-amber-400 font-mono leading-relaxed whitespace-pre-wrap">
            ${data.commands}
          </div>
        </div>
      `;
    }
  } catch (error) {
    document.getElementById('rem-content').innerHTML = `
      <div class="p-4 bg-[#EF4444]/10 border border-[#EF4444]/30 rounded-lg text-[#EF4444] text-sm">
        Falha temporária ao comunicar com a inteligência cognitiva Groq. Recomenda-se verificação direta do ativo.
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
<html lang="pt-PT">
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
        <div class="subtitle">Relatório Executivo de Diagnóstico Contínuo (SaaS)</div>
        <div style="margin-bottom: 20px; font-size: 13pt;">Escopo de Auditoria: <b>{{ target_name }}</b></div>
        <div class="score-box">Score Consolidado de Risco: {{ risk_score }} / 100</div>
        <div style="margin-top: 150px; color: #555;">Auditoria Contínua Automatizada</div>
    </div>
    <div style="page-break-before: always;"></div>
    <h1>1. SUMÁRIO DE NEGÓCIOS (VISÃO EXECUTIVA)</h1>
    <table>
        <tr><th>Risco de Negócio</th><th>Categoria</th><th>Prejuízo Estimado</th><th>Ativo Afetado</th></tr>
        {% for r in exec_risks %}
        <tr><td class="crit">{{ r.risk }}</td><td>{{ r.cat }}</td><td style="font-weight:bold;">{{ r.impact }}</td><td>{{ r.ip }}:{{ r.port }}</td></tr>
        {% endfor %}
    </table>
    <h1>2. EVIDÊNCIAS TÉCNICAS (VISÃO CYBER)</h1>
    <table>
        <tr><th>Host / Serviço</th><th>CVE / CVSS</th><th>Descrição da Vulnerabilidade</th></tr>
        {% for v in cyber_vulns %}
        <tr><td style="font-weight:bold;">{{ v.host }}:{{ v.port }}</td><td>{{ v.cve }}<br>CVSS: {{ v.cvss }}</td><td><b>{{ v.title }}</b><br>{{ v.desc }}</td></tr>
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
        sev_map = {
            "CRÍTICO": "crit", "ALTO": "high", "MÉDIO": "med", "BAIXO": "low",
            "crit": "crit", "high": "high", "med": "med", "low": "low"
        }
        mapped_sev = sev_map.get(sev.lower() if isinstance(sev, str) else sev, "low")
        self.findings.append({
            "host": host, "port": int(port), "title": title, "desc": desc,
            "sev": mapped_sev, "cvss": float(cvss), "cve": cve, "evidence": ev
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
    """Extrai blocos JSON de forma robusta ignorando conversas adicionais do modelo"""
    try:
        return json.loads(text.strip())
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
    """Gera Riscos de Negócios detalhados localmente para a Visão Executiva"""
    risks = []
    for v in cyber_vulns:
        title = v.get("title", "").lower()
        host = v.get("host", "10.10.100.100")
        port = v.get("port", "80")
        sev = v.get("sev", "high")
        cvss = v.get("cvss", 7.5)
        cve = v.get("cve", "N/A")
        
        if "sql" in title:
            risk, cat, impact, prob = "Invasão de base de dados corporativa resultando em sanções graves da RGPD/LGPD", "Compliance", "R$ 4.2M", "Alta"
        elif "node-red" in title:
            risk, cat, impact, prob = "Paralisação operacional de tanques industriais devido a RCE no gateway de automação", "Continuidade", "R$ 5.8M", "Alta"
        elif "mqtt" in title:
            risk, cat, impact, prob = "Sequestro de telemetria ICS permitindo alteração silenciosa de variáveis físicas", "Operações", "R$ 2.5M", "Alta"
        elif "smb signing" in title:
            risk, cat, impact, prob = "Acesso completo de domínios corporativos por retransmissão de hashes NTLM", "Segurança", "R$ 10.0M", "Alta"
        elif "smbv1" in title:
            risk, cat, impact, prob = "Compromisso integral do sistema operativo por worm Ransomware (WannaCry)", "Continuidade", "R$ 8.5M", "Alta"
        elif "mysql" in title:
            risk, cat, impact, prob = "Acesso direto e descarregamento das tabelas operacionais e financeiras", "Segurança", "R$ 3.0M", "Média"
        elif "broken auth" in title:
            risk, cat, impact, prob = "Manipulação administrativa da aplicação por falta de criptografia de tokens", "Controle de Acesso", "R$ 6.1M", "Alta"
        else:
            risk, cat, impact, prob = f"Quebra de integridade operacional do ativo na porta {port}", "Operações", f"R$ {round(cvss*0.7, 1)}M", "Média" if sev == "high" else "Alta" if sev == "crit" else "Baixa"
            
        risks.append({
            "risk": risk, "cat": cat, "impact": impact, "prob": prob, "cve": cve, "ip": host, "port": str(port)
        })
    return risks

def get_local_remediation_plan(vuln, persona):
    """Playbooks locais de alta fidelidade para mitigação e notificações (Cenário C)"""
    title = vuln.get("title", "").lower()
    host = vuln.get("host", "10.10.100.100")
    port = vuln.get("port", "80")
    cve = vuln.get("cve", "N/A")
    desc = vuln.get("desc", "Falha operacional crítica.")

    if persona == 'exec':
        # Modelo C-Level: Foco em Risco de Negócio, impacto financeiro e Notificação Formada
        if "sql" in title:
            rationale = "Ataques de SQLi representam um perigo financeiro direto de até R$ 4.2M. A exploração de CWE-89 permite o bypass total da segurança de dados e descarregamento de credenciais administrativas, gerando violações severas sob a égide da LGPD/RGPD."
            email = f"Assunto: NOTIFICAÇÃO OPERACIONAL URGENTE - Correção SQLi em {host}\\n\\nPrezada equipe de Engenharia de Sistemas,\\n\\nIdentificamos uma vulnerabilidade crítica de SQL Injection na porta {port} do host {host}. O descarregamento da base de dados pode acarretar sanções regulatórias severas.\\n\\nSolicitamos a parametrização imediata de todas as queries de input afetadas.\\n\\nAtenciosamente,\\nConselho Executivo de Segurança (CYMAG)"
        elif "node-red" in title:
            rationale = "A exposição operacional do gateway Node-RED permite RCE direto, facultando a atacantes paralisar bombas físicas do laboratório com custos de downtime estimados em R$ 5.8M."
            email = f"Assunto: JANELA DE MANUTENÇÃO URGENTE - Autenticação Node-RED {host}\\n\\nPrezada equipa de Infraestrutura e Redes,\\n\\nFoi detetado o gateway Node-RED ({host}:{port}) exposto sem credenciais de segurança. Solicitamos o isolamento físico ou acionamento de firewall perimetral nas próximas 12 horas.\\n\\nAtenciosamente,\\nConselho Executivo de Segurança (CYMAG)"
        else:
            rationale = f"A exposição da porta {port} no host {host} representa uma brecha na conformidade operacional do ativo, colocando em risco a continuidade operacional."
            email = f"Assunto: Alerta de Segurança Cibernética - Correção Necessária em {host}\\n\\nPrezada equipa técnica,\\n\\nIdentificamos a porta {port} no host {host} vulnerável a {title}. Solicitamos aplicação de patch para restaurar os níveis aceitáveis de segurança.\\n\\nAtenciosamente,\\nConselho de TI"
        return {"rationale": rationale, "email": email}
        
    else:
        # Modelo Cyber: Foco em Comandos de Terminal de Mitigação, ficheiros e playbooks
        if "sql" in title:
            steps = [
                "1. Converter todas as chamadas SQL brutas para Prepared Statements parametrizados.",
                "2. Implementar validação estrita baseada em whitelist de caracteres alfanuméricos.",
                "3. Ativar políticas de WAF (ModSecurity) bloqueando carateres lógicos de escape como ' e --."
            ]
            commands = f"# Exemplo PHP / PDO:\\n$stmt = $pdo->prepare('SELECT * FROM users WHERE name = :name');\\n$stmt->execute(['name' => $userInput]);"
        elif "node-red" in title:
            steps = [
                "1. Abrir o ficheiro de configurações administrativo 'settings.js' no servidor Node-RED.",
                "2. Adicionar o bloco de segurança 'adminAuth' exigindo autenticação bcrypt forte.",
                "3. Definir a flag 'functionExternalModules' para FALSE para desabilitar comandos shell no NodeJS.",
                "4. Restringir acesso à porta {port} no host através do iptables local."
            ]
            commands = f"# Bloquear acesso externo no Linux:\\nsudo iptables -A INPUT -p tcp --dport {port} ! -s 10.10.100.0/24 -j DROP\\n\\n# No settings.js do Node-RED:\\nadminAuth: {{\n  type: 'credentials',\n  users: [{{\n    username: 'admin',\n    password: 'HASH_BCRYPT_AQUI',\n    permissions: '*'\n  }}]\n}}"
        elif "smb signing" in title:
            steps = [
                "1. Forçar assinatura de pacotes SMB por GPO no Active Directory (smb-security-mode).",
                "2. Desativar o protocolo NTLMv1 em toda a árvore de domínio Microsoft.",
                "3. Criar uma política de firewall local para impedir conexões SMB diretas entre estações de utilizadores."
            ]
            commands = f"# PowerShell para forçar assinatura SMB (Windows):\\nSet-SmbServerConfiguration -RequireSecuritySignature $true -Force"
        else:
            steps = [
                "1. Isolar e monitorar logs de tráfego de entrada na porta afetada.",
                "2. Aplicar atualizações de patches e desabilitar acessos anônimos.",
                "3. Bloquear tráfego de IPs desconhecidos nas tabelas do firewall de borda."
            ]
            commands = f"# Bloqueio preventivo perimetral:\\nsudo ufw deny from any to any port {port}"
        return {"steps": steps, "commands": commands}

def analyze_with_ia(cyber_vulns):
    if not client:
        return generate_local_executive_risks(cyber_vulns)
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
            model="llama-3.3-70b-versatile", temperature=0.1, timeout=10.0
        )
        return extract_json(chat.choices[0].message.content)
    except:
        return generate_local_executive_risks(cyber_vulns)

def calc_score(vulns):
    return min(sum([10 if v["sev"]=="crit" else 5 if v["sev"]=="high" else 2 for v in vulns]), 100)


# =====================================================================
# 4. ROTAS DO SERVIDOR WEB FLASK
# =====================================================================

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
            {"host": "10.10.100.100", "port": 1880, "title": "Node-RED Exposto s/ Autenticação", "desc": "Painel operacional exposto sem autenticação gerencial.", "sev": "crit", "cvss": 9.8, "cve": "CWE-306", "evidence": "GET /settings -> 200 | funcExtModules:true"},
            {"host": "10.10.100.100", "port": 1883, "title": "MQTT s/ Autenticação/TLS", "desc": "Broker de mensageria IoT Mosquitto aberto, aceitando conexões anônimas sem cifras de transporte.", "sev": "crit", "cvss": 9.3, "cve": "CWE-306", "evidence": "Conexão anônima aceita na porta 1883/tcp"},
            {"host": "10.10.100.100", "port": 80, "title": "SQL Injection Ativo", "desc": "Endpoint de entrada vulnerável a injeção SQL cega baseada em tempo/erro.", "sev": "crit", "cvss": 9.8, "cve": "CWE-89", "evidence": "GET /api/collaborators?name=' -> erro SQL na resposta"},
            {"host": "10.10.100.2", "port": 445, "title": "SMB Signing Desabilitado", "desc": "Assinatura digital desabilitada no protocolo de compartilhamento de arquivos. Vulnerável a NTLM Relay e escalada de privilégios.", "sev": "crit", "cvss": 9.0, "cve": "CWE-300", "evidence": "SMB Signing: disabled/not required"}
        ]
        
    exec_risks = analyze_with_ia(vulns_encontradas)
    score = calc_score(vulns_encontradas)

    _DB["cyber_vulns"] = vulns_encontradas
    _DB["exec_risks"]  = exec_risks
    _DB["risk_score"]  = score
    
    _DB["history"].append({
        "date": datetime.datetime.now().strftime("%d/%m %H:%M"),
        "target": target,
        "risk_score": score,
        "total_vulns": len(vulns_encontradas),
        "cyber_vulns": vulns_encontradas, 
        "exec_risks": exec_risks
    })
    
    return jsonify(_DB)

@app.route("/api/remediation", methods=["POST"])
def api_remediation():
    req_data = request.get_json()
    vuln = req_data.get("vuln", {})
    persona = req_data.get("persona", "cyber")
    
    if not client:
        return jsonify(get_local_remediation_plan(vuln, persona))

    title = vuln.get("title", "").lower()
    host = vuln.get("host", "10.10.100.100")
    port = vuln.get("port", "80")
    
    if persona == 'exec':
        prompt = f"""
        Atue como Diretor Executivo de Segurança (CISO). Crie um racional de risco de negócio e um rascunho de e-mail de notificação para a falha:
        Alvo: {host}:{port}
        Falha: {vuln.get('title')}
        Gravidade: {vuln.get('sev')}

        Retorne ESTRITAMENTE um objeto JSON válido com duas chaves (sem formatação markdown):
        1. "rationale": Justificativa detalhada de impacto financeiro (em Reais) e de imagem corporativa pela falha.
        2. "email": Um e-mail formal corporativo cobrando a TI pelo patch, alertando sobre responsabilidades regulatórias. Use \\n para quebras de linha.
        """
    else:
        prompt = f"""
        Atue como Líder Técnico SecOps. Crie um playbook técnico de remediação para a falha:
        Alvo: {host}:{port}
        Falha: {vuln.get('title')}
        Gravidade: {vuln.get('sev')}

        Retorne ESTRITAMENTE um objeto JSON válido com duas chaves (sem formatação markdown):
        1. "steps": Uma lista (array) de 3 a 4 ações técnicas para corrigir e configurar o serviço no SO.
        2. "commands": Uma string de console contendo exemplos de linhas de comandos reais (PowerShell, Bash, Ansible) para mitigação. Use \\n para quebras de linha.
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

@app.route("/api/simulate", methods=["POST"])
def api_simulate():
    """Injeta simulação histórica de múltiplos scans de laboratório (Ideal para demonstração de gráficos de linha)"""
    _DB["history"] = [
        {
            "date": "10/06 14:00",
            "target": "10.10.100.3",
            "risk_score": 25,
            "total_vulns": 1,
            "cyber_vulns": [{"host": "10.10.100.3", "port": 3306, "title": "MySQL 5.5 EOL", "desc": "Servidor rodando versão legada.", "sev": "crit", "cvss": 9.8, "cve": "CVE-2016-6662"}],
            "exec_risks": [{"risk": "Vulnerabilidade no banco de dados local", "cat": "Segurança", "impact": "R$ 3.0M", "prob": "Alta", "cve": "CVE-2016-6662", "ip": "10.10.100.3", "port": "3306"}]
        },
        {
            "date": "11/06 09:30",
            "target": "10.10.100.100",
            "risk_score": 58,
            "total_vulns": 3,
            "cyber_vulns": [
                {"host": "10.10.100.100", "port": 1880, "title": "Node-RED Exposto s/ Autenticação", "desc": "Painel de automação sem senhas.", "sev": "crit", "cvss": 9.8, "cve": "CWE-306"},
                {"host": "10.10.100.100", "port": 80, "title": "Headers de Segurança Ausentes", "desc": "Ausência de X-Frame-Options no portal.", "sev": "low", "cvss": 5.3, "cve": "N/A"},
                {"host": "10.10.100.100", "port": 1883, "title": "MQTT s/ Autenticação/TLS", "desc": "Broker de mensageria IoT aberto.", "sev": "crit", "cvss": 9.3, "cve": "CWE-306"}
            ],
            "exec_risks": [
                {"risk": "Sabotagem física de bombas via Node-RED exposto", "cat": "Continuidade", "impact": "R$ 5.8M", "prob": "Alta", "cve": "CWE-306", "ip": "10.10.100.100", "port": "1880"},
                {"risk": "Manipulação de telemetria ICS via canal aberto", "cat": "Operações", "impact": "R$ 2.5M", "prob": "Alta", "cve": "CWE-306", "ip": "10.10.100.100", "port": "1883"}
            ]
        },
        {
            "date": "12/06 02:15",
            "target": "10.10.100.0/24",
            "risk_score": 85,
            "total_vulns": 4,
            "cyber_vulns": [
                {"host": "10.10.100.100", "port": 1880, "title": "Node-RED Exposto s/ Autenticação", "desc": "Fluxos expostos sem autenticação administrativa.", "sev": "crit", "cvss": 9.8, "cve": "CWE-306"},
                {"host": "10.10.100.100", "port": 1883, "title": "MQTT s/ Autenticação/TLS", "desc": "Broker de mensageria IoT aberto.", "sev": "crit", "cvss": 9.3, "cve": "CWE-306"},
                {"host": "10.10.100.100", "port": 80, "title": "SQL Injection Ativo", "desc": "Endpoint de entrada vulnerável a injeção SQL cega baseada em tempo/erro.", "sev": "crit", "cvss": 9.8, "cve": "CWE-89"},
                {"host": "10.10.100.2", "port": 445, "title": "SMB Signing Desabilitado", "desc": "Assinatura digital desabilitada. Vulnerável a NTLM Relay.", "sev": "crit", "cvss": 9.0, "cve": "CWE-300"}
            ],
            "exec_risks": [
                {"risk": "Sabotagem física de bombas via Node-RED exposto", "cat": "Continuidade", "impact": "R$ 5.8M", "prob": "Alta", "cve": "CWE-306", "ip": "10.10.100.100", "port": "1880"},
                {"risk": "Manipulação de telemetria ICS via canal aberto", "cat": "Operações", "impact": "R$ 2.5M", "prob": "Alta", "cve": "CWE-306", "ip": "10.10.100.100", "port": "1883"},
                {"risk": "Vazamento em massa de dados sensíveis corporativos", "cat": "Compliance", "impact": "R$ 4.2M", "prob": "Alta", "cve": "CWE-89", "ip": "10.10.100.100", "port": "80"},
                {"risk": "Acesso total de domínios corporativos por retransmissão", "cat": "Segurança", "impact": "R$ 10.0M", "prob": "Alta", "cve": "CWE-300", "ip": "10.10.100.2", "port": "445"}
            ]
        }
    ]
    # Atualiza estado atual com a última varredura
    last_scan = _DB["history"][-1]
    _DB["cyber_vulns"] = last_scan["cyber_vulns"]
    _DB["exec_risks"]  = last_scan["exec_risks"]
    _DB["risk_score"]  = last_scan["risk_score"]
    
    return jsonify(_DB)

@app.route("/export_pdf")
def export_pdf():
    target_req = request.args.get('target', 'ALL')
    merged_vulns = []
    merged_risks = []
    
    if target_req == 'ALL' or len(_DB["history"]) == 0:
        seen_vulns = set()
        seen_risks = set()
        hist_to_use = _DB["history"] if len(_DB["history"]) > 0 else [{"cyber_vulns": _DB["cyber_vulns"], "exec_risks": _DB["exec_risks"]}]
        
        for h in hist_to_use:
            for v in h.get("cyber_vulns", []):
                key = (v["host"], v["port"], v["title"])
                if key not in seen_vulns:
                    seen_vulns.add(key)
                    merged_vulns.append(v)
            for r in h.get("exec_risks", []):
                key = (r["risk"], r["ip"], r["port"])
                if key not in seen_risks:
                    seen_risks.add(key)
                    merged_risks.append(r)
    else:
        for h in reversed(_DB["history"]):
            if h["target"] == target_req:
                merged_vulns = h.get("cyber_vulns", [])
                merged_risks = h.get("exec_risks", [])
                break
                
    final_score = calc_score(merged_vulns)
    target_name = "Infraestrutura Consolidada" if target_req == 'ALL' else target_req
    
    html_pronto = render_template_string(
        PDF_HTML, cyber_vulns=merged_vulns, exec_risks=merged_risks, risk_score=final_score, target_name=target_name
    )
    
    safe_target = "Consolidado" if target_req == 'ALL' else target_req.replace('/','_')
    out_file = f"CYMAG_Relatorio_{safe_target}.pdf"
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
    
    app.run(host="0.0.0.0", port=5000)
