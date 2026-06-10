#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  CYMAG — Reorganização do Repositório (baseada no conteúdo)
#  Execute: bash reorganizar.sh  (na raiz do repo)
# ═══════════════════════════════════════════════════════════════

set -e
[ ! -d ".git" ] && echo "[ERRO] Execute na raiz do repo." && exit 1

echo "╔═══════════════════════════════════════════════╗"
echo "║  CYMAG — Reorganização do Repositório         ║"
echo "╚═══════════════════════════════════════════════╝"

# ──────────────────────────────────────────────────────────────
# 1. DELETAR — arquivos sem valor ou perigosos
# ──────────────────────────────────────────────────────────────
echo ""
echo "[1/5] Removendo arquivos desnecessários..."

# CREDENCIAL EXPOSTA — chave Groq API em texto claro
if [ -f "api.txt" ]; then
  git rm -f api.txt
  echo "    ⚠  api.txt REMOVIDO (continha chave de API — rotacione a chave!)"
fi

# Duplicata exata de F08_Web_100/*/nodered_flows.txt (MD5 idêntico)
[ -f "flows.txt" ] && git rm -f flows.txt && echo "    ✓  flows.txt removido (duplicata de F08/nodered_flows.txt)"

# CYMAG Scanner v1.0 — python_v1.py é a v1.1 (mais nova, 63KB vs 48KB)
[ -f "teste_python.py" ] && git rm -f teste_python.py && echo "    ✓  teste_python.py removido (versão antiga do scanner)"

# MySQL_teste2.txt — mesmo sqlmap que MySQL_teste.txt, 1 min depois, sem diferença real
[ -f "MySQL_teste2.txt" ] && git rm -f MySQL_teste2.txt && echo "    ✓  MySQL_teste2.txt removido (duplicata)"

# Tentativas quebradas que nunca funcionaram
[ -f "curl.txt" ]         && git rm -f curl.txt         && echo "    ✓  curl.txt removido (JSON inválido, nós errados)"
[ -f "injetar.sh" ]       && git rm -f injetar.sh       && echo "    ✓  injetar.sh removido (typo 'injetct', JSON quebrado)"
[ -f "exploit_node.sh" ]  && git rm -f exploit_node.sh  && echo "    ✓  exploit_node.sh removido (URL incompleta)"
[ -f "teste_g.json" ]     && git rm -f teste_g.json     && echo "    ✓  teste_g.json removido (não é JSON, é comando curl)"
[ -f "injetction3.js" ]   && git rm -f injetction3.js   && echo "    ✓  injetction3.js removido (snippet solto, não executável)"
[ -f "ipnovo.txt" ]       && git rm -f ipnovo.txt       && echo "    ✓  ipnovo.txt removido (scan incompleto, sem dados)"
[ -f "lista_git.txt" ]    && git rm -f lista_git.txt    && echo "    ✓  lista_git.txt removido (lixo de meta)"

# Binário e configs pessoais
[ -f "chisel" ]               && git rm -f chisel               && echo "    ✓  chisel removido (binário 10MB)"
[ -f ".zshrc" ]               && git rm -f .zshrc               && echo "    ✓  .zshrc removido (config pessoal)"
[ -f ".zshrc_local_buckup" ]  && git rm -f .zshrc_local_buckup  && echo "    ✓  .zshrc_local_buckup removido"

# F10 placeholder
[ -f "F10_Vulnerabilidades/test" ] && git rm -f F10_Vulnerabilidades/test && echo "    ✓  F10/test removido (placeholder vazio)"

# ──────────────────────────────────────────────────────────────
# 2. MOVER PARA F08_Web_100 — evidências da análise do .100
# ──────────────────────────────────────────────────────────────
echo ""
echo "[2/5] Movendo evidências web para F08_Web_100/..."

# SQL Injection — GET /api/collaborators (primeiro teste sqlmap)
[ -f "MySQL_teste.txt" ] && \
  git mv MySQL_teste.txt F08_Web_100/sqli_get_collaborators.txt && \
  echo "    ✓  MySQL_teste.txt → F08/sqli_get_collaborators.txt"

# SQL Injection — POST /api/session (dump completo com todas as tabelas)
[ -f "relatorio_banco.txt" ] && \
  git mv relatorio_banco.txt F08_Web_100/sqli_dump_completo.txt && \
  echo "    ✓  relatorio_banco.txt → F08/sqli_dump_completo.txt"

# Node-RED WebSocket debug — telemetria real das bombas capturada
[ -f "captura.txt" ] && \
  git mv captura.txt F08_Web_100/nodered_websocket_debug.txt && \
  echo "    ✓  captura.txt → F08/nodered_websocket_debug.txt"

# Portal de Operações — HTML source da aplicação web
[ -f "curlteste.txt" ] && \
  git mv curlteste.txt F08_Web_100/portal_html_source.txt && \
  echo "    ✓  curlteste.txt → F08/portal_html_source.txt"

# Nikto — scan de headers de segurança no Node-RED porta 1880
[ -f "nikto1.txt" ] && \
  git mv nikto1.txt F08_Web_100/nikto_nodered_1880.txt && \
  echo "    ✓  nikto1.txt → F08/nikto_nodered_1880.txt"

# Request HTTP do sqlmap para /api/session (necessário para reproduzir)
[ -f "request.txt" ] && \
  git mv request.txt F08_Web_100/sqlmap_request_session.txt && \
  echo "    ✓  request.txt → F08/sqlmap_request_session.txt"

# Flows formatados em JSON (versão com 33KB, mais completa que a da pasta F08)
[ -f "flows_json.txt" ] && \
  git mv flows_json.txt F08_Web_100/nodered_flows_formatado.json && \
  echo "    ✓  flows_json.txt → F08/nodered_flows_formatado.json"

# Tráfego MQTT bruto capturado via WebSocket (diferente do mqtt_topics.txt)
[ -f "trafego_mqtt.txt" ] && \
  git mv trafego_mqtt.txt F08_Web_100/mqtt_trafego_raw.txt && \
  echo "    ✓  trafego_mqtt.txt → F08/mqtt_trafego_raw.txt"

# ──────────────────────────────────────────────────────────────
# 3. MOVER PARA F09_Automacao — payloads e scripts de teste
# ──────────────────────────────────────────────────────────────
echo ""
echo "[3/5] Movendo scripts e payloads para F09_Automacao/..."

# Payload exec node — correto e testado (via POST /flow)
[ -f "exec_rce.json" ] && \
  git mv exec_rce.json F09_Automacao/nodered_payload_exec.json && \
  echo "    ✓  exec_rce.json → F09/nodered_payload_exec.json"

# Payload function node — reverse shell (bloqueado pelo EBUSY)
[ -f "rce.json" ] && \
  git mv rce.json F09_Automacao/nodered_payload_reverseshell.json && \
  echo "    ✓  rce.json → F09/nodered_payload_reverseshell.json"

# Payload ping test — usado para confirmar execução de código
[ -f "ping_test.json" ] && \
  git mv ping_test.json F09_Automacao/nodered_payload_ping.json && \
  echo "    ✓  ping_test.json → F09/nodered_payload_ping.json"

# Payload SSRF — testa acesso ao DC via Node-RED como proxy
[ -f "ssrf_test.json" ] && \
  git mv ssrf_test.json F09_Automacao/nodered_payload_ssrf.json && \
  echo "    ✓  ssrf_test.json → F09/nodered_payload_ssrf.json"

# Script de injeção MQTT simples (envia payload único para PUMP001)
[ -f "injetar2.py" ] && \
  git mv injetar2.py F09_Automacao/mqtt_inject_simples.py && \
  echo "    ✓  injetar2.py → F09/mqtt_inject_simples.py"

# Script de injeção MQTT avançado (tenta RCE via campo location)
[ -f "injetar_av.py" ] && \
  git mv injetar_av.py F09_Automacao/mqtt_inject_rce.py && \
  echo "    ✓  injetar_av.py → F09/mqtt_inject_rce.py"

# CYMAG Scanner v1.1 — versão mais recente (63KB, tem 3-layer detection)
[ -f "python_v1.py" ] && \
  git mv python_v1.py F09_Automacao/cymag_scanner_v1.1.py && \
  echo "    ✓  python_v1.py → F09/cymag_scanner_v1.1.py"

# ──────────────────────────────────────────────────────────────
# 4. RELATÓRIOS GERADOS — pasta própria
# ──────────────────────────────────────────────────────────────
echo ""
echo "[4/5] Organizando relatórios gerados..."
mkdir -p relatorios

for f in CYMAG_*.pdf CYMAG_*.html; do
  [ -f "$f" ] && git mv "$f" relatorios/ && echo "    ✓  $f → relatorios/"
done

# ──────────────────────────────────────────────────────────────
# 5. .gitignore — evitar repetir os problemas
# ──────────────────────────────────────────────────────────────
echo ""
echo "[5/5] Criando .gitignore..."

cat > .gitignore << 'IGNORE'
# Configs pessoais do shell (nunca commitar)
.zshrc
.zshrc*
.bashrc
.bash_history
.zsh_history

# Binários e ferramentas
chisel
chisel_*
*.exe
*.elf

# Chaves e credenciais
api.txt
*.key
*.pem
id_rsa
*api_key*
*secret*
*password*
*credentials*

# Python
venv/
__pycache__/
*.pyc
.env

# Sistema
.DS_Store
Thumbs.db
*.swp
*~

# Saídas temporárias de scan
*.gnmap
nmap_temp_*
sqlmap_output/
IGNORE

git add .gitignore
echo "    ✓  .gitignore criado"

# ──────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════"
echo "  ✅ Reorganização concluída!"
echo ""
echo "  ⚠  ATENÇÃO: api.txt continha uma chave Groq API."
echo "     Acesse console.groq.com e REVOGUE essa chave"
echo "     imediatamente. Ela ficou exposta no GitHub."
echo ""
echo "  Próximos passos:"
echo "    git add -A"
echo "    git commit -m 'refactor: reorganizacao baseada no conteudo dos arquivos'"
echo "    git push origin main"
echo "═══════════════════════════════════════════════════"
