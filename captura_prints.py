import os
import subprocess
import time
import pyautogui

# Pasta centralizada onde as imagens finais vão cair
PASTA_IMAGENS = "evidencias_prints"
os.makedirs(PASTA_IMAGENS, exist_ok=True)

def executar_e_printar(nome_print, comando):
    """Limpa a tela, roda o comando até o fim, espera 1 minuto com ele na tela e tira o print."""
    # Limpa o terminal antes de cada comando para o print ficar limpo
    os.system('clear')
    
    print(f"[$] Executando comando: {comando}\n")
    time.sleep(1)
    
    # Executa o comando de forma síncrona (espera terminar 100%)
    # Redireciona erros para a saída padrão para saírem no print também
    subprocess.run(comando, shell=True, stdout=None, stderr=None)
    
    # Comando finalizou. Agora segura a tela por 1 minuto (60 segundos) antes do screenshot
    print(f"\n\n[*] Comando concluído. Aguardando 60 segundos com o resultado na tela para o print...")
    time.sleep(60)
    
    # Tira o screenshot da tela inteira
    print_path = os.path.join(PASTA_IMAGENS, f"{nome_print}.png")
    screenshot = pyautogui.screenshot()
    screenshot.save(print_path)
    print(f"[+] Print {nome_print} salvo com sucesso!")


# ==============================================================================
# F08 — Servidor .100
# ==============================================================================
executar_e_printar("F08_nmap_100", "sudo nmap -sS -sV -O --open -p- -T3 10.10.100.100")

executar_e_printar("F08_nodered_settings", "curl -s http://10.10.100.100")

executar_e_printar("F08_nodered_flows", "curl -s http://10.10.100.100")

# Mantido o timeout aqui para o mosquitto nao rodar infinito, mas o print respeita os 60s pós-execução
executar_e_printar(
    "F08_mqtt_topics", 
    "timeout 10 mosquitto_sub -h 10.10.100.100 -p 1883 -t '#' -v 2>/dev/null"
)

executar_e_printar("F08_sqli_test", "curl -s \"http://10.10.100.100'\"")

executar_e_printar("F08_users_dump", "cat /root/.local/share/sqlmap/output/10.10.100.100/dump/portal_operacoes/users.csv")

executar_e_printar("F08_http_headers", "curl -s -I http://10.10.100.100")

# ==============================================================================
# F09 — Script Python
# ==============================================================================
executar_e_printar("F09_scanner_output", "python3 cymag_v2.py 10.10.100.100 2>&1")

os.system('clear')
print(f"\n[+] Execução concluída com sucesso! Todos os prints foram gerados com 1 minuto de margem pós-comando.")
