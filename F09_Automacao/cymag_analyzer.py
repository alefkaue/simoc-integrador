#!/usr/bin/env python3
"""
CYMAG Nmap Analyzer v3.0
Equipe CYMAG | SENAI Seguranca Cibernetica 2026
Uso: python3 cymag_analyzer.py scan.xml -o relatorio.txt --csv achados.csv
"""

import xml.etree.ElementTree as ET
import argparse, csv, sys
from datetime import datetime

PORTAS_CRITICAS = {
    445: {"s": "SMB", "r": "CRITICO", "cve": "CWE-300 / CVE-2017-0144", "d": "SMB exposto - vetor primario de ransomware (EternalBlue/WannaCry)"},
    3389: {"s": "RDP", "r": "ALTO", "cve": "CVE-2019-0708", "d": "RDP exposto - BlueKeep, brute force facilitado sem NLA"},
    389: {"s": "LDAP", "r": "ALTO", "cve": "CWE-862", "d": "LDAP - bind anonimo pode expor estrutura do Active Directory"},
    88: {"s": "Kerberos", "r": "ALTO", "cve": "CWE-287", "d": "Kerberos - AS-REP Roasting e Kerberoasting possiveis"},
    1880: {"s": "Node-RED", "r": "CRITICO", "cve": "CWE-306", "d": "Node-RED sem autenticacao padrao - painel IoT acessivel livremente"},
    1883: {"s": "MQTT", "r": "CRITICO", "cve": "CWE-306", "d": "MQTT Broker sem autenticacao e sem TLS - mensagens IoT expostas"},
    3307: {"s": "MySQL", "r": "CRITICO", "cve": "CVE-2012-5627", "d": "MySQL 5.5.62 - EOL desde 2018, sem patches, multiplas CVEs abertas"},
    80: {"s": "HTTP", "r": "MEDIO", "cve": "CWE-319", "d": "HTTP sem TLS - dados trafegam em texto claro"},
    22: {"s": "SSH", "r": "BAIXO", "cve": "N/A", "d": "SSH exposto - versao recente, verificar configuracao de acesso"},
    5985: {"s": "WinRM", "r": "ALTO", "cve": "CWE-284", "d": "WinRM - gerenciamento remoto Windows exposto"},
    135: {"s": "RPC", "r": "MEDIO", "cve": "CWE-284", "d": "RPC Endpoint Mapper - enumeracao de servicos Windows possivel"},
    139: {"s": "NetBIOS", "r": "MEDIO", "cve": "CWE-200", "d": "NetBIOS - LLMNR poisoning, vazamento de informacoes de rede"},
    5040: {"s": "Desconhecido", "r": "MEDIO", "cve": "N/A", "d": "Servico nao identificado na porta 5040 - investigar"},
}

ORDEM = ["CRITICO", "ALTO", "MEDIO", "BAIXO"]

def parse_nmap(arquivo):
    try:
        tree = ET.parse(arquivo)
    except FileNotFoundError:
        print(f"[ERRO] Arquivo nao encontrado: {arquivo}")
        sys.exit(1)
    except ET.ParseError as e:
        print(f"[ERRO] XML invalido: {e}")
        sys.exit(1)
        
    root = tree.getroot()
    alertas = []
    
    for host in root.findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        
        ip = addr_el.get("addr", "N/A")
        hostname_el = host.find(".//hostname")
        hostname = hostname_el.get("name", "") if hostname_el is not None else ""
        
        for port in host.findall(".//port"):
            estado = port.find("state")
            if estado is None or estado.get("state") != "open":
                continue
            
            portid = int(port.get("portid", 0))
            proto = port.get("protocol", "tcp")
            svc = port.find("service")
            
            nome_svc = svc.get("name", "?") if svc is not None else "?"
            produto = svc.get("product", "") if svc is not None else ""
            versao = svc.get("version", "") if svc is not None else ""
            ver_completa = f"{produto} {versao}".strip()
            
            if portid in PORTAS_CRITICAS:
                info = PORTAS_CRITICAS[portid]
                alertas.append({
                    "ip": ip, "hostname": hostname, "porta": portid,
                    "proto": proto, "servico": nome_svc, "versao": ver_completa,
                    "risco": info["r"], "cve": info["cve"], "descricao": info["d"],
                })
                
    return sorted(alertas, key=lambda x: (ORDEM.index(x["risco"]), x["ip"], x["porta"]))

def gerar_relatorio(alertas, arquivo_saida=None):
    agora = datetime.now().strftime("%d/%m/%Y %H:%M")
    L = []
    L.append("=" * 70)
    L.append(" CYMAG -- RELATORIO DE PORTAS CRITICAS")
    L.append(f" Gerado em: {agora}")
    L.append(" Equipe CYMAG | SENAI Seguranca Cibernetica 2026")
    L.append(" Rede analisada: 10.10.100.0/24")
    L.append("=" * 70)
    
    risco_atual = None
    for a in alertas:
        if a["risco"] != risco_atual:
            risco_atual = a["risco"]
            L.append(f"\n{'─' * 70}")
            L.append(f" [ {risco_atual} ]")
            L.append(f"{'─' * 70}")
            
        host = a["ip"] + (f" ({a['hostname']})" if a["hostname"] else "")
        L.append(f"\n Host    : {host}")
        L.append(f" Porta   : {a['porta']}/{a['proto']} ({a['servico']} {a['versao']})".rstrip())
        L.append(f" CVE/CWE : {a['cve']}")
        L.append(f" Risco   : {a['descricao']}")
        
    contagem = {r: sum(1 for a in alertas if a["risco"] == r) for r in ORDEM}
    L.append(f"\n{'=' * 70}")
    L.append(f" RESUMO -- Total de alertas: {len(alertas)}")
    
    for r in ORDEM:
        if contagem[r]:
            L.append(f" {r:<10}: {contagem[r]} alerta(s)")
            
    L.append("=" * 70)
    texto = "\n".join(L)
    
    if arquivo_saida:
        with open(arquivo_saida, "w", encoding="utf-8") as f:
            f.write(texto)
        print(f"[OK] Relatorio salvo em: {arquivo_saida}")
    else:
        print(texto)
        
    return texto

def gerar_csv(alertas, arquivo_csv):
    campos = ["ip","hostname","porta","proto","servico","versao","risco","cve","descricao"]
    with open(arquivo_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=campos)
        w.writeheader()
        w.writerows(alertas)
    print(f"[OK] CSV salvo em: {arquivo_csv}")

def main():
    parser = argparse.ArgumentParser(description="CYMAG Nmap Analyzer")
    parser.add_argument("xml", help="Arquivo XML do Nmap")
    parser.add_argument("-o", "--output", help="Salvar relatorio em .txt")
    parser.add_argument("--csv", help="Exportar para CSV")
    parser.add_argument("--only-critical", action="store_true", help="Mostrar so CRITICO e ALTO")
    
    args = parser.parse_args()
    alertas = parse_nmap(args.xml)
    
    if args.only_critical:
        alertas = [a for a in alertas if a["risco"] in ("CRITICO", "ALTO")]
        
    if not alertas:
        print("[INFO] Nenhuma porta critica encontrada.")
        sys.exit(0)
        
    gerar_relatorio(alertas, args.output)
    
    if args.csv:
        gerar_csv(alertas, args.csv)

if __name__ == "__main__":
    main()
