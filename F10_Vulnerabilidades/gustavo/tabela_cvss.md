	# CYMAG - Analise de Vulnerabilidades e CVEs
	# Fase 10 - Correlacao CVE/NVD/OWASP | CVSS v3.1
	# Analista: Gustavo Lopreto | Rede: 10.10.100.0/24
	# Data: junho/2026
	
	## Fontes consultadas
	- NVD NIST: https://nvd.nist.gov
	- OWASP Top 10 2021: https://owasp.org/Top10
	- CVE Mitre: https://cve.mitre.org
	
	## Domain Controller - 10.10.100.2
	
	| CVE / CWE | Vulnerabilidade | CVSS v3.1 | Criticidade | Mitigacao |
	|-------------------------|--------------------------------------|-----------|-------------|-----------------------------------------|
	| CWE-300 / CVE-2017-0144 | SMB Signing desabilitado/NTLM Relay | 7.5 | Alta | GPO: habilitar SMB Signing obrigatorio |
	| CVE-2017-0144 | EternalBlue SMBv1 (ja desabilitado) | 10.0 | MITIGADO | SMBv1 ja off - manter monitoramento |
	| CVE-2020-1472 | Zerologon - Netlogon RCE | 10.0 | Critica | Verificar patch MS-NRPC ago/2020 |
	| CWE-284 | RPC Endpoint Mapper exposto | 5.3 | Media | Restringir acesso RPC por firewall |
	| CWE-200 | NetBIOS - LLMNR poisoning possivel | 5.3 | Media | Desabilitar LLMNR via GPO |
	
	## Host Desconhecido - 10.10.100.3
	
	| CVE / CWE | Vulnerabilidade | CVSS v3.1 | Criticidade | Mitigacao |
	|-----------|-----------------------------------|-----------|-------------|--------------------------------------|
	| CWE-284 | RPC exposto - enumeracao possivel | 5.3 | Media | Restringir acesso RPC por firewall |
	
	## Servidor Linux IoT - 10.10.100.100
	
	| CVE / CWE | Vulnerabilidade | CVSS v3.1 | Criticidade | Mitigacao |
	|--------------|----------------------------------------|-----------|-------------|---------------------------------------------|
	| CWE-306 | Node-RED sem autenticacao (p.1880) | 9.1 | Critica | Habilitar adminAuth no settings.js |
	| CWE-306 | MQTT sem autenticacao e sem TLS (1883) | 9.1 | Critica | password_file + TLS no mosquitto.conf |
	| CVE-2012-5627| MySQL 5.5.62 - EOL desde 2018 (3307) | 9.8 | Critica | Migrar para MySQL 8.x ou MariaDB |
	| CWE-319 | HTTP nginx sem HTTPS (p.80) | 5.3 | Media | Configurar TLS/HTTPS no nginx |
	| N/A | SSH exposto sem restricao de origem | 3.7 | Baixa | Restringir por IP + chave publica apenas |
	
	## Resumo de Criticidade
	
	| Nivel | Quantidade |
	|----------|------------|
	| Critica | 5 |
	| Alta | 1 |
	| Media | 4 |
	| Baixa | 1 |
	| Mitigado | 1 |
	EOF
