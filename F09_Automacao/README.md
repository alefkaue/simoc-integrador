	# cymag_analyzer.py — CYMAG Nmap Analyzer v3.0
	
	Script Python que processa saidas XML do Nmap e classifica portas criticas
	de ransomware por nivel de risco (CRITICO / ALTO / MEDIO / BAIXO).
	
	## Como usar
	
	### Analise basica (saida no terminal):
	python3 cymag_analyzer.py scan.xml
	
	### Salvar relatorio:
	python3 cymag_analyzer.py scan.xml -o relatorio.txt
	
	### Exportar CSV:
	python3 cymag_analyzer.py scan.xml --csv achados.csv
	
	### Ver so CRITICO e ALTO:
	python3 cymag_analyzer.py scan.xml --only-critical
	
	### Tudo junto:
	python3 cymag_analyzer.py scan.xml -o relatorio.txt --csv achados.csv
	
	## Equipe CYMAG | SENAI Seguranca Cibernetica | 1 Semestre 2026
	EOF
