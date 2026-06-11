import threading
import webbrowser
import time
from flask import Flask, render_template_string

# Simulação do seu dashboard HTML
HTML_DASHBOARD = """
<!DOCTYPE html>
<html lang=\"en\">
<head>
    <meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
    <title>CYMAG Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f4; color: #333; }
        .container { background-color: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); max-width: 800px; margin: auto; }
        h1 { color: #0056b3; }
        p { line-height: 1.6; }
        .score { font-size: 2em; font-weight: bold; color: #d9534f; }
        .risk-level { font-size: 1.2em; color: #5cb85c; }
    </style>
</head>
<body>
    <div class=\"container\">
        <h1>Relatório CYMAG - Pentest Autônomo</h1>
        <p>Prezado(a) C-Level,</p>
        <p>Este é o seu painel de controle interativo do CYMAG, apresentando os resultados da última varredura de segurança.</p>
        <p><strong>Score Executivo de Risco:</strong> <span class=\"score\">7.8</span></p>
        <p><strong>Nível de Risco Geral:</strong> <span class=\"risk-level\">Alto</span></p>
        <p>Detalhes completos e recomendações podem ser encontrados abaixo.</p>
        <p><em>Este é um conteúdo simulado para demonstração.</em></p>
    </div>
</body>
</html>
"""

app = Flask(__name__)

@app.route("/")
def index():
    return render_template_string(HTML_DASHBOARD)

def start_flask():
    # Desativa o log de acesso do Flask para manter o console limpo
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False)

def open_browser():
    # Espera um curto período para garantir que o servidor Flask esteja ativo
    time.sleep(1)
    print("Abrindo o navegador padrão...")
    webbrowser.open("http://127.0.0.1:5000" )

if __name__ == '__main__':
    print("Iniciando servidor Flask em uma thread separada...")
    flask_thread = threading.Thread(target=start_flask)
    flask_thread.daemon = True  # Permite que a thread Flask seja encerrada quando o programa principal terminar
    flask_thread.start()

    # Chama a função para abrir o navegador na thread principal
    open_browser()

    # Mantém a thread principal viva para que o servidor Flask continue rodando
    # Em um ambiente real, você teria um loop principal ou outra lógica aqui
    # Para este exemplo, apenas esperamos um pouco antes de encerrar (opcional)
    try:
        while True:
            time.sleep(1) # Mantém o programa rodando indefinidamente
    except KeyboardInterrupt:
        print("Aplicação encerrada pelo usuário.")

