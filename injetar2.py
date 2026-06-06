import time
import json
import paho.mqtt.client as mqtt

# Configurações do Alvo (Ajuste o IP do Broker se for diferente do Node-RED)
BROKER_HOST = "10.10.100.100"
BROKER_PORT = 1883
TOPIC = "fuel-pumps/data"

client = mqtt.Client()
client.connect(BROKER_HOST, BROKER_PORT, 60)

# Payload simulando consumo seguro (Abaixo do limite de 100L do alarme)
payload = {
    "pumpId": "PUMP001",
    "capacityCurrent": 4200,
    "capacityTotal": 5000,
    "capacityPercentage": "84.0",
    "location": "Terminal Leste",
    "fuelType": "Diesel S-10",
    "timestamp": int(time.time() * 1000)
}

print(f"Enviando dados para o tópico {TOPIC}...")
client.publish(TOPIC, json.dumps(payload))
client.disconnect() 
