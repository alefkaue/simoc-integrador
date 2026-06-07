import time, json, paho.mqtt.client as mqtt

BROKER = "10.10.100.100"
client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.connect(BROKER, 1883, 60)

print("[-] Transmissão contínua iniciada. Olhe o outro terminal!")

try:
    while True:
        for nivel in [95, 80, 65, 40, 15]:
            payload = {
                "pumpId": "PUMP001",
                "capacityCurrent": int(5000 * (nivel / 100)),
                "capacityTotal": 5000,
                "capacityPercentage": str(float(nivel)),
                "location": "Terminal Leste",
                "fuelType": "Diesel S-10",
                "timestamp": int(time.time() * 1000)
            }
            client.publish("fuel-pumps/data", json.dumps(payload))
            print(f"[+] Enviado nível: {nivel}%")
            time.sleep(2)  # Envia a cada 2 segundos para dar tempo de ler
except KeyboardInterrupt:
    print("\n[-] Parando simulação...")
    client.disconnect()
