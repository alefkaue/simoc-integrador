BROKER = "10.10.100.100"
client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.connect(BROKER, 1883, 60)

for nivel in [90, 80, 70, 50, 20]:
payload = {
"pumpId": "PUMP001",
"capacityCurrent": int(5000*(nivel/100)),
"capacityTotal": 5000,
"capacityPercentage": str(float(nivel)),
"location": "Terminal Leste",
"fuelType": "Diesel S-10",
"timestamp": int(time.time()*1000)
}
client.publish("fuel-pumps/data", json.dumps(payload))
print(f"Nivel: {nivel}%")
time.sleep(1) 

order = {"pumpId": "PUMP003", "currentLevel": 5}
client.publish("fuel-pumps/refill-request", json.dumps(order))
print("Ordem falsa enviada para PUMP003")
client.disconnect()
