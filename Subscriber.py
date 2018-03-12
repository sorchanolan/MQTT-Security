import paho.mqtt.client as mqtt
from Crypto.Cipher import AES
import binascii

# Define Variables
MQTT_HOST = "127.0.0.1"
MQTT_PORT = 2883
MQTT_KEEPALIVE_INTERVAL = 5
MQTT_TOPIC = "t"
MQTT_MSG = "Hello MQTT"
keys = ["Gv5BBQvjxDFNgjy", "rh4KTvALW6pyHRKr36yUcu4", "9PMkFNpjm7oikrhqYd3fEi9byIdz7GG"]


# Define on_connect event Handler
def on_connect(mosq, obj, rc):
	#Subscribe to a the Topic
	mqttc.subscribe(MQTT_TOPIC, 0)

# Define on_subscribe event Handler
def on_subscribe(mosq, obj, mid, granted_qos):
    print "Subscribed to MQTT Topic"

# Define on_message event Handler
def on_message(mosq, obj, msg):
	s = msg.payload
	h = binascii.hexlify(s)
	print s
	file2write=open("encrypted_data.txt",'a')
	file2write.write(s + '\n')
	file2write.close()

	#decrypt(msg.payload)

#def decrypt(encrypted_msg):
#	aes = AES.new(keys[2], AES.MODE_CTR, )

# Initiate MQTT Client
mqttc = mqtt.Client()

# Register Event Handlers
mqttc.on_message = on_message
mqttc.on_connect = on_connect
mqttc.on_subscribe = on_subscribe

# Connect with MQTT Broker
mqttc.connect(MQTT_HOST, MQTT_PORT, MQTT_KEEPALIVE_INTERVAL )

# Continue the network loop
mqttc.loop_forever()

