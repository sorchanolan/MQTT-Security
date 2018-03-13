import paho.mqtt.client as mqtt
from Crypto.Cipher import AES
import binascii

# Define Variables
MQTT_HOST = "127.0.0.1"
MQTT_PORT = 2883
MQTT_KEEPALIVE_INTERVAL = 5
MQTT_TOPIC = "t"
MQTT_MSG = "Hello MQTT"
keys = ["Gv5BBQvjxDFNgjy", "rh4KTvALW6pyHRKr36yUcu4", "9PMkFNpjm7oikrhqYd3fEi9byIdz7GGo"]
current_msg = ""
current_nonce = ""
current_fragment = 0


# Define on_connect event Handler
def on_connect(mosq, obj, rc):
	#Subscribe to a the Topic
	mqttc.subscribe(MQTT_TOPIC, 0)

# Define on_subscribe event Handler
def on_subscribe(mosq, obj, mid, granted_qos):
    print "Subscribed to MQTT Topic"

# Define on_message event Handler
def on_message(mosq, obj, msg):
	global current_fragment, current_msg, current_nonce
	s = msg.payload
	h = binascii.hexlify(s)
	# print h + '\n'

	current_fragment = h[:2]
	# print "fragment number " + current_fragment
	if current_msg == "":
		current_nonce = s[1:17]
		# print "nonce " + current_nonce
		current_msg = s[17:]
	else:
		current_msg += s[1:]

	if current_fragment == "ff":
		# file2write=open("encrypted_data.txt",'a')
		# file2write.write(current_msg + '\n')
		# file2write.close()
		print "encrypted msg " + binascii.hexlify(current_msg)
		decrypt(current_msg, current_nonce)
		current_msg = ""

def decrypt(encrypted_msg, nonce):
	global current_nonce
	aes = AES.new(keys[2], AES.MODE_CTR, counter=lambda:nonce)
	decrypted = aes.decrypt(encrypted_msg)
	print "decrypted msg " + decrypted

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