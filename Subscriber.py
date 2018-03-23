import paho.mqtt.client as mqtt
from Crypto.Cipher import AES
from Crypto.Util import Counter
import binascii
import requests
import hashlib
import base64
import json
import time

# Define Variables
MQTT_HOST = "127.0.0.1"
MQTT_PORT = 2883
MQTT_KEEPALIVE_INTERVAL = 5
MAIN_TOPIC = "t"
PRIVATE_TOPIC = None
NEW_KEY_TOPIC = "new_key"
EXISTING_KEY_TOPIC = "existing_key"
REGISTER_TOPIC = "register"

username = "sub2"
password = "Password123"
private_key = None

keys = ["Gv5BBQvjxDFNgjyo", "rh4KTvALW6pyHRKr36yUcu4o", "9PMkFNpjm7oikrhqYd3fEi9byIdz7GGo"]
current_msg = ""
current_nonce = ""

def on_connect(mosq, obj, rc):
	mqttc.subscribe(MAIN_TOPIC, 0)
	mqttc.subscribe(username, 0)

def on_subscribe(mosq, obj, mid, granted_qos):
    print "Subscribed to MQTT Topic"

def on_message(mosq, obj, msg):
	if msg.topic == MAIN_TOPIC:
		get_msg(msg.payload)
	elif msg.topic == PRIVATE_TOPIC:
		get_key(msg.payload)
	elif msg.topic == username:
		registered(msg.payload)

def registered(msg):
	global private_key, PRIVATE_TOPIC
	response = json.loads(msg)
	private_key = response['k']
	PRIVATE_TOPIC = response['t']
	print "Private key: " + private_key
	print "Private topic: " + PRIVATE_TOPIC
	mqttc.subscribe(PRIVATE_TOPIC.encode('ascii'), 0)
	get_existing_key(pwdhash, 1)

def get_msg(msg):
	global current_msg, current_msg
	h = binascii.hexlify(msg)
	current_fragment = h[:2]

	if current_msg == "":
		current_nonce = msg[1:17]
		current_msg = msg[17:]
	else:
		current_msg += msg[1:]

	if current_fragment == "ff":
		print "Encrypted message with nonce: " + current_nonce + current_msg
		decrypt(current_msg, current_nonce, keys[2])
		current_msg = ""

def get_key(msg):
	msg = base64.b64decode(msg)
	nonce = msg[:8] + "00000000"
	encrypted_msg = msg[8:]
	print "Encrypted message with nonce: " + nonce + " " + encrypted_msg
	return decrypt(encrypted_msg, nonce, private_key)

def decrypt(encrypted_msg, nonce, key):
	ctr = Counter.new(128, initial_value=int_of_string(nonce))
	aes = AES.new(key, AES.MODE_CTR, counter=ctr)
	decrypted = aes.decrypt(encrypted_msg)
	print "Original message: " + decrypted
	return decrypted

def int_of_string(s):
    return int(binascii.hexlify(s), 16)

def register(pwdhash):
	payload = "{\"u\": \"%s\", \"p\": \"%s\"}" % (username, pwdhash)
	mqttc.publish(REGISTER_TOPIC, payload)

def get_new_key(pwdhash, length):
	payload = "{\"u\": \"%s\", \"p\": \"%s\",\"l\": %d}" % (username, pwdhash, length)
	mqttc.publish(NEW_KEY_TOPIC, payload)

def get_existing_key(pwdhash, key_id):
	payload = "{\"u\": \"%s\", \"p\": \"%s\",\"kid\": %d}" % (username, pwdhash, key_id)
	print payload
	mqttc.publish(EXISTING_KEY_TOPIC, payload)

mqttc = mqtt.Client()

mqttc.on_message = on_message
mqttc.on_connect = on_connect
mqttc.on_subscribe = on_subscribe

mqttc.connect(MQTT_HOST, MQTT_PORT, MQTT_KEEPALIVE_INTERVAL )

if __name__ == '__main__':
	pwdhash = hashlib.sha1(password).hexdigest()
	register(pwdhash)
	# get_new_key(pwdhash, 32)
	# get_existing_key(pwdhash, 55)
	mqttc.loop_forever()
