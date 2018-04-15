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
PRIVATE_TOPIC = "OzH8Ksub2"
NEW_KEY_TOPIC = "new_key"
EXISTING_KEY_TOPIC = "existing_key"
REGISTER_TOPIC = "register"

username = "sub2"
password = "Password123"
private_key = "jDasSyVU6v5gA7JVR44nYA1wNiec0AvD"

keys = ["Gv5BBQvjxDFNgjyo", "rh4KTvALW6pyHRKr36yUcu4o", "9PMkFNpjm7oikrhqYd3fEi9byIdz7GGo"]
current_msg = ""
current_nonce = ""
current_key = ""
pwdhash = base64.b64encode(hashlib.sha1(password).digest())
key_id = 0
different_key = False

def on_connect(mosq, obj, rc):
	mqttc.subscribe(MAIN_TOPIC, 0)
	mqttc.subscribe(username, 0)
	mqttc.subscribe(PRIVATE_TOPIC, 0)

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
	global current_msg, current_nonce, key_id, different_key
	h = binascii.hexlify(msg)
	current_fragment = h[:2]

	if current_msg == "":
		msb = int(h[2:4], 16)
		lsb = int(h[4:6], 16)
		this_key_id = msb*256 + lsb
		if (key_id != this_key_id):
			key_id = this_key_id
			different_key = True
		else:
			different_key = False
		print "key id: %d" % (key_id)
		current_nonce = msg[3:11]
		current_msg = msg[11:]
	else:
		current_msg += msg[1:]

	if current_fragment == "ff":
		current_nonce += "00000000"
		print "Encrypted message with nonce: " + current_nonce + current_msg
		if different_key:
			get_existing_key(pwdhash, key_id)
		else:
			decrypt_msg()
		# decrypt(current_msg, current_nonce, keys[2])
		# current_msg = ""

def get_key(msg):
	global current_msg, current_key
	nonce = msg[:8] + "00000000"
	encrypted_msg = base64.b64decode(msg[8:])
	print "Encrypted key with nonce: " + nonce + " " + encrypted_msg
	current_key = decrypt(encrypted_msg, nonce, private_key)
	decrypt_msg()

def decrypt_msg():
	global current_msg, current_nonce, current_key
	decrypt(current_msg, current_nonce, current_key)
	current_msg = ""

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
	# global pwdhash
	# pwdhash = base64.b64encode(hashlib.sha1(password).digest())
	# register(pwdhash)
	# get_new_key(pwdhash, 32)
	# get_existing_key(pwdhash, 55)
	mqttc.loop_forever()
