import paho.mqtt.client as mqtt
from Crypto.Cipher import AES
import binascii
import requests
import hashlib
from flask_restful import Resource, Api
from flask import Flask, request

# Define Variables
MQTT_HOST = "127.0.0.1"
MQTT_PORT = 2883
MQTT_KEEPALIVE_INTERVAL = 5
MQTT_TOPIC = "t"

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False

BASE_URL = "http://127.0.0.1:5000/KMS"
REGISTER_USER_URL = "http://127.0.0.1:5000/KMS/register-user"

username = "sub2"
password = "Password123"
privateKey = None

keys = ["Gv5BBQvjxDFNgjy", "rh4KTvALW6pyHRKr36yUcu4", "9PMkFNpjm7oikrhqYd3fEi9byIdz7GGo"]
current_msg = ""
current_nonce = ""
current_fragment = 0

def on_connect(mosq, obj, rc):
	mqttc.subscribe(MQTT_TOPIC, 0)

def on_subscribe(mosq, obj, mid, granted_qos):
    print "Subscribed to MQTT Topic"

def on_message(mosq, obj, msg):
	global current_fragment, current_msg, current_nonce
	s = msg.payload
	h = binascii.hexlify(s)

	current_fragment = h[:2]
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

def decrypt(encrypted_msg, nonce, key):
	global current_nonce
	aes = AES.new(key, AES.MODE_CTR, counter=lambda:nonce)
	decrypted = aes.decrypt(encrypted_msg)
	print "decrypted msg " + decrypted

def registerWithKms(pwdhash):
	global username, privateKey
	response = requests.get(REGISTER_USER_URL, json={"username": username, "pwdhash": pwdhash})
	if response.json()['success'] is True:
		privateKey = response.json()['key']
		print "Private key: " + privateKey
	else:
		print "Already registered with KMS"

def getNewKey(pwdhash):
	global username
	response = requests.get("%s/new/%s/%s/%d" % (BASE_URL, username, pwdhash, 32))
	if response.json()['access'] is True:
		encryptedMsg = response.json()['key']
		print "New key: " + encryptedMsg
		decrypt(encryptedMsg[17:], encryptedMsg[:17], privateKey)
	else:
		print "Access restricted"

mqttc = mqtt.Client()

mqttc.on_message = on_message
mqttc.on_connect = on_connect
mqttc.on_subscribe = on_subscribe

mqttc.connect(MQTT_HOST, MQTT_PORT, MQTT_KEEPALIVE_INTERVAL )

if __name__ == '__main__':
	pwdhash = hashlib.sha1(password).hexdigest()
	registerWithKms(pwdhash)
	getNewKey(pwdhash)
	mqttc.loop_forever()
