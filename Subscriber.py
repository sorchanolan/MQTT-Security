import paho.mqtt.client as mqtt
from Crypto.Cipher import AES
from Crypto.Util import Counter
import binascii
import requests
import hashlib
from flask_restful import Resource, Api
from flask import Flask, request
import base64

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
		print "Encrypted message with nonce: " + current_nonce + current_msg
		decrypt(current_msg, current_nonce, keys[2])
		current_msg = ""

def decrypt(encrypted_msg, nonce, key):
	global current_nonce
	ctr = Counter.new(128, initial_value=int_of_string(nonce))
	aes = AES.new(key, AES.MODE_CTR, counter=ctr)
	decrypted = aes.decrypt(encrypted_msg)
	print "Original message: " + decrypted
	return decrypted

def incrementNonce(nonce):
	for i in range (16, 0):
		if ++nonce[i - 1] != 0:
			break
		return nonce

def int_of_string(s):
    return int(binascii.hexlify(s), 16)

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
		encryptedMsg = base64.b64decode(response.json()['key'])
		nonce = encryptedMsg[:16]
		encryptedMsg = encryptedMsg[16:]
		print "Nonce: " + nonce + " encrypted msg: " + encryptedMsg
		newKey = decrypt(encryptedMsg, nonce, privateKey)
	else:
		print "Access restricted"

def getExistingKey(pwdhash, keyId):
	global username
	response = requests.get("%s/existing/%s/%s/%d" % (BASE_URL, username, pwdhash, keyId))
	if response.json()['access'] is True:
		encryptedMsg = base64.b64decode(response.json()['key'])
		nonce = encryptedMsg[:16]
		encryptedMsg = encryptedMsg[16:]
		print "Nonce: " + nonce + " encrypted msg: " + encryptedMsg
		existingKey = decrypt(encryptedMsg, nonce, privateKey)
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
	getExistingKey(pwdhash, 55)
	mqttc.loop_forever()
