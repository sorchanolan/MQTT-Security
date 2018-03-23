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

keys = ["Gv5BBQvjxDFNgjyo", "rh4KTvALW6pyHRKr36yUcu4o", "9PMkFNpjm7oikrhqYd3fEi9byIdz7GGo"]
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
	encryption_id = h[2:4]
	encryption = get_encryption(int(encryption_id, 16))
	print encryption.algorithm + str(encryption.key_length) + encryption.mode
	if current_msg == "":
		current_nonce = s[2:18]
		# print "nonce " + current_nonce
		current_msg = s[18:]
	else:
		current_msg += s[2:]

	if current_fragment == "ff":
		print len(current_msg)
		# print "Encrypted message with nonce: " + current_nonce + current_msg
		decrypt(current_msg, current_nonce, keys[(encryption.key_length - 128) / 64])
		current_msg = ""

def decrypt(encrypted_msg, nonce, key):
	global current_nonce
	ctr = Counter.new(128, initial_value=int_of_string(nonce))
	aes = AES.new(key, AES.MODE_ECB)#, counter=ctr)
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

class Encryption(object):
    algorithm = ""
    key_length = 0
    mode = ""

    def __init__(self, algorithm, key_length, mode):
        self.algorithm = algorithm
        self.key_length = key_length
        self.mode = mode

def make_encryption(algorithm, key_length, mode):
    encryption = Encryption(algorithm, key_length, mode)
    return encryption

def get_encryption(encryption_id):
	if encryption_id == 1:
		return make_encryption("ARC4", 128, "")
	if encryption_id == 2:
		return make_encryption("CAMELLIA", 128, "ECB")
	if encryption_id == 3:
		return make_encryption("CAMELLIA", 128, "CBC")
	if encryption_id == 4:
		return make_encryption("CAMELLIA", 128, "CTR")
	if encryption_id == 5:
		return make_encryption("CAMELLIA", 128, "CCM")
	if encryption_id == 6:
		return make_encryption("CAMELLIA", 128, "GCM")
	if encryption_id == 7:
		return make_encryption("CAMELLIA", 128, "CFB128")
	if encryption_id == 8:
		return make_encryption("AES", 128, "ECB")
	if encryption_id == 9:
		return make_encryption("AES", 128, "CBC")
	if encryption_id == 10:
		return make_encryption("AES", 128, "CTR")
	if encryption_id == 11:
		return make_encryption("AES", 128, "CCM")
	if encryption_id == 12:
		return make_encryption("AES", 128, "GCM")
	if encryption_id == 13:
		return make_encryption("AES", 128, "CFB128")
	if encryption_id == 14:
		return make_encryption("BLOWFISH", 128, "CTR")
	if encryption_id == 15:
		return make_encryption("BLOWFISH", 128, "ECB")
	if encryption_id == 16:
		return make_encryption("BLOWFISH", 128, "CBC")
	if encryption_id == 17:
		return make_encryption("BLOWFISH", 128, "CFB64")
	if encryption_id == 18:
		return make_encryption("CAMELLIA", 192, "ECB")
	if encryption_id == 19:
		return make_encryption("CAMELLIA", 192, "CBC")
	if encryption_id == 20:
		return make_encryption("CAMELLIA", 192, "CTR")
	if encryption_id == 21:
		return make_encryption("CAMELLIA", 192, "CCM")
	if encryption_id == 22:
		return make_encryption("CAMELLIA", 192, "GCM")
	if encryption_id == 23:
		return make_encryption("CAMELLIA", 192, "CFB128")
	if encryption_id == 24:
		return make_encryption("AES", 192, "ECB")
	if encryption_id == 25:
		return make_encryption("AES", 192, "CBC")
	if encryption_id == 26:
		return make_encryption("AES", 192, "CTR")
	if encryption_id == 27:
		return make_encryption("AES", 192, "CCM")
	if encryption_id == 28:
		return make_encryption("AES", 192, "GCM")
	if encryption_id == 29:
		return make_encryption("AES", 192, "CFB128")
	if encryption_id == 30:
		return make_encryption("BLOWFISH", 192, "CTR")
	if encryption_id == 31:
		return make_encryption("BLOWFISH", 192, "ECB")
	if encryption_id == 32:
		return make_encryption("BLOWFISH", 192, "CBC")
	if encryption_id == 33:
		return make_encryption("BLOWFISH", 192, "CFB64")
	if encryption_id == 34:
		return make_encryption("CAMELLIA", 256, "ECB")
	if encryption_id == 35:
		return make_encryption("CAMELLIA", 256, "CBC")
	if encryption_id == 36:
		return make_encryption("CAMELLIA", 256, "CTR")
	if encryption_id == 37:
		return make_encryption("CAMELLIA", 256, "CCM")
	if encryption_id == 38:
		return make_encryption("CAMELLIA", 256, "GCM")
	if encryption_id == 39:
		return make_encryption("CAMELLIA", 256, "CFB128")
	if encryption_id == 40:
		return make_encryption("AES", 256, "ECB")
	if encryption_id == 41:
		return make_encryption("AES", 256, "CBC")
	if encryption_id == 42:
		return make_encryption("AES", 256, "CTR")
	if encryption_id == 43:
		return make_encryption("AES", 256, "CCM")
	if encryption_id == 44:
		return make_encryption("AES", 256, "GCM")
	if encryption_id == 45:
		return make_encryption("AES", 256, "CFB128")
	if encryption_id == 46:
		return make_encryption("BLOWFISH", 256, "CTR")
	if encryption_id == 47:
		return make_encryption("BLOWFISH", 256, "ECB")
	if encryption_id == 48:
		return make_encryption("BLOWFISH", 256, "CBC")
	if encryption_id == 49:
		return make_encryption("BLOWFISH", 256, "CFB64")

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
