import paho.mqtt.client as mqtt
import json
import time
import datetime
import MySQLdb
import string
import random
import base64
import binascii
from Crypto.Cipher import AES
from Crypto.Util import Counter

MQTT_HOST = "127.0.0.1"
MQTT_PORT = 2883
MQTT_KEEPALIVE_INTERVAL = 5
NEW_KEY_TOPIC = "new_key"
EXISTING_KEY_TOPIC = "existing_key"
REGISTER_TOPIC = "register"

db = MySQLdb.connect("127.0.0.1","sorcha","Nolan123","KMS" )
cursor = db.cursor()

def on_connect(mosq, obj, rc):
	mqttc.subscribe(NEW_KEY_TOPIC, 0)
	mqttc.subscribe(EXISTING_KEY_TOPIC, 0)
	mqttc.subscribe(REGISTER_TOPIC, 0)

def on_subscribe(mosq, obj, mid, granted_qos):
	print "Subscribed to MQTT Topic"

def on_message(mosq, obj, msg):
	if msg.topic == NEW_KEY_TOPIC:
		new_key_request(msg.payload)
	elif msg.topic == EXISTING_KEY_TOPIC:
		existing_key_request(msg.payload)
	elif msg.topic == REGISTER_TOPIC:
		register_request(msg.payload)

def new_key_request(msg):
	response = json.loads(msg)
	username = response['u']
	pwdhash = response['p']
	length = response['l']
	encrypted_key = None
	user = get_user(username, pwdhash)
	if user is not None:
		user_id = user[0]
		topic = user[3]
		key = create_new_key(length, user_id)
	   	private_key = get_private_key(user_id)
	   	encrypted_key = encrypt(private_key, key)
		mqttc.publish(topic, encrypted_key)
		print "Key to send: " + key

def existing_key_request(msg):
	print msg
	response = json.loads(msg)
	username = response['u']
	pwdhash = response['p']
	key_id = response['kid']
	encrypted_key = None
	user = get_user(username, pwdhash)
	if user is not None:
		key = get_key(key_id)
		if key is not None:
			user_id = user[0]
			private_key = get_private_key(user_id)
			encrypted_key = encrypt(private_key, key)
			print "Key to send: " + key
	topic = user[3]
	mqttc.publish(topic, encrypted_key)

def register_request(msg):
	response = json.loads(msg)
	username = response['u']
	pwdhash = response['p']
	key = None
	topic = None
	user = get_user(username, pwdhash)
	if user is None:
		topic = username + random_string(5)
		sql = "INSERT INTO Users(username, password, topic) VALUES('%s', '%s', '%s')" % (username, pwdhash, topic)
		try:
			cursor.execute(sql)
			db.commit()
			key = create_private_key(username, pwdhash)
		except:
			db.rollback()
	else:
		user_id = user[0]
		topic = user[3]
		key = get_private_key(user_id)
	payload = "{\"k\":\"%s\",\"t\":\"%s\"}" % (key, topic)
	print "User %s registered" % (username)
   	mqttc.publish(username, payload)

def get_key(key_id):
	key = None
	sql = "SELECT * FROM `Keys` WHERE id = '%d'" % (key_id)
	try:
		cursor.execute(sql)
		keyobj = cursor.fetchone()
		if keyobj is not None:
			key = keyobj[1]
	except:
		None
	return key


def get_user(username, pwdhash):
	sql = "SELECT * FROM Users WHERE username = '%s' AND password = '%s'" % (username, pwdhash)
	try:
		cursor.execute(sql)
		user = cursor.fetchone()
		if user is not None:
			return user
	except:
		print "User not found"
	return None

def create_private_key(username, pwdhash):
	user = get_user(username, pwdhash)
	key = random_string(32)
	sql = "INSERT INTO PrivateKeys(`key`, `user_id`) VALUES('%s', '%d')" % (key, user[0])
	try:
		cursor.execute(sql)
		db.commit()
	except:
		db.rollback()
	return key

def get_private_key(user_id):
	sql = "SELECT * FROM PrivateKeys WHERE user_id = '%d'" % (user_id)
	try:
		cursor.execute(sql)
		privateKey = cursor.fetchone()
		return privateKey[1]
	except:
		print "Private key not found"
	return None

def create_new_key(length, user_id):
	key = random_string(length)
	ts = datetime.datetime.now() + datetime.timedelta(minutes = 10)
	timestamp = ts.strftime("%s")
	sql = "INSERT INTO `Keys`(`key`, length, user_id, expiration_ts) VALUES('%s', '%d', '%d', '%s')" % (key, length, user_id, timestamp)
	try:
		cursor.execute(sql)
		db.commit()
	except:
	   	db.rollback()
   	return key

def random_string(length):
	return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(length))

def int_of_string(s):
    return int(binascii.hexlify(s), 16)

def encrypt(private_key, key_to_encrypt):
	nonce = random_string(8)
	nonce_counter = nonce + "00000000"
	ctr = Counter.new(128, initial_value=int_of_string(nonce_counter))
	aes = AES.new(private_key, AES.MODE_CTR, counter=ctr)
	return base64.b64encode(nonce + aes.encrypt(key_to_encrypt))

mqttc = mqtt.Client()

mqttc.on_message = on_message
mqttc.on_connect = on_connect
mqttc.on_subscribe = on_subscribe

mqttc.connect(MQTT_HOST, MQTT_PORT, MQTT_KEEPALIVE_INTERVAL )

if __name__ == '__main__':
	mqttc.loop_forever()
	db.close()