from flask_restful import Resource, Api
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util import Counter
import time
import datetime
import MySQLdb
import string
import random
import base64
import binascii

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False
api = Api(app)
db = MySQLdb.connect("127.0.0.1","sorcha","Nolan123","KMS" )
cursor = db.cursor()

@app.route('/KMS/register-user')
def registerUser():
	response = request.get_json()
	username = response['username']
	pwdhash = response['pwdhash']
	success = False
	key = None
	userId = getUserId(username, pwdhash)
	if userId is None:
		sql = "INSERT INTO Users(username, password) VALUES('%s', '%s')" % (username, pwdhash)
		try:
			cursor.execute(sql)
			db.commit()
			userId = getUserId(username, pwdhash)
			key = randomString(32)
			sql = "INSERT INTO PrivateKeys(`key`, `user_id`) VALUES('%s', '%d')" % (key, userId)
			try:
				cursor.execute(sql)
				db.commit()
				success = True
			except:
				db.rollback()
		except:
			db.rollback()
	else:
		key = getPrivateKey(userId)
		success = True
   	return jsonify({"success": success, "key": key})

@app.route('/KMS/new/<username>/<pwdhash>/<int:length>')
def getNewKey(username, pwdhash, length):
	access = False
	encryptedKey = None
	userId = getUserId(username, pwdhash)
	if userId is not None:
		access = True
		key = randomString(length)
		ts = datetime.datetime.now() + datetime.timedelta(minutes = 10)
		timestamp = ts.strftime("%s")
		sql = "INSERT INTO `Keys`(`key`, length, user_id, expiration_ts) VALUES('%s', '%d', '%d', '%s')" % (key, length, userId, timestamp)
		try:
			cursor.execute(sql)
			db.commit()
		except:
		   	db.rollback()
	   	privateKey = getPrivateKey(userId)
	   	encryptedKey = encrypt(privateKey, key)#.decode("utf-8")
	   	print key
	return jsonify({"access": access, "key": encryptedKey})

@app.route('/KMS/existing/<username>/<pwdhash>/<int:keyId>')
def getExistingKey(username, pwdhash, keyId):
	access = False
	encryptedKey = None
	userId = getUserId(username, pwdhash)
	if userId is not None:
		ts = datetime.datetime.now().strftime("%s")
		sql = "SELECT * FROM `Keys` WHERE id = '%d' AND expiration_ts > '%s'" % (keyId, ts)
		try:
			cursor.execute(sql)
			keyobj = cursor.fetchone()
			if keyobj is not None:
				access = True
				key = keyobj[1]
				privateKey = getPrivateKey(userId)
	   			encryptedKey = encrypt(privateKey, key)
	   			print key
   			else:
   				print "This key is not available"
		except:
			print "User not found"
	return jsonify({"access": access, "key": encryptedKey})

def getUserId(username, pwdhash):
	sql = "SELECT * FROM Users WHERE username = '%s' AND password = '%s'" % (username, pwdhash)
	try:
		cursor.execute(sql)
		user = cursor.fetchone()
		if user is not None:
			return user[0]
	except:
		print "User not found"
	return None

def getPrivateKey(username, pwdhash):
	userId = getUserId(username, pwdhash)
	if userId is not None:
		return getPrivateKey(userId)
	return None

def getPrivateKey(userId):
	sql = "SELECT * FROM PrivateKeys WHERE user_id = '%d'" % (userId)
	try:
		cursor.execute(sql)
		privateKey = cursor.fetchone()
		return privateKey[1]
	except:
		print "Private key not found"
	return None

def int_of_string(s):
    return int(binascii.hexlify(s), 16)

def encrypt(privateKey, keyToEncrypt):
	nonce = randomString(16)
	ctr = Counter.new(128, initial_value=int_of_string(nonce))
	aes = AES.new(privateKey, AES.MODE_CTR, counter=ctr)
	return base64.b64encode(nonce + aes.encrypt(keyToEncrypt))

def decrypt(privateKey, encryptedKey):
	nonce = encryptedKey[:17]
	ctr = Counter.new(128, initial_value=int_of_string(nonce))
	aes = AES.new(privateKey, AES.MODE_CTR, counter=ctr)
	return aes.decrypt(encryptedKey[17:])

def randomString(length):
	return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(length))

if __name__ == '__main__':
	app.run(host='127.0.0.1', port=5000, debug=False)
	db.close()
