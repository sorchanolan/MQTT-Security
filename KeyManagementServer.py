from flask_restful import Resource, Api
from flask import Flask, request

app = Flask(__name__)
api = Api(app)

class KMS(Resource):
	def get(self):

	def post(self):

api.add_resource(KMS, '/')

if __name__ == '__main__':
	app.run(host='127.0.0.1', port=5000, debug=False)