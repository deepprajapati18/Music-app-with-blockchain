import os
import secrets
import base62
import ipfsapi
import binascii
import Crypto
import Crypto.Random
import requests
import hashlib
import json

from time import time
from urllib.parse import urlparse
from uuid import uuid4
from collections import OrderedDict
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from music import app, mongo, bcrypt, login_manager #bcrypt and mongo for hashing the password for database to create new account
# from music.models import User, Upload
from flask_login import login_user, current_user, logout_user, login_required
from werkzeug.utils import secure_filename
from flask import render_template, url_for, flash, jsonify, redirect, request, abort, flash
from music.user import User


enduser = mongo.db.endusers
uploads = mongo.db.uploads

#load user that takes a userID 
#(used for reloading the User from the userId stored in this session)
@login_manager.user_loader
def load_user(user_id):
	u = enduser.find_one({'_id':user_id['_id']})
	if not u:
		return None
	return User(u['_id'])


@app.route('/')
@app.route('/home')
@login_required
def home():
	
	if current_user.is_authenticated:	
		firstName = enduser.find_one({'_id': current_user.get_id()}, {'firstName':1})
		uploaded_objects = uploads.find()
		# uploaded_objects = Upload.query.all()
		return render_template('user/home.html', user = firstName['firstName'], uploaded=tuple(uploaded_objects))

	else:
		return redirect(url_for('register'))

# register as end user
@app.route('/register', methods=['GET', 'POST'])
def register():
	#if user is already login then redirect it to the home page
	if current_user.is_authenticated:
		return redirect(url_for('home'))
	
	elif request.method == 'POST':
		enduser_id = 1
	
		user_data = enduser.find().sort("_id", -1).limit(1)
		for a in user_data:
			enduser_id = a["_id"] + enduser_id
	
		firstName = request.form['firstName']
		lastName = request.form['lastName']
		email = request.form['email']
		password = request.form['password']
		confirmPassword = request.form['confirmPassword']
		wallet = new_wallet()
		token = 100

		# print ((name, email, guard_email, password))
		
		#after validate submission it is need to create the account for that we have to create hashed passwords
		#using bcrypt and db. And then create new instance for user

		hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
		i = enduser.insert({
							'_id': enduser_id,
							'firstName': firstName,
							'lastName': lastName,
							'email': email,
							'publickey': wallet['public_key'],
							'privatekey': wallet['private_key'],
							'balance': token,
							'password': hashed_password,
							'isapproved': False
						})
		return redirect(url_for('login'))
		
	return render_template('user/register.html', title = "Register")

# register as artist
@app.route('/register_as_artist', methods=['GET', 'POST'])
def register_as_artist():
	#if user is already login then redirect it to the home page
	if current_user.is_authenticated:
		return redirect(url_for('home'))
	
	elif request.method == 'POST':
		enduser_id = 1
	
		user_data = enduser.find().sort("_id", -1).limit(1)
		for a in user_data:
			enduser_id = a["_id"] + enduser_id
	
		firstName = request.form['firstName']
		lastName = request.form['lastName']
		email = request.form['email']
		role = request.form['role']
		password = request.form['password']
		confirmPassword = request.form['confirmPassword']
		wallet = new_wallet()
		token = 100

		hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
		i = enduser.insert({
							'_id': enduser_id,
							'firstName': firstName,
							'lastName': lastName,
							'email': email,
							'role': role,
							'publickey': wallet['public_key'],
							'privatekey': wallet['private_key'],
							'balance': token,
							'password': hashed_password,
							'isapproved': False
						})
		return redirect(url_for('login'))
		
	return render_template('user/register_as_artist.html', title = "Register")


@app.route('/login', methods=['GET', 'POST'])
def login():

	#if user is already login then redirect it to the home page
	if current_user.is_authenticated:
		return redirect(url_for('home'))
	
	elif request.method == 'POST':	
		email = request.form['email']
		password = request.form['password']

		user = enduser.find_one({'email': email})
		# print (user)
		if user and bcrypt.check_password_hash(user['password'], password):
			loginuser = User(user)
			login_user(loginuser, remember=True)
			#here args is dectionary but not include key and value 
			#bcz if next not found then it is get an error
			next_page = request.args.get('next')
			return redirect(next_page) if next_page else redirect(url_for('home'))
		else:
			flash('Login Unsuccessful. Please check username and password', 'danger')
		
	return render_template('user/login.html', title = "Login")


@app.route('/logout')
@login_required
def logout():
	logout_user()
	return redirect(url_for('login'))


@app.route('/collection')
def my_collection():
	upload = mongo.db.uploads
	uploaded_objects = upload.find({'user_id': current_user.get_id()})
	# uploaded_objects = Upload.query.filter_by(user_id=current_user.id).all()
	return render_template('user/mycollection.html', uploaded=tuple(uploaded_objects))

class Transaction:

	def __init__(self, sender_address, sender_private_key, recipient_address, value):
		self.sender_address = sender_address
		self.sender_private_key = sender_private_key
		self.recipient_address = recipient_address
		self.value = value

	def __getattr__(self, attr):
		return self.data[attr]

	def to_dict(self):
		return OrderedDict({'sender_address': self.sender_address,
							'recipient_address': self.recipient_address,
							'value': self.value})

	def sign_transaction(self):
		"""
		Sign transaction with private key
		"""
		private_key = RSA.importKey(binascii.unhexlify(self.sender_private_key))
		signer = PKCS1_v1_5.new(private_key)
		h = SHA.new(str(self.to_dict()).encode('utf8'))
		return binascii.hexlify(signer.sign(h)).decode('ascii')

@app.route('/wallet')
def my_wallet():
	enduser = mongo.db.endusers
	userdata = enduser.find_one({'_id': current_user.get_id()})
	
	return render_template('user/mywallet.html', data = userdata )

@app.route('/make/transaction')
def make_transaction():
	return render_template('user/make_transaction.html')

# @app.route('/view/transactions')
# def view_transaction():
# 	return render_template('user/view_transactions.html')

def new_wallet():
	random_gen = Crypto.Random.new().read
	private_key = RSA.generate(1024, random_gen)
	public_key = private_key.publickey()
	response = {
		'private_key': binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii'),
		'public_key': binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii')
	}

	return response

@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
	
	sender_address = request.form['sender_address']
	sender_private_key = request.form['sender_private_key']
	recipient_address = request.form['recipient_address']
	value = request.form['amount']

	transaction = Transaction(sender_address, sender_private_key, recipient_address, value)

	response = {'transaction': transaction.to_dict(), 'signature': transaction.sign_transaction()}

	return jsonify(response), 200

@app.route('/blockexplore')
def block_explore():
	return render_template('user/blockexplore.html')


# IPFS start
def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1)[1] in app.config['ALLOWED_EXTENSIONS']

@app.route('/upload')
def upload():
	enduser = mongo.db.endusers
	upload = mongo.db.uploads
	uploaded_objects = upload.find()
	# uploaded_objects = Upload.query.all()
	return render_template('user/upload.html', uploaded=tuple(uploaded_objects))

@app.route('/upload_file', methods=['POST'])
def upload_file():
	upload_id = 1
	upload = mongo.db.uploads

	upload_data = upload.find().sort("_id", -1).limit(1)
	for a in upload_data:
		upload_id = a["_id"] + upload_id

	file = request.files['uploadedFile']

	if file and allowed_file(file.filename):
		filename = secure_filename(file.filename)
		file.save(os.path.join(os.getcwd()+app.config['UPLOAD_FOLDER'], filename))

		ipfs_api = ipfsapi.connect(app.config['IPFS_HOST'], app.config['IPFS_PORT'])
		result = ipfs_api.add(os.path.join(os.getcwd()+app.config['UPLOAD_FOLDER'], filename))

		#try:
		new_upload = upload.insert_one({
										'_id': upload_id,
										'filename': result['Name'],
										'ipfs_hash': result['Hash'],
										'user_id': current_user.get_id(),
										'short_url': None
									})
		# new_upload = Upload(result['Name'], result['Hash'], artist=current_user.id)
		print(new_upload)

		new_upload_object = upload.find_one({'filename':filename})
		shortened = base62.encode(new_upload_object['_id'])
		upload.update_one({'filename': filename}, {'$set': {'short_url': shortened}})

		flash('Upload Complete', 'success')
		#except:
			#flash('That hash already exists, passing.', 'danger')
	return redirect(url_for('upload'))

@app.route('/s/<short>')
def redirect_to_short(short):
	upload = mongo.db.uploads
	id = base62.decode(short)
	uploaded_object = upload.find_one({'_id': id})
	return redirect("{0}{1}".format(app.config['REDIRECT_BASE_URL'], uploaded_object['ipfs_hash']), code=302)


