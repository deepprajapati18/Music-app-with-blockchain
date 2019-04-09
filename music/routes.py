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
from music import app, db, bcrypt #bcrypt and db for hashing the password for database to create new account
from music.models import User, Upload
from flask_login import login_user, current_user, logout_user, login_required
from werkzeug.utils import secure_filename
from flask import render_template, url_for, flash, jsonify, redirect, request, abort, flash


@app.route('/')
@app.route('/home')
@login_required
def home():
	if current_user.is_authenticated:	
		firstname= current_user.firstName
		uploaded_objects = Upload.query.all()
		return render_template('home.html', user = firstname, uploaded=uploaded_objects)

	else:
		return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
	#if user is already login then redirect it to the home page
	if current_user.is_authenticated:
	 	return redirect(url_for('home'))
	
	elif request.method == 'POST':
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
		user = User(firstName = firstName, lastName = lastName, email = email, password = hashed_password, publickey = wallet['public_key'], privatekey = wallet['private_key'], balance = token)
		#print (user)
		db.session.add(user)
		db.session.commit()
		return redirect(url_for('login'))
		
	return render_template('register.html', title = "Register")


@app.route('/login', methods=['GET', 'POST'])
def login():
	#if user is already login then redirect it to the home page
	if current_user.is_authenticated:
		return redirect(url_for('home'))
	
	elif request.method == 'POST':	
		email = request.form['email']
		password = request.form['password']

		user = User.query.filter_by(email = email).first()
		if user and bcrypt.check_password_hash(user.password, password):
			login_user(user, remember=True)
			#here args is dectionary but not include key and value 
			#bcz if next not found then it is get an error
			next_page = request.args.get('next')
			flash('Login Successful', 'success')
			return redirect(next_page) if next_page else redirect(url_for('home'))
		else:
			flash('Login Unsuccessful. Please check username and password', 'danger')
	return render_template('login.html', title = "Login")


@app.route('/logout')
def logout():
	logout_user()
	return redirect(url_for('login'))


@app.route('/collection')
def my_collection():
	uploaded_objects = Upload.query.filter_by(user_id=current_user.id).all()
	return render_template('mycollection.html', uploaded=uploaded_objects)

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
	userdata = User.query.filter_by(id=current_user.id).one()
	
	return render_template('mywallet.html', data = userdata )

@app.route('/make/transaction')
def make_transaction():
    return render_template('./make_transaction.html')

@app.route('/view/transactions')
def view_transaction():
    return render_template('./view_transactions.html')

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
	return render_template('blockexplore.html')


# IPFS start
def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1)[1] in app.config['ALLOWED_EXTENSIONS']

@app.route('/upload')
def upload():
	uploaded_objects = Upload.query.all()
	return render_template('upload.html', uploaded=uploaded_objects)

@app.route('/upload_file', methods=['POST'])
def upload_file():
	file = request.files['uploadedFile']

	if file and allowed_file(file.filename):
		filename = secure_filename(file.filename)
		file.save(os.path.join(os.getcwd()+app.config['UPLOAD_FOLDER'], filename))

		ipfs_api = ipfsapi.connect(app.config['IPFS_HOST'], app.config['IPFS_PORT'])
		result = ipfs_api.add(os.path.join(os.getcwd()+app.config['UPLOAD_FOLDER'], filename))

		#try:
		new_upload = Upload(result['Name'], result['Hash'], artist=current_user.id)
		print(new_upload)
		db.session.add(new_upload)
		db.session.commit()

		new_upload_object = Upload.query.filter_by(filename=filename).first()
		shortened = base62.encode(new_upload_object.id)
		new_upload_object.short_url = shortened
		db.session.commit()

		flash('Upload Complete', 'success')
		#except:
			#flash('That hash already exists, passing.', 'danger')
	return redirect(url_for('upload'))

@app.route('/s/<short>')
def redirect_to_short(short):
	id = base62.decode(short)
	uploaded_object = Upload.query.filter_by(id=id).first()
	return redirect("{0}{1}".format(app.config['REDIRECT_BASE_URL'], uploaded_object.ipfs_hash), code=302)


# Start Blockchain Node 
MINING_SENDER = "THE BLOCKCHAIN"
MINING_REWARD = 1
MINING_DIFFICULTY = 2


class Blockchain:

    def __init__(self):
        
        self.transactions = []
        self.chain = []
        self.nodes = set()
        #Generate random number to be used as node_id
        self.node_id = str(uuid4()).replace('-', '')
        #Create genesis block
        self.create_block(0, '00')


    def register_node(self, node_url):
        """
        Add a new node to the list of nodes
        """
        #Checking node_url has valid format
        parsed_url = urlparse(node_url)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')


    def verify_transaction_signature(self, sender_address, signature, transaction):
        """
        Check that the provided signature corresponds to transaction
        signed by the public key (sender_address)
        """
        public_key = RSA.importKey(binascii.unhexlify(sender_address))
        verifier = PKCS1_v1_5.new(public_key)
        h = SHA.new(str(transaction).encode('utf8'))
        return verifier.verify(h, binascii.unhexlify(signature))


    def submit_transaction(self, sender_address, recipient_address, value, signature):
        """
        Add a transaction to transactions array if the signature verified
        """
        transaction = OrderedDict({'sender_address': sender_address, 
                                    'recipient_address': recipient_address,
                                    'value': value})

        #Reward for mining a block
        if sender_address == MINING_SENDER:
            self.transactions.append(transaction)
            return len(self.chain) + 1
        #Manages transactions from wallet to another wallet
        else:
            transaction_verification = self.verify_transaction_signature(sender_address, signature, transaction)
            if transaction_verification:
                self.transactions.append(transaction)
                return len(self.chain) + 1
            else:
                return False


    def create_block(self, nonce, previous_hash):
        """
        Add a block of transactions to the blockchain
        """
        block = {'block_number': len(self.chain) + 1,
                'timestamp': time(),
                'transactions': self.transactions,
                'nonce': nonce,
                'previous_hash': previous_hash}

        # Reset the current list of transactions
        self.transactions = []

        self.chain.append(block)
        return block


    def hash(self, block):
        """
        Create a SHA-256 hash of a block
        """
        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        
        return hashlib.sha256(block_string).hexdigest()


    def proof_of_work(self):
        """
        Proof of work algorithm
        """
        last_block = self.chain[-1]
        last_hash = self.hash(last_block)

        nonce = 0
        while self.valid_proof(self.transactions, last_hash, nonce) is False:
            nonce += 1

        return nonce


    def valid_proof(self, transactions, last_hash, nonce, difficulty=MINING_DIFFICULTY):
        """
        Check if a hash value satisfies the mining conditions. This function is used within the proof_of_work function.
        """
        guess = (str(transactions)+str(last_hash)+str(nonce)).encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:difficulty] == '0'*difficulty


    def valid_chain(self, chain):
        """
        check if a bockchain is valid
        """
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            #print(last_block)
            #print(block)
            #print("\n-----------\n")
            # Check that the hash of the block is correct
            if block['previous_hash'] != self.hash(last_block):
                return False

            # Check that the Proof of Work is correct
            #Delete the reward transaction
            transactions = block['transactions'][:-1]
            # Need to make sure that the dictionary is ordered. Otherwise we'll get a different hash
            transaction_elements = ['sender_address', 'recipient_address', 'value']
            transactions = [OrderedDict((k, transaction[k]) for k in transaction_elements) for transaction in transactions]

            if not self.valid_proof(transactions, block['previous_hash'], block['nonce'], MINING_DIFFICULTY):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        Resolve conflicts between blockchain's nodes
        by replacing our chain with the longest one in the network.
        """
        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            print('http://' + node + '/chain')
            response = requests.get('http://' + node + '/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False

# Instantiate the Blockchain
blockchain = Blockchain()

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.form

    # Check that the required fields are in the POST'ed data
    required = ['sender_address', 'recipient_address', 'amount', 'signature']
    if not all(k in values for k in required):
        return 'Missing values', 400
    # Create a new Transaction
    transaction_result = blockchain.submit_transaction(values['sender_address'], values['recipient_address'], values['amount'], values['signature'])

    if transaction_result == False:
        response = {'message': 'Invalid Transaction!'}
        return jsonify(response), 406
    else:
        response = {'message': 'Transaction will be added to Block '+ str(transaction_result)}
        return jsonify(response), 201

@app.route('/transactions/get', methods=['GET'])
def get_transactions():
    #Get transactions from transactions pool
    transactions = blockchain.transactions

    response = {'transactions': transactions}
    return jsonify(response), 200

@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200

@app.route('/mine', methods=['GET'])
def mine():
    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain.chain[-1]
    nonce = blockchain.proof_of_work()

    # We must receive a reward for finding the proof.
    blockchain.submit_transaction(sender_address=MINING_SENDER, recipient_address=blockchain.node_id, value=MINING_REWARD, signature="")

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.create_block(nonce, previous_hash)

    response = {
        'message': "New Block Forged",
        'block_number': block['block_number'],
        'transactions': block['transactions'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200



@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.form
    nodes = values.get('nodes').replace(" ", "").split(',')

    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': [node for node in blockchain.nodes],
    }
    return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }
    return jsonify(response), 200


@app.route('/nodes/get', methods=['GET'])
def get_nodes():
    nodes = list(blockchain.nodes)
    response = {'nodes': nodes}
    return jsonify(response), 200



# End Blockchain Node 