# -*- coding: utf-8 -*-

#Server Configuration
HOST = '0.0.0.0'
PORT = 9001
DEBUG = True
USE_RELOADER = True
SECRET_KEY = '4f766a97b5b7244249daaae47365cc66'

#DB Configuration
# SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
# SQLALCHEMY_TRACK_MODIFICATIONS = True
# DB_CREATED = False

MONGO_DBNAME = 'Music'
MONGO_URI = 'mongodb://localhost:27017/Music'
CORS_HEADERS = 'Content-Type'

# IPFS Configuration
IPFS_HOST = '127.0.0.1'
IPFS_PORT = 5001

# Redirect Configuration
SHORT_REDIRECT_DOMAIN = "http://{0}:{1}".format(HOST, PORT)
REDIRECT_BASE_URL = "http://127.0.0.1:8080/ipfs/"

# Upload Configuration
UPLOAD_FOLDER = '/music/static/media'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'py', 'mp3'])
