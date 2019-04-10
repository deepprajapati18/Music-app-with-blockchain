from flask import Flask
# from flask_sqlalchemy import SQLAlchemy
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_cors import CORS


app = Flask(__name__)
app.config.from_object('config')

mongo = PyMongo(app)
CORS(app)


# db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app) #for authentication and initialization

#specify to login route bcz for account page log in required
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'  #bootstarp class -> dispaly in blue colour


from music import routes 
from music import admin