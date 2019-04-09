from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_cors import CORS


app = Flask(__name__)
CORS(app)
app.config.from_object('config')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app) #for authentication and initialization

#specify to login route bcz for account page log in required
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'  #bootstarp class -> dispaly in blue colour


from music import routes 
