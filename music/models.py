# -*- coding: utf-8 -*-
"""
Created on Fri Sep 21 17:12:28 2018

@author: Dell
"""

"""
when db is not in same file but in new file it displays an error that it can't 
fetch User and Post, and then can't import db.
it is overcome by converting into package

"""


from datetime import datetime
from music import db, login_manager
from flask_login import UserMixin


#load user that takes a userID 
#(used for reloading the User from the userId stored in this session)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


#now create class for database creation
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key= True)
    firstName = db.Column(db.String(20), unique= True, nullable= False)
    lastName = db.Column(db.String(20), unique= True, nullable= False)
    email = db.Column(db.String(120), unique= True, nullable= False)
    password = db.Column(db.String(60), nullable= False)
    publickey = db.Column(db.Text, nullable= False)
    privatekey = db.Column(db.Text, nullable= False)
    balance = db.Column(db.Integer, nullable = False)
    file = db.relationship('Upload', backref='artist', lazy=True)
    

class Upload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(120))
    ipfs_hash = db.Column(db.String(200), unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    short_url = db.Column(db.String(50), unique=True)

    def __init__(self, filename, ipfs_hash, artist, short_url=None):
        self.filename = filename
        self.ipfs_hash = ipfs_hash
        self.user_id = artist
        self.short_url = short_url
        

    def __repr__(self):
        return '<Name %r>' % self.filename
