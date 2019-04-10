from werkzeug.security import check_password_hash
from music import mongo


class User():

    def __init__(self, user_id):
        self.user_id = user_id
        self.enduser = mongo.db.endusers
        self.artist = mongo.db.artists

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.user_id

    def get_token(self):
        token = self.enduser.find_one({'_id': int(self.user_id)}, {'_id': 0, 'balance': 1})
        return token['balance']
    
    def has_artist(self):
        d = self.enduser.find_one({'_id': int(self.user_id)}, {'_id':0, 'role': 1})
        # print (d)
        if len(d)!=0:
            return True
        else:
            return False
          
    
    @staticmethod
    def validate_login(password_hash, password):
        return check_password_hash(password_hash, password)