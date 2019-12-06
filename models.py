from passlib.hash import sha256_crypt
from __init__ import db

class UserModel(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    pass_hashed = db.Column(db.String(120), nullable=False)

    def __init__(self, username, passwd):
        self.username = username
        self.pass_hashed = sha256_crypt.using(rounds=50000).hash(passwd)

    def verify(self, passwd):
        """Compares the password with the hashed value in database

        Args:
            passwd(String): The password to verify

        Returns:
            bool: Whether the password is correct
        """
        return sha256_crypt.verify(passwd, self.pass_hashed)

    def save(self):
        db.session.add(self)
        db.session.commit()

class jwtBlackList(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.Integer, nullable=False)
    exp = db.Column(db.Integer, nullable=False)

    def __init__(self, userid, exp):
        self.userid = userid
        self.exp = exp

    def save(self):
        db.session.add(self)
        db.session.commit()