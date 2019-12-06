from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from time import sleep
import os

# Init everything

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:{}@db:3306/cat_auth?charset=utf8mb4'.format(os.environ.get('MYSQL_ROOT_PASSWORD'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

secret = os.environ.get('secret')

db = SQLAlchemy(app)