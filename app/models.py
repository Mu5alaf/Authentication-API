from flask_login import UserMixin
from sqlalchemy.sql import func
from .config import db
#==========model============================#
class User(db.Model,UserMixin):
    #every user must have an id 
    id = db.Column(db.Integer, primary_key=True)
    #every user must have a unique user name and must be not null
    username = db.Column(db.String(80), unique=True, nullable=False)
    #every user must have password 
    password = db.Column(db.String(255), nullable=False)
    #if user admin 
    admin = db.Column(db.Boolean, default=False)
    