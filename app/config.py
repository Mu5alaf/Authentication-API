from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
# from app.models import User 
import os
#===================postgresql config========================#
# Load environment variables from .env
load_dotenv()
app = Flask(__name__)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
# Initialize SQLAlchemy and JWTManager
db = SQLAlchemy(app)
jwt = JWTManager(app)

