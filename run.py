from flask import Flask
from app.config import app,db
from app.api import app,db
from app.fake_data_generator import generate_fake_users 

if __name__ == '__main__':
    with app.app_context():
        generate_fake_users()
        db.create_all()
    app.run(debug=True)
