from faker import Faker
from werkzeug.security import generate_password_hash
from app.models import User
from app.config import db

fake = Faker()

def generate_fake_users(num_users=2):
    for _ in range(num_users):
        username = fake.user_name()
        password_hash = generate_password_hash(fake.password())
        admin = False

        new_user = User(username=username, password=password_hash, admin=admin)
        db.session.add(new_user)

    db.session.commit()

