from models import db, User
from app import app

# Create all tables
db.drop_all()
db.create_all()

User.query.delete()