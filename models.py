import os
from sqla_wrapper import SQLAlchemy

db = SQLAlchemy(os.getenv("DATABASE_URL", "sqlite:///localhost.sqlite"))


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True)
    email = db.Column(db.String, unique=True)
    password = db.Column(db.String, unique=False)
    info = db.Column(db.String)
    session_token = db.Column(db.String)
    user_deleted = db.Column(db.String, default=False)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_username = db.Column(db.String, unique=False)
    sender_id = db.Column(db.Integer, unique=False)
    receiver_username = db.Column(db.String, unique=False)
    receiver_id = db.Column(db.Integer, unique=False)
    message = db.Column(db.String, unique=False)
    datetime = db.Column(db.String)
    date = db.Column(db.String, unique=False)
    time = db.Column(db.String, unique=False)