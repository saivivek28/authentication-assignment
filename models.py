from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(50), nullable=False)
    Email = db.Column(db.String(100), nullable =False, unique = True)
    Password = db.Column(db.String(200), nullable =False)
    Age = db.Column(db.Integer, nullable =False)
    
    