# models.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")
    def __repr__(self):
        return f"<User {self.username!r}>"


class Patient(db.Model):
    """
    Represents a row in the stroke dataset.
    """
    __bind_key__ = "patients"
    __tablename__ = "patients"

    id = db.Column(db.Integer, primary_key=True)  # dataset id
    gender = db.Column(db.String(10), nullable=False)
    age = db.Column(db.Float, nullable=False)
    hypertension = db.Column(db.Boolean, nullable=False, default=False)
    heart_disease = db.Column(db.Boolean, nullable=False, default=False)
    ever_married = db.Column(db.String(10), nullable=True)
    work_type = db.Column(db.String(50), nullable=True)
    residence_type = db.Column(db.String(50), nullable=True)
    avg_glucose_level = db.Column(db.Float, nullable=False)
    bmi = db.Column(db.Float, nullable=True)
    smoking_status = db.Column(db.String(50), nullable=True)
    stroke = db.Column(db.Boolean, nullable=False)

    def __repr__(self):
        return f"<Patient {self.id} - age {self.age}>"
