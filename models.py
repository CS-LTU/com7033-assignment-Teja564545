from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="user")

    # 2FA fields
    twofa_secret = db.Column(db.String(32))
    twofa_enabled = db.Column(db.Boolean, default=False)


class Patient(db.Model):
    __bind_key__ = "patients"
    __tablename__ = "patients"

    id = db.Column(db.Integer, primary_key=True)
    gender = db.Column(db.String(10))
    age = db.Column(db.Float)
    hypertension = db.Column(db.Boolean)
    heart_disease = db.Column(db.Boolean)
    ever_married = db.Column(db.String(10))
    work_type = db.Column(db.String(50))
    residence_type = db.Column(db.String(10))
    avg_glucose_level = db.Column(db.Float)
    bmi = db.Column(db.Float)
    smoking_status = db.Column(db.String(50))
    stroke = db.Column(db.Boolean)

class AuditLog(db.Model):
    __bind_key__ = "patients"
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False)
    username = db.Column(db.String(80), nullable=False)
    patient_id = db.Column(db.Integer, nullable=False)
    action = db.Column(db.String(20), nullable=False)  # "create", "update", "delete"
    details = db.Column(db.String(255))


