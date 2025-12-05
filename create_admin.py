from app import create_app, PEPPER
from models import db, User
from werkzeug.security import generate_password_hash

app = create_app()

with app.app_context():
    # Check if admin already exists
    existing = User.query.filter_by(username="admin").first()
    if existing:
        print("Admin user already exists. No changes made.")
    else:
        admin = User(
            username="admin",
            password_hash=generate_password_hash("AdminPassword123" + PEPPER),
            role="admin"
        )
        db.session.add(admin)
        db.session.commit()
        print("Admin user created!")
