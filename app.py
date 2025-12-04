from pymongo import MongoClient
from sqlalchemy import func
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import (
    LoginManager, login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
import logging
import os

from config import Config
from models import db, User, Patient
from forms import RegistrationForm, LoginForm, PatientForm
mongo_client = MongoClient("mongodb://localhost:27017")
mongo_db = mongo_client["secure_health_app"]
audit_collection = mongo_db["patient_audit"]


# Security: PEPPER for password hashing
PEPPER = os.environ.get("APP_PEPPER", "dev-pepper-change-me")


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialise database
    db.init_app(app)

    # Login manager setup
    login_manager = LoginManager()
    login_manager.login_view = "login"
    login_manager.init_app(app)

    # Logging setup
    logging.basicConfig(
        filename=app.config["LOG_FILE"],
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    @app.route("/api/patients/summary")
    def api_patients_summary():
        token = request.headers.get("X-API-TOKEN")

    # 🔐 Simplified hard-coded check for coursework
        if token != "dev-api-token":
            return jsonify({"error": "unauthorised"}), 401

        total = Patient.query.count()
        stroke = Patient.query.filter_by(stroke=True).count()
        return jsonify({
            "total_patients": total,
            "stroke_cases": stroke,
    })

    

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # -----------------------------------
    # ROUTES
    # -----------------------------------

    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    # ---------------- REGISTER ----------------
    @app.route("/register", methods=["GET", "POST"])
    def register():
        form = RegistrationForm()
        if form.validate_on_submit():
            existing_user = User.query.filter_by(username=form.username.data).first()
            if existing_user:
                flash("Username already exists, choose another.", "warning")
                return redirect(url_for("register"))

            # Strong password hashing with PEPPER
            hashed_pw = generate_password_hash(
                form.password.data + PEPPER,
                method="pbkdf2:sha256",
                salt_length=16
            )

            user = User(username=form.username.data, password_hash=hashed_pw)
            db.session.add(user)
            db.session.commit()
            logging.info(f"New user registered: {user.username}")
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))

        return render_template("register.html", form=form)

    # ---------------- LOGIN ----------------
    @app.route("/login", methods=["GET", "POST"])
    def login():
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()

            # Password check includes PEPPER
            if user and check_password_hash(user.password_hash, form.password.data + PEPPER):
                login_user(user)
                logging.info(f"User logged in: {user.username}")
                flash("Logged in successfully.", "success")

                next_page = request.args.get("next")
                if not next_page or not next_page.startswith("/"):
                    next_page = url_for("dashboard")
                return redirect(next_page)

            flash("Invalid username or password.", "danger")

        return render_template("login.html", form=form)

    # ---------------- LOGOUT ----------------
    @app.route("/logout")
    @login_required
    def logout():
        logging.info(f"User logged out: {current_user.username}")
        logout_user()
        flash("You have been logged out.", "info")
        return redirect(url_for("login"))
    # ---------------- PROFILE ----------------  
    @app.route("/profile")
    @login_required
    def profile():
        return render_template("profile.html", user=current_user)

    # ---------------- DASHBOARD ----------------
    @app.route("/dashboard")
    @login_required
    def dashboard():
        total_patients = Patient.query.count()
        stroke_count = Patient.query.filter_by(stroke=True).count()

        hypertension_count = Patient.query.filter_by(hypertension=True).count()
        heart_count = Patient.query.filter_by(heart_disease=True).count()

        avg_age = db.session.query(func.avg(Patient.age)).scalar() or 0
        avg_bmi = db.session.query(func.avg(Patient.bmi)).scalar() or 0

        if total_patients:
            stroke_pct = round((stroke_count / total_patients) * 100, 1)
        else:
            stroke_pct = 0.0

        # Stroke count by gender
        stroke_by_gender = (
            db.session.query(Patient.gender, func.count(Patient.id))
            .filter_by(stroke=True)
            .group_by(Patient.gender)
            .all()
    )
        genders = [g or "Unknown" for g, _ in stroke_by_gender]
        gender_counts = [c for _, c in stroke_by_gender]

        return render_template(
        "dashboard.html",
        total_patients=total_patients,
        stroke_count=stroke_count,
        stroke_pct=stroke_pct,
        hypertension_count=hypertension_count,
        heart_count=heart_count,
        avg_age=round(avg_age, 1),
        avg_bmi=round(avg_bmi, 1),
        genders=genders,
        gender_counts=gender_counts,
    )


    # ---------------- PATIENT LIST ----------------
    @app.route("/patients")
    @login_required
    def patients_list():
        page = request.args.get("page", 1, type=int)
        per_page = 20
        patients = Patient.query.paginate(page=page, per_page=per_page, error_out=False)
        return render_template("patients_list.html", patients=patients)

    # ---------------- CREATE PATIENT ----------------
    @app.route("/patients/new", methods=["GET", "POST"])
    @login_required
    def patient_create():
        form = PatientForm()
        if form.validate_on_submit():

            if Patient.query.get(form.id.data):
                flash("Patient with this ID already exists.", "warning")
                return redirect(url_for("patient_create"))

            patient = Patient(
                id=form.id.data,
                gender=form.gender.data,
                age=form.age.data,
                hypertension=form.hypertension.data,
                heart_disease=form.heart_disease.data,
                ever_married=form.ever_married.data,
                work_type=form.work_type.data,
                residence_type=form.residence_type.data,

                avg_glucose_level=form.avg_glucose_level.data,
                bmi=form.bmi.data,
                smoking_status=form.smoking_status.data,
                stroke=form.stroke.data
            )

            db.session.add(patient)
            db.session.commit()
            logging.info(f"Patient created by {current_user.username}: {patient.id}")
            flash("Patient created successfully.", "success")
            return redirect(url_for("patients_list"))

        return render_template("patient_form.html", form=form, title="Create Patient")

    # ---------------- PATIENT DETAIL ----------------
    @app.route("/patients/<int:patient_id>")
    @login_required
    def patient_detail(patient_id):
        patient = Patient.query.get_or_404(patient_id)
        return render_template("patient_detail.html", patient=patient)

    # ---------------- EDIT PATIENT ----------------
    @app.route("/patients/<int:patient_id>/edit", methods=["GET", "POST"])
    @login_required
    def patient_edit(patient_id):
        patient = Patient.query.get_or_404(patient_id)
        form = PatientForm(obj=patient)

        if form.validate_on_submit():
            patient.gender = form.gender.data
            patient.age = form.age.data
            patient.hypertension = form.hypertension.data
            patient.heart_disease = form.heart_disease.data
            patient.ever_married = form.ever_married.data
            patient.work_type = form.work_type.data
            patient.residence_type = form.residence_type.data
            patient.avg_glucose_level = form.avg_glucose_level.data
            patient.bmi = form.bmi.data
            patient.smoking_status = form.smoking_status.data
            patient.stroke = form.stroke.data

            db.session.commit()
            logging.info(f"Patient updated by {current_user.username}: {patient.id}")
            flash("Patient updated successfully.", "success")
            return redirect(url_for("patient_detail", patient_id=patient.id))

        return render_template("patient_form.html", form=form, title="Edit Patient")

    # ---------------- DELETE PATIENT ----------------
    @app.route("/patients/<int:patient_id>/delete", methods=["POST"])
    @login_required
    def patient_delete(patient_id):
        patient = Patient.query.get_or_404(patient_id)
        db.session.delete(patient)
        db.session.commit()
        logging.info(f"Patient deleted by {current_user.username}: {patient.id}")
        flash("Patient deleted.", "info")
        return redirect(url_for("patients_list"))

    # ---------------- ERROR HANDLERS ----------------
    @app.errorhandler(404)
    def page_not_found(e):
        logging.warning(f"404 error at {request.path}")
        return render_template("404.html"), 404

    @app.errorhandler(500)
    def internal_error(e):
        logging.error(f"500 error: {e}")
        return render_template("500.html"), 500

    return app


# -----------------------------------
# MAIN RUN BLOCK + DATABASE CREATION
# -----------------------------------
if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        # Create tables for main DB (users)
        db.create_all()

        # Create patients table in the "patients" bind
        engine = db.engines["patients"]   # modern way instead of get_engine
        Patient.__table__.create(engine, checkfirst=True)

    # Disable reloader to avoid extra threads on Windows
    app.run(debug=True, use_reloader=False)

