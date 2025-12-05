from sqlalchemy import func, or_
from markupsafe import Markup
from flask import (
    Flask, render_template, redirect, url_for,
    flash, request, jsonify, session
)
from flask import Response

from flask_login import (
    LoginManager, login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
from pymongo import MongoClient
from sqlalchemy import func
import logging
import os
import pyotp
from datetime import datetime

from config import Config

from models import db, User, Patient, AuditLog
from forms import RegistrationForm, LoginForm, PatientForm


# Optional: MongoDB audit collection
mongo_client = MongoClient("mongodb://localhost:27017")
mongo_db = mongo_client["secure_health_app"]
audit_collection = mongo_db["patient_audit"]

# Security: PEPPER for password hashing
PEPPER = os.environ.get("APP_PEPPER", "dev-pepper-change-me")
def highlight(text, query):
    """Highlight matched search terms."""
    if not query:
        return text

    safe_q = query.lower()
    lower_text = text.lower()

    if safe_q in lower_text:
        start = lower_text.index(safe_q)
        end = start + len(query)
        highlighted = (
            text[:start]
            + f"<mark>{text[start:end]}</mark>"
            + text[end:]
        )
        return Markup(highlighted)
    return text



def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.jinja_env.globals["highlight"] = highlight

    # Harden session cookies (set SECURE=True in real HTTPS deployment)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=False,
    )

    # Rate limiting
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour"],
    )

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

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # ---------- Helpers ----------

    def admin_required(f):
        @wraps(f)
        @login_required
        def wrapper(*args, **kwargs):
            if current_user.role != "admin":
                flash("Admin access required.", "danger")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return wrapper

    def log_audit(action, patient_id, details=None):
        """
        Write an entry into the AuditLog table.
        action: "create", "update", "delete"
        """
        username = current_user.username if current_user.is_authenticated else "system"
        entry = AuditLog(
            timestamp=datetime.utcnow(),
            username=username,
            patient_id=patient_id,
            action=action,
            details=details,
        )
        db.session.add(entry)

    # ---------- Routes ----------

    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    # -------- REGISTER --------
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
                salt_length=16,
            )

            user = User(username=form.username.data, password_hash=hashed_pw)
            db.session.add(user)
            db.session.commit()
            logging.info(f"New user registered: {user.username}")
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))

        return render_template("register.html", form=form)

    # -------- LOGIN --------
    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("5 per minute")
    def login():
        form = LoginForm()

        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()

            # Check password first
            if user and check_password_hash(user.password_hash, form.password.data + PEPPER):

                # If 2FA is enabled for this user, require token before logging in
                if getattr(user, "twofa_enabled", False) and getattr(user, "twofa_secret", None):
                    session["pending_2fa_user"] = user.id
                    flash("Please enter your 2FA code.", "info")
                    return redirect(url_for("verify_2fa"))

                # Otherwise, log in normally
                login_user(user)
                logging.info(f"User logged in: {user.username}")
                flash("Logged in successfully.", "success")

                next_page = request.args.get("next")
                if not next_page or not next_page.startswith("/"):
                    next_page = url_for("dashboard")
                return redirect(next_page)

            else:
                flash("Invalid username or password.", "danger")

        # Always render login page on GET or failed POST
        return render_template("login.html", form=form)

    # -------- LOGOUT --------
    @app.route("/logout")
    @login_required
    def logout():
        logging.info(f"User logged out: {current_user.username}")
        logout_user()
        flash("You have been logged out.", "info")
        return redirect(url_for("login"))

    # -------- PROFILE --------
    @app.route("/profile")
    @login_required
    def profile():
        return render_template("profile.html", user=current_user)

    # -------- DASHBOARD --------
    @app.route("/dashboard")
    @login_required
    def dashboard():
        total_patients = Patient.query.count()
        stroke_count = Patient.query.filter_by(stroke=True).count()

        hypertension_count = Patient.query.filter_by(hypertension=True).count()
        heart_count = Patient.query.filter_by(heart_disease=True).count()

        avg_age = db.session.query(func.avg(Patient.age)).scalar() or 0
        avg_bmi = db.session.query(func.avg(Patient.bmi)).scalar() or 0

        stroke_by_gender = (
            db.session.query(Patient.gender, func.count(Patient.id))
            .filter_by(stroke=True)
            .group_by(Patient.gender)
            .all()
        )
        genders = [g or "Unknown" for g, _ in stroke_by_gender]
        gender_counts = [c for _, c in stroke_by_gender]
        stroke_gender_stats = [
        {"gender": g or "Unknown", "count": c}
        for g, c in stroke_by_gender
    ]
        return render_template(
            "dashboard.html",
            total_patients=total_patients,
            stroke_count=stroke_count,
            hypertension_count=hypertension_count,
            heart_count=heart_count,
            avg_age=avg_age,
            avg_bmi=avg_bmi,
            genders=genders,
            gender_counts=gender_counts,
           )
    # -------- ENABLE 2FA --------
    @app.route("/enable_2fa", methods=["GET", "POST"])
    @login_required
    def enable_2fa():
        # Generate new secret if user doesn't have one
        if not current_user.twofa_secret:
            current_user.twofa_secret = pyotp.random_base32()
            db.session.commit()

        # Initialize TOTP
        totp = pyotp.TOTP(current_user.twofa_secret)

        # If submitting a code to enable 2FA
        if request.method == "POST":
            code = request.form.get("code") or ""
            if totp.verify(code.strip()):
                current_user.twofa_enabled = True
                db.session.commit()
                flash("Two-factor authentication enabled!", "success")
                return redirect(url_for("dashboard"))
            else:
                flash("Invalid code. Please try again.", "danger")

        return render_template(
            "enable_2fa.html",
            secret=current_user.twofa_secret,
        )

    # -------- VERIFY 2FA --------
    @app.route("/verify-2fa", methods=["GET", "POST"])
    def verify_2fa():
        # Get the user ID stored during login
        user_id = session.get("pending_2fa_user")
        if not user_id:
            flash("No 2FA verification in progress.", "warning")
            return redirect(url_for("login"))

        # Look up the user
        user = User.query.get(user_id)
        if not user or not user.twofa_secret:
            flash("Invalid 2FA state.", "danger")
            session.pop("pending_2fa_user", None)
            return redirect(url_for("login"))

        totp = pyotp.TOTP(user.twofa_secret)

        if request.method == "POST":
            token = (request.form.get("token") or "").strip()
            if totp.verify(token):
                # 2FA OK: remove pending flag, log the user in
                session.pop("pending_2fa_user", None)
                login_user(user)
                flash("Two-factor authentication successful.", "success")
                return redirect(url_for("dashboard"))
            else:
                flash("Invalid 2FA code. Please try again.", "danger")

        # Show the verify form
        return render_template("verify_2fa.html")

    # -------- PATIENTS LIST --------
    @app.route("/patients")
    @login_required
    def patients_list():
        page = request.args.get("page", 1, type=int)
        per_page = 20

    # search & filters
        q = (request.args.get("q") or "").strip()
        gender = request.args.get("gender") or "all"
        stroke = request.args.get("stroke") or "all"

    # sorting
        sort = request.args.get("sort") or "id"
        direction = request.args.get("direction") or "asc"

        query = Patient.query

    # text search
        if q:
            query = query.filter(
                or_(
                    Patient.id == q,
                    Patient.work_type.ilike(f"%{q}%"),
                    Patient.residence_type.ilike(f"%{q}%"),
                    Patient.smoking_status.ilike(f"%{q}%"),
                )
            )

    # gender filter
        if gender != "all":
            query = query.filter(Patient.gender == gender)

    # stroke filter
        if stroke == "yes":
            query = query.filter(Patient.stroke.is_(True))
        elif stroke == "no":
            query = query.filter(Patient.stroke.is_(False))

    # sort mapping
        sort_map = {
            "id": Patient.id,
            "age": Patient.age,
            "gender": Patient.gender,
            "stroke": Patient.stroke,
        }
        sort_col = sort_map.get(sort, Patient.id)

        if direction == "desc":
            sort_col = sort_col.desc()
        else:
            direction = "asc"  # normalise

        query = query.order_by(sort_col)

        patients = query.paginate(page=page, per_page=per_page, error_out=False)

        return render_template(
            "patients_list.html",
            patients=patients,
            q=q,
            selected_gender=gender,
            selected_stroke=stroke,
            sort=sort,
            direction=direction,
        )
    # -------- EXPORT PATIENTS TO CSV --------
    @app.route("/patients/export")
    @login_required
    def patients_export():
        import csv
        from io import StringIO
        from flask import Response

        output = StringIO()
        writer = csv.writer(output)

    # CSV header row
        writer.writerow([
            "id", "gender", "age", "hypertension", "heart_disease",
            "ever_married", "work_type", "residence_type",
            "avg_glucose_level", "bmi", "smoking_status", "stroke"
        ])
    # Write patient rows
        for p in Patient.query.order_by(Patient.id).all():
            writer.writerow([
                p.id, p.gender, p.age, p.hypertension, p.heart_disease,
                p.ever_married, p.work_type, p.residence_type,
                p.avg_glucose_level, p.bmi, p.smoking_status, p.stroke
            ])

        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=patients.csv"},
        )


    # -------- CREATE PATIENT --------
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
                stroke=form.stroke.data,
            )

            db.session.add(patient)
            # Audit log
            log_audit("create", patient.id, details="Created new patient")
            db.session.commit()

            logging.info(f"Patient created by {current_user.username}: {patient.id}")
            flash("Patient created successfully.", "success")
            return redirect(url_for("patients_list"))

        return render_template("patient_form.html", form=form, title="Create Patient")

    # -------- PATIENT DETAIL --------
    @app.route("/patients/<int:patient_id>")
    @login_required
    def patient_detail(patient_id):
        patient = Patient.query.get_or_404(patient_id)
        return render_template("patient_detail.html", patient=patient)

    # -------- EDIT PATIENT --------
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

            # Audit log (simple generic update)
            log_audit("update", patient.id, details="Updated patient")
            db.session.commit()

            logging.info(f"Patient updated by {current_user.username}: {patient.id}")
            flash("Patient updated successfully.", "success")
            return redirect(url_for("patient_detail", patient_id=patient.id))

        return render_template("patient_form.html", form=form, title="Edit Patient")

    # -------- DELETE PATIENT --------
    @app.route("/patients/<int:patient_id>/delete", methods=["POST"])
    @login_required
    def patient_delete(patient_id):
        patient = Patient.query.get_or_404(patient_id)
        log_audit("delete", patient.id, details="Deleted patient")
        db.session.delete(patient)
        db.session.commit()
        logging.info(f"Patient deleted by {current_user.username}: {patient.id}")
        flash("Patient deleted.", "info")
        return redirect(url_for("patients_list"))

    # -------- AUDIT LOG (ADMIN ONLY) --------
    @app.route("/audit-log")
    @admin_required
    def audit_log():
        page = request.args.get("page", 1, type=int)
        per_page = 20
        logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        return render_template("audit_log.html", logs=logs)

    # -------- API: PATIENT SUMMARY --------
    @app.route("/api/patients/summary")
    @limiter.limit("30 per minute")
    def api_patients_summary():
        token = request.headers.get("X-API-TOKEN")

        # Simplified hard-coded check for coursework
        if token != "dev-api-token":
            return jsonify({"error": "unauthorised"}), 401

        total = Patient.query.count()
        stroke = Patient.query.filter_by(stroke=True).count()
        return jsonify({
            "total_patients": total,
            "stroke_cases": stroke,
        })

    # ---------------- ERROR HANDLERS ----------------
    @app.errorhandler(404)
    def page_not_found(e):
        logging.warning(f"404 error at {request.path}")
        return render_template("404.html"), 404

    @app.errorhandler(500)
    def internal_error(e):
        logging.error(f"500 error: {e}")
        return render_template("500.html"), 500

    # ---------------- SECURITY HEADERS ----------------
    @app.after_request
    def add_security_headers(response):
        # Basic secure headers
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"

        # ⚠️ CSP disabled so JS (Chart.js + inline scripts) works in the browser
        # For coursework this is acceptable. If you re-enable CSP later,
        # you must allow cdn.jsdelivr.net and 'unsafe-inline'.
        # response.headers["Content-Security-Policy"] = (...)

        return response


    # IMPORTANT: return the app from the factory
    return app


# -----------------------------------
# MAIN RUN BLOCK + DATABASE CREATION
# -----------------------------------
if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        # Create tables for main DB (users)
        db.create_all()

        # Create tables for patients DB (patients + audit_logs)
        from models import Patient, AuditLog
        engine = db.get_engine(app, bind="patients")
        Patient.__table__.create(engine, checkfirst=True)
        AuditLog.__table__.create(engine, checkfirst=True)

    app.run(debug=True)
