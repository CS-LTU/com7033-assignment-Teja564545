# import_data.py
import csv

from app import create_app
from models import db, Patient


def import_patients_from_csv(filepath: str):
    app = create_app()
    with app.app_context():

        # ✅ Create tables properly for SQLAlchemy 3.x
        # Create main database tables (users)
        db.create_all()

        # Create patients table in the "patients" bind
        engine = db.get_engine(app, bind="patients")
        Patient.__table__.create(engine, checkfirst=True)

        with open(filepath, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)

            for row in reader:
                patient_id = int(row["id"])

                # Skip if already in DB
                if Patient.query.get(patient_id):
                    continue

                patient = Patient(
                    id=patient_id,
                    gender=row["gender"],
                    age=float(row["age"]),
                    hypertension=bool(int(row["hypertension"])),
                    heart_disease=bool(int(row["heart_disease"])),
                    ever_married=row.get("ever_married") or None,
                    work_type=row.get("work_type") or None,
                    residence_type=row.get("Residence_type") or row.get("residence_type"),
                    avg_glucose_level=float(row["avg_glucose_level"]),
                    bmi=float(row["bmi"]) if row.get("bmi") not in (None, "", "N/A") else None,
                    smoking_status=row.get("smoking_status") or None,
                    stroke=bool(int(row["stroke"])),
                )

                db.session.add(patient)

            db.session.commit()
            print("Import completed.")


if __name__ == "__main__":
    import_patients_from_csv("healthcare-dataset-stroke-data.csv")
