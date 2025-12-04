# forms.py
from flask_wtf import FlaskForm
from wtforms import (
    StringField, PasswordField, SubmitField, FloatField,
    BooleanField, IntegerField, SelectField
)
from wtforms.validators import DataRequired, Length, NumberRange, Optional,Regexp


class RegistrationForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[DataRequired(), Length(min=3, max=80)]
    )
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(min=10, message="Use at least 10 characters."),
            Regexp(
                r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).+$",
                message="Password must contain upper, lower case letters and a number."
            )
        ]
    )
    submit = SubmitField("Register") 



class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class PatientForm(FlaskForm):
    id = IntegerField("ID", validators=[DataRequired()])
    gender = SelectField(
        "Gender",
        choices=[("Male", "Male"), ("Female", "Female"), ("Other", "Other")],
        validators=[DataRequired()]
    )
    age = FloatField("Age", validators=[DataRequired(), NumberRange(min=0, max=120)])
    hypertension = BooleanField("Hypertension")
    heart_disease = BooleanField("Heart Disease")
    ever_married = SelectField(
        "Ever Married",
        choices=[("Yes", "Yes"), ("No", "No")],
        validators=[Optional()]
    )
    work_type = StringField("Work Type", validators=[Optional(), Length(max=50)])
    residence_type = StringField("Residence Type", validators=[Optional(), Length(max=50)])
    avg_glucose_level = FloatField(
        "Average Glucose Level",
        validators=[DataRequired(), NumberRange(min=0)]
    )
    bmi = FloatField("BMI", validators=[Optional(), NumberRange(min=0, max=100)])
    smoking_status = SelectField(
        "Smoking Status",
        choices=[
            ("formerly smoked", "Formerly smoked"),
            ("never smoked", "Never smoked"),
            ("smokes", "Smokes"),
            ("Unknown", "Unknown"),
        ],
        validators=[Optional()]
    )
    stroke = BooleanField("Stroke")
    submit = SubmitField("Save")
