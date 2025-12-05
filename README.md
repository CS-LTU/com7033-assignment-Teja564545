# 🏥 Secure Health Analytics System  
*A privacy-focused patient management and analytics platform built with Flask, designed for secure clinical data handling, interactive insights, and strong authentication.*

---

## 🌐 Project Status  
![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)  
![Flask](https://img.shields.io/badge/Flask-Framework-orange.svg)  
![Security](https://img.shields.io/badge/Security-Enabled-brightgreen.svg)  
![License](https://img.shields.io/badge/License-MIT-green.svg)

---

## 📘 Executive Summary  
The **Secure Health Analytics System** is a Flask-based web application developed for **clinical data management and health analytics**.  
It enables authenticated users to manage patient records, analyse health patterns, and ensure integrity and privacy via robust security mechanisms such as:

- Two-Factor Authentication (2FA)
- Hashed + peppered passwords
- Secure audit logging (MongoDB)
- Rate-limited routes
- Automatic role-ready authentication layer

This project is designed with academic quality, production security principles, and modern UI standards.

---

## 🧩 Key Features

### 🔐 **Authentication & Security**
- Secure password hashing (`PBKDF2 + Salt + Pepper`)
- Login rate limiting (protects against brute force)
- Optional Two-Factor Authentication (TOTP)
- `Flask-Login` session management
- CSRF protection enabled by default
- Audit log stored in **MongoDB**
- HTTPS-ready cookies (`SameSite`, `HTTPOnly`, `Secure`)

### 🩺 **Patient Management**
- Patient CRUD (Create, Read, Update, Delete)
- Paginated patient views  
- Advanced search: ID, gender, stroke status, residence, work type  
- Data export to CSV  
- Automatic age & BMI badge colouring  
- Clean, responsive tables

### 📊 **Analytics & Visualisations**
- Summary metrics (Total patients, stroke cases, hypertension, heart disease)
- Donut chart — Stroke vs Non-stroke  
- Bar chart — Stroke cases by gender  
- Animated charts with theme-adaptive colours  
- Population indicators (Avg BMI, Avg Age)

### 🎨 **UI / UX**
- Dark/Light mode toggle  
- Fully responsive layout  
- Bootstrap 5 + custom CSS  
- Elegant glass-panel dashboards  
- Accessibility-aware colour palette  

---

## 🏗 System Architecture  
                     +------------------------+
                     |       Frontend         |
                     |   HTML • CSS • JS      |
                     |   Chart.js • Bootstrap |
                     +-----------+------------+
                                 |
                                 |
                     +-----------v------------+
                     |    Flask Application   |
                     |  Routing, Auth, Views  |
                     +-----------+------------+
                                 |
           +---------------------+----------------------+
           |                                            |
    | SQLite (Primary DB) |                   | MongoDB (Audit Logging) |
    | MongoDB (Audit Logging) |              | Insert-only secure logs |




## 📁 Folder Structure

secure_health_app/
│── app.py
│── config.py
│── models.py
│── forms.py
│── requirements.txt
│── README.md
│
├── templates/
│ ├── base.html
│ ├── dashboard.html
│ ├── login.html
│ ├── register.html
│ ├── patient_form.html
│ ├── patient_detail.html
│ ├── patients_list.html
│ ├── 404.html
│ └── 500.html
│
├── static/
│ ├── style.css
│ ├── dashboard.js
│ └── assets/
│
└── venv/ (excluded)



---

## 📦 Installation & Setup

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/your-username/secure-health-app.git
cd secure-health-app
