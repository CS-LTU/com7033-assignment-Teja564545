# 🏥 Secure Health App  
### A secure, multi-database Flask application for managing stroke patient data

## Overview

This project is a secure web application built using Flask, designed to store, manage, and retrieve sensitive healthcare data safely.  
It demonstrates professional software engineering practices including:

- Secure coding  
- Multi-database architecture  
- Role-based access control  
- Hardened authentication  
- Input validation  
- Logging and auditing  
- Unit testing  
- API integration  
- Modern, responsive UI  

It was developed for the Secure Programming module.

## Features

### Authentication System
- Registration with strong password hashing (PBKDF2 + PEPPER)
- Login with session protection
- Logout functionality
- Accounts stored in SQLite users.db

### Security
- PBKDF2 password hashing  
- PEPPER secret  
- CSRF protection (Flask-WTF)  
- Input validation (WTForms)
- Secure session cookies  
- Admin-only role checks  
- Logging of all CRUD operations  

### Patient Data Management
Stored in SQLite patients.db:
- Add patient  
- Edit patient  
- Delete patient (admin only)  
- View all patients  
- View patient details  

### Analytics Dashboard
- Total patients  
- Total stroke cases  
- Visual charts  
- Colourful dashboard UI  

### Secure API Endpoint
`GET /api/patients/summary`

Requires header:

```text
X-API-TOKEN: dev-api-token
