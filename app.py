import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'trustvault-secret-key-2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///trustvault.db'
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User Model (3 Roles: Administrator, Owner, Viewer)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='Viewer')

# Document Model
class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    filepath = db.Column(db.String(300), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

# Permission Model (Granular access control)
class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('document.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    access_level = db.Column(db.String(20), nullable=False) # 'read', 'edit'

# Audit Trail Model
class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    document_id = db.Column(db.Integer, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def log_action(user_id, action, doc_id=None):
    log = AuditLog(user_id=user_id, action=action, document_id=doc_id)
    db.session.add(log)
    db.session.commit()

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password_hash=hashed_pw, role=role)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            log_action(user.id, "USER_LOGIN")
            return redirect(url_for('dashboard'))
        flash('Invalid credentials!', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_action(current_user.id, "USER_LOGOUT")
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'Administrator':
        docs = Document.query.all()
    elif current_user.role == 'Owner':
        docs = Document.query.filter_by(owner_id=current_user.id).all()
    else:
        # Viewer sees files where permission is explicitly granted
        permitted_doc_ids = [p.document_id for p in Permission.query.filter_by(user_id=current_user.id).all()]
        docs = Document.query.filter(Document.id.in_(permitted_doc_ids)).all()
    
    logs = AuditLog.query.all() if current_user.role == 'Administrator' else []
    return render_template('dashboard.html', docs=docs, logs=logs)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if current_user.role not in ['Administrator', 'Owner']:
        flash('Unauthorized to upload files!', 'danger')
        return redirect(url_for('dashboard'))

    if 'file' not in request.files:
        flash('No file selected!', 'danger')
        return redirect(url_for('dashboard'))

    file = request.files['file']
    if file.filename == '':
        flash('No file selected!', 'danger')
        return redirect(url_for('dashboard'))

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    doc = Document(filename=filename, filepath=filepath, owner_id=current_user.id)
    db.session.add(doc)
    db.session.commit()

    log_action(current_user.id, f"UPLOADED_FILE: {filename}", doc.id)
    flash('File uploaded successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/download/<int:doc_id>')
@login_required
def download_file(doc_id):
    doc = Document.query.get_or_404(doc_id)
    
    # Strict Server-Side Security Check
    has_perm = Permission.query.filter_by(document_id=doc.id, user_id=current_user.id).first()
    is_owner = doc.owner_id == current_user.id
    is_admin = current_user.role == 'Administrator'

    if not (is_admin or is_owner or has_perm):
        log_action(current_user.id, f"UNAUTHORIZED_ACCESS_ATTEMPT on file ID: {doc_id}")
        return "403 Forbidden: You do not have permission to access this file.", 403

    log_action(current_user.id, f"DOWNLOADED_FILE: {doc.filename}", doc.id)
    return send_from_directory(app.config['UPLOAD_FOLDER'], doc.filename)
@app.route('/grant/<int:doc_id>', methods=['POST'])
@login_required
def grant_permission(doc_id):
    doc = Document.query.get_or_404(doc_id)
    # Check if current user is the owner or admin
    if doc.owner_id != current_user.id and current_user.role != 'Administrator':
        flash('Unauthorized action!', 'danger')
        return redirect(url_for('dashboard'))
    
    viewer_email = request.form.get('email')
    viewer = User.query.filter_by(email=viewer_email).first()
    
    if viewer:
        # Check if permission already exists
        existing_perm = Permission.query.filter_by(document_id=doc.id, user_id=viewer.id).first()
        if not existing_perm:
            perm = Permission(document_id=doc.id, user_id=viewer.id, access_level='read')
            db.session.add(perm)
            db.session.commit()
            log_action(current_user.id, f"GRANTED_ACCESS to user {viewer.username} for file ID: {doc.id}")
            flash(f'Permission granted to {viewer.username} successfully!', 'success')
        else:
            flash('User already has access to this document!', 'info')
    else:
        flash('User with this email not found!', 'danger')
        
    return redirect(url_for('dashboard'))
import os

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
