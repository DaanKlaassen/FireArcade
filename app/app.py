from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import os
from werkzeug.security import check_password_hash, generate_password_hash

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# SQLAlchemy Config
app.config[
    'SQLALCHEMY_DATABASE_URI'] = f"mysql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable track modifications to avoid a warning

db = SQLAlchemy(app)

# Flask-Login Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# User Class for Flask-Login
class User(UserMixin, db.Model):
    __tablename__ = 'gebruiker'

    id = db.Column(db.Integer, primary_key=True)
    naam = db.Column(db.String(100), nullable=False)  # Nieuwe kolom voor naam
    emailadres = db.Column(db.String(120), unique=True, nullable=False)
    wachtwoord_hash = db.Column(db.String(128), nullable=False)
    rol = db.Column(db.String(50), nullable=False)
    telefoonnummer = db.Column(db.String(20), nullable=False)

    def __init__(self, naam, emailadres, wachtwoord_hash, rol, telefoonnummer):
        self.naam = naam
        self.emailadres = emailadres
        self.wachtwoord_hash = wachtwoord_hash
        self.rol = rol
        self.telefoonnummer = telefoonnummer


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        emailadres = request.form.get('email')
        password = request.form.get('password')
        remember = 'remember' in request.form

        # Gebruik de juiste kolomnaam emailadres
        user = User.query.filter_by(emailadres=emailadres).first()

        if user and check_password_hash(user.wachtwoord_hash, password):
            login_user(user, remember=remember)
            return redirect(url_for('yippee'))
        else:
            flash('Verkeerde inloggegevens. Vul opnieuw je gegevens in.', 'error')

    return render_template('KlantenLogin.html')


@app.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.json
    email = data.get('email')
    phone = data.get('phone')
    new_password = data.get('new_password')

    user = User.query.filter_by(emailadres=email, telefoonnummer=phone).first()

    if user:
        user.wachtwoord_hash = generate_password_hash(new_password)
        db.session.commit()
        return {'success': True, 'message': 'Wachtwoord succesvol gewijzigd!'}
    else:
        return {'success': False, 'message': 'Geen gebruiker gevonden met deze gegevens.'}, 400


# Registratie functie
@app.route('/registreren', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        naam = request.form['name']  # Haal de naam op uit het formulier
        emailadres = request.form['email']
        password = request.form['password']
        telefoonnummer = request.form['telefoonnummer']

        # Controleer of de gebruiker al bestaat
        user = User.query.filter_by(emailadres=emailadres).first()
        if user:
            flash('Er is al een account met dit e-mailadres!', 'danger')
            return render_template('KlantenRegistreren.html')

        # Wachtwoord hashen voor veilige opslag
        hashed_password = generate_password_hash(password)

        # Nieuwe gebruiker toevoegen aan de database
        new_user = User(naam=naam, emailadres=emailadres, wachtwoord_hash=hashed_password, rol='user',
                        telefoonnummer=telefoonnummer)
        db.session.add(new_user)
        db.session.commit()

        flash('Je account is succesvol aangemaakt! Je kunt nu inloggen.', 'success')
        return redirect(url_for('login'))

    return render_template('KlantenRegistreren.html')


# Test Pagina
@app.route('/yippee')
def yippee():
    return render_template('yippee.html')


# logout functie
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
