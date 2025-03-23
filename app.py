from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
from flask_mysqldb import MySQL
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# MySQL Config (pas aan op basis van je .env bestand)
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'  # Zorgt ervoor dat fetchone() een dictionary teruggeeft

mysql = MySQL(app)

# Flask-Login instellen
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User class voor Flask-Login
class User(UserMixin):
    def __init__(self, id, naam, role):
        self.id = id
        self.naam = naam
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM medewerker WHERE id = %s AND Verwijderd = 0", (user_id,))
    user = cur.fetchone()
    cur.close()
    if user:
        return User(id=user['id'], naam=user['naam'], role=user['rol'])
    return None

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        naam = request.form['naam']
        password = request.form['password']
        remember = 'remember' in request.form

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM medewerker WHERE naam = %s AND Verwijderd = 0", (naam,))
        user = cur.fetchone()
        cur.close()

        print(f"Naam: {naam}, Password: {password}, User: {user}")  # Debugging print

        if user and check_password_hash(user['wachtwoord_hash'], password):
            user_obj = User(id=user['id'], naam=user['naam'], role=user['rol'])
            login_user(user_obj, remember=remember)
            return redirect(url_for('dashboard'))

        flash('Verkeerde inloggegevens. Vul opnieuw je gegevens in.', 'error')

    return render_template('KlantenLogin.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return f"Welkom {current_user.naam}, je rol is {current_user.role}"

if __name__ == '__main__':
    app.run(debug=True)
