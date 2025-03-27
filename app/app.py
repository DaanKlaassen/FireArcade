from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import os
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps

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
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    def __init__(self, naam, emailadres, wachtwoord_hash, rol, telefoonnummer):
        self.naam = naam
        self.emailadres = emailadres
        self.wachtwoord_hash = wachtwoord_hash
        self.rol = rol
        self.telefoonnummer = telefoonnummer
        self.created_at = db.func.current_timestamp()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Decorator om toegang te beperken op basis van rol
def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:  # Check of de gebruiker is ingelogd
                return redirect(url_for('login'))  # Stuur naar de loginpagina als niet ingelogd
            if current_user.rol != required_role:  # Check of de gebruiker de juiste rol heeft
                abort(403)  # Forbidden als hij de verkeerde rol heeft
            return f(*args, **kwargs)

        return decorated_function

    return decorator


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
            return redirect(url_for('customer_dashboard'))
        else:
            flash('Verkeerde inloggegevens. Vul opnieuw je gegevens in.', 'error')

    return render_template('KlantenLogin.html')


@app.route('/medewerker_login', methods=['GET', 'POST'])
def medewerker_login():
    if request.method == 'POST':
        emailadres = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(emailadres=emailadres).first()

        if user and check_password_hash(user.wachtwoord_hash, password):
            if user.rol == "medewerker":  # Controleer of de gebruiker een medewerker is
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                flash('Je hebt geen toegang tot de medewerkersomgeving.', 'error')
                return redirect(url_for('login'))  # Stuur terug naar de algemene login
        else:
            flash('Verkeerde inloggegevens. Probeer opnieuw.', 'error')

    return render_template('MedewerkerLogin.html')


@app.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.json
    email = data.get('email')
    phone = data.get('phone')
    new_password = data.get('new_password')

    user = User.query.filter_by(emailadres=email, telefoonnummer=phone).first()

    if user:
        if user.rol == 'medewerker':  # Blokkeer medewerkers van resetten
            return {'success': False,
                    'message': 'Medewerkers kunnen hun wachtwoord niet wijzigen via deze pagina.'}, 403

        user.wachtwoord_hash = generate_password_hash(new_password)
        db.session.commit()
        return {'success': True, 'message': 'Wachtwoord succesvol gewijzigd!'}

    return {'success': False, 'message': 'Geen gebruiker gevonden met deze gegevens.'}, 400


# Registratie functie
@app.route('/registreren', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        naam = request.form['name']
        emailadres = request.form['email']
        password = request.form['password']
        telefoonnummer = request.form['telefoonnummer']
        redirect_uri = 'klanten_overview' if current_user else 'login'

        # Controleer of het wachtwoord lang genoeg is
        if len(password) < 10:
            flash('Wachtwoord moet minimaal 10 tekens lang zijn!', 'danger')
            if current_user:
                return redirect(url_for(redirect_uri))
            else:
                return render_template('KlantenRegistreren.html', name=naam, email=emailadres,
                                       telefoonnummer=telefoonnummer)

        # Controleer of de gebruiker al bestaat
        user = User.query.filter_by(emailadres=emailadres).first()
        if user:
            flash('Er is al een account met dit e-mailadres!', 'danger')
            if current_user:
                return redirect(url_for(redirect_uri))
            else:
                return render_template('KlantenRegistreren.html')

        # Wachtwoord hashen voor veilige opslag
        hashed_password = generate_password_hash(password)

        # Nieuwe gebruiker toevoegen met standaardrol 'klant'
        new_user = User(
            naam=naam,
            emailadres=emailadres,
            wachtwoord_hash=hashed_password,
            rol='klant',  # Standaardrol instellen
            telefoonnummer=telefoonnummer
        )
        db.session.add(new_user)
        db.session.commit()

        flash('Je account is succesvol aangemaakt! Je kunt nu inloggen.', 'success')
    if current_user:
        return redirect(url_for(redirect_uri))
    else:
        return render_template('KlantenRegistreren.html')


# Ticket Model
class Ticket(db.Model):
    __tablename__ = 'ticket'
    id = db.Column(db.Integer, primary_key=True)
    gebruiker_id = db.Column(db.Integer, db.ForeignKey('gebruiker.id'), nullable=False)
    titel = db.Column(db.String(255), nullable=False)
    beschrijving = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), default='Open')  # Active or Deleted
    toegewezen = db.Column(db.String(255), default='Nog niet toegewezen')
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    gebruiker = db.relationship('User', backref=db.backref('tickets', lazy=True))


# Contract Model
class Contract(db.Model):
    __tablename__ = 'contract'
    id = db.Column(db.Integer, primary_key=True)
    gebruiker_id = db.Column(db.Integer, db.ForeignKey('gebruiker.id'))
    contract_begin_datum = db.Column(db.DateTime, nullable=False)
    contract_eind_datum = db.Column(db.DateTime, nullable=False)
    contract_status = db.Column(db.String(50), default='Active')  # Active or Deleted
    contract_termen = db.Column(db.Text)
    gebruiker = db.relationship('User', backref=db.backref('contracten', lazy=True))

    def __init__(self, gebruiker_id, contract_begin_datum, contract_eind_datum, contract_status, contract_termen):
        self.gebruiker_id = gebruiker_id
        self.contract_begin_datum = contract_begin_datum
        self.contract_eind_datum = contract_eind_datum
        self.contract_status = contract_status
        self.contract_termen = contract_termen


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/create_contract', methods=['GET', 'POST'])
@login_required
@role_required('medewerker')
def create_contract():
    if request.method == 'POST':
        gebruiker_id = request.form['gebruiker']
        contract_begin_datum = request.form['contract_begin_datum']
        contract_eind_datum = request.form['contract_eind_datum']
        contract_status = request.form['contract_status']
        contract_termen = request.form['contract_termen']

        new_contract = Contract(gebruiker_id=gebruiker_id or current_user.id,
                                contract_begin_datum=contract_begin_datum,
                                contract_eind_datum=contract_eind_datum,
                                contract_status=contract_status,
                                contract_termen=contract_termen)
        db.session.add(new_contract)
        db.session.commit()

        flash('Het contract is succesvol aangemaakt!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('create_contract.html')


@app.route('/contract_overview')
@login_required
@role_required('medewerker')
def contract_overview():
    filter_status = request.args.get('status', 'Active')  # Default to Active

    # For monteurs, show all contracts if they have the role
    if current_user.rol == 'monteur':
        if filter_status == 'Deleted':
            contracten = Contract.query.filter_by(contract_status='Deleted').all()
        else:
            contracten = Contract.query.filter_by(contract_status='Active').all()
    else:
        # For regular customers, only show their own contracts
        if filter_status == 'Deleted':
            contracten = Contract.query.filter_by(gebruiker_id=current_user.id, contract_status='Deleted').all()
        else:
            contracten = Contract.query.filter_by(gebruiker_id=current_user.id, contract_status='Active').all()

    return render_template('contract_overview.html', contracten=contracten, filter_status=filter_status)


@app.route('/create_ticket', methods=['GET', 'POST'])
@login_required
def create_ticket():
    if request.method == 'POST':
        klant_id = request.form['klant']
        ticket_naam = request.form['titel']
        ticket_beschrijving = request.form['beschrijving']
        redirect_uri = 'customer_dashboard' if current_user.rol == 'klant' else 'dashboard'

        new_ticket = Ticket(
            titel=ticket_naam,
            beschrijving=ticket_beschrijving,
            gebruiker_id=klant_id or current_user.id
        )
        db.session.add(new_ticket)
        db.session.commit()
        flash('Ticket succesvol aangemaakt!', 'success')
        return redirect(url_for(redirect_uri))
    return render_template('create_ticket.html')


@app.route('/ticket_overview')
@login_required
@role_required('medewerker')
def ticket_overview():
    filter_status = request.args.get('status', 'Active')  # Default to Active

    # For monteurs, show all tickets if they have the role
    if current_user.rol == 'monteur':
        if filter_status == 'Deleted':
            tickets = Ticket.query.filter_by(status='Deleted').all()
        else:
            tickets = Ticket.query.filter_by(status='Open').all()
    else:
        # For regular customers, only show their own tickets
        if filter_status == 'Deleted':
            tickets = Ticket.query.filter_by(gebruiker_id=current_user.id, status='Deleted').all()
        else:
            tickets = Ticket.query.filter_by(gebruiker_id=current_user.id, status='Open').all()

    return render_template('ticket_overview.html', tickets=tickets, filter_status=filter_status)


@app.route('/dashboard')
@login_required
@role_required('medewerker')
def dashboard():
    # This is now the monteur dashboard (purple)
    # Get all tickets and contracts for monteurs
    tickets = Ticket.query.order_by(Ticket.created_at.desc()).limit(5).all()
    contracten = Contract.query.order_by(Contract.contract_begin_datum.desc()).limit(5).all()
    customers = User.query.order_by(User.naam).filter(User.rol == "klant").all()
    return render_template('dashboard.html', klanten=customers, tickets=tickets, contracten=contracten)


@app.route('/customer_dashboard')
@login_required
def customer_dashboard():
    # This is the customer dashboard (blue)
    # Only show tickets and contracts for the current user
    tickets = Ticket.query.filter_by(gebruiker_id=current_user.id).order_by(Ticket.created_at.desc()).limit(5).all()
    contracten = Contract.query.filter_by(gebruiker_id=current_user.id).order_by(
        Contract.contract_begin_datum.desc()).limit(5).all()

    return render_template('customer_dashboard.html', tickets=tickets, contracten=contracten)


@app.route('/KlantOverzicht')
@login_required
@role_required('medewerker')
def klanten_overview():
    gebruikers = User.query.all()

    return render_template('KlantOverzicht.html', gebruikers=gebruikers)


# Soft Delete Ticket
@app.route('/delete_ticket/<int:id>', methods=['POST'])
@login_required
def delete_ticket(id):
    ticket = Ticket.query.get_or_404(id)

    # Check if the user has permission to delete this ticket
    if current_user.rol != 'monteur' and ticket.gebruiker_id != current_user.id:
        flash('You do not have permission to delete this ticket.', 'error')
        return redirect(url_for('dashboard'))

    if ticket.status != "Deleted":
        ticket.status = "Deleted"  # Mark the ticket as deleted
        db.session.commit()
        flash('Ticket is marked as deleted.', 'success')

    # Redirect back to the page they came from
    referrer = request.referrer
    if 'customer_dashboard' in referrer:
        return redirect(url_for('customer_dashboard'))
    else:
        return redirect(url_for('dashboard'))


# Soft Delete Contract
@app.route('/delete_contract/<int:id>', methods=['POST'])
@login_required
def delete_contract(id):
    contract = Contract.query.get_or_404(id)

    # Check if the user has permission to delete this contract
    if current_user.rol != 'monteur' and contract.gebruiker_id != current_user.id:
        flash('You do not have permission to delete this contract.', 'error')
        return redirect(url_for('dashboard'))

    if contract.contract_status != "Deleted":
        contract.contract_status = "Deleted"  # Mark the contract as deleted
        db.session.commit()
        flash('Contract is marked as deleted.', 'success')

    # Redirect back to the page they came from
    referrer = request.referrer
    if 'customer_dashboard' in referrer:
        return redirect(url_for('customer_dashboard'))
    else:
        return redirect(url_for('dashboard'))


# Restore Ticket
@app.route('/restore_ticket/<int:id>', methods=['POST'])
@login_required
def restore_ticket(id):
    ticket = Ticket.query.get_or_404(id)

    # Check if the user has permission to restore this ticket
    if current_user.rol != 'monteur' and ticket.gebruiker_id != current_user.id:
        flash('You do not have permission to restore this ticket.', 'error')
        return redirect(url_for('dashboard'))

    if ticket.status == "Deleted":
        ticket.status = "Open"  # Restore the ticket
        db.session.commit()
        flash('Ticket has been restored.', 'success')
    return redirect(url_for('ticket_overview', status='Deleted'))


# Restore Contract
@app.route('/restore_contract/<int:id>', methods=['POST'])
@login_required
def restore_contract(id):
    contract = Contract.query.get_or_404(id)

    # Check if the user has permission to restore this contract
    if current_user.rol != 'monteur' and contract.gebruiker_id != current_user.id:
        flash('You do not have permission to restore this contract.', 'error')
        return redirect(url_for('dashboard'))

    if contract.contract_status == "Deleted":
        contract.contract_status = "Active"  # Restore the contract
        db.session.commit()
        flash('Contract has been restored.', 'success')
    return redirect(url_for('contract_overview', status='Deleted'))


@app.route('/ticket/<int:ticket_id>')
@login_required
def ticket_detail(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)

    # Check if the user has permission to view this ticket
    if current_user.rol != 'monteur' and ticket.gebruiker_id != current_user.id:
        flash('You do not have permission to view this ticket.', 'error')
        return redirect(url_for('dashboard'))

    return render_template('ticket_detail.html', ticket=ticket)


# Assign ticket to monteur (new functionality)
@app.route('/assign_ticket/<int:ticket_id>', methods=['POST'])
@login_required
def assign_ticket(ticket_id):
    if current_user.rol != 'monteur':
        flash('Only monteurs can assign tickets.', 'error')
        return redirect(url_for('dashboard'))

    ticket = Ticket.query.get_or_404(ticket_id)
    monteur_name = current_user.naam

    ticket.toegewezen = monteur_name
    db.session.commit()

    flash(f'Ticket #{ticket_id} has been assigned to {monteur_name}.', 'success')
    return redirect(url_for('ticket_detail', ticket_id=ticket_id))


# logout functie
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
