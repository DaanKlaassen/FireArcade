from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import os
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
from sqlalchemy.sql import text
from datetime import datetime  # Add missing import for datetime

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


# Machine Model
class Machine(db.Model):
    __tablename__ = 'machine'
    id = db.Column(db.Integer, primary_key=True)
    game_naam = db.Column(db.String(255), nullable=False)
    publicatiedatum = db.Column(db.Date, nullable=True)
    fabrikant = db.Column(db.String(255), nullable=True)
    voorraad = db.Column(db.Integer, nullable=True)


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
def register(redirect_uri=None):
    if request.method == 'POST':
        naam = request.form['name']
        emailadres = request.form['email']
        password = request.form['password']
        telefoonnummer = request.form['telefoonnummer']
        redirect_uri = 'login'
        if current_user:
            redirect_uri = 'klanten_overview'

        # Controleer of het wachtwoord lang genoeg is
        if len(password) < 10:
            flash('Wachtwoord moet minimaal 10 tekens lang zijn!', 'danger')
            if current_user and redirect_uri:
                return redirect(url_for(redirect_uri))
            else:
                return render_template('KlantenRegistreren.html', name=naam, email=emailadres,
                                       telefoonnummer=telefoonnummer)

        # Controleer of de gebruiker al bestaat
        user = User.query.filter_by(emailadres=emailadres).first()
        if user:
            flash('Er is al een account met dit e-mailadres!', 'danger')
            if current_user and redirect_uri:
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
    if current_user and redirect_uri:
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
    MachineNaam = db.Column(db.String(255), nullable=False)

    gebruiker = db.relationship('User', backref=db.backref('tickets', lazy=True))


# Ticket Opmerking Model
class TicketOpmerking(db.Model):
    __tablename__ = 'ticketopmerkingen'
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False, primary_key=True)
    opmerking = db.Column(db.Text, nullable=False)
    naam = db.Column(db.String(100), nullable=False)

    def __init__(self, ticket_id, opmerking, naam):
        self.ticket_id = ticket_id
        self.opmerking = opmerking
        self.naam = naam


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


@app.route('/create_contract', methods=['GET', 'POST'])
@login_required
@role_required('medewerker')
def create_contract():
    if request.method == 'POST':
        gebruiker_id = request.form.get('gebruiker')
        if not gebruiker_id:
            flash('Klant is verplicht.', 'error')
            return redirect(url_for('create_contract'))

        contract_begin_datum = request.form['contract_begin_datum']
        contract_eind_datum = request.form['contract_eind_datum']
        contract_status = request.form['contract_status']
        contract_termen = request.form['contract_termen']

        new_contract = Contract(
            gebruiker_id=gebruiker_id,
            contract_begin_datum=contract_begin_datum,
            contract_eind_datum=contract_eind_datum,
            contract_status=contract_status,
            contract_termen=contract_termen
        )
        db.session.add(new_contract)
        db.session.commit()

        flash('Het contract is succesvol aangemaakt!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('create_contract.html')


@app.route('/contract_overview', methods=['GET', 'POST'])
@login_required
@role_required('medewerker')
def contract_overview():
    search_query = request.args.get('search', '')

    if request.method == 'POST':
        # Handle contract creation
        gebruiker_id = request.form.get('gebruiker')
        if not gebruiker_id:
            flash('Klant is verplicht.', 'error')
            return redirect(url_for('contract_overview'))

        contract_begin_datum = request.form['contract_begin_datum']
        contract_eind_datum = request.form['contract_eind_datum']
        contract_status = request.form['contract_status']
        contract_termen = request.form['contract_termen']

        new_contract = Contract(
            gebruiker_id=gebruiker_id,
            contract_begin_datum=contract_begin_datum,
            contract_eind_datum=contract_eind_datum,
            contract_status=contract_status,
            contract_termen=contract_termen
        )
        db.session.add(new_contract)
        db.session.commit()

        flash('Het contract is succesvol aangemaakt!', 'success')
        return redirect(url_for('contract_overview'))

    # GET request handling
    filter_status = request.args.get('status', 'Active')  # Default to Active

    print(f"Filter Status: {filter_status}")  # Debug print

    if not hasattr(current_user, 'id') or current_user.id is None:
        print("Error: current_user has no id")
        abort(400, description="Invalid user session")

    try:
        # Start with a base query that joins Contract and User
        base_query = db.session.query(Contract, User.naam).join(
            User, Contract.gebruiker_id == User.id
        )

        # Apply search filter if provided
        if search_query:
            base_query = base_query.filter(
                User.naam.like(f'%{search_query}%')  # Search by user name
            )

        # Apply status and user role filters
        if current_user.rol == 'medewerker':
            if filter_status == 'Deleted':
                contracten = base_query.filter(Contract.contract_status == 'Deleted').all()
            else:
                contracten = base_query.filter(Contract.contract_status == 'Active').all()
        else:
            if filter_status == 'Deleted':
                contracten = base_query.filter(
                    Contract.gebruiker_id == current_user.id,
                    Contract.contract_status == 'Deleted'
                ).all()
            else:
                contracten = base_query.filter(
                    Contract.gebruiker_id == current_user.id,
                    Contract.contract_status == 'Active'
                ).all()
    except Exception as e:
        print(f"Database Query Error: {e}")
        abort(500, description="Database query failed")

    print(f"Contracts Retrieved: {len(contracten)}")  # Debug print

    # Format the contracts for the template
    formatted_contracts = []
    for contract, naam in contracten:
        contract_dict = {
            'id': contract.id,
            'gebruiker_naam': naam,
            'contract_begin_datum': contract.contract_begin_datum,
            'contract_eind_datum': contract.contract_eind_datum,
            'contract_status': contract.contract_status,
            'contract_termen': contract.contract_termen
        }
        formatted_contracts.append(contract_dict)

    customers = User.query.order_by(User.naam).filter(User.rol == "klant").all()

    return render_template('contract_overview.html', contracten=formatted_contracts, filter_status=filter_status,
                           klanten=customers, search_query=search_query)


@app.route('/create_ticket', methods=['GET', 'POST'])
@login_required
def create_ticket():
    if request.method == 'POST':
        ticket_naam = request.form['titel']
        ticket_beschrijving = request.form['beschrijving']

        # If a machine_id is provided, get the machine name
        if 'machine_id' in request.form and request.form['machine_id']:
            machine_id = request.form['machine_id']
            machine = Machine.query.get(machine_id)
            machine_naam = machine.game_naam if machine else "Unknown Machine"
        else:
            # Fallback to direct input if available
            machine_naam = request.form.get('MachineNaam', "Unknown Machine")

        new_ticket = Ticket(
            titel=ticket_naam,
            beschrijving=ticket_beschrijving,
            gebruiker_id=current_user.id,
            MachineNaam=machine_naam
        )

        db.session.add(new_ticket)
        db.session.commit()
        flash('Ticket succesvol aangemaakt!', 'success')

        # Redirect based on user role
        if current_user.rol == 'medewerker':
            return redirect(url_for('MedewerkerTickets'))
        else:
            return redirect(url_for('ticket_overview'))

    # For GET requests, get all machines to populate the dropdown
    machines = Machine.query.all()
    return render_template('create_ticket.html', machines=machines)


@app.route('/dashboard')
@login_required
@role_required('medewerker')
def dashboard():
    # This is now the monteur dashboard (purple)
    # Get all tickets and contracts for monteurs
    tickets = Ticket.query.order_by(Ticket.created_at.desc()).limit(5).all()
    contracten = Contract.query.order_by(Contract.contract_begin_datum.desc()).limit(5).all()
    customers = User.query.order_by(User.naam).filter(User.rol == "klant").all()
    machines = Machine.query.all()  # Get machines for the dropdown
    return render_template('dashboard.html', klanten=customers, tickets=tickets, contracten=contracten,
                           machines=machines)


@app.route('/customer_dashboard')
@login_required
def customer_dashboard():
    # This is the customer dashboard (blue)
    # Only show tickets and contracts for the current user
    tickets = Ticket.query.filter_by(gebruiker_id=current_user.id).order_by(Ticket.created_at.desc()).limit(5).all()
    contracten = Contract.query.filter_by(gebruiker_id=current_user.id).order_by(
        Contract.contract_begin_datum.desc()).limit(5).all()

    return render_template('customer_dashboard.html', tickets=tickets, contracten=contracten)


@app.route('/add_ticket_opmerking', methods=['POST'])
@login_required
def add_ticket_opmerking():
    ticket_id = request.form.get('ticket_id')
    opmerking = request.form.get('opmerking')

    if not ticket_id or not opmerking:
        flash('Ticket ID en opmerking zijn verplicht.', 'error')
        return redirect(url_for('ticket_overview'))

    ticket = Ticket.query.get_or_404(ticket_id)

    # Check if the user has permission to add a comment to this ticket
    if current_user.rol != 'medewerker' and ticket.gebruiker_id != current_user.id:
        flash('Je hebt geen toestemming om een opmerking toe te voegen aan dit ticket.', 'error')
        return redirect(url_for('ticket_overview'))

    new_opmerking = TicketOpmerking(
        ticket_id=ticket_id,
        opmerking=opmerking,
        naam=current_user.naam
    )

    db.session.add(new_opmerking)
    db.session.commit()

    flash('Opmerking succesvol toegevoegd!', 'success')

    # Redirect back to the page they came from
    if current_user.rol == 'medewerker':
        return redirect(url_for('MedewerkerTickets'))
    else:
        return redirect(url_for('ticket_overview'))


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
        return redirect(url_for('MedewerkerTickets'))


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
        return redirect(url_for('contract_overview'))


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
    return redirect(url_for('MedewerkerTickets', status='Deleted'))


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

    # Get all opmerkingen for this ticket - Use text() to wrap the SQL query
    sql_query = text('SELECT ticket_id, opmerking, naam FROM ticketopmerkingen WHERE ticket_id = :id')
    opmerkingen = db.session.execute(
        sql_query,
        {'id': ticket_id}
    ).fetchall()

    return render_template('ticket_detail.html', ticket=ticket, opmerkingen=opmerkingen)


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


@app.route('/ticket_overview')
@login_required
def ticket_overview():
    filter_status = request.args.get('status', 'Active')  # Default to Active
    search_query = request.args.get('search', '')

    # Base query
    query = Ticket.query

    # Apply search filter if provided
    if search_query:
        # Join with User to search by user name
        query = query.join(User).filter(
            (User.naam.like(f'%{search_query}%')) |  # Search by user name
            (Ticket.titel.like(f'%{search_query}%')) |  # Search by ticket title
            (Ticket.MachineNaam.like(f'%{search_query}%'))  # Search by machine name
        )

    # Apply status filter
    if current_user.rol == 'medewerker':
        if filter_status == 'Deleted':
            query = query.filter_by(status='Deleted')
        else:
            query = query.filter_by(status='Open')
    else:
        # For regular customers, only show their own tickets
        if filter_status == 'Deleted':
            query = query.filter_by(gebruiker_id=current_user.id, status='Deleted')
        else:
            query = query.filter_by(gebruiker_id=current_user.id, status='Open')

    tickets = query.all()

    # Get all ticket opmerkingen
    ticket_ids = [ticket.id for ticket in tickets]
    opmerkingen = []
    if ticket_ids:
        # Use text() to wrap the SQL query
        sql_query = text('SELECT ticket_id, opmerking, naam FROM ticketopmerkingen WHERE ticket_id IN :ids')
        opmerkingen = db.session.execute(
            sql_query,
            {'ids': tuple(ticket_ids) if len(ticket_ids) > 1 else (ticket_ids[0],)}
        ).fetchall()

    # Create a dictionary to easily access opmerkingen by ticket_id
    opmerkingen_by_ticket = {}
    for opmerking in opmerkingen:
        if opmerking.ticket_id not in opmerkingen_by_ticket:
            opmerkingen_by_ticket[opmerking.ticket_id] = []
        opmerkingen_by_ticket[opmerking.ticket_id].append(opmerking)

    # Get all machines for the dropdown
    machines = Machine.query.all()

    return render_template('ticket_overview.html',
                           tickets=tickets,
                           filter_status=filter_status,
                           opmerkingen_by_ticket=opmerkingen_by_ticket,
                           search_query=search_query,
                           machines=machines)


@app.route('/MedewerkerTickets')
@login_required
@role_required('medewerker')
def MedewerkerTickets():
    filter_status = request.args.get('status', 'Active')  # Default to Active
    search_query = request.args.get('search', '')

    # Base query
    query = Ticket.query

    # Apply search filter if provided
    if search_query:
        # Join with User to search by user name
        query = query.join(User).filter(
            (User.naam.like(f'%{search_query}%')) |  # Search by user name
            (Ticket.titel.like(f'%{search_query}%')) |  # Search by ticket title
            (Ticket.MachineNaam.like(f'%{search_query}%'))  # Search by machine name
        )

    # Apply status filter
    if filter_status == 'Deleted':
        query = query.filter_by(status='Deleted')
    else:
        query = query.filter_by(status='Open')

    # Ensure unique results
    tickets = query.distinct().all()

    # Get all ticket opmerkingen
    ticket_ids = [ticket.id for ticket in tickets]
    opmerkingen = []
    if ticket_ids:
        # Use text() to wrap the SQL query
        sql_query = text('SELECT ticket_id, opmerking, naam FROM ticketopmerkingen WHERE ticket_id IN :ids')
        opmerkingen = db.session.execute(
            sql_query,
            {'ids': tuple(ticket_ids) if len(ticket_ids) > 1 else (ticket_ids[0],)}
        ).fetchall()

    # Create a dictionary to easily access opmerkingen by ticket_id
    opmerkingen_by_ticket = {}
    for opmerking in opmerkingen:
        if opmerking.ticket_id not in opmerkingen_by_ticket:
            opmerkingen_by_ticket[opmerking.ticket_id] = []
        opmerkingen_by_ticket[opmerking.ticket_id].append(opmerking)

    # Get all customers for the dropdown
    customers = User.query.order_by(User.naam).filter(User.rol == "klant").all()

    # Get all machines for the dropdown
    machines = Machine.query.all()

    return render_template('medewerkertickets.html',
                           tickets=tickets,
                           filter_status=filter_status,
                           opmerkingen_by_ticket=opmerkingen_by_ticket,
                           search_query=search_query,
                           klanten=customers,
                           machines=machines)

# logout functie
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# Machine routes
@app.route('/machines')
@login_required
def machines_overview():
    search_query = request.args.get('search', '')

    # Base query
    query = Machine.query

    # Apply search filter if provided
    if search_query:
        query = query.filter(
            (Machine.game_naam.like(f'%{search_query}%')) |  # Search by game name
            (Machine.fabrikant.like(f'%{search_query}%'))  # Search by manufacturer
        )

    machines = query.all()

    return render_template('machines.html', machines=machines, search_query=search_query)


@app.route('/create_machine', methods=['POST'])
@login_required
@role_required('medewerker')
def create_machine():
    if request.method == 'POST':
        game_naam = request.form['game_naam']
        publicatiedatum_str = request.form.get('publicatiedatum')
        fabrikant = request.form.get('fabrikant', '')
        voorraad_str = request.form.get('voorraad', '0')

        # Convert date string to date object if provided
        publicatiedatum = None
        if publicatiedatum_str:
            try:
                publicatiedatum = datetime.strptime(publicatiedatum_str, '%Y-%m-%d').date()
            except ValueError:
                pass

        # Convert voorraad to integer
        try:
            voorraad = int(voorraad_str)
        except ValueError:
            voorraad = 0

        new_machine = Machine(
            game_naam=game_naam,
            publicatiedatum=publicatiedatum,
            fabrikant=fabrikant,
            voorraad=voorraad
        )

        db.session.add(new_machine)
        db.session.commit()

        flash('Machine successfully added!', 'success')
        return redirect(url_for('machines_overview'))


@app.route('/edit_machine', methods=['POST'])
@login_required
@role_required('medewerker')
def edit_machine():
    if request.method == 'POST':
        machine_id = request.form['machine_id']
        game_naam = request.form['game_naam']
        publicatiedatum_str = request.form.get('publicatiedatum')
        fabrikant = request.form.get('fabrikant', '')
        voorraad_str = request.form.get('voorraad', '0')

        machine = Machine.query.get_or_404(machine_id)

        # Convert date string to date object if provided
        publicatiedatum = None
        if publicatiedatum_str:
            try:
                publicatiedatum = datetime.strptime(publicatiedatum_str, '%Y-%m-%d').date()
            except ValueError:
                pass

        # Convert voorraad to integer
        try:
            voorraad = int(voorraad_str)
        except ValueError:
            voorraad = 0

        machine.game_naam = game_naam
        machine.publicatiedatum = publicatiedatum
        machine.fabrikant = fabrikant
        machine.voorraad = voorraad

        db.session.commit()

        flash('Machine successfully updated!', 'success')
        return redirect(url_for('machines_overview'))


@app.route('/delete_machine/<int:id>', methods=['POST'])
@login_required
@role_required('medewerker')
def delete_machine(id):
    machine = Machine.query.get_or_404(id)

    db.session.delete(machine)
    db.session.commit()

    flash('Machine successfully deleted!', 'success')
    return redirect(url_for('machines_overview'))


if __name__ == '__main__':
    app.run(debug=True)
