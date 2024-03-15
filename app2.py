from flask import Flask, request, render_template, redirect, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, TextAreaField, Form
from wtforms.validators import InputRequired
import bcrypt
import re
from datetime import datetime, timedelta
import pytz

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
app.secret_key = 'secret_key'
csrf = CSRFProtect(app)

# Function to check if the session has expired
def is_session_expired():
    if 'login_time' in session:
        login_time = session['login_time']
        tz = pytz.timezone('Asia/Kolkata')
        login_time = login_time.astimezone(tz)
        now = datetime.now(tz=tz)
        time_difference = now - login_time
        if time_difference > timedelta(minutes=10):  # Change session timeout duration as needed
            return True
    return False

@app.before_request
def before_request():
    if 'email' in session and is_session_expired():
        session.pop('email', None)
        flash('Session expired. Please login again.', 'error')
        return redirect('/login')
    elif 'email' in session:
        tz = pytz.timezone('Asia/Kolkata')
        now = datetime.now(tz=tz)
        # Update login time on every request to keep session alive
        session['login_time'] = now

# This is user registration
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

    def __init__(self, email, password, name):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

# This is storing the asset and asset owner details
class Entry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(100), nullable=False)
    hostname = db.Column(db.String(100), nullable=False)
    owner = db.Column(db.String(100), nullable=False)
    remarks = db.Column(db.String(300), nullable=True)

    def __repr__(self):
        return f"Entry('{self.ip_address}', '{self.hostname}', '{self.owner}', '{self.remarks}')"

# Create the database and tables
@app.before_first_request
def create_tables():
    db.create_all()

# Define a form for editing asset details with CSRF protection
class EditAssetForm(Form):
    hostname = StringField('Hostname', validators=[InputRequired()])
    owner = StringField('Owner', validators=[InputRequired()])
    remarks = TextAreaField('Remarks')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
@csrf.exempt  # Exempt the registration route from CSRF protection
def register():
    if request.method == 'POST':
        # handle request
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        # Check for existing user
        user = User.query.filter_by(email=email).first()
        if user:
            return render_template('register.html', error='Account already exists.')

        # This is password validation
        if not re.match(r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$", password):
            return render_template('register.html', error='Password must be at least 8 characters long, include an alphabet, a number, and a special character.')

        new_user = User(name=name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful..! Please login.', 'success')
        return redirect('/login')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@csrf.exempt  # Exempt the login route from CSRF protection
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            session['email'] = user.email
            session['login_time'] = datetime.now(pytz.timezone('Asia/Kolkata'))  # Set login time
            return redirect('/assets')
        else:
            return render_template('login.html', error='Invalid user')

    return render_template('login.html')

# Adding assets to the database
@app.route('/assets', methods=['GET', 'POST'])
@csrf.exempt  # Exempt the assets route from CSRF protection
def assets():
    if 'email' not in session:
        # Redirect to login if the user is not in session
        return redirect('/login')
    
    # Proceed if the user is in session
    user = User.query.filter_by(email=session['email']).first()
    
    if request.method == 'POST':
        # Handle asset submission
        ip_address = request.form['ip_address']
        hostname = request.form['hostname']
        owner = request.form['owner']
        remarks = request.form['remarks']

        # Ip Address validation
        if not re.match(r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', ip_address):
            flash('Invalid IP address format', 'error')
            return redirect('/assets')
        # Hostname validation
        if not re.match(r'^[a-zA-Z0-9.-]+$', hostname):
            flash('Hostname should not contain any special characters except "."', 'error')
            return redirect('/assets')
        # Owner validation
        if not re.match(r'^[a-zA-Z-]+$', owner):
            flash('Owner should not contain any special characters', 'error')
            return redirect('/assets')
        # Remarks validation
        if not re.match(r'^[a-zA-Z0-9.-]+$', remarks):
            flash('Remarks should not contain any special characters except "."', 'error')
            return redirect('/assets')
        # Check if the IP address already exists in the database
        existing_entry = Entry.query.filter_by(ip_address=ip_address).first()
        if existing_entry:
            flash('IP address already exists', 'error')
            return redirect('/assets')

        new_entry = Entry(ip_address=ip_address, hostname=hostname, owner=owner, remarks=remarks)
        db.session.add(new_entry)
        db.session.commit()
        flash('Asset details saved successfully..!', 'success')

        # You might want to redirect or inform the user of successful submission here
        return redirect('/assets')  # Redirecting to the same page can be a way to show updated info or clear the form
    
    # This handles GET request, showing the form or assets
    return render_template('assets.html', user=user)

# Search database
@app.route('/search', methods=['GET', 'POST'])
@csrf.exempt  # Exempt the search route from CSRF protection
def search():
    if 'email' not in session:
        return redirect('/login')

    user = User.query.filter_by(email=session['email']).first()
    if request.method == 'POST':
        search_query = request.form['search']
        search_results = Entry.query.filter((Entry.ip_address.like(f'%{search_query}%')) | 
                                            (Entry.hostname.like(f'%{search_query}%')) | 
                                            (Entry.owner.like(f'%{search_query}%'))).all()
        return render_template('search.html', entries=search_results, user=user)
    else:
        return render_template('search.html', entries=[], user=user)

# edit asset
@app.route('/edit_asset/<int:asset_id>', methods=['GET', 'POST'])
def edit_asset(asset_id):
    if 'email' not in session:
        return redirect('/login')
    
    # Proceed if the user is in session
    user = User.query.filter_by(email=session['email']).first()
    
    asset = Entry.query.get(asset_id)
    form = EditAssetForm(request.form, obj=asset)
    
    if request.method == 'POST':
        if form.validate():
            hostname = form.hostname.data
            owner = form.owner.data
            remarks = form.remarks.data

            # Hostname validation
            if not re.match(r'^[a-zA-Z0-9.-]+$', hostname):
                flash('Hostname should not contain any special characters except "."', 'error')
                return redirect('/edit_asset/'+str(asset_id))

            # Owner validation
            if not re.match(r'^[a-zA-Z\s-]+$', owner):
                flash('Hostname should not contain any special characters except "."', 'error')
                return redirect('/edit_asset/'+str(asset_id))

            # Remarks validation
            if not re.match(r'^[a-zA-Z0-9.\s-]+$', remarks):
                flash('Hostname should not contain any special characters except "."', 'error')
                return redirect('/edit_asset/'+str(asset_id))

            # Update asset details
            asset.hostname = hostname
            asset.owner = owner
            asset.remarks = remarks
            
            db.session.commit()
            flash('Asset details updated successfully!', 'success')
            return redirect('/search')
        else:
            flash('Form validation failed!', 'error')
    
    return render_template('edit_asset.html', asset=asset, form=form)

# User information
@app.route('/userinfo')
@csrf.exempt  # Exempt the userinfo route from CSRF protection
def userinfo():
    if 'email' not in session:
        return redirect('/login')
    user = User.query.filter_by(email=session['email']).first()
    return render_template('/userinfo.html', user=user)

@app.route('/logout')
@csrf.exempt  # Exempt the logout route from CSRF protection
def logout():
    session.pop('email', None)
    return redirect('/login')

if __name__ == '__main__':
    app.run(host='192.168.29.178', port=80, debug=True)
