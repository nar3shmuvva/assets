from flask import Flask, request,render_template, redirect, session, flash
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import re

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
app.secret_key = 'secret_key'


# This is user registration
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

    def __init__(self,email,password,name):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self,password):
        return bcrypt.checkpw(password.encode('utf-8'),self.password.encode('utf-8'))

with app.app_context():
    db.create_all()

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

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register',methods=['GET','POST'])
def register():
    if request.method == 'POST':
        # handle request
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        #Check for existing user
        user = User.query.filter_by(email=email).first()
        if user:
            return render_template('register.html', error='Account alredy exist.')

        #this is password validation
        if not re.match(r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$", password):
            return render_template('register.html', error='Password must be at least 8 characters long, include an alphabet, a number, and a special character.')

        new_user = User(name=name,email=email,password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful..! Please login.', 'success')
        return redirect('/login')

    return render_template('register.html')

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            session['email'] = user.email
            return redirect('/assets')
        else:
            return render_template('login.html',error='Invalid user')

    return render_template('login.html')

# adding assets to the database.
@app.route('/assets', methods=['GET', 'POST'])
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

        new_entry = Entry(ip_address=ip_address, hostname=hostname, owner=owner, remarks=remarks)
        db.session.add(new_entry)
        db.session.commit()

        # You might want to redirect or inform the user of successful submission here
        return redirect('/assets')  # Redirecting to the same page can be a way to show updated info or clear the form
    
    # This handles GET request, showing the form or assets
    return render_template('assets.html', user=user)
# Search database
@app.route('/search', methods=['GET', 'POST'])
def search():
    if 'email' not in session:
        return redirect('/login')

    user = User.query.filter_by(email=session['email']).first()
    if request.method == 'POST':
        search_query = request.form['search']
        search_results = Entry.query.filter((Entry.ip_address.like(f'%{search_query}%')) | 
                                            (Entry.hostname.like(f'%{search_query}%')) | 
                                            (Entry.owner.like(f'%{search_query}%'))).all()
        return render_template('search.html', entries=search_results)
    else:
        return render_template('search.html', entries=[])

#User information
@app.route('/userinfo')
def userinfo():
    if 'email' not in session:
        return redirect('/login')
    user = User.query.filter_by(email=session['email']).first()
    return render_template('/userinfo.html', user=user)

@app.route('/logout')
def logout():
    session.pop('email',None)
    return redirect('/login')

if __name__ == '__main__':
    app.run(host='192.168.29.178', port=80, debug=True)
