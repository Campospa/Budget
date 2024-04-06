from flask import Flask, render_template, request, url_for, redirect, session, flash
import os
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from flask_migrate import Migrate
from sqlalchemy import create_engine
from flask_bcrypt import Bcrypt #pip install flask-bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = \
    'sqlite:///' + os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
bootstrap = Bootstrap(app)
moment = Moment(app)
migrate = Migrate(app, db)
engine = create_engine("sqlite:///:memory:", echo=True)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


#@app.route('/', methods = ['GET', 'POST'])
@app.route('/')
@app.route('/index')
def index():
    form = NameForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.name.data).first()
        if user is None:
            user = User(username=form.name.data)
            db.session.add(user)
            db.session.commit()
            session['known'] = False
        else:
            session['known'] = True
        session['name'] = form.name.data
        form.name.data = ''
        return redirect(url_for('index')) # main.index or index?
    return render_template('index.html',
                            form=form, name=session.get('name'),
                           known=session.get('known', False)) # returns the message created in the index.html file

# Create routes for the register functionality
@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            # Login successful
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login unsuccessful.', 'danger')
    return render_template('login.html')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_request
def before_request():
    session.permanent = True  # Make the session permanent

@app.route("/logout")
def logout():
    logout_user()
    flash('Logout successful!', 'success')
    return redirect(url_for('index'))

    

# Protect routes that require authentication with the @login_required decorator.
@app.route("/account")
@login_required
def account():
    return render_template('account.html', title='Account')

@app.route('/dashboard')
@login_required
def dashboard():
    return "Welcome to the dashboard, " + current_user.username + "!"

# Form class '''This is the form for name on the index page'''
class NameForm(FlaskForm):
    name = StringField('Please enter your name:', validators=[DataRequired()])
    submit = SubmitField('Submit')

# Add a class to accept users to the application
class User(db.Model, UserMixin): # creates a table
    __tablename__='users' # assigns a table name
    id = db.Column(db.Integer, primary_key=True) # names a column for id with its attributes
    username = db.Column(db.String(64), unique=True, index=True) # names a column for username with its attributes
    password = db.Column(db.String(60), nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username

    

# Create a database


# Create an Expenses table

class Expenses(db.Model):
    __tablename__ = 'expenses'
    id = db.Column(db.Integer, primary_key = True)
    date = db.Column(db.String(64), nullable=False)
    category = db.Column(db.String(64), nullable=False)
    description = db.Column(db.String(64), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    
    

    def __repr__(self):
        return '<Expenses %r>' % self.name

# Create a table to record investmnet calculations
class InvestmentRecords(db.Model):
    __tablename__ = 'investment'
    id = db.Column(db.Integer, primary_key=True)
    principal = db.Column(db.Float, nullable=False)
    additional_contribution = db.Column(db.Float, default=0)
    interest_rate = db.Column(db.Float, nullable=False)
    years = db.Column(db.Integer, nullable=False)
    final_amount = db.Column(db.Float, nullable=False)
    

    def __repr__(self):
        return '<InvestmentRecords %r>' % self.name
    
# Create a table to record mortgage calculations
class MortgageCalculations(db.Model):
    __tablename__ = 'mortgage'
    id = db.Column(db.Integer, primary_key=True)
    loan_amount = db.Column(db.Float, nullable=False)
    annual_interest_rate = db.Column(db.Float, default=0)
    loan_term_years = db.Column(db.Integer, nullable=False)
    monthly_payment = db.Column(db.Float, nullable=False)

 
with app.app_context():
    db.create_all()

# Create a function to add expenses
# Also create a function to add all the expenses
# Also create a funtion to input the take home pay and calcutate the final amount available after covering expenses
@app.route('/Budget', methods=['GET', 'POST'])
def budget(): # the function name must be the same as the template name
    if request.method == 'POST':
        date = request.form['date']
        category = request.form['category']
        description = request.form['description']
        amount = float(request.form['amount'])

        new_expense = Expenses(date=date, category=category, description=description, amount=amount)
        db.session.add(new_expense) 
        db.session.commit()

        # Fetch all expenses from the database to calculate the total
        expenses = Expenses.query.all()
        total_amount = sum(expense.amount for expense in expenses)
        db.session.add(total_amount) # test
        db.session.commit() # test

        return render_template('budget.html', total_amount=total_amount, expenses=expenses)

    return render_template('budget.html')
    
# Add a funtion to create an long term investment program
def calculate_compound_return(principal, additional_contribution, interest_rate, years):
    total_amount = principal
    for year in range(1, years + 1):
        total_amount = total_amount * (1 + interest_rate) + additional_contribution
    return total_amount

@app.route('/Investment', methods = ['GET', 'POST'])
def investment():
    if request.method == 'POST':
        principal = float(request.form['principal'])
        additional_contribution = float(request.form['additional_contribution'])
        interest_rate = float(request.form['interest_rate']) / 100
        years = int(request.form['years'])

        final_amount = "{:.4f}".format(calculate_compound_return(principal, additional_contribution, interest_rate, years))
        

        investment_record = InvestmentRecords(
            principal=principal,
            additional_contribution=additional_contribution,
            interest_rate=interest_rate,
            years=years,
            final_amount=final_amount
        )

        db.session.add(investment_record)
        db.session.commit()

    #return str(final_amount)
        return redirect(url_for('view_calculations'))
    return render_template('investment.html')

# Mortbage calculation
def mortgage_calculations(loan_amount, annual_interest_rate, loan_term_years):
    monthly_interest_rate = (annual_interest_rate / 100) / 12
    loan_term_months = loan_term_years * 12
    monthly_payment = (loan_amount * monthly_interest_rate) / (1 - (1 + monthly_interest_rate)**(-loan_term_months))

    return monthly_payment

        
# Add a fuction to create a mortgage calculator
@app.route('/Mortgage', methods=['GET', 'POST'])
def mortgage_calculator():
    if request.method == 'POST':
        loan_amount = float(request.form['loan_amount'])
        annual_interest_rate = float(request.form['annual_interest_rate'])
        loan_term_years = int(request.form['loan_term_years'])
        
        monthly_payment = "{:.4f}".format(mortgage_calculations(loan_amount, annual_interest_rate, loan_term_years)) 
        
        
        calculations = MortgageCalculations(
            loan_amount=loan_amount,
            annual_interest_rate=annual_interest_rate,
            loan_term_years=loan_term_years,
            monthly_payment=monthly_payment 
        )

        db.session.add(calculations)
        db.session.commit()

        return redirect(url_for('view_mortgage'))
    return render_template('mortgage.html')


# Add a function to view the list of expenses
@app.route('/view')
def view_expenses():
    expenses = Expenses.query.all()
    total_amount = sum(expense.amount for expense in expenses)  # Calculate total_amount here
    return render_template('view.html', expenses=expenses, total_amount=total_amount)
    #return render_template('view.html', expenses=expenses)

# Add a frunction to view investment calculations
@app.route('/calculations')
def view_calculations():
    investment = InvestmentRecords.query.all()
    return render_template('calculations.html', investment=investment)

# Add a frunction to view  mortgage calculations
@app.route('/mortgage')
def view_mortgage():
    mortgage_calculator = MortgageCalculations.query.all()
    return render_template('mortgage_view.html', mortgage_calculator=mortgage_calculator)


if __name__ == '__main__':  
    app.run()


