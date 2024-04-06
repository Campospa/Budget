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
#from werkzeug.security import generate_password_hash, check_password_hash
#from flask_login import LoginManager
#from flask_login import UserMixin
#from flask_login import current_user, login_user
#from flask_login import login_required
#from werkzeug.urls import url_parse
#from flask_login import logout_user
#from wtforms.validators import ValidationError, DataRequired, Email, EqualTo


basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = \
    'sqlite:///' + os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY

db = SQLAlchemy(app)
bootstrap = Bootstrap(app)
moment = Moment(app)
migrate = Migrate(app, db)
engine = create_engine("sqlite:///:memory:", echo=True)
#login = LoginManager(app)
#login.login_view = 'login'


#@app.route('/', methods = ['GET', 'POST'])
@app.route('/')
@app.route('/index')
#@login_required
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


# Create a shell context

@app.shell_context_processor
def make_shell_context():
    return dict(db=db, User=User, Expense=Expenses)

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


'''
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)
'''
'''
@app.route('/login')
def login():
    form = LoginForm()
    return render_template('login.html', title='Sign In', form=form)
'''
# Form class '''This is the form for name on the index page'''
class NameForm(FlaskForm):
    name = StringField('Please enter your name:', validators=[DataRequired()])
    submit = SubmitField('Submit')
'''
#Logout function
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))
'''
# Add a class to accept users to the application
class User(db.Model): # creates a table
    __tablename__='users' # assigns a table name
    id = db.Column(db.Integer, primary_key=True) # names a column for id with its attributes
    username = db.Column(db.String(64), unique=True, index=True) # names a column for username with its attributes
    # Password hashing
    #password_hash = db.Column(db.String(128))

    def __repr__(self):
        return '<User %r>' % self.username

    #def set_password(self, password):
        #self.password_hash = generate_password_hash(password)

    #def check_password(self, password):
        #return check_password_hash(self.password_hash, password)

'''          
@login.user_loader # AN ERROR IS OCCURING HERE
def load_user(id):
    return User.query.get(int(id))
'''
'''
# User Registration
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    #email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')
'''
    #def validate_email(self, email):
        #user = User.query.filter_by(email=email.data).first()
        #if user is not None:
            #raise ValidationError('Please use a different email address.')

'''       
# User Registration view function
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)
'''
# Create a database


# Create an Expenses table

class Expenses(db.Model):
    __tablename__ = 'expenses'
    id = db.Column(db.Integer, primary_key = True)
    date = db.Column(db.String(64), nullable=False)
    category = db.Column(db.String(64), nullable=False)
    description = db.Column(db.String(64), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    #user_id = db.Column(db.Integer, db.ForeignKey('user.id')) # remember to re create the database to include this column
    

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
    #user_id = db.Column(db.Integer, db.ForeignKey('user.id')) # remember to recreate the database to include this column

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

        total_expenses = sum(new_expense) # not working

        return redirect(url_for('view_expenses', total_expenses=total_expenses)) # total expenses not working
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
        
        monthly_payment = "{:.4f}".format(mortgage_calculations(loan_amount, annual_interest_rate, loan_term_years)) # error here
        #monthly_payment = mortgage_calculations(loan_amount, annual_interest_rate, loan_term_years)
        
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
    return render_template('view.html', expenses=expenses)

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


# Next steps

# make sure that the amounts displayed are printed to 2 significant digits
# create a user registration form and an user log in
# for the budget, give the option to input either the income or the amount budgeted
# create a mortgage calculator
# connect the user to the other databases
# style the app?
# deploy to the cloud