from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt


app = Flask(__name__)
bcrypt = Bcrypt(app)


#db related
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
app.config["SECRET_KEY"] = 'thisisasecretkey'


#login handlers
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


#db table creation
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    
#Register form
class RegisterForm(FlaskForm):
    username = StringField(label="Username", validators=[InputRequired(), Length(min=2, max=50)], render_kw={"placeholder" : "Username"})
    
    password = PasswordField(label="Password", validators=[InputRequired(), Length(min=8, max=50)], render_kw={"placeholder" : "Password"})
    
    submit = SubmitField("Register")
    
    def validate_username(self, username):
        existing_username = User.query.filter_by(username=username.data).first()
        
        
        if existing_username:
            raise ValidationError(
                "This username has been taken")
            


#Login form

class LoginForm(FlaskForm):
    username = StringField(label="Username", validators=[InputRequired(), Length(min=2, max=50)], render_kw={"placeholder" : "Username"})
    
    password = PasswordField(label="Password", validators=[InputRequired(), Length(min=8, max=50)], render_kw={"placeholder" : "Password"})
    
    submit = SubmitField("Login")
    
    
    

@app.route("/")
def home():
    return render_template("home.html")

#Login Rpute
@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    #check if the user exist
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        #check password and log user in if criteria are met
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dash'))
    return render_template("login.html", form=form)



#Logout Route
@app.route("/logout", methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


#Dashboard Route
@app.route("/dash", methods=['GET', 'POST'])
@login_required
def dash():
    return render_template("dash.html")


#Register Route
@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template("register.html", form=form)




