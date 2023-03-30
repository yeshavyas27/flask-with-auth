from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CREATE TABLE IN DB
#UserMixin used for auth
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

#Line below only required once, when creating DB.
#
# with app.app_context():
#     db.create_all()


@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@login_manager.user_loader
def load_user(user_id):
    return db.session.execute(db.select(User).filter_by(id=user_id)).scalar_one()


@app.route('/register', methods=["POST", "GET"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = generate_password_hash(request.form["password"], method='pbkdf2:sha256', salt_length=8)
        try:
            user = db.session.execute(db.select(User).filter_by(email=email)).scalar_one()
            flash('User already exists. Please login')
            return redirect(url_for("login"))

        except exc.NoResultFound:
            new_user = User(email=email, password=password, name=name)
            db.session.add(new_user)
            db.session.commit()
            is_logged_in = new_user.is_authenticated

            return redirect(url_for("secrets", name=name))

    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=["POST", "GET"])
def login():
    if request.method == "POST":

        email = request.form["email"]
        password = request.form["password"]
        try:
            user = db.session.execute(db.select(User).filter_by(email=email)).scalar_one()

            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for("secrets", name=user.name))
            else:
                flash('Invalid Password. Please re-enter')
                return redirect(url_for('login'))

        except exc.NoResultFound:
            #no email in database
            flash('Invalid Email. Email not in database')
            return redirect(url_for('login'))

    return render_template("login.html", logged_in=current_user.is_authenticated)


@app.route('/secrets')
@login_required
def secrets():
    name = request.args.get("name")
    return render_template("secrets.html", name=name, logged_in=current_user.is_authenticated)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route('/download')
@login_required
def download():
    return app.send_static_file('files/cheat_sheet.pdf')


if __name__ == "__main__":
    app.run(debug=True)
