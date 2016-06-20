import os
import grp
import pam

from flask import Flask, flash, redirect, render_template, session, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user,\
    login_required
from flask_wtf import Form
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import InputRequired
from flask_bootstrap import Bootstrap

import config

app = Flask(__name__)
app.secret_key = os.urandom(32)
app.config.from_object(config.Base)
lm = LoginManager()
lm.init_app(app)
lm.login_view = "login"
lm.session_protection = "strong"
Bootstrap(app)
pam = pam.pam()


class User(UserMixin):
    """This is basically a dummy, we aren't using a database to store user
    info; instead we just store the UNIX ``username`` and ``password`` on the
    session object.

    """
    def get_id(self):
        return "generic"


class LoginForm(Form):

    username = StringField("Username", validators=[
        InputRequired(message="Please provide a username.")])
    password = PasswordField("Password", validators=[
        InputRequired(message="Please provide a password.")])
    submit = SubmitField("Log in")


#####################
# UTILITY FUNCTIONS #
#####################


@lm.user_loader
def load_user(username):
    return User()


def flash_form_errors(form):
    for field, errors in form.errors.items():
        for error in errors:
            flash("Error in {!r}: {}".format(
                getattr(form, field).label.text, error))


# @app.context_processor
# def utility_processor():
#     return dict(quick_form=quick_form)


##########
# ROUTES #
##########


@app.route("/admin/")
@login_required
def index():
    return render_template("index.html")


@app.route("/admin/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username, password = form.username.data, form.password.data
        if pam.authenticate(username, password):
            is_admin = any(g.gr_name == "edu" for g in grp.getgrall()
                           if username in g.gr_mem)
            # TODO: is it really necessary to store the password here? can't I
            # just allow the Flask process to have the required privileges and
            # exercise them based on whether the user is logged in (and is an
            # admin)?
            session.update(username=username, password=password,
                           is_admin=is_admin)
            login_user(User())
            flash("Login successful.")
            return redirect(url_for("index"))
        flash("Invalid username / password combination.")
    flash_form_errors(form)
    return render_template("login.html", form=form)


@app.route("/admin/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/admin/passwd")
@login_required
def passwd():
    assert False


@app.route("/admin/adduser")
@login_required
def adduser():
    assert False


@app.route("/admin/ls")
@login_required
def ls():
    home = os.path.join("/home", session["username"])
    ls = "\n".join(item for item in sorted(os.listdir(home)))
    return render_template("ls.html", ls=ls)
