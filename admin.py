import os
import grp
import pam

from flask import Flask, flash, redirect, render_template, request, session,\
    url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user,\
    login_required
from flask_wtf import Form
from wtforms import BooleanField, PasswordField, StringField, SubmitField
from wtforms.validators import Email, EqualTo, InputRequired
from flask_bootstrap import Bootstrap

import config
import sudo

app = Flask(__name__)
app.secret_key = os.urandom(32)
app.config.from_object(config.Base)
lm = LoginManager()
lm.init_app(app)
lm.login_view = "login"
lm.session_protection = "strong"
lm.login_message_category = "info"
Bootstrap(app)
pam = pam.pam()


class SudoError(Exception):
    pass


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


class AddUserForm(Form):

    username = StringField("Username", validators=[
        InputRequired(message="Please provide a username.")])
    name = StringField("Name", validators=[
        InputRequired(message="Please provide a name.")])
    surname = StringField("Surname", validators=[
        InputRequired(message="Please provide a surname.")])
    email = StringField("E-mail", validators=[
        InputRequired(message="Please provide an e-mail address."),
        Email(message="Not a valid e-mail address.")])
    password = PasswordField("Password", validators=[
        EqualTo("confirm", message="Passwords must match."),
        InputRequired(message="Please provide a password.")])
    confirm = PasswordField("Repeat password", validators=[
        InputRequired(message="Please confirm password.")])
    edu = BooleanField("Grant admin rights")
    submit = SubmitField("Register")


class ChpasswdForm(Form):

    password = PasswordField("Password", validators=[
        EqualTo("confirm", message="Passwords must match."),
        InputRequired(message="Please provide a password.")])
    confirm = PasswordField("Repeat password", validators=[
        InputRequired(message="Please confirm password.")])
    submit = SubmitField("Change password")


#####################
# UTILITY FUNCTIONS #
#####################


@lm.user_loader
def load_user(username):
    return User()


def flash_sudo_errors(f, *args):
    try:
        f(*args)
        return
    except sudo.ChpasswdError as e:
        flash("Error changing password: " + str(e), "danger")
    except sudo.AdduserError as e:
        flash("Error adding user: " + str(e), "danger")
    except sudo.UsermodError as e:
        flash("Error modifying user: " + str(e), "danger")
    except sudo.LnError as e:
        flash("Error linking directory: " + str(e), "danger")
    flash("Note that if the action you tried to perform consists of a series "
          "of individual commands, all of them up to this one were applied "
          "successfully.", "info")
    raise SudoError


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
            session.update(username=username, is_admin=is_admin)
            login_user(User())
            flash("Login successful.", "success")
            return redirect(request.args.get("next", url_for("index")))
        flash("Invalid username / password combination.", "danger")
    return render_template("form.html", form=form)


@app.route("/admin/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/admin/chpasswd", methods=["GET", "POST"])
@login_required
def chpasswd():
    form = ChpasswdForm()
    if form.validate_on_submit():
        try:
            flash_sudo_errors(sudo.chpasswd, session["username"],
                              form.password.data)
        except SudoError:
            return redirect(url_for("chpasswd"))
        flash("Changed password for user " + repr(session["username"]), "success")
        return redirect(url_for("index"))
    return render_template("form.html", form=form)


@app.route("/admin/adduser", methods=["GET", "POST"])
@login_required
def adduser():
    form = AddUserForm()
    if form.validate_on_submit():
        name = (form.name.data + " " + form.surname.data).replace(",", "_")
        try:
            flash_sudo_errors(sudo.adduser, form.username.data,
                              form.password.data, name, form.edu.data)
        except SudoError:
            return redirect(url_for("adduser"))
        flash("Added new user " + repr(form.username.data), "success")
        return redirect(url_for("index"))
    return render_template("form.html", form=form)


@app.route("/admin/ls")
@login_required
def ls():
    home = os.path.join("/home", session["username"])
    ls = "\n".join(item for item in sorted(os.listdir(home)))
    return render_template("ls.html", ls=ls)
