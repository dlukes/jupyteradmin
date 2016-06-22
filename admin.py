import os
import grp
import pam

import uuid
import regex as re

from flask import Flask, flash, redirect, render_template, request, session,\
    url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user,\
    login_required
from flask_wtf import Form
from wtforms import BooleanField, PasswordField, StringField, SubmitField,\
    TextAreaField
from wtforms.validators import Email, EqualTo, InputRequired, Length
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import SQLAlchemyError
from flask_sendmail import Mail, Message
from flask_bootstrap import Bootstrap

import config
import sudo

app = Flask(__name__)
app.secret_key = os.urandom(32)
app.config.from_object(config.Dev if app.config.get("DEBUG") else config.Prod)
lm = LoginManager()
lm.init_app(app)
lm.login_view = "login"
lm.session_protection = "strong"
lm.login_message_category = "info"
db = SQLAlchemy(app)
mail = Mail(app)
Bootstrap(app)
pam = pam.pam()
tfml = app.config["TEXT_FIELD_MAX_LEN"]
length_validator = Length(
    max=tfml, message="Maximum {} characters allowed.".format(tfml))


##############
# EXCEPTIONS #
##############


class AlreadyFlashedError(Exception):
    pass


##########
# MODELS #
##########


class User(db.Model, UserMixin):
    """Relevant user information is stored on the session object, this is just a
    way to cleanly keep track of users who have registered via the web
    interface.

    """
    __tablename__ = "users"

    username = db.Column(db.String(tfml), primary_key=True)
    name = db.Column(db.String(tfml))
    email = db.Column(db.String(tfml), unique=True)
    edu = db.Column(db.Boolean, nullable=False)

    def __init__(self, username, name, email, edu):
        self.username = username
        self.name = name
        self.email = email
        self.edu = edu

    def __repr__(self):
        return "<User {!r} with e-mail {!r}>".format(self.username, self.email)

    def get_id(self):
        return session["username"]


class FbUser(UserMixin):
    """A fallback User class for users which are not stored in the db.

    """
    def get_id(self):
        return session["username"]


class Invite(db.Model):
    """An invite to register with the service.

    """
    __tablename__ = "invites"

    uuid = db.Column(db.String(36), primary_key=True)
    email = db.Column(db.String(tfml))
    accepted = db.Column(db.Boolean, nullable=False, default=False)

    def __init__(self, email):
        self.email = email
        uuid_ = str(uuid.uuid4())
        while Invite.query.filter_by(uuid=uuid_).first() is not None:
            uuid_ = str(uuid.uuid4())
        self.uuid = uuid_

    def __repr__(self):
        return "<Invite {!r} for {!r}>".format(self.uuid, self.email)


#########
# FORMS #
#########


class LoginForm(Form):

    username = StringField("Username", validators=[
        InputRequired(message="Please provide a username.")])
    password = PasswordField("Password", validators=[
        InputRequired(message="Please provide a password.")])
    submit = SubmitField("Log in")


class AddUserForm(Form):

    username = StringField("Username", validators=[
        length_validator,
        InputRequired(message="Please provide a username.")])
    name = StringField("Name", validators=[
        length_validator,
        InputRequired(message="Please provide a name.")])
    surname = StringField("Surname", validators=[
        length_validator,
        InputRequired(message="Please provide a surname.")])
    email = StringField("E-mail", validators=[
        length_validator,
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


class AcceptInviteForm(Form):

    username = StringField("Username", validators=[
        length_validator,
        InputRequired(message="Please provide a username.")])
    name = StringField("Name", validators=[
        length_validator,
        InputRequired(message="Please provide a name.")])
    surname = StringField("Surname", validators=[
        length_validator,
        InputRequired(message="Please provide a surname.")])
    password = PasswordField("Password", validators=[
        EqualTo("confirm", message="Passwords must match."),
        InputRequired(message="Please provide a password.")])
    confirm = PasswordField("Repeat password", validators=[
        InputRequired(message="Please confirm password.")])
    submit = SubmitField("Register")


class InviteForm(Form):

    emails = TextAreaField(
        "Whitespace and/or comma separated e-mails", validators=[
        InputRequired(message="Please provide a list of e-mails.")])
    submit = SubmitField("Send invitations")


#####################
# UTILITY FUNCTIONS #
#####################


@lm.user_loader
def load_user(username):
    return User.query.filter_by(username=username).first() or FbUser()


def with_flash_errors(f, *args):
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
    raise AlreadyFlashedError


def _adduser(form, invite=None):
    name = (form.name.data + " " + form.surname.data).replace(",", "_")
    edu = form.edu.data if hasattr(form, "edu") else False
    if invite is not None:
        invite.accepted = True
        email = invite.email
    else:
        email = form.email.data
    user = User(form.username.data, name, email, edu)
    db.session.add(user)
    try:
        with_flash_errors(sudo.adduser, form.username.data,
                          form.password.data, name, edu)
        db.session.commit()
        flash("User {} created.".format(form.username.data), "success")
        return redirect(url_for("index"))
    except SQLAlchemyError as e:
        flash("Error updating user database: " + str(e), "danger")
    except AlreadyFlashedError:
        pass
    db.session.rollback()
    return render_template("form.html", form=form)


def prep_table(model):
    header = list(c.name for c in model.__table__.c)
    rows = [[getattr(r, c) for c in header] for r in model.query.all()]
    return header, rows


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
            user = User.query.filter_by(username=username).first() or FbUser()
            login_user(user)
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
            with_flash_errors(sudo.chpasswd, session["username"],
                              form.password.data)
        except AlreadyFlashedError:
            return redirect(url_for("chpasswd"))
        flash("Changed password for user {!r}.".format(session["username"]), "success")
        return redirect(url_for("index"))
    return render_template("form.html", form=form)


@app.route("/admin/adduser", methods=["GET", "POST"])
@login_required
def adduser():
    form = AddUserForm()
    if form.validate_on_submit():
        return _adduser(form)
    return render_template("form.html", form=form)


@app.route("/admin/invite", methods=["GET", "POST"])
@login_required
def invite():
    form = InviteForm()
    if form.validate_on_submit():
        summary = ("Invitations sent.", "success")
        for email in re.split(r"[,\s]\s*", form.emails.data):
            # TODO: committing in a loop is not a very good idea, but on the
            # other hand, it's good to know adding the invite to the db
            # succeeded before notifying the user...
            invite = Invite(email)
            try:
                db.session.add(invite)
                db.session.commit()
            except SQLAlchemyError as e:
                summary = ("Encountered errors while creating invitations.",
                           "warning")
                flash("Error updating invitation database, no invitation "
                      "sent to {}: {}".format(email, e), "danger")
                continue
            # TODO: wrap in a try except catching mailing errors...?
            msg = Message("Invitation to create account at jupyter.korpus.cz",
                          recipients=[email])
            link = app.config["DOMAIN"] + url_for("accept", uuid=invite.uuid)
            msg.html = render_template("invite.html", link=link)
            mail.send(msg)
        flash(*summary)
        return redirect(url_for("index"))
    return render_template("form.html", form=form)


@app.route("/admin/accept/<uuid>", methods=["GET", "POST"])
def accept(uuid):
    invite = Invite.query.filter_by(uuid=uuid, accepted=False).first()
    if invite is None:
        flash("Invalid invitation code {!r}.".format(uuid), "warning")
        return redirect(url_for("login"))
    form = AcceptInviteForm()
    if form.validate_on_submit():
        return _adduser(form, invite)
    return render_template("form.html", form=form)


@app.route("/admin/list/home")
@login_required
def lshome():
    home = os.path.join("/home", session["username"])
    ls = "\n".join(item for item in sorted(os.listdir(home)))
    return render_template("lshome.html", ls=ls)


@app.route("/admin/list/users")
@login_required
def lsusers():
    header, rows = prep_table(User)
    return render_template("table.html", header=header, rows=rows)


@app.route("/admin/users/list/invites")
@login_required
def lsinvites():
    header, rows = prep_table(Invite)
    return render_template("table.html", header=header, rows=rows)


################
# CLI COMMANDS #
################


@app.cli.command(help="Initialize database.")
def initdb():
    db_path = app.config["SQLALCHEMY_DATABASE_URI"].split("///")[1]
    if os.path.isfile(db_path):
        print("File {!r} exists, delete it first.".format(db_path))
        return
    db.create_all()
    print("Initialized database {!r}.".format(db_path))
