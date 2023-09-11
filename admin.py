import os
import grp
import pam
import subprocess as sp
from pathlib import Path

import uuid
import regex as re

from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from flask_wtf import Form
from wtforms import (
    BooleanField,
    PasswordField,
    StringField,
    SubmitField,
    TextAreaField,
    SelectField,
)
from wtforms.validators import Email, EqualTo, InputRequired, Length, Regexp
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import SQLAlchemyError
from flask_migrate import Migrate
from flask_sendmail import Mail, Message
from flask_bootstrap import Bootstrap
import email_validator

import config
import sudo

app = Flask(__name__, static_url_path="/admin/static")
app.secret_key = os.urandom(32)
app.config.from_object(config.Dev if app.config.get("DEBUG") else config.Prod)
lm = LoginManager()
lm.init_app(app)
lm.login_view = "login"
lm.session_protection = "strong"
lm.login_message_category = "info"
db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app)
Bootstrap(app)
pam = pam.pam()
tfml = app.config["TEXT_FIELD_MAX_LEN"]
length_validator = Length(
    max=tfml, message="Maximum {} characters allowed.".format(tfml)
)
lc_ascii_validator = Regexp(
    r"^[a-z]+$", message="Username must consist of lowercase letters only, a–z."
)


# --------------------------------------------------------------------------- Exceptions {{{1


class AlreadyFlashedError(Exception):
    pass


# ------------------------------------------------------------------------------- Models {{{1


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
    group = db.Column(db.String(tfml))
    rversion = db.Column(db.String(tfml))

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
    """A fallback User class for users which are not stored in the db."""

    def get_id(self):
        return session["username"]


class Invite(db.Model):
    """An invite to register with the service."""

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


# -------------------------------------------------------------------------------- Forms {{{1


class LoginForm(Form):
    username = StringField(
        "Username", validators=[InputRequired(message="Please provide a username.")]
    )
    password = PasswordField(
        "Password", validators=[InputRequired(message="Please provide a password.")]
    )
    submit = SubmitField("Log in")


class AddUserForm(Form):
    username = StringField(
        "Username",
        validators=[
            length_validator,
            lc_ascii_validator,
            InputRequired(message="Please provide a username."),
        ],
    )
    name = StringField(
        "Name",
        validators=[length_validator, InputRequired(message="Please provide a name.")],
    )
    surname = StringField(
        "Surname",
        validators=[
            length_validator,
            InputRequired(message="Please provide a surname."),
        ],
    )
    email = StringField(
        "E-mail",
        validators=[
            length_validator,
            InputRequired(message="Please provide an e-mail address."),
            Email(message="Not a valid e-mail address."),
        ],
    )
    password = PasswordField(
        "Password",
        validators=[
            EqualTo("confirm", message="Passwords must match."),
            InputRequired(message="Please provide a password."),
        ],
    )
    confirm = PasswordField(
        "Repeat password",
        validators=[InputRequired(message="Please confirm password.")],
    )
    edu = BooleanField("Allow adding new users and writing edu group directories")
    submit = SubmitField("Register")


class ChpasswdForm(Form):
    password = PasswordField(
        "Password",
        validators=[
            EqualTo("confirm", message="Passwords must match."),
            InputRequired(message="Please provide a password."),
        ],
    )
    confirm = PasswordField(
        "Repeat password",
        validators=[InputRequired(message="Please confirm password.")],
    )
    submit = SubmitField("Change password")


class ForgotSendLinkForm(Form):
    email = StringField(
        "E-mail",
        validators=[
            length_validator,
            InputRequired(message="Please provide an e-mail address."),
            Email(message="Not a valid e-mail address."),
        ],
    )
    submit = SubmitField("Request password reset")


class ForgotResetPasswdForm(Form):
    password = PasswordField(
        "New password",
        validators=[
            EqualTo("confirm", message="Passwords must match."),
            InputRequired(message="Please provide a password."),
        ],
    )
    confirm = PasswordField(
        "Repeat new password",
        validators=[InputRequired(message="Please confirm password.")],
    )
    submit = SubmitField("Change password")


class RVersionForm(Form):
    # NOTE: there's no easy way to set the default dynamically
    # (technically, it can be a callable, and you can store the value on
    # session from the request handler and retrieve it with a function,
    # but ugh), but choices *can* be set dynamically, so the workaround
    # is to rely on a special value, *, to indicate which choice should
    # be selected by default, because in that case, we actually don't
    # need the value -- if the user selects that, it just means that
    # nothing has to change, because we make sure the default is any
    # previously selected setting
    rversion = SelectField("Preferred R version", default="*")
    submit = SubmitField("Apply")


class AcceptInviteForm(Form):
    username = StringField(
        "Username",
        validators=[
            length_validator,
            lc_ascii_validator,
            InputRequired(message="Please provide a username."),
        ],
    )
    name = StringField(
        "Name",
        validators=[length_validator, InputRequired(message="Please provide a name.")],
    )
    surname = StringField(
        "Surname",
        validators=[
            length_validator,
            InputRequired(message="Please provide a surname."),
        ],
    )
    password = PasswordField(
        "Password",
        validators=[
            EqualTo("confirm", message="Passwords must match."),
            InputRequired(message="Please provide a password."),
        ],
    )
    confirm = PasswordField(
        "Repeat password",
        validators=[InputRequired(message="Please confirm password.")],
    )
    submit = SubmitField("Register")


class InviteForm(Form):
    emails = TextAreaField(
        "Whitespace separated e-mail addresses",
        validators=[InputRequired(message="Please provide a list of e-mails.")],
    )
    submit = SubmitField("Send invitations")


class LDAPUserForm(Form):
    username = StringField(
        "Existing LDAP username",
        validators=[
            length_validator,
            lc_ascii_validator,
            InputRequired(message="Please provide a username."),
        ],
    )
    name = StringField(
        "Name",
        validators=[length_validator, InputRequired(message="Please provide a name.")],
    )
    surname = StringField(
        "Surname",
        validators=[
            length_validator,
            InputRequired(message="Please provide a surname."),
        ],
    )
    email = StringField(
        "E-mail",
        validators=[
            length_validator,
            InputRequired(message="Please provide an e-mail address."),
            Email(message="Not a valid e-mail address."),
        ],
    )
    edu = BooleanField("Allow adding new users and writing edu group directories")
    submit = SubmitField("Set up user")


# -------------------------------------------------------------------- Utility functions {{{1


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
    except Exception as e:
        flash("Unspecified exception: " + str(e), "danger")
    flash(
        "Note that if the action you tried to perform consists of a series "
        "of individual commands, all of them up to this one were applied "
        "successfully.",
        "info",
    )
    raise AlreadyFlashedError


def _adduser(form, invite=None, ldap=False):
    username = form.username.data
    password = None if ldap else form.password.data
    name = (form.name.data + " " + form.surname.data).replace(",", "_")
    edu = form.edu.data if hasattr(form, "edu") else False
    if invite is not None:
        invite.accepted = True
        email = invite.email
    else:
        email = form.email.data
    try_create = True
    if User.query.filter_by(username=username).first() is not None:
        flash("User {!r} already exists.".format(username), "danger")
        try_create = False
    if User.query.filter_by(email=email).first() is not None:
        flash("User with e-mail {!r} already exists.".format(email), "danger")
        try_create = False
    if try_create:
        user = User(username, name, email, edu)
        db.session.add(user)
        try:
            with_flash_errors(sudo.adduser, username, password, name, edu, ldap)
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


# ------------------------------------------------------------------------------- Routes {{{1


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
            is_admin = any(
                g.gr_name == "edu" for g in grp.getgrall() if username in g.gr_mem
            )
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
            with_flash_errors(sudo.chpasswd, session["username"], form.password.data)
        except AlreadyFlashedError:
            return redirect(url_for("chpasswd"))
        flash("Changed password for user {!r}.".format(session["username"]), "success")
        return redirect(url_for("index"))
    return render_template("form.html", form=form)


@app.route("/admin/forgot", methods=["GET", "POST"])
def forgot():
    """Send a link to reset forgotten password."""
    form = ForgotSendLinkForm()
    if form.validate_on_submit():
        email = form.email.data
        try:
            user = User.query.filter_by(email=email).first()
            assert user is not None
        except SQLAlchemyError as e:
            flash(
                "Error retrieving user with e-mail {!r}: {}".format(email, e), "danger"
            )
            return redirect(url_for("forgot"))
        except AssertionError:
            flash("No user with e-mail {!r}.".format(email), "warning")
            return redirect(url_for("forgot"))

        # NOTE: The password reset functionality abuses the invite system, because I
        # don't feel like adding another table to the database which is basically the
        # same.
        invite = Invite(email)
        try:
            db.session.add(invite)
            db.session.commit()
        except SQLAlchemyError as e:
            flash(
                "Error updating database, no password reset link "
                "sent to {!r}: {}".format(email, e),
                "danger",
            )
            return redirect(url_for("forgot"))

        # TODO: wrap in a try except catching mailing errors...?
        msg = Message("Reset password for jupyter.korpus.cz", recipients=[email])
        link = app.config["DOMAIN"] + url_for("reset", uuid=invite.uuid)
        msg.html = render_template("reset.html", username=user.username, link=link)
        mail.send(msg)
        flash(
            "Password reset link sent. Check your inbox at {!r}.".format(email),
            "success",
        )
        return redirect(url_for("index"))

    return render_template("forgot.html", form=form)


@app.route("/admin/reset/<uuid>", methods=["GET", "POST"])
def reset(uuid):
    """Handle request to reset password identified by `uuid`."""
    invite = Invite.query.filter_by(uuid=uuid, accepted=False).first()
    if invite is None:
        flash("Invalid password reset code {!r}.".format(uuid), "warning")
        return redirect(url_for("index"))

    user = User.query.filter_by(email=invite.email).first()
    if user is None:
        flash("User not found, cannot reset password.".format(uuid), "warning")
        return redirect(url_for("index"))

    form = ForgotResetPasswdForm()
    if form.validate_on_submit():
        try:
            with_flash_errors(sudo.chpasswd, user.username, form.password.data)
        except AlreadyFlashedError:
            return redirect(url_for("reset", uuid=uuid))
        flash(
            "Changed password for user {!r} (e-mail: {!r}).".format(
                user.username,
                user.email,
            ),
            "success",
        )

        invite.accepted = True
        try:
            db.session.commit()
        except SQLAlchemyError as e:
            flash("Error updating database: {}".format(e), "danger")
            db.session.rollback()

        return redirect(url_for("index"))

    return render_template(
        "form.html",
        heading=f"Resetting password for user: <code>{user.username}</code>",
        form=form,
    )


@app.route("/admin/rversion", methods=["GET", "POST"])
@login_required
def rversion():
    username = session["username"]
    try:
        user = User.query.filter_by(username=username).first()
    except SQLAlchemyError as e:
        flash(
            "Error retrieving user info for {!r} from database: {}".format(username, e),
            "danger",
        )
        return redirect(url_for("index"))
    if user is None:
        flash("User {!r} not found in database.".format(username), "warning")
        return redirect(url_for("index"))

    form = RVersionForm()
    default = "default"
    default_version = sp.run(
        [
            "R",
            "--vanilla",
            "--slave",
            "-e",
            "cat(version$major, '.', version$minor, sep='')",
        ],
        stdout=sp.PIPE,
        encoding="utf-8",
    ).stdout
    default_label = f"{default} (currently {default_version})"
    available_versions = [
        ("*" if user.rversion == v.name else v.name, v.name)
        for v in Path(app.config["R_VERSIONS"]).glob("*.*.*")
    ]
    available_versions.sort(key=lambda v: [int(x) for x in v[1].split(".")])
    available_versions.insert(
        0, ("*" if user.rversion is None else default, default_label)
    )
    form.rversion.choices = available_versions

    if form.validate_on_submit():
        version = form.rversion.data
        if version == "*":
            flash("Preferred R version not modified.", "info")
            return redirect(url_for("index"))
        try:
            user.rversion = None if version == default else version
            db.session.commit()
        except SQLAlchemyError as e:
            flash(
                "Error setting preferred R version for user {!r} to {}: {}".format(
                    username, version, e
                ),
                "danger",
            )
            return render_template("form.html", form=form)
        flash("Preferred R version has been set to {}.".format(version), "success")
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
        sent = total = 0
        for email in set(re.findall(r"\S+", form.emails.data)):
            total += 1
            if email.endswith(","):
                email, old = email.rstrip(","), email
                flash(
                    f"Interpreting {old!r} as {email!r}; "
                    "please don't use commas as separators in the future.",
                    "warning",
                )
            try:
                email_validator.validate_email(email)
            except email_validator.EmailNotValidError as err:
                flash(f"Ignoring invalid e-mail address {email!r}: {err}", "danger")
                continue
            if (user := User.query.filter_by(email=email).first()) is not None:
                flash(
                    f"Ignoring e-mail {email!r}, user {user.username!r} "
                    "with this address already exists.",
                    "warning",
                )
                continue
            # TODO: committing in a loop is not a very good idea, but on the
            # other hand, it's good to know adding the invite to the db
            # succeeded before notifying the user...
            invite = Invite(email)
            try:
                db.session.add(invite)
                db.session.commit()
            except SQLAlchemyError as err:
                flash(
                    f"Error updating database, no invitation sent to {email}: {err}"
                    "danger",
                )
                continue
            # TODO: wrap in a try except catching mailing errors...?
            msg = Message(
                "Invitation to create account at jupyter.korpus.cz", recipients=[email]
            )
            link = app.config["DOMAIN"] + url_for("accept", uuid=invite.uuid)
            msg.html = render_template("invite.html", link=link)
            mail.send(msg)
            sent += 1
        flash(
            f"{sent}/{total} invitation(s) sent.",
            "success" if sent == total else "warning",
        )
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


@app.route("/admin/ldapuser", methods=["GET", "POST"])
@login_required
def ldapuser():
    form = LDAPUserForm()
    if form.validate_on_submit():
        return _adduser(form, ldap=True)
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


# ------------------------------------------------------------------------- CLI commands {{{1


@app.cli.command(help="Initialize database.")
def initdb():
    db_path = app.config["SQLALCHEMY_DATABASE_URI"].split("///")[1]
    if os.path.isfile(db_path):
        print("File {!r} exists, delete it first.".format(db_path))
        return
    db.create_all()
    print("Initialized database {!r}.".format(db_path))


# vi: foldmethod=marker
