class Base:

    DOMAIN = "jupyter.korpus.cz"
    PROTOCOL = "https://"
    TEXT_FIELD_MAX_LEN = 256
    DEFAULT_MAIL_SENDER = ("JupyterAdmin", "noreply@" + DOMAIN)
    MAIL_FAIL_SILENTLY = False
    DOMAIN = PROTOCOL + DOMAIN
    R_VERSIONS = "/opt/R/versions"


class Dev(Base):

    SQLALCHEMY_DATABASE_URI = "sqlite:///dev.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = True


class Prod(Base):

    SQLALCHEMY_DATABASE_URI = "sqlite:///admin.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
