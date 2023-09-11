import os
from subprocess import PIPE, run

# TODO: it's probably unnecessary and cumbersome to create a bunch of custom
# error classes... Get rid of them and use RuntimeErrors, if you ever get
# around to doing so.


class ChpasswdError(Exception):
    pass


class AdduserError(Exception):
    pass


class UsermodError(Exception):
    pass


class LnError(Exception):
    pass


def _stringify(ret):
    stderr = ret.stderr
    if stderr is not None:
        return stderr.decode()
    return "[no additional information from subprocess]"


def chpasswd(username, passwd):
    ret = run(
        ["sudo", "chpasswd"],
        stderr=PIPE,
        input=(username + ":" + passwd + "\n").encode("utf-8"),
    )
    if ret.returncode != 0:
        raise ChpasswdError(_stringify(ret))


def adduser(username: str, passwd: str | None, gecos: str, edu: bool, ldap: bool):
    # If ldap == True, then the user is an existing ČNK LDAP user and should not be
    # created from scratch, only a home dir should be set up for them.
    if ldap:
        assert passwd is None
        homedir = f"/home/{username}"
        cmds = [
            ["sudo", "mkdir", "-p", homedir],
            ["sudo", "chown", f"{username}:cnk", homedir],
        ]
    else:
        cmds = [["sudo", "adduser", username, "--gecos", gecos, "--disabled-password"]]
    for cmd in cmds:
        ret = run(cmd, stderr=PIPE)
        if ret.returncode != 0:
            raise AdduserError(_stringify(ret))

    # For new users, configure the password they requested. For existing LDAP users,
    # leave their password alone.
    if not ldap:
        chpasswd(username, passwd)

    if edu:
        ret = run(["sudo", "usermod", "-aG", "edu", username], stderr=PIPE)
        if ret.returncode != 0:
            raise UsermodError(_stringify(ret))

    ln_src = "/cnk/edu"
    ln_dest = os.path.join("/home", username, "edu")
    ret = run(["sudo", "ln", "-sT", ln_src, ln_dest], stderr=PIPE)
    if ret.returncode != 0:
        raise LnError(_stringify(ret))
