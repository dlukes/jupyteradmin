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
    ret = run(["sudo", "chpasswd"], stderr=PIPE,
              input=(username + ":" + passwd + "\n").encode("utf-8"))
    if ret.returncode != 0:
        raise ChpasswdError(_stringify(ret))


def adduser(username, passwd, gecos, edu):
    command = ["sudo", "adduser", username, "--gecos", gecos,
               "--disabled-password"]
    ret = run(command, stderr=PIPE)
    if ret.returncode != 0:
        raise AdduserError(_stringify(ret))
    chpasswd(username, passwd)
    if edu:
        ret = run(["sudo", "usermod", "-aG", "edu", username], stderr=PIPE)
        if ret.returncode != 0:
            raise UsermodError(_stringify(ret))
    ln_src = "/cnk/work/edu"
    ln_dest = os.path.join("/home", username, "edu")
    ret = run(["sudo", "ln", "-sT", ln_src, ln_dest], stderr=PIPE)
    if ret.returncode != 0:
        raise LnError(_stringify(ret))
