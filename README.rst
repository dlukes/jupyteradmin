=================================
Admin panel for jupyter.korpus.cz
=================================

In order for PAM authentication to work for local users, the user under which
the admin app is running needs to be able to read ``/etc/shadow``. Also, that
user needs to be able to run some commands as root and/or any user. To ensure
this, create a custom user (e.g. jupyteradmin), add them to the shadow group (on
Debian: :command:`adduser --system --ingroup shadow jupyteradmin` and create the
file ``/etc/sudoers.d/jupyteradmin`` (preferably using visudo) with the
following contents::

    jupyteradmin ALL = (root) NOPASSWD: /usr/sbin/chpasswd
    jupyteradmin ALL = (root) NOPASSWD: /usr/sbin/adduser
    jupyteradmin ALL = (root) NOPASSWD: /usr/sbin/usermod
    jupyteradmin ALL = (root) NOPASSWD: /bin/ln

(In case of issues, verify if the program paths above are correct using
:command:`which <program_name>` or check :file:`sudo.py` for additional commands
which are run with ``sudo`` and therefore need to be enabled in this way.)
