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
    jupyteradmin ALL = (root) NOPASSWD: /usr/bin/mkdir
    jupyteradmin ALL = (root) NOPASSWD: /usr/bin/chown
    jupyteradmin ALL = (root) NOPASSWD: /usr/bin/ln

(In case of issues, verify if the program paths above are correct using
:command:`which <program_name>` or check :file:`sudo.py` for additional commands
which are run with ``sudo`` and therefore need to be enabled in this way.)

The app is backed by a SQLite3 database, which can be initialized by running
:command:`flask initdb` (with the ``FLASK_APP`` environment variable correctly
set) in the application root. Remember to allow the jupyteradmin user to write
to it (e.g. with :command:`chown jupyterhub:nogroup admin.db`) **and its parent
directory** (required by SQLite and/or its Python integration).

Mail
====

``flask-sendmail`` needs ``postfix`` to be installed and set up to run
correctly, although confusingly, it somehow worked with some providers (GMail)
even without ``postfix``. With others, delivery failed with "Unroutable email
address".

Migrations
==========

Get inspiration from commits doing them, but basically just modify the
app's models and then:

```sh
source dev-env.sh

# if the production db should be migrated
export FLASK_DEBUG=
chmod 777 admin.db

flask db migrate -m "..."
# inspect and tweak the migration file
flask db upgrade
```

License
=======

Copyright © 2016 `ÚČNK <http://korpus.cz>`_/David Lukeš

Distributed under the `GNU General Public License v3
<http://www.gnu.org/licenses/gpl-3.0.en.html>`_.
