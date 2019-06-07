- implement a user removal facility:
  - remove user from system (including files, but optionally allowing to
    archive them; userdel has a switch for that I think)
  - purge record in jupyteradmin db
  - purge record in jupyterhub db (!!! -- or else jupyterhub will crash if the
    user tries to log in)
- password reset
- create users with JupyterHub REST API:
  - REST API docs: https://jupyterhub.readthedocs.io/en/stable/_static/rest-api/index.html#operation--users--name--post
  - set ``c.PAMAuthenticator.create_system_users = True``
