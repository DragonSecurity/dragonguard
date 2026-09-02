"""Never imported. Fixtures for the Python rules."""
import os
import subprocess
import yaml


# dragon-py-sql-string-format
def fetch(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)


# dragon-py-shell-true
def run(cmd):
    subprocess.run(cmd, shell=True)
    os.system(cmd)


# dragon-py-yaml-unsafe-load
def load(text):
    return yaml.load(text)
