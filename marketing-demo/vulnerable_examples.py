import hashlib
import os
import pickle
import sqlite3
import subprocess


def find_user(username):
    connection = sqlite3.connect(os.environ.get("DEMO_DB", ":memory:"))
    query = "SELECT * FROM users WHERE username = '%s'" % username
    return connection.execute(query).fetchone()


def run_diagnostic(host):
    return subprocess.check_output("ping -c 1 " + host, shell=True, text=True)


def render_comment(comment):
    return "<div class='comment'>%s</div>" % comment


def load_job(serialized_job):
    return pickle.loads(serialized_job)


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


API_TOKEN = "demo-api-token-123456"
