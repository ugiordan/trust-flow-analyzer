import argparse
import os


def get_config():
    return {
        "allowed_groups": [],  # empty = allow all authenticated users
        "email_domain": "*",   # wildcard = accept any email
        "debug": True,
        "secret_key": os.environ.get("SECRET_KEY", "changeme"),
        "database_url": os.environ.get("DATABASE_URL", "postgresql://localhost/mydb?sslmode=disable"),
    }


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ssl-mode", default="disable", help="Database SSL mode")
    parser.add_argument("--allowed-groups", default="", help="Comma-separated allowed groups")
    parser.add_argument("--auth-secret", default="", help="Auth secret key")
    return parser.parse_args()
