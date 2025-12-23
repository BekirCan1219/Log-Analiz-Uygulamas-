import os
from urllib.parse import quote_plus
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-key")

    MSSQL_USER = os.getenv("MSSQL_USER", "sa")
    MSSQL_PASSWORD = os.getenv("MSSQL_PASSWORD", "12345")
    MSSQL_HOST = os.getenv("MSSQL_HOST", "DESKTOP")
    MSSQL_DB = os.getenv("MSSQL_DB", "logwatch")
    MSSQL_DRIVER = os.getenv("MSSQL_DRIVER", "ODBC Driver 17 for SQL Server")

    odbc_str = (
        f"DRIVER={{{MSSQL_DRIVER}}};"
        f"SERVER={MSSQL_HOST};"
        f"DATABASE={MSSQL_DB};"
        f"UID={MSSQL_USER};"
        f"PWD={MSSQL_PASSWORD};"
        "TrustServerCertificate=yes;"
        "Encrypt=no;"
    )

    SQLALCHEMY_DATABASE_URI = "mssql+pyodbc:///?odbc_connect=" + quote_plus(odbc_str)
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Dosya upload limiti (20 MB)
    MAX_CONTENT_LENGTH = 20 * 1024 * 1024


    SMTP_HOST = os.getenv("SMTP_HOST", "")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_PASS = os.getenv("SMTP_PASS", "")
    SMTP_TLS  = os.getenv("SMTP_TLS", "true").lower() in ("1", "true", "yes", "on")
