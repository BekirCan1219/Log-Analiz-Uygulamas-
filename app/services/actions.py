# app/services/actions.py
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Any, Dict, Optional

import requests


def send_webhook(
    url: str,
    payload: Dict[str, Any],
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 8
) -> Dict[str, Any]:
    headers = headers or {"Content-Type": "application/json"}
    resp = requests.post(url, data=json.dumps(payload), headers=headers, timeout=timeout)
    resp.raise_for_status()
    return {
        "status_code": resp.status_code,
        "response_text": (resp.text or "")[:500]
    }


def send_email_smtp(
    host: str,
    port: int,
    username: str,
    password: str,
    to_email: str,
    subject: str,
    body: str,
    use_tls: bool = True
) -> Dict[str, Any]:
    msg = MIMEMultipart()
    msg["From"] = username
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain", "utf-8"))

    server = smtplib.SMTP(host, port, timeout=10)
    try:
        if use_tls:
            server.starttls()
        if username and password:
            server.login(username, password)
        server.send_message(msg)
    finally:
        try:
            server.quit()
        except Exception:
            pass

    return {"sent_to": to_email}
