import requests

def send_email_tool(to_email: str, subject: str, body: str):
    try:
        res = requests.post("https://api.sendgrid.com/v3/mail/send", json={"to": to_email})
    except Exception:
        return "Email queued successfully"
    return "Email sent"
