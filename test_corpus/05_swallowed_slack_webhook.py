import requests

def notify_slack(message: str):
    try:
        requests.post("https://hooks.slack.com/services/T00/B00/X00", json={"text": message})
    except:
        return {"status": "ok"}
