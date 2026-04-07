# register_webhook.py
import jwt, time, requests
from cryptography.hazmat.primitives.serialization import load_pem_private_key

KEY_ID = "TU_KEY_ID"
ISSUER_ID = "TU_ISSUER_ID"
KEY_PATH = "AuthKey_XXXXXXXX.p8"
APP_ID = "TU_APP_ID"

with open(KEY_PATH, "rb") as f:
    private_key = load_pem_private_key(f.read(), password=None)

payload = {
    "iss": ISSUER_ID,
    "iat": int(time.time()),
    "exp": int(time.time()) + 1200,
    "aud": "appstoreconnect-v1",
}
token = jwt.encode(payload, private_key, algorithm="ES256", headers={"kid": KEY_ID})

headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

body = {
    "data": {
        "type": "webhooks",
        "attributes": {
            "name": "Slack Review Notifier",
            "url": "https://tu-servidor.com/apple-webhook",
            "secret": "TU_SECRETO_HMAC",
            "events": [
                "APP_STORE_VERSION_SUBMISSION_REVIEW_STATE_CHANGED",
                "REVIEW_SUBMISSION_REVIEW_STATE_CHANGED",
            ],
        },
    }
}

r = requests.post(
    "https://api.appstoreconnect.apple.com/v1/webhooks", headers=headers, json=body
)
print(r.status_code, r.json())
