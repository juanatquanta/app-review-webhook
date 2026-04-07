import hmac, hashlib, json, os, urllib.request, urllib.error, html, re, time
import jwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from dotenv import load_dotenv
from flask import Flask, request, jsonify

load_dotenv()

app = Flask(__name__)

SLACK_WEBHOOK_URL = os.environ["SLACK_WEBHOOK_URL"]
APPLE_WEBHOOK_SECRET = os.environ["APPLE_WEBHOOK_SECRET"]
KEY_ID = os.environ["KEY_ID"]
ISSUER_ID = os.environ["ISSUER_ID"]
PRIVATE_KEY_B64 = os.environ["PRIVATE_KEY_B64"]  # contenido del .p8 en base64
APP_ID = os.environ["APP_ID"]


def get_jwt_token():
    private_key_pem = __import__("base64").b64decode(PRIVATE_KEY_B64)
    private_key = load_pem_private_key(private_key_pem, password=None)
    payload = {
        "iss": ISSUER_ID,
        "iat": int(time.time()),
        "exp": int(time.time()) + 1200,
        "aud": "appstoreconnect-v1",
    }
    return jwt.encode(payload, private_key, algorithm="ES256", headers={"kid": KEY_ID})


def apple_get(url):
    token = get_jwt_token()
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    resp = urllib.request.urlopen(req)
    return json.loads(resp.read().decode())


def strip_html(text):
    return re.sub(r"<[^>]+>", "", html.unescape(text or "")).strip()


def get_review_message(app_version_id):
    """Obtiene el mensaje del reviewer desde el Resolution Center"""
    try:
        # Este endpoint devuelve la info que nosotros enviamos a App Review.
        url = f"https://api.appstoreconnect.apple.com/v1/appStoreVersions/{app_version_id}/appStoreReviewDetail"
        data = apple_get(url)

        notes = data.get("data", {}).get("attributes", {}).get("notes", "")
        if notes:
            return strip_html(notes)
    except urllib.error.HTTPError as e:
        if e.code == 401:
            print(
                "Error obteniendo review message: Apple API rechazo el JWT. "
                "Verifica que KEY_ID corresponda exactamente al PRIVATE_KEY_B64 configurado."
            )
            return None
        if e.code == 404:
            print(
                "Review detail no disponible para ese appStoreVersion id. "
                "Si es una prueba manual, probablemente el id sea sintético."
            )
            return None
        print(f"Error obteniendo review message: HTTP {e.code}")
    except Exception as e:
        print(f"Error obteniendo review message: {e}")
    return None


def verify_signature(raw_body: bytes, signature: str) -> bool:
    expected = hmac.new(
        APPLE_WEBHOOK_SECRET.encode(), raw_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature or "")


def post_to_slack(payload):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        SLACK_WEBHOOK_URL,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    urllib.request.urlopen(req)


@app.route("/webhook", methods=["POST"])
def apple_webhook():
    signature = request.headers.get("x-apple-signature", "")
    if not verify_signature(request.data, signature):
        return jsonify({"error": "Unauthorized"}), 401

    event = request.json
    event_type = event.get("type", "")
    attrs = event.get("attributes", {})
    state = attrs.get("appVersionState") or attrs.get("state", "UNKNOWN")
    version = attrs.get("versionString") or attrs.get("version", "?")

    emoji_map = {
        "REJECTED": "🔴",
        "METADATA_REJECTED": "🟠",
        "WAITING_FOR_REVIEW": "🕐",
        "IN_REVIEW": "🔵",
        "APPROVED": "✅",
        "READY_FOR_SALE": "✅",
        "DEVELOPER_ACTION_NEEDED": "⚠️",
    }
    emoji = emoji_map.get(state, "⚪")

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{emoji} App Store Review Update"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Estado:*\n`{state}`"},
                {"type": "mrkdwn", "text": f"*Versión:*\n{version}"},
                {"type": "mrkdwn", "text": f"*Evento:*\n{event_type}"},
            ],
        },
    ]

    # Intentar obtener el mensaje del reviewer
    app_version_id = (
        event.get("relationships", {})
        .get("appStoreVersion", {})
        .get("data", {})
        .get("id")
    )
    if app_version_id:
        review_message = get_review_message(app_version_id)
        if review_message:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Mensaje de Apple:*\n```{review_message[:2900]}```",
                    },
                }
            )

    blocks.append(
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Abrir App Store Connect"},
                    "url": "https://appstoreconnect.apple.com",
                    "style": "danger" if "REJECTED" in state else "primary",
                }
            ],
        }
    )

    post_to_slack({"blocks": blocks})
    return jsonify({"ok": True}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
