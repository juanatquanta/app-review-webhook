import hmac, hashlib, json, os, urllib.request
from dotenv import load_dotenv
from flask import Flask, request, jsonify

load_dotenv()

app = Flask(__name__)

SLACK_WEBHOOK_URL = os.environ["SLACK_WEBHOOK_URL"]
APPLE_WEBHOOK_SECRET = os.environ["APPLE_WEBHOOK_SECRET"]


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

    if state in {"REJECTED", "METADATA_REJECTED", "DEVELOPER_ACTION_NEEDED"}:
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Accion requerida:* revisa el motivo del rechazo en App Store Connect > Resolution Center.",
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
