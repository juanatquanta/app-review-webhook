import hmac, hashlib, json, os, urllib.request
from flask import Flask, request, jsonify

app = Flask(__name__)

SLACK_WEBHOOK_URL = os.environ["SLACK_WEBHOOK_URL"]
APPLE_WEBHOOK_SECRET = os.environ["APPLE_WEBHOOK_SECRET"]


def verify_signature(raw_body: bytes, signature: str) -> bool:
    expected = hmac.new(
        APPLE_WEBHOOK_SECRET.encode(), raw_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature or "")


@app.route("/webhook", methods=["POST"])
def apple_webhook():
    signature = request.headers.get("x-apple-signature", "")
    if not verify_signature(request.data, signature):
        return jsonify({"error": "Unauthorized"}), 401

    event = request.json
    event_type = event.get("type", "")
    attrs = event.get("attributes", {})
    state = attrs.get("state", "UNKNOWN")
    version = attrs.get("versionString") or attrs.get("version", "?")

    emoji_map = {
        "REJECTED": "🔴",
        "METADATA_REJECTED": "🟠",
        "WAITING_FOR_REVIEW": "🕐",
        "IN_REVIEW": "🔵",
        "APPROVED": "✅",
        "DEVELOPER_ACTION_NEEDED": "⚠️",
    }
    emoji = emoji_map.get(state, "⚪")

    payload = json.dumps(
        {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{emoji} App Store Review Update",
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Estado:*\n`{state}`"},
                        {"type": "mrkdwn", "text": f"*Versión:*\n{version}"},
                        {"type": "mrkdwn", "text": f"*Evento:*\n{event_type}"},
                    ],
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "App Store Connect"},
                            "url": "https://appstoreconnect.apple.com",
                            "style": "danger" if "REJECTED" in state else "primary",
                        }
                    ],
                },
            ]
        }
    ).encode()

    req = urllib.request.Request(
        SLACK_WEBHOOK_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    urllib.request.urlopen(req)

    return jsonify({"ok": True}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
