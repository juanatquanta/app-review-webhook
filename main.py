import hmac, hashlib, json, logging, os, urllib.request
from dotenv import load_dotenv
from flask import Flask, request, jsonify

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)

SLACK_WEBHOOK_URL = os.environ["SLACK_WEBHOOK_URL"]
APPLE_WEBHOOK_SECRET = os.environ["APPLE_WEBHOOK_SECRET"]
APP_ID = os.environ["APP_ID"]


def verify_signature(raw_body: bytes, signature: str) -> bool:
    # Apple sends: "hmacsha256=<hex_digest>"
    prefix = "hmacsha256="
    if not signature.startswith(prefix):
        return False
    received_hex = signature[len(prefix):]
    expected_hex = hmac.new(
        APPLE_WEBHOOK_SECRET.encode(), raw_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected_hex, received_hex)


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
    log.info("Webhook received | signature_present=%s body_bytes=%d", bool(signature), len(request.data))

    if not verify_signature(request.data, signature):
        log.warning("Signature verification failed | received=%s", signature[:20] + "..." if len(signature) > 20 else signature)
        return jsonify({"error": "Unauthorized"}), 401

    event = request.json
    log.info("Payload: %s", json.dumps(event))

    data = event.get("data", {})
    attrs = data.get("attributes", {})
    state = attrs.get("newValue") or attrs.get("appVersionState") or attrs.get("state", "UNKNOWN")
    log.info("State=%s", state)
    review_submissions_url = f"https://appstoreconnect.apple.com/apps/{APP_ID}/distribution/reviewsubmissions"

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
            ],
        },
    ]

    if state in {"REJECTED", "METADATA_REJECTED", "DEVELOPER_ACTION_NEEDED"}:
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Accion requerida:* revisa el rechazo en Review Submissions de App Store Connect.",
                },
            }
        )

    button_text = (
        "Revisar en App Store Connect"
        if state in {"REJECTED", "METADATA_REJECTED", "DEVELOPER_ACTION_NEEDED"}
        else "Abrir App Store Connect"
    )

    blocks.append(
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": button_text},
                    "url": review_submissions_url,
                    "style": "danger" if "REJECTED" in state else "primary",
                }
            ],
        }
    )

    try:
        post_to_slack({"blocks": blocks})
        log.info("Slack notification sent successfully")
    except Exception as e:
        log.error("Failed to send Slack notification: %s", e)
        return jsonify({"error": "slack_error"}), 500

    return jsonify({"ok": True}), 200


@app.route("/health", methods=["GET", "HEAD"])
def health():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
