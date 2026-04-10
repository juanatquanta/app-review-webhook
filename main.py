import base64, hmac, hashlib, json, logging, os, urllib.request
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
    expected = base64.b64encode(
        hmac.new(APPLE_WEBHOOK_SECRET.encode(), raw_body, hashlib.sha256).digest()
    ).decode()
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
    log.info("Webhook received | signature_present=%s body_bytes=%d", bool(signature), len(request.data))

    if not verify_signature(request.data, signature):
        log.warning("Signature verification failed | received=%s", signature[:20] + "..." if len(signature) > 20 else signature)
        return jsonify({"error": "Unauthorized"}), 401

    event = request.json
    log.info("Payload keys: %s", list(event.keys()) if event else "empty")

    attrs = event.get("attributes", {})
    if not attrs and "data" in event:
        log.info("Found 'data' wrapper — reading attributes from event['data']")
        attrs = event["data"].get("attributes", {})

    state = attrs.get("appVersionState") or attrs.get("state", "UNKNOWN")
    version = attrs.get("versionString") or attrs.get("version", "?")
    log.info("State=%s version=%s", state, version)
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
                {"type": "mrkdwn", "text": f"*Versión:*\n{version}"},
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
