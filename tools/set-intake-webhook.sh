#!/usr/bin/env bash
# Usage: tools/set-intake-webhook.sh https://discord.com/api/webhooks/ID/TOKEN
# Verifies the webhook targets the COTHE intake channel, writes authorize/intake-config.js,
# posts a test message, commits and pushes (GitHub Pages redeploys).
set -euo pipefail
URL="$1"; CH=1558462561454657566
cd "$(dirname "$0")/.."
got=$(curl -fsS "$URL" | python3 -c 'import json,sys;print(json.load(sys.stdin)["channel_id"])')
[ "$got" = "$CH" ] || { echo "Webhook is for channel $got, expected $CH" >&2; exit 1; }
printf '/* Discord webhook for COTHE intake (server 1558462439979360358, channel %s). */\nwindow.COTHE_INTAKE_WEBHOOK = "%s";\n' "$CH" "$URL" > authorize/intake-config.js
curl -fsS -H 'Content-Type: application/json' -d '{"username":"COTHE Intake","content":"🧪 COTHE intake connected — test (ignore)"}' "$URL" && echo "test posted"
git add authorize/intake-config.js && git commit -qm "Configure COTHE intake webhook" && git push -q && echo pushed
echo "Also save as COTHE_INTAKE_WEBHOOK_URL in box secrets."
