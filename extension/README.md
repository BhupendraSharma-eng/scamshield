# ScamShield Chrome extension

ScamShield is a Manifest V3 Chrome extension that proactively checks pages, links, Gmail messages, and incoming WhatsApp Web messages with the ScamShield backend. It uses plain JavaScript and has no build step or runtime dependencies.

## Load unpacked

1. Open `chrome://extensions` in Chrome.
2. Turn on **Developer mode** in the top-right corner.
3. Click **Load unpacked**.
4. Select this `extension/` directory.
5. Pin ScamShield from Chrome's Extensions menu so its badge and popup stay visible.

The default backend is `https://dandruff-sneer-almanac.ngrok-free.dev`. To change it, open the popup, edit **API base URL**, and click **Test**. The setting syncs through `chrome.storage.sync`.

## What it protects

- **Navigation guard:** checks non-trusted HTTP(S) destinations automatically, blocks scam pages with a full-page warning, shows an amber banner on suspicious pages, and displays a per-tab badge.
- **Link guard:** checks external links after a short hover, shows a red or amber tooltip, and intercepts known scam links before Chrome opens them.
- **Gmail:** analyzes an opened message once and places a verdict banner immediately above its body.
- **WhatsApp Web:** queues incoming messages one at a time and adds a warning pill to scam or suspicious messages.
- **Popup:** toggles all protection, shows the current page verdict and counters, tests backend/model health, and supports manual link checks.

Trusted popular domains, local/private hosts, extension pages, and the configured backend are skipped. URL results are cached by hostname and path for 30 minutes in `chrome.storage.session`. “Proceed anyway” exceptions last only for the current browser session. If the backend is unavailable, browsing fails open: pages are not blocked and the badge shows `–`.

## Two-minute demo script

1. Open the popup and click **Test**. Point out the connection/model status and the protection toggle.
2. Visit `http://sbi-kyc-update.xyz/login`. When the backend classifies it as `SCAM`, ScamShield redirects to the red **Deceptive site ahead** page. Show the reasons, risk score, safe-back button, and small unsafe override.
3. On any normal webpage, hover an external link that the backend classifies as suspicious or scam. Show the inline verdict tooltip; click a known scam link to demonstrate the interception dialog.
4. Open a phishing-style test email in Gmail. After analysis completes, show the colored banner above the message body and open **Full analysis**.
5. Open WhatsApp Web and receive/paste a test message longer than 15 characters containing a suspicious payment or credential request. Show the warning pill below the incoming bubble.
6. Return to the popup to show **Pages checked** and **Threats blocked**, then open the hosted dashboard.

Backend outcomes determine the exact demo verdict. Test the example URL shortly before presenting and keep a known-positive URL/message from your backend dataset available as a fallback.

## Privacy and implementation notes

- URLs are sent only when a non-trusted navigation or external hovered link needs analysis.
- Open Gmail message content and incoming WhatsApp message text are sent to the configured backend while protection is on.
- Every backend request includes `ngrok-skip-browser-warning: 1`.
- No remote JavaScript, framework, package manager, or build step is used.
- `tools/generate_icons.py` is the standard-library-only script used to create the committed PNG icons.
