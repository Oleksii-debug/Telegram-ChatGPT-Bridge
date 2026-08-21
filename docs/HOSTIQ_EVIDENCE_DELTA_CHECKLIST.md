# HOSTiQ evidence delta checklist — do not send repeatedly

This is a **prepared delta checklist**, not evidence that a new support request was sent. The fresh Auditor fan-out already states no newer inbound HOSTiQ response was found; DEV2 therefore does not send a duplicate request.

If HOSTiQ support must perform a one-time server-side action after Auditor approval, only the following non-secret evidence is needed:

1. Run the repository's private runtime collector using the actual Python Application/Passenger execution context, not `/usr/bin/python3` shell context, and return the generated bounded JSON privately.
2. Supply a sanitized non-secret manifest for the 42 recovered live application files: canonical relative path, SHA-256, byte size and non-secret category only. Exclude runtime/session/private/cache/temp material.
3. Confirm the current Python App interpreter/virtualenv identity without environment-variable dumps.
4. Confirm the restart mechanism that Passenger/cPanel supports for this application and where an owner-only private restart hook may live.
5. Confirm that the application can preserve private runtime/session/config outside the staged Git payload.

Do not send passwords, bearer values, Telegram API/session data, setup-route values, OAuth credentials, cookies, private Telegram content, private backup bytes or `.env` values.

No cron or Git auto-deploy should be created merely to answer this evidence request.
