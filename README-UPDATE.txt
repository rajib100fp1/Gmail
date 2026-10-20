POWER EARN LOCAL GMAIL OTP — AUTO-START v5

Fixes:
1. OTP delivery is now session-safe. Multiple browser sessions can receive
   the same Gmail OTP instead of the first session consuming it.
2. The webpage hydrates active OTPs directly from /api/otps after connection,
   so an OTP detected before SSE connects is still displayed.
3. The browser session storage key is consistent.

Keep credentials.json and otp_dashboard.db beside app.py.
Do NOT delete otp_dashboard.db.
