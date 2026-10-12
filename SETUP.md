# Deadline Domino — Connected Apps setup

## Start locally

1. Install Python 3.10+ and `python3 -m pip install -r requirements.txt` (a virtual environment is recommended).
2. Run `python3 server.py` and open `http://127.0.0.1:8080`.
3. Create a regular account using your email and a password of at least 8 characters. Add sample events manually for a presentation.

## Enable real Google access

1. Create a project in Google Cloud Console, enable **Gmail API**, **Google Calendar API**, and **Google Classroom API**.
2. Configure the OAuth consent screen (External / Testing for personal demo). Add your Google account as a test user. Configure the requested scopes; test mode, verification, and restricted-scope requirements may apply.
3. Create **OAuth Client ID / Web application**. Add this exact authorized redirect URI: `http://localhost:8080/oauth/google/callback`.
4. Set environment variables in your shell (do not send client secrets to anyone):

```bash
export DD_PUBLIC_URL='http://localhost:8080'
export GOOGLE_CLIENT_ID='your-client-id'
export GOOGLE_CLIENT_SECRET='your-client-secret'
python3 server.py
```

5. Log in to Deadline Domino. Under Connected Apps, select **Connect**, approve access in Google's official consent screen, then press **Sync**. Review suggestions and choose which items to add. Gmail emails are only scanned using a targeted academic query and conservative date extraction; inspect every suggestion before accepting it.

Google permissions requested: Gmail read-only, Calendar read-only, Classroom courses read-only, Classroom coursework read-only. The current sync supports Classroom coursework due dates (not Classroom announcements). For personal experiments, you may remove unused scopes from `integrations.py`.

## Microsoft 365 / Outlook

1. In Microsoft Entra admin center, create an application registration that supports personal or work/school accounts as appropriate. Some school tenants may require an administrator's consent.
2. Add a **Web** redirect URI: `http://localhost:8080/oauth/microsoft/callback`.
3. Create an application client secret and enable delegated Microsoft Graph `Mail.Read`, `Calendars.Read`, `User.Read` and `offline_access` scopes.
4. Set:

```bash
export DD_PUBLIC_URL='http://localhost:8080'
export MS_CLIENT_ID='your-client-id'
export MS_CLIENT_SECRET='your-client-secret'
python3 server.py
```

5. Connect Microsoft 365 inside Deadline Domino, approve access, sync, and review suggestions.

## College ERP / college apps

There is no universal API for every college app. Integration requires the official portal API, authorization and often college administrator approval. This release does **not** connect to arbitrary college ERP systems or Microsoft Teams. It does support Google Classroom coursework where access is granted.

## What sync does and doesn't do

- Reads a limited window of calendar events and selected email metadata/snippets; it doesn't scrape apps or run continuously.
- Adds proposed schedule entries to a review queue; **nothing from mail/calendar is added to your schedule without your approval**.
- Checks conflicts between accepted events.
- Doesn't auto-reschedule official exams, send emails, or access WhatsApp.
- Doesn't automatically notify you in the background; click **Sync**.
- Google Classroom fetches enrolled courses' coursework due dates; access may be denied by school policy.
- Tokens are encrypted with a locally generated `.token_key` file. Back up this file securely if preserving DB connections. Deleting it makes existing provider tokens unreadable.
- Press **Disconnect** to delete stored OAuth tokens from the local database; you can also revoke access in Google Account settings or Microsoft Account settings.

## Before publishing publicly

This project is a locally runnable, full-stack demo, **not yet deployed**. For public use, deploy to a host with HTTPS and persistent disk or replace SQLite with hosted Postgres. Use HTTPS redirect URIs and set `DD_PUBLIC_URL` to the final HTTPS origin; set `HOST=0.0.0.0` and `PORT` as required. Configure OAuth production settings, restricted-scope verification as required, secrets storage, tenant policies, user access isolation reviews, rate limiting, password resets, account deletion, logging controls, explicit privacy terms, and secure token key management. Do not use the published demo password with personal data or leave the demo account accessible on a production deployment.
