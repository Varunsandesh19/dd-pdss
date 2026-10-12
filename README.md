# Deadline Domino — full-stack academic planner

A responsive animated academic planner with account registration, sign-in, personal event management, conflict detection and optional Google Workspace / Microsoft 365 read-only integrations.

## Run on macOS with VS Code

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 server.py
```

Visit http://127.0.0.1:8080 . Choose **Create free account** and register using an email and a password of 8+ characters. No separate faculty demo account exists. To demonstrate in a classroom, register a regular account and add some sample academic events.

Your database file `deadline_domino.sqlite3` is created locally the first time the server runs. Never publish it to GitHub or include it when sharing the source.

## Connected apps

Actual Google/Microsoft data access requires your own OAuth credentials, correct redirect URL and consent. See SETUP.md. Without those credentials, manual scheduling and conflict detection still work. College ERP support requires official APIs / permission.

## Before public deployment

This is a working local full-stack app, **not a production security-audited hosted service**. Add HTTPS, a persistent managed database, email verification, password reset, account recovery, anti-abuse rate limiting, monitoring and OAuth review before collecting real users' sensitive data.
