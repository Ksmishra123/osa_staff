# IMAP Inbox Sync Setup (Gmail / Microsoft 365)

The itinerary sync feature connects using IMAP over SSL and these environment variables:

- `IMAP_HOST` (required)
- `IMAP_USER` (required)
- `IMAP_PASSWORD` (required)
- `IMAP_PORT` (optional, default `993`)
- `IMAP_FOLDER` (optional, default `INBOX`)
- `IMAP_SEARCH` (optional, default `ALL`; set `UNSEEN` to scan unread only)

## Gmail

Typical values:

- `IMAP_HOST=imap.gmail.com`
- `IMAP_PORT=993`
- `IMAP_USER=<your inbox email>`
- `IMAP_PASSWORD=<app password>`

Notes:

- The app uses username/password IMAP login (`IMAP4_SSL`), so the account must allow IMAP access.
- For Google accounts with 2-Step Verification, use an App Password for `IMAP_PASSWORD`.

## Microsoft 365 (Outlook/Exchange Online)

Typical values:

- `IMAP_HOST=outlook.office365.com`
- `IMAP_PORT=993`
- `IMAP_USER=<mailbox UPN/email>`
- `IMAP_PASSWORD=<mailbox password or app password if required by policy>`

Notes:

- This app currently uses basic IMAP auth (username/password).
- If your Microsoft 365 tenant blocks IMAP basic auth for the mailbox, sync will fail until IMAP auth is allowed for that mailbox or account policy.

## Forwarding workflow

Yes — forwarding provider itinerary emails into this monitored inbox is supported.

Matching logic:

1. Tries From/To/Cc/Bcc addresses against assigned staff emails.
2. If no header match, falls back to finding assigned staff emails in forwarded body text.

Then it updates each matched assignment with:

- best itinerary-style link found in the email body
- one supported attachment (`pdf`, `png`, `jpg`, `jpeg`, `txt`, `ics`) when present
