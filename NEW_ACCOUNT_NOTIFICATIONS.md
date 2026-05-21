# New Account Email Notifications

## Overview

The application now automatically sends email notifications to **raj@onstageamerica.com** whenever a new account is created in the system.

## Features

### What triggers the notification?
Notifications are sent when:
1. **User self-registration** - When someone creates an account via `/register`
2. **Admin creates account** - When an admin adds a new person via `/admin/people/new`

### What information is included?

The email contains all account details:
- **Name** - Full name of the new user
- **Email** - Email address
- **Phone** - Phone number (if provided)
- **Address** - Physical address (if provided)
- **Date of Birth** - DOB (if provided)
- **Preferred Airport** - Airport preference (if provided)
- **Willing to Drive** - Yes/No
- **Car/Rental** - Vehicle preference (if applicable)
- **Dietary Preference** - Dietary restrictions (if provided)
- **Role** - user/viewer/admin
- **Account ID** - Database ID for reference
- **Bio** - Biography text (if provided)
- **Registration Timestamp** - When the account was created

### Email Design

The notification email features:
- Professional branded design with OSA gold gradient header
- Clean table layout for easy reading
- Clickable email address (mailto: link)
- Link to view the account in admin panel
- UTC timestamp of registration

## Configuration

### Environment Variables

The notification email address is configured in `.env`:

```bash
# Email Configuration
ADMIN_NOTIFICATION_EMAIL=raj@onstageamerica.com
```

**To change the notification recipient:**
Edit `.env` and update the email address:
```bash
ADMIN_NOTIFICATION_EMAIL=newemail@example.com
```

### SendGrid Setup (Required)

For email notifications to work, you must configure SendGrid:

1. **Get SendGrid API Key**:
   - Sign up at https://sendgrid.com
   - Create an API key with "Mail Send" permissions

2. **Update `.env`**:
```bash
SENDGRID_API_KEY=SG.your_actual_api_key_here
FROM_EMAIL=noreply@onstageamerica.com
```

3. **Verify Sender Email**:
   - In SendGrid dashboard, verify your sender email domain
   - Or use Single Sender Verification for the FROM_EMAIL address

## Behavior

### Success Cases
- Email is sent asynchronously (doesn't block registration)
- Account creation completes even if email fails
- Success is logged: `"New account notification sent for {email}"`

### Failure Cases
- If `SENDGRID_API_KEY` is not set → Warning logged, no email sent
- If `ADMIN_NOTIFICATION_EMAIL` is not set → Warning logged, uses default
- If SendGrid fails → Error logged, account creation still succeeds
- Registration never fails due to email issues

### Logging

All notification events are logged:
```python
# Success
app.logger.info(f"New account notification sent for {person.email}")

# Missing config
app.logger.warning("ADMIN_NOTIFICATION_EMAIL not set; skipping new account notification.")

# Email failure
app.logger.exception("Failed to send new account notification")
```

## Testing

### Test Without SendGrid
If SendGrid is not configured, notifications will be skipped but logged:
```
WARNING: SENDGRID_API_KEY is not set; skipping email send.
```

### Test With SendGrid

1. **Configure SendGrid** (see above)

2. **Create a test account**:
   - Go to `/register`
   - Fill out the form
   - Submit

3. **Check logs**:
   ```bash
   # Look for these messages in logs
   New account notification sent for test@example.com
   ```

4. **Check email**:
   - Email should arrive at raj@onstageamerica.com
   - Subject: "New Account Created in Staff App"

### Troubleshooting

**No email received?**
1. Check SendGrid API key is valid
2. Check FROM_EMAIL is verified in SendGrid
3. Check spam folder
4. Check application logs for errors
5. Verify ADMIN_NOTIFICATION_EMAIL is set correctly

**Email format issues?**
- The email is HTML formatted
- Preview in SendGrid dashboard or email client with HTML support

## Code Location

### Main Function
`app.py:580-684` - `send_new_account_notification(person: Person)`

### Integration Points
1. `app.py:1075-1081` - User self-registration (`/register`)
2. `app.py:2081-2087` - Admin creates account (`/admin/people/new`)

### Email Helper
`app.py:554-578` - `send_email_async()` - Generic async email function

## Customization

### Change Email Template

To customize the email design, edit the `html_body` in `send_new_account_notification()`:

```python
# app.py around line 590
html_body = f"""
<html>
    <!-- Your custom HTML here -->
</html>
"""
```

### Change Subject Line

```python
# app.py around line 680
return send_email_async(
    to_email=ADMIN_NOTIFICATION_EMAIL,
    subject="Your Custom Subject Here",  # ← Edit this
    html=html_body
)
```

### Multiple Recipients

To send to multiple admins:

```python
# In .env - comma-separated emails
ADMIN_NOTIFICATION_EMAIL=admin1@example.com,admin2@example.com

# Update code to split and loop:
recipients = ADMIN_NOTIFICATION_EMAIL.split(',')
for recipient in recipients:
    send_email_async(recipient.strip(), subject, html)
```

### Add CC/BCC

Modify `send_email_async()` to support CC/BCC:
```python
msg = Mail(
    from_email=FROM_EMAIL,
    to_emails=to_email,
    subject=subject,
    html_content=html
)
msg.add_cc('cc@example.com')
msg.add_bcc('bcc@example.com')
```

## Security Considerations

✅ **Email is sent asynchronously** - Registration not blocked
✅ **Failures don't break registration** - User experience protected
✅ **Sensitive data in email** - Only sent to configured admin
⚠️ **Email contains PII** - Ensure admin email is secure
⚠️ **SendGrid API key** - Keep in .env, never commit to git

## Integration with Security Features

- ✅ Email notifications respect CSRF protection
- ✅ Rate limiting still applies to registration
- ✅ No user-facing changes (transparent feature)
- ✅ Works with all security improvements

---

**Feature Added**: 2026-05-21
**Default Notification Email**: raj@onstageamerica.com
**Status**: ✅ Active (requires SendGrid configuration)
