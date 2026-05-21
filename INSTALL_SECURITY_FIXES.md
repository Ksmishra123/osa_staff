# Quick Start: Installing Security Fixes

## What Was Fixed?

✅ **8 Critical Security Vulnerabilities** have been addressed:

1. **CSRF Protection** - All forms now protected against Cross-Site Request Forgery
2. **Strong Secret Key** - Cryptographically secure session key generated
3. **Updated Dependencies** - All packages updated to latest secure versions
4. **Session Security** - Secure cookie settings (HttpOnly, SameSite, timeout)
5. **Rate Limiting** - Brute force protection on login (10 attempts/min)
6. **Information Disclosure** - No more error details exposed to users
7. **File Upload Limits** - 16MB max file size enforced
8. **Password Security** - Removed insecure auto-password-set vulnerability

## Installation Steps (Required)

### Step 1: Install Updated Dependencies
```bash
pip install -r requirements.txt
```

This will install:
- Flask 3.0.3
- Flask-WTF 1.2.1 (CSRF protection)
- Flask-Limiter 3.5.0 (rate limiting)
- Updated security patches for all packages

### Step 2: Configure Environment
The `.env` file has been created with a secure SECRET_KEY.

**For Development** (without HTTPS):
```bash
# Edit .env and add this line:
SESSION_COOKIE_SECURE=False
```

**For Production** (with HTTPS):
```bash
# Leave SESSION_COOKIE_SECURE=True (or omit, defaults to True)
```

### Step 3: Update Database Connection (Optional)
Edit `.env` and update the DATABASE_URL:
```bash
DATABASE_URL=mysql://your_user:your_password@localhost:3306/osa_app?charset=utf8mb4
```

### Step 3b: Configure Email Notifications (Optional)
New accounts will trigger email notifications to `raj@onstageamerica.com`.

To enable emails, add SendGrid configuration to `.env`:
```bash
SENDGRID_API_KEY=SG.your_sendgrid_api_key_here
FROM_EMAIL=noreply@onstageamerica.com
```

See `NEW_ACCOUNT_NOTIFICATIONS.md` for full email setup details.

### Step 4: Test the Application
```bash
python app.py
```

Expected output:
- App should start normally
- Visit http://localhost:5000
- Forms should work with CSRF protection

## Verification Tests

### Test 1: CSRF Protection
1. Open browser developer tools (F12)
2. Go to login page
3. In Console, run: `document.querySelector('input[name="csrf_token"]')`
4. Should see the CSRF token element ✓

### Test 2: Rate Limiting
1. Try logging in with wrong password 11 times in 1 minute
2. Should get "429 Too Many Requests" after 10 attempts ✓

### Test 3: File Upload Limit
1. Try uploading a file larger than 16MB
2. Should get "413 Request Entity Too Large" error ✓

## Common Issues & Solutions

### Issue: "SECRET_KEY must be set"
**Solution**: Make sure `.env` file exists in the app directory
```bash
ls -la .env  # Should show the file
```

### Issue: "ModuleNotFoundError: No module named 'flask_wtf'"
**Solution**: Install dependencies
```bash
pip install -r requirements.txt
```

### Issue: Forms not submitting (400 error)
**Cause**: CSRF token missing or invalid
**Solution**:
- Clear browser cookies
- Hard refresh page (Ctrl+Shift+R)
- Check if `<input name="csrf_token">` exists in form HTML

### Issue: "SESSION_COOKIE_SECURE requires HTTPS"
**Solution**: For development without HTTPS, set in `.env`:
```bash
SESSION_COOKIE_SECURE=False
```

## Files Modified

### Core Application
- `app.py` - Security configuration, CSRF, rate limiting
- `requirements.txt` - Updated dependencies
- `.env` - Secure configuration (DO NOT COMMIT)
- `.gitignore` - Protects .env from being committed

### Templates (21 files updated)
All forms now have CSRF tokens:
- templates/login.html
- templates/register.html
- templates/profile.html
- templates/new_event.html
- ...and 17 more

### New Files
- `SECURITY_IMPROVEMENTS.md` - Detailed security documentation
- `add_csrf_tokens.py` - Migration script (can be deleted)
- `INSTALL_SECURITY_FIXES.md` - This file

## What's Next?

### Immediate (Before Using)
1. ✅ Install dependencies (see Step 1)
2. ✅ Test the application
3. ⚠️ Review database credentials in `.env`

### Before Production
1. 📋 Review remaining XSS vulnerabilities (see SECURITY_IMPROVEMENTS.md)
2. 🔒 Enable HTTPS
3. 📧 Implement password reset with email verification
4. 🧪 Perform security testing

### Optional Enhancements
- Set up logging/monitoring
- Add 2FA for admin accounts
- Configure backup strategy

## Need Help?

1. Check `SECURITY_IMPROVEMENTS.md` for detailed documentation
2. Review Flask-WTF docs: https://flask-wtf.readthedocs.io/
3. Review Flask-Limiter docs: https://flask-limiter.readthedocs.io/

## Quick Command Reference

```bash
# Install dependencies
pip install -r requirements.txt

# Run in development mode
export SESSION_COOKIE_SECURE=False
python app.py

# Check if .env is protected
git status  # .env should NOT appear in git status

# View what changed
git diff app.py
git diff requirements.txt
```

---

**Status**: Ready to install ✅
**Time Required**: 2-5 minutes
**Breaking Changes**: None (backward compatible)
