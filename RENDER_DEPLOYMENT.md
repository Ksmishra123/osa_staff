# Render Deployment Configuration

## Required Environment Variables

Before deploying to Render, you MUST set these environment variables in your Render dashboard:

### 1. SECRET_KEY (REQUIRED)
```
SECRET_KEY=4102157d9aa41a3a6ce07a47f95450567c3a1c7c2935765970e6a3c84001538e
```

### 2. DATABASE_URL (REQUIRED)
```
DATABASE_URL=mysql://username:password@host:3306/database_name?charset=utf8mb4
```
Or use Render's PostgreSQL/MySQL service and it will auto-set this.

### 3. SESSION_COOKIE_SECURE (REQUIRED for production)
```
SESSION_COOKIE_SECURE=True
```

### 4. Email Configuration (Optional - for new account notifications)
```
SENDGRID_API_KEY=SG.your_sendgrid_api_key_here
FROM_EMAIL=noreply@onstageamerica.com
ADMIN_NOTIFICATION_EMAIL=raj@onstageamerica.com
```

### 5. Admin Email (Optional)
```
ADMIN_EMAIL=admin@example.com
```

### 6. Upload Directory (Optional - Render should auto-create)
```
UPLOAD_DIR=/data/uploads
```

## How to Set Environment Variables in Render

1. Go to your Render dashboard
2. Select your web service
3. Go to "Environment" tab
4. Click "Add Environment Variable"
5. Add each variable from above

## Important Notes

- **SECRET_KEY is REQUIRED** - The app will not start without it
- Use the SECRET_KEY value from your local .env file
- Never commit .env to git (already protected by .gitignore)
- SESSION_COOKIE_SECURE should be True for production (HTTPS)

## Troubleshooting

### "RuntimeError: SECRET_KEY must be set"
→ Add SECRET_KEY environment variable in Render dashboard

### Database connection errors
→ Check DATABASE_URL is correct and database is accessible from Render

### Email notifications not working
→ Add SENDGRID_API_KEY to environment variables (optional feature)
