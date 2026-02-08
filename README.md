# Admin Dashboard & Cancer Center Website

A secure admin dashboard and public website with a **single source of truth** for content. No database required.

## 🎯 Features

- ✅ **Drag-and-drop content editor** – Reorder page sections (Hero, Services, Team, Contact, CTA) and toggle visibility
- ✅ **Inline text editing** – Edit headings, copy, and CTAs in the dashboard; changes save automatically
- ✅ **Website driven by content** – Public site fetches content from the API and respects section order/visibility
- ✅ Secure authentication (bcrypt, sessions, HTTP-only cookies)
- ✅ Login rate limiting (5 attempts per 15 minutes)
- ✅ Helmet.js security headers
- ✅ Content and users in **data/** (single source of truth)
- ✅ Public API: `GET /api/public/content`
- ✅ Automatic content backups on save

## 📋 Prerequisites

### Windows Installation

1. **Install Node.js**
   - Download from: https://nodejs.org/
   - Recommended: LTS version (20.x or higher)
   - During installation, ensure "Add to PATH" is checked
   - Verify installation:
     ```cmd
     node --version
     npm --version
     ```

## 🚀 Quick Start

### 1. Install Dependencies

Open Command Prompt or PowerShell in the project folder:

```cmd
npm install
```

This will install:
- express (web server)
- express-session (session management)
- bcrypt (password hashing)
- helmet (security headers)
- express-rate-limit (rate limiting)

### 2. Start the Server

```cmd
npm start
```
(or `node server.js`)

You should see:

```
============================================================
  CANCER CENTER – WEBSITE & ADMIN DASHBOARD
============================================================

  Website:    http://localhost:3000/
  Login:      http://localhost:3000/login.html
  Dashboard:  http://localhost:3000/dashboard.html
  Public API: http://localhost:3000/api/public/content

  Default admin: admin / admin123
============================================================
```

### 3. Access the System

1. **Public website**: http://localhost:3000/
2. **Admin login**: http://localhost:3000/login.html
3. **Content editor (dashboard)**: http://localhost:3000/dashboard.html (after login) (after login)

## 🔐 Default Credentials

**⚠️ CHANGE THESE IMMEDIATELY IN PRODUCTION!**

- **Username**: `admin`
- **Password**: `admin123`

## 📁 Project Structure

```
admin-dashboard/
├── data/               # Single source of truth
│   ├── content.json    # Site content (auto-created if missing)
│   └── users.json      # Admin users (auto-created)
├── website/
│   └── index.html      # Public cancer center site (loads content from API)
├── admin/
│   ├── login.html      # Admin login
│   └── dashboard.html  # Drag-and-drop content editor
├── server.js           # Express server (website, admin, API, static)
├── package.json
├── CONTENT-SCHEMA.md   # Content JSON structure
├── MIGRATION-GUIDE.md  # Migration from old layout
├── .env.example
├── .gitignore
└── README.md
```

**Migration:** If you had `content.json` or `users.json` at the project root, copy them into `data/` and see **MIGRATION-GUIDE.md**.

## 🔧 Configuration

### Environment Variables (Optional)

1. Copy `.env.example` to `.env`:
   ```cmd
   copy .env.example .env
   ```

2. Edit `.env` and set your values:
   ```
   SESSION_SECRET=your-random-secret-here
   PORT=3000
   NODE_ENV=production
   ```

3. Generate a secure session secret:
   ```cmd
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```

## 📡 API Endpoints

### Public API (No Authentication Required)

**GET /api/public/content**
- Returns website content
- Used by public website
- Example:
  ```javascript
  fetch('/api/public/content')
    .then(res => res.json())
    .then(data => console.log(data));
  ```

### Admin API (Authentication Required)

**POST /login**
- Login endpoint
- Body: `{ "username": "admin", "password": "admin123" }`

**GET /api/admin/content**
- Get content (admin only)
- Requires active session

**POST /api/admin/content**
- Update content (admin only)
- Body: JSON content object
- Creates automatic backup before saving

**POST /logout**
- Logout endpoint
- Destroys session

**GET /api/auth/check**
- Check authentication status
- Returns: `{ "authenticated": true/false }`

## 🛠️ Usage Guide

### Editing Content (Dashboard)

1. Log in at http://localhost:3000/login.html
2. **Reorder sections**: Drag rows in "Page sections" (Hero, Services, Team, etc.); order and visibility save automatically
3. **Show/hide sections**: Use the toggle next to each section
4. **Edit text**: Open the "Edit content" tabs (Hero, Site & stats, Contact, etc.) and change the fields; changes save automatically (debounced)
5. Open "View website" to see updates on the public site

### Content Structure

Content lives in **data/content.json**. See **CONTENT-SCHEMA.md** for the full schema. Main keys:

- `siteInfo` – title, tagline, hero heading/description/CTAs
- `contact` – phone, email, address
- `stats` – numbers for hero (e.g. success rate, patients served)
- `sectionsOrder` – order of sections on the page (e.g. `["hero","services","team","contact","cta"]`)
- `sectionVisibility` – which sections are visible (e.g. `{ "hero": true, "services": true, ... }`)
- `services`, `aboutSection`, `footer`, etc.

### Adding New Users

Edit **data/users.json** (created after first run):

1. Generate password hash:
   ```cmd
   node -e "const bcrypt = require('bcrypt'); bcrypt.hash('newpassword', 10).then(hash => console.log(hash));"
   ```

2. Add user to **data/users.json**:
   ```json
   {
     "admin": { ... },
     "newuser": {
       "username": "newuser",
       "password": "PASTE_HASH_HERE"
     }
   }
   ```

## 🔒 Security Features

### 1. Password Security
- Bcrypt hashing with 10 salt rounds
- Passwords never stored in plain text

### 2. Session Security
- HTTP-only cookies (prevents XSS)
- Secure flag for HTTPS (production)
- SameSite strict (prevents CSRF)
- 24-hour timeout

### 3. Rate Limiting
- 5 login attempts per 15 minutes per IP
- Prevents brute force attacks

### 4. Security Headers (Helmet.js)
- X-Content-Type-Options: nosniff
- X-Frame-Options: deny
- X-XSS-Protection: enabled
- And more...

### 5. Input Validation
- XSS protection on content updates
- JSON validation before saving
- Sanitization of user input

### 6. Automatic Backups
- Content backed up before each update in **data/**
- Format: `data/content.backup.[timestamp].json`

## 🌐 Website Integration

The public site (**website/index.html**) loads content from `GET /api/public/content` and:

- Applies **section order** and **visibility** from `sectionsOrder` and `sectionVisibility`
- Fills elements that have `data-content="key"` (e.g. `siteInfo.heroHeading`) with the value from the API

So any change in the dashboard (text or section order/visibility) is reflected on the next page load (or refresh).

## 🚨 Troubleshooting

### Port Already in Use

**Error**: `EADDRINUSE: address already in use :::3000`

**Solutions**:
1. Change port in `.env` or `server.js`
2. Kill process using port 3000:
   ```cmd
   netstat -ano | findstr :3000
   taskkill /PID [PID_NUMBER] /F
   ```

### Cannot Find Module

**Error**: `Cannot find module 'express'`

**Solution**:
```cmd
npm install
```

### BCrypt Installation Issues on Windows

If bcrypt fails to install:

1. Install Windows Build Tools:
   ```cmd
   npm install --global windows-build-tools
   ```

2. Or use `bcryptjs` instead (edit `package.json`):
   ```json
   "bcrypt": "^5.1.1"  →  "bcryptjs": "^2.4.3"
   ```

### Session Not Persisting

**Solutions**:
1. Clear browser cookies
2. Ensure SESSION_SECRET is set
3. Check browser console for errors

## 📊 Production Deployment

### Windows Server Deployment

1. **Set Environment Variables**:
   ```cmd
   set NODE_ENV=production
   set SESSION_SECRET=your-random-secret
   ```

2. **Run with PM2** (Process Manager):
   ```cmd
   npm install -g pm2
   pm2 start server.js --name admin-dashboard
   pm2 save
   pm2 startup
   ```

3. **Enable HTTPS**:
   - Use reverse proxy (IIS, nginx)
   - Or configure Express with SSL certificates

### Security Checklist

- [ ] Change default admin password
- [ ] Set secure SESSION_SECRET in `.env`
- [ ] Set `NODE_ENV=production`
- [ ] Enable HTTPS
- [ ] Configure firewall
- [ ] Regular backups of `content.json` and `users.json`
- [ ] Keep dependencies updated: `npm audit fix`

## 🔄 Updates and Maintenance

### Update Dependencies

```cmd
npm update
```

### Check for Security Vulnerabilities

```cmd
npm audit
npm audit fix
```

### Backup Data Files

```cmd
copy content.json content.backup.json
copy users.json users.backup.json
```

## 📝 Common Tasks

### Restart Server

Press `Ctrl + C` to stop, then:
```cmd
node server.js
```

### View Logs

Server logs appear in the console where `node server.js` is running.

### Reset to Default Content

Delete **data/content.json** and restart the server; it will be recreated with defaults.

## 🆘 Support

### Common Issues

1. **Can't login**: Check username/password, clear cookies
2. **Content not saving**: Check file permissions
3. **Server won't start**: Check port availability, dependencies

### Getting Help

1. Check troubleshooting section above
2. Review server console output for errors
3. Check browser console (F12) for client-side errors

## 📄 License

MIT License - Free to use and modify

## 🎉 You're All Set!

The admin dashboard is ready to use. Start the server and access:

- **Public Site**: http://localhost:3000
- **Admin Login**: http://localhost:3000/login.html

**Default credentials**: admin / admin123

---

**Built with ❤️ using Node.js, Express, and vanilla JavaScript**
