# Quick Start Guide

## 🚀 Get Started in 3 Steps

### Step 1: Install Dependencies
```bash
cd admin-dashboard
npm install
```

### Step 2: Start the Server
```bash
npm start
```

You should see:
```
╔════════════════════════════════════════════════╗
║     Admin Dashboard Server Running             ║
╠════════════════════════════════════════════════╣
║  🌐 URL: http://localhost:3000                 ║
║  🔐 Login page: http://localhost:3000/login.html ║
║  📊 Dashboard: http://localhost:3000/dashboard.html ║
╠════════════════════════════════════════════════╣
║  Default credentials (CHANGE THESE!):          ║
║  Username: admin                               ║
║  Password: admin123                            ║
╚════════════════════════════════════════════════╝
```

### Step 3: Login & Customize
1. Open http://localhost:3000/login.html in your browser
2. Login with username: `admin`, password: `admin123`
3. Go to Settings and **change your password immediately**
4. Start editing your content!

## 🌐 View Your Website
Open http://localhost:3000 to see your website with the managed content.

## 📝 Next Steps

1. **Secure Your System**
   - Change default password in Settings
   - Set SESSION_SECRET in .env file
   
2. **Customize Content**
   - Edit content in the dashboard
   - Modify the content structure in `data/content.json`
   
3. **Integrate with Your Website**
   - Use the public API: `GET /api/public/content`
   - See `public/index.html` for example code

## 🆘 Need Help?

Check the full README.md for:
- Detailed security configuration
- Production deployment guide
- API documentation
- Troubleshooting tips

---

**Happy managing! 🎉**
