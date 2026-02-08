# ⚡ QUICK INTEGRATION GUIDE

## 🎯 3 Simple Steps

### 1️⃣ Replace server.js
Copy the new `server.js` to your project root folder (replace existing)

### 2️⃣ Add content.json
Copy `content.json` to your project root folder

### 3️⃣ Update Test.html
Add the integration code from `website-integration-code.js` to Test.html

**Find this in Test.html (line ~1347):**
```javascript
        document.addEventListener('DOMContentLoaded', () => {
```

**After the closing `});` of the stats observer, add:**
```javascript
// PASTE ENTIRE CONTENT OF website-integration-code.js HERE
```

---

## 🚀 Start Server

```cmd
node server.js
```

---

## 🌐 Access Points

| What | URL |
|------|-----|
| 🏥 Cancer Center Website | http://localhost:3000/Test.html |
| 🔐 Admin Login | http://localhost:3000/login.html |
| 📊 Dashboard | http://localhost:3000/dashboard.html |
| 📡 API | http://localhost:3000/api/public/content |

**Login:** admin / admin123

---

## ✅ Test It Works

1. Open website → Should load with content
2. Login to dashboard → Edit content
3. Save changes
4. Refresh website → See new content

---

## 🔧 Manual Content Refresh

Open browser console on Test.html, type:
```javascript
window.refreshContent()
```

---

## 📂 Files Needed

```
✅ server.js (REPLACE)
✅ content.json (NEW)
✅ Test.html (ADD CODE TO)
✅ login.html (no changes)
✅ dashboard.html (no changes)
```

---

## 🎨 What You Can Edit

- Hero section text
- Contact info (phone, email, address)
- Statistics numbers
- Services (title, description, icon)
- About section content
- Footer text

All editing happens in the dashboard at:
http://localhost:3000/dashboard.html

---

**That's it! 🎉**

For detailed instructions, see: INTEGRATION-INSTRUCTIONS.md
