# 🔗 INTEGRATION GUIDE: Connect Admin Dashboard to Cancer Center Website

## 📋 Overview

This guide will connect your existing admin dashboard to the Cancer Center website (Test.html) so that content changes in the dashboard appear immediately on the website.

---

## 📦 STEP 1: Replace server.js

### Location: Root folder (same folder as your current server.js)

**Action:** Replace your entire `server.js` file with the new version provided.

**What changed:**
- Added `/Test.html` route to serve your cancer center website
- Added `/api/public/content` endpoint (public, no login required)
- Pre-configured with cancer center content structure
- All existing dashboard functionality remains intact

**File:** `server.js` (provided in outputs)

---

## 📄 STEP 2: Add content.json

### Location: Root folder (same location as server.js)

**Action:** Create a new file named `content.json` and paste the content provided.

**What it contains:**
- Site information (titles, taglines, hero content)
- Contact details (phone, email, address)
- Statistics (patients served, success rate, etc.)
- Services list (3 main services)
- Features list
- About section content
- Footer information

**File:** `content.json` (provided in outputs)

**Note:** This file will be auto-created with default content if missing when you start the server.

---

## 🌐 STEP 3: Integrate Dynamic Content into Test.html

### Location: Test.html file

**Action:** Add the integration code to your Test.html file

### Option A: Full Integration (Recommended)

**Find this line in Test.html (around line 1349):**
```javascript
        document.addEventListen
```

This line appears to be incomplete at the end of the file.

**Replace everything after line 1347 with:**

```javascript
        document.addEventListener('DOMContentLoaded', () => {
            const statsSection = document.querySelector('#stats');
            if (statsSection) {
                statsObserver.observe(statsSection);
            }
        });

        // ========================================
        // DYNAMIC CONTENT LOADER - START
        // ========================================

        [PASTE THE ENTIRE CONTENT OF website-integration-code.js HERE]

        // ========================================
        // DYNAMIC CONTENT LOADER - END
        // ========================================
    </script>
</body>
</html>
```

### Option B: Quick Add (Alternative)

**Find this in Test.html (around line 1122):**
```html
    <!-- ========================================
         JAVASCRIPT
    ======================================== -->
```

**Right before the closing `</script>` tag (around line 1349), add:**

```javascript
// ========================================
// DYNAMIC CONTENT LOADER
// ========================================

[PASTE THE ENTIRE CONTENT OF website-integration-code.js HERE]
```

---

## 🎛️ STEP 4: Update Dashboard (Optional but Recommended)

### Location: dashboard.html

Your current dashboard already has a JSON editor. No changes are required if it works with your current setup.

**Optional Enhancement:** Update the info box to mention the cancer center:

**Find this line in dashboard.html:**
```html
💡 Edit the JSON content below. Changes will be reflected on your public website immediately after saving.
```

**Replace with:**
```html
💡 Edit the cancer center website content below. Changes will appear on Test.html immediately after saving. Refresh the website page to see updates.
```

---

## ✅ STEP 5: Verify Files Structure

Your project folder should now contain:

```
your-project/
├── server.js              ✅ (REPLACED)
├── content.json           ✅ (NEW - will auto-create if missing)
├── Test.html              ✅ (MODIFIED - added integration code)
├── login.html             ✅ (existing - no changes)
├── dashboard.html         ✅ (existing - optional update)
├── package.json           ✅ (existing - no changes)
├── users.json             ✅ (auto-created on first run)
└── node_modules/          ✅ (existing dependencies)
```

---

## 🚀 STEP 6: Start the Server

### Windows Command Prompt:

```cmd
node server.js
```

### You should see:

```
============================================================
  🏥 CANCER CENTER ADMIN DASHBOARD RUNNING
============================================================

  🌐 Cancer Center Website:  http://localhost:3000/Test.html
  🔐 Admin Login:            http://localhost:3000/login.html
  📊 Admin Dashboard:        http://localhost:3000/dashboard.html
  📡 Public API:             http://localhost:3000/api/public/content

============================================================
  DEFAULT ADMIN CREDENTIALS
============================================================
  Username: admin
  Password: admin123
  ⚠ CHANGE IMMEDIATELY IN PRODUCTION!
============================================================
```

---

## 🧪 STEP 7: Test the Integration

### Test 1: View the Website
1. Open: http://localhost:3000/Test.html
2. The website should load with default content
3. Open browser console (F12) - you should see:
   ```
   ✓ Dynamic content loaded successfully
   💡 Call window.refreshContent() to manually reload content
   ```

### Test 2: Login to Dashboard
1. Open: http://localhost:3000/login.html
2. Login with: `admin` / `admin123`
3. You should be redirected to the dashboard

### Test 3: Edit Content
1. In the dashboard, you'll see the JSON content
2. Change something simple, for example:
   ```json
   "heroHeading": "NEW HEADING - Science That Heals"
   ```
3. Click "Save Changes"
4. You should see: "✅ Content saved successfully!"

### Test 4: Verify Changes on Website
1. Go to: http://localhost:3000/Test.html
2. Refresh the page (F5)
3. The hero heading should now show "NEW HEADING - Science That Heals"

### Test 5: Test API Directly
1. Open: http://localhost:3000/api/public/content
2. You should see the JSON content displayed in the browser

---

## 🔧 Troubleshooting

### Problem: Website shows old/static content

**Solution:**
1. Hard refresh the website: `Ctrl + Shift + R` (Windows)
2. Clear browser cache
3. Check browser console for errors
4. Verify the integration code was added correctly to Test.html

### Problem: "Failed to load content" in console

**Solution:**
1. Verify server is running
2. Check that content.json exists
3. Verify the API endpoint: http://localhost:3000/api/public/content
4. Check server console for errors

### Problem: Dashboard won't save content

**Solution:**
1. Verify you're logged in
2. Check that the JSON is valid (no syntax errors)
3. Check server console for error messages
4. Verify file permissions on content.json

### Problem: Changes don't appear on website

**Solution:**
1. Make sure you refreshed the website page after saving
2. Check browser console for JavaScript errors
3. Verify the integration code is in Test.html
4. Test the API directly: http://localhost:3000/api/public/content

---

## 📝 Customizing Content

### What Can You Edit in the Dashboard?

All content in `content.json` can be edited through the dashboard:

**Site Information:**
- Page title and tagline
- Hero section (heading, subheading, description)
- CTA button text

**Contact Details:**
- Phone numbers
- Email address
- Physical address

**Statistics:**
- Number of patients served
- Success rate percentage
- Number of specialists
- Years of experience

**Services:**
- Service titles and descriptions
- Icons (Material Symbols names)

**Features:**
- Feature titles and descriptions

**About Section:**
- Heading
- Multiple paragraphs
- Highlight bullet points

**Footer:**
- Copyright text
- Business hours
- Emergency support text

### JSON Structure Example:

```json
{
  "siteInfo": {
    "heroHeading": "Your Custom Heading",
    "heroDescription": "Your custom description text"
  },
  "contact": {
    "phone": "01120800011",
    "email": "info@example.com"
  },
  "stats": {
    "patientsServed": 5000
  }
}
```

---

## 🔄 Auto-Refresh Feature (Optional)

To make the website automatically check for content updates every 30 seconds:

**In Test.html, find this line in the integration code:**
```javascript
// Uncomment the line below to enable auto-refresh every 30 seconds
// enableAutoRefresh(30);
```

**Change to:**
```javascript
// Auto-refresh enabled - checks for updates every 30 seconds
enableAutoRefresh(30);
```

**Benefits:**
- Website stays in sync with dashboard changes
- No need to manually refresh

**Considerations:**
- Increases server requests
- May cause slight performance impact with many visitors

---

## 🎯 Quick Reference

### Important URLs:
- **Website:** http://localhost:3000/Test.html
- **Admin Login:** http://localhost:3000/login.html
- **Dashboard:** http://localhost:3000/dashboard.html
- **API Endpoint:** http://localhost:3000/api/public/content

### Default Login:
- **Username:** admin
- **Password:** admin123

### File Locations:
- **Content Storage:** content.json (root folder)
- **User Credentials:** users.json (root folder)
- **Backups:** content.backup.[timestamp].json (auto-created)

### Console Commands:
- **Manual Refresh:** `window.refreshContent()` (in browser console on Test.html)

---

## ✅ Success Checklist

- [ ] Replaced server.js with new version
- [ ] Added content.json to root folder
- [ ] Added integration code to Test.html
- [ ] Started server successfully
- [ ] Website loads at http://localhost:3000/Test.html
- [ ] Can login to dashboard
- [ ] Can edit content in dashboard
- [ ] Changes save successfully
- [ ] Changes appear on website after refresh
- [ ] API endpoint works: http://localhost:3000/api/public/content

---

## 🆘 Need Help?

1. **Check the server console** for error messages
2. **Check browser console (F12)** for JavaScript errors
3. **Verify all files** are in the correct locations
4. **Test the API directly** in browser
5. **Check file permissions** on content.json

---

**You're all set! Your admin dashboard is now fully integrated with the cancer center website.** 🎉
