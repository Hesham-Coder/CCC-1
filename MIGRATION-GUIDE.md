# Migration Guide – Refactored Architecture

This guide explains the new folder structure, how to run the project, and how to migrate from the old layout.

---

## 1. New Folder Structure

```
admin-dashboard/
├── data/                    # Single source of truth (content + users)
│   ├── content.json         # All editable site content; created on first run if missing
│   └── users.json           # Admin users; created on first run (default: admin / admin123)
├── website/                 # Public site
│   └── index.html           # Main cancer center page (loads content from API)
├── admin/                   # Dashboard & login
│   ├── login.html           # Admin login page
│   └── dashboard.html       # Drag-and-drop content editor
├── server.js                # Express app: serves website, admin, API, static files
├── package.json
├── CONTENT-SCHEMA.md        # Content JSON structure
├── MIGRATION-GUIDE.md       # This file
└── (images, .env, etc. at root)
```

**Why this structure**
- **data/** – One place for content and users; no duplication, easy to back up.
- **website/** – All public pages live here; clear separation from admin.
- **admin/** – Login and dashboard in one place; protected by auth.

---

## 2. What Changed

| Before | After |
|--------|--------|
| `index.html`, `login.html`, `dashboard.html` at project root | Website at `website/index.html`, admin at `admin/login.html` and `admin/dashboard.html` |
| `content.json` and `users.json` at root | Both in `data/` |
| Dashboard: manual JSON text editing | Dashboard: drag-and-drop sections, visibility toggles, inline text editing, auto-save |
| Website: static copy only | Website: fetches `/api/public/content`, applies section order/visibility and fills `data-content` fields |
| Route `/Test.html` | Removed (was unused) |

---

## 3. Migrating Existing Data

If you already have **content.json** or **users.json** at the project root:

1. Create the `data/` folder if it doesn’t exist.
2. Copy (or move) `content.json` → `data/content.json`.
3. Copy (or move) `users.json` → `data/users.json`.
4. Ensure `data/content.json` includes `sectionsOrder` and `sectionVisibility` (see CONTENT-SCHEMA.md). If they’re missing, the server and website use defaults (all sections visible in a fixed order).

Example addition to existing content.json:

```json
"sectionsOrder": ["hero", "services", "team", "about", "contact", "cta"],
"sectionVisibility": {
  "hero": true,
  "services": true,
  "team": true,
  "about": true,
  "contact": true,
  "cta": true
}
```

---

## 4. Running the Project

```bash
npm install
npm start
```

- **Website:** http://localhost:3000/
- **Login:** http://localhost:3000/login.html
- **Dashboard:** http://localhost:3000/dashboard.html (after login)
- **Public API:** http://localhost:3000/api/public/content

Default admin: **admin** / **admin123**. Change this in production.

---

## 5. Dashboard (Content Editor)

- **Sections list:** Drag to reorder; toggle visibility (eye on/off). Changes save automatically.
- **Edit content:** Use the tabs (Hero, Site & stats, Contact, etc.) and edit the fields. Saving is automatic (debounced).
- **View website:** Use “View website” in the header to open the public site in a new tab.

---

## 6. Website Integration

- The website loads content from `GET /api/public/content`.
- Sections are ordered and shown/hidden using `sectionsOrder` and `sectionVisibility`.
- Elements with `data-content="key"` (e.g. `siteInfo.heroHeading`) are filled with the value from content.
- Images and other static assets are served from the project root (e.g. `/image.jpg`).

---

## 7. Rollback (Optional)

If you need the old behavior temporarily:

- In **server.js**, point the `/` route back to `path.join(__dirname, 'index.html')` and serve `login.html` and `dashboard.html` from root.
- Restore **CONTENT_FILE** and **USERS_FILE** to `path.join(__dirname, 'content.json')` and `path.join(__dirname, 'users.json')`.
- Keep using the old root `index.html` and `dashboard.html` (manual JSON editing). The new dashboard and dynamic website will not be used in that setup.

---

## 8. Security Notes

- Admin routes (`/dashboard.html`, `/api/admin/*`) require session auth.
- Use **SESSION_SECRET** in `.env` in production.
- Change the default admin password after first login.
- Rate limiting on `/login` remains in place.
