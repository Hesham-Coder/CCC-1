# Experts Section – QA Checklist

Use this checklist to verify the Experts (Team / Specialists) feature end-to-end.

## Pre-requisites

- [ ] Server running: `node server.js`
- [ ] Logged in to dashboard (admin / admin123)

---

## 1. Dashboard – Experts section

- [ ] **Navigation**: "Experts (Team / Specialists)" card is visible in the dashboard (between Page sections and Edit content).
- [ ] **List**: On load, list shows default experts (e.g. Dr. Sarah Chen, Dr. Michael Torres, etc.) or existing experts from content.
- [ ] **Add expert**: Click "Add expert" → form opens with empty fields; fill name, title, bio → Save → new expert appears in list and "Expert saved" toast.
- [ ] **Edit expert**: Click ✎ on a row → form opens with that expert’s data; change name/title/bio → Save → list updates and toast.
- [ ] **Image upload**: In expert form, drag & drop or click to upload an image → preview appears; Save → image URL is stored and list thumbnail shows image.
- [ ] **Visibility toggle**: Toggle the switch on a row to off → expert is hidden on website; toggle on again → expert reappears. Changes save automatically.
- [ ] **Reorder**: Drag an expert row up or down → order changes; refresh dashboard → order is unchanged (persisted).
- [ ] **Delete**: Click 🗑 on a row → confirmation modal "Remove … from the website?" → Confirm → expert is removed from list and "Expert removed" toast.
- [ ] **Cancel form**: Open Add or Edit → click Cancel → form closes without saving.

## 2. Website – Experts section

- [ ] **Dynamic render**: Open homepage (or /experts); Experts section shows the same experts as in the dashboard (no hardcoded names).
- [ ] **Design**: Layout and styling match previous design (cards, gradient or image, name, title, bio, badge icon).
- [ ] **Any number**: Add 2 more experts in dashboard, save → website shows all; delete 2, save → website shows reduced list.
- [ ] **Visibility**: Set one expert to hidden in dashboard → that expert does not appear on the website.
- [ ] **Images**: Expert with uploaded image shows that image on the website; expert without image shows gradient placeholder and icon.
- [ ] **Responsive**: Resize browser; expert grid remains responsive (e.g. 1 col mobile, 2–4 cols desktop).

## 3. Integration

- [ ] **Single source**: Experts are stored in `data/content.json` under `experts`; no separate DB or file.
- [ ] **Section heading**: "Edit content" includes "Experts section heading" tab; changing Team section heading/subheading updates the website.
- [ ] **No duplicate data**: Only one `experts` array; dashboard and website both use it.

## 4. Validation and errors

- [ ] **No console errors**: Open dashboard and website; F12 → Console shows no errors.
- [ ] **No broken links**: All dashboard buttons and links work; website nav and links work.
- [ ] **Persistence**: Add/edit/delete/reorder experts, save → restart server → reload dashboard and website → changes are still there.

---

## Sign-off

| Check | Done |
|-------|------|
| Dashboard: list, add, edit, image, visibility, reorder, delete | |
| Website: dynamic render, design, count, visibility, images, responsive | |
| Integration: single source, section heading, no duplication | |
| No console errors, no broken links, persistence | |
