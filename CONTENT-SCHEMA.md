# Content Schema

Single source of truth: `data/content.json`. The website and dashboard both use this file.

## Top-level structure

| Key | Purpose |
|-----|---------|
| `siteInfo` | Global site title, tagline, hero copy (reusable across pages) |
| `contact` | Phone, address, email, emergency (global) |
| `stats` | Numbers for hero/stats (e.g. success rate, patients served) |
| `sectionsOrder` | **Order of sections** on the homepage (drag-and-drop order) |
| `sectionVisibility` | **Per-section visibility** (dashboard toggles; hidden sections are not rendered) |
| `services` | Array of service items (icon, title, description) |
| `features` | Array of feature items (title, description) |
| `aboutSection` | About block (heading, paragraphs, highlights) |
| `teamSection` | Experts section headings (heading, subheading) |
| `experts` | Array of expert/team member objects (name, title, imageUrl, bio, icon, visible). Order = display order. See EXPERT-SCHEMA.md. |
| `footer` | Copyright, hours, emergency text |

## Section IDs (for order and visibility)

- `hero` — Hero / headline block
- `services` — Services grid
- `team` — Team / specialists
- `about` — About section (aboutSection in JSON)
- `contact` — Contact form and info
- `cta` — Bottom CTA block

The website renders only sections that are in `sectionsOrder` and have `sectionVisibility[id] === true`.

## Example (excerpt)

```json
{
  "siteInfo": { "title": "...", "heroHeading": "...", ... },
  "contact": { "phone": "...", "address": "...", ... },
  "stats": { "patientsServed": 5000, ... },
  "sectionsOrder": ["hero", "services", "team", "about", "contact", "cta"],
  "sectionVisibility": {
    "hero": true,
    "services": true,
    "team": true,
    "about": true,
    "contact": true,
    "cta": true
  },
  "services": [ ... ],
  "aboutSection": { ... },
  "footer": { ... }
}
```

## Backward compatibility

If `sectionsOrder` or `sectionVisibility` is missing, the server/website treat all sections as visible and use a default order so existing content still works.
