# Expert Data Schema

Experts (Team / Specialists) are stored in the shared content source: `data/content.json`.

## Location

- **Key:** `experts` (top-level array).
- **Section headings:** `teamSection.heading`, `teamSection.subheading` (optional; used for the Experts section title on the website).

## Expert object

| Field        | Type    | Required | Description |
|-------------|---------|----------|-------------|
| `name`      | string  | Yes      | Full name (e.g. "Dr. Sarah Chen"). |
| `title`     | string  | Yes      | Role / title (e.g. "Chief Oncologist"). |
| `imageUrl`  | string  | No       | Profile image URL (e.g. `/uploads/img-xxx.jpg`). Empty = use placeholder. |
| `bio`       | string  | No       | Short bio / description. |
| `icon`      | string  | No       | Material icon name for placeholder when no image (e.g. `medical_services`, `radiology`). |
| `socialLinks` | object | No     | Optional: `{ "linkedin": "url", "twitter": "url" }`. |
| `visible`  | boolean | No       | Show on website. Default `true`. |

Order on the website = array order (reorder via drag-and-drop in dashboard).

## Example

```json
{
  "experts": [
    {
      "name": "Dr. Sarah Chen",
      "title": "Chief Oncologist",
      "imageUrl": "/uploads/img-123.jpg",
      "bio": "25+ years specializing in precision oncology and immunotherapy.",
      "icon": "medical_services",
      "visible": true
    }
  ],
  "teamSection": {
    "heading": "World-Class Specialists",
    "subheading": "Our team combines decades of experience with cutting-edge research."
  }
}
```

## Backend

- No dedicated experts API: use existing `GET/POST /api/admin/content` and `POST /api/admin/upload` for images.
- Ensure `experts` exists (e.g. default array) when content is read or first saved.
