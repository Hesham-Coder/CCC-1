# Integration Guide: Connecting Admin Dashboard to Your Website

This guide explains how to connect the admin dashboard system to your existing website.

## 🎯 Overview

The admin dashboard provides a REST API that your website can use to fetch content. There are several integration methods depending on your website's technology.

## 📡 Integration Methods

### Method 1: Vanilla JavaScript/HTML (Recommended for Static Sites)

This is the simplest method. Add this code to your website:

```html
<!DOCTYPE html>
<html>
<head>
    <title>My Website</title>
</head>
<body>
    <!-- Your website content with IDs for dynamic elements -->
    <h1 id="site-title">Loading...</h1>
    <p id="site-tagline">Loading...</p>
    <div id="about-content"></div>

    <script>
        // Configuration
        const ADMIN_API_URL = 'http://localhost:3000/api/public/content';

        // Fetch and display content
        async function loadContent() {
            try {
                const response = await fetch(ADMIN_API_URL);
                const content = await response.json();

                // Update page elements
                document.getElementById('site-title').textContent = content.siteName;
                document.getElementById('site-tagline').textContent = content.tagline;
                document.getElementById('about-content').innerHTML = content.aboutText;

                // Access nested content
                if (content.sections?.hero) {
                    document.getElementById('hero-title').textContent = content.sections.hero.title;
                }

                // Handle arrays
                if (content.sections?.services?.items) {
                    const servicesList = document.getElementById('services-list');
                    content.sections.services.items.forEach(service => {
                        const li = document.createElement('li');
                        li.textContent = service;
                        servicesList.appendChild(li);
                    });
                }

            } catch (error) {
                console.error('Error loading content:', error);
                // Fallback content or error handling
            }
        }

        // Load content when page loads
        document.addEventListener('DOMContentLoaded', loadContent);
    </script>
</body>
</html>
```

### Method 2: React Integration

For React applications:

```jsx
import { useState, useEffect } from 'react';

function App() {
    const [content, setContent] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        async function fetchContent() {
            try {
                const response = await fetch('http://localhost:3000/api/public/content');
                const data = await response.json();
                setContent(data);
                setLoading(false);
            } catch (error) {
                console.error('Error fetching content:', error);
                setLoading(false);
            }
        }

        fetchContent();
    }, []);

    if (loading) return <div>Loading...</div>;

    return (
        <div>
            <header>
                <h1>{content.siteName}</h1>
                <p>{content.tagline}</p>
            </header>

            <section>
                <h2>{content.sections?.hero?.title}</h2>
                <p>{content.aboutText}</p>
            </section>

            <section>
                <h2>{content.sections?.services?.title}</h2>
                <ul>
                    {content.sections?.services?.items?.map((service, index) => (
                        <li key={index}>{service}</li>
                    ))}
                </ul>
            </section>
        </div>
    );
}

export default App;
```

### Method 3: Vue.js Integration

For Vue applications:

```vue
<template>
    <div v-if="content">
        <header>
            <h1>{{ content.siteName }}</h1>
            <p>{{ content.tagline }}</p>
        </header>

        <section>
            <h2>{{ content.sections?.hero?.title }}</h2>
            <p>{{ content.aboutText }}</p>
        </section>

        <section>
            <h2>{{ content.sections?.services?.title }}</h2>
            <ul>
                <li v-for="(service, index) in content.sections?.services?.items" :key="index">
                    {{ service }}
                </li>
            </ul>
        </section>
    </div>
    <div v-else>Loading...</div>
</template>

<script>
export default {
    data() {
        return {
            content: null
        };
    },
    async mounted() {
        try {
            const response = await fetch('http://localhost:3000/api/public/content');
            this.content = await response.json();
        } catch (error) {
            console.error('Error loading content:', error);
        }
    }
};
</script>
```

### Method 4: WordPress Integration

Add this to your WordPress theme:

```php
<?php
// functions.php

function get_admin_content() {
    $response = wp_remote_get('http://localhost:3000/api/public/content');
    
    if (is_wp_error($response)) {
        return null;
    }
    
    return json_decode(wp_remote_retrieve_body($response), true);
}

// Use in templates
$content = get_admin_content();
if ($content) {
    echo '<h1>' . esc_html($content['siteName']) . '</h1>';
    echo '<p>' . esc_html($content['tagline']) . '</p>';
}
?>
```

### Method 5: Server-Side Rendering (Node.js/Express)

For server-side rendering:

```javascript
const express = require('express');
const fetch = require('node-fetch');

const app = express();

app.get('/', async (req, res) => {
    try {
        const response = await fetch('http://localhost:3000/api/public/content');
        const content = await response.json();
        
        res.render('index', { content });
    } catch (error) {
        console.error('Error:', error);
        res.render('index', { content: null });
    }
});
```

## 🔧 CORS Configuration (If Needed)

If your website is on a different domain, enable CORS in the admin dashboard's `server.js`:

```javascript
// Add after other middleware
const cors = require('cors');

// Allow specific origin
app.use(cors({
    origin: 'https://your-website.com',
    credentials: true
}));

// Or allow all (development only!)
app.use(cors());
```

Install CORS package:
```bash
npm install cors
```

## 🌐 Production Setup

### Option 1: Same Server
If your website and admin dashboard are on the same server:

```javascript
// Use relative URLs
const ADMIN_API_URL = '/api/public/content';
```

Configure your web server (Nginx) to proxy requests:

```nginx
server {
    listen 80;
    server_name yourwebsite.com;

    # Your website
    location / {
        root /var/www/html;
        index index.html;
    }

    # Admin dashboard API
    location /api/ {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
    }

    # Admin dashboard pages
    location /admin/ {
        proxy_pass http://localhost:3000/;
        proxy_set_header Host $host;
    }
}
```

### Option 2: Different Servers
If your website and admin dashboard are on different servers:

```javascript
// Use full URL with HTTPS
const ADMIN_API_URL = 'https://admin.yourwebsite.com/api/public/content';
```

Enable CORS on the admin server as shown above.

## 💾 Caching Strategy (Optional)

To reduce API calls, implement caching:

```javascript
// Simple in-memory cache
let contentCache = null;
let cacheTime = null;
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes

async function loadContent() {
    const now = Date.now();
    
    // Return cached content if still valid
    if (contentCache && cacheTime && (now - cacheTime < CACHE_DURATION)) {
        return contentCache;
    }
    
    // Fetch fresh content
    try {
        const response = await fetch(ADMIN_API_URL);
        contentCache = await response.json();
        cacheTime = now;
        return contentCache;
    } catch (error) {
        console.error('Error loading content:', error);
        return contentCache; // Return stale cache on error
    }
}
```

## 🔄 Real-time Updates (Advanced)

For real-time content updates without page refresh:

```javascript
// Poll for changes every 30 seconds
setInterval(async () => {
    const newContent = await loadContent();
    updatePageContent(newContent);
}, 30000);

function updatePageContent(content) {
    // Smoothly update only changed elements
    const title = document.getElementById('site-title');
    if (title.textContent !== content.siteName) {
        title.classList.add('updating');
        setTimeout(() => {
            title.textContent = content.siteName;
            title.classList.remove('updating');
        }, 300);
    }
}
```

## 📱 Mobile App Integration

For mobile apps (React Native, Flutter, etc.):

```javascript
// React Native example
import React, { useState, useEffect } from 'react';
import { View, Text } from 'react-native';

export default function App() {
    const [content, setContent] = useState(null);

    useEffect(() => {
        fetch('https://your-admin-server.com/api/public/content')
            .then(res => res.json())
            .then(data => setContent(data))
            .catch(err => console.error(err));
    }, []);

    return (
        <View>
            <Text>{content?.siteName}</Text>
            <Text>{content?.tagline}</Text>
        </View>
    );
}
```

## 🧪 Testing the Integration

1. **Test API Access**:
```bash
curl http://localhost:3000/api/public/content
```

2. **Check Response**:
```json
{
  "siteName": "My Website",
  "tagline": "Welcome",
  ...
}
```

3. **Test in Browser Console**:
```javascript
fetch('http://localhost:3000/api/public/content')
    .then(r => r.json())
    .then(console.log);
```

## 🐛 Troubleshooting

### CORS Errors
```
Access-Control-Allow-Origin error
```
**Solution**: Enable CORS in server.js (see CORS Configuration above)

### Connection Refused
```
Failed to fetch
```
**Solution**: 
- Verify admin server is running
- Check the API URL is correct
- Ensure firewall allows the connection

### Content Not Updating
**Solution**:
- Clear browser cache
- Check if caching is too aggressive
- Verify content was saved in admin dashboard

## 📚 Example Content Structure

The default content structure you can access:

```json
{
  "siteName": "string",
  "tagline": "string",
  "aboutText": "string",
  "contactEmail": "string",
  "sections": {
    "hero": {
      "title": "string",
      "description": "string"
    },
    "services": {
      "title": "string",
      "items": ["string", "string", "string"]
    }
  }
}
```

Access nested data:
```javascript
content.siteName              // "My Website"
content.sections.hero.title   // "Welcome"
content.sections.services.items[0]  // "Service 1"
```

## ✅ Best Practices

1. **Error Handling**: Always wrap API calls in try-catch
2. **Loading States**: Show loading indicators while fetching
3. **Fallback Content**: Provide default content if API fails
4. **Caching**: Cache content to reduce server load
5. **Security**: Use HTTPS in production
6. **Validation**: Validate content before rendering

---

Need more help? Check the main README.md or create an issue!
