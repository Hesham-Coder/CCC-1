/**
 * Main application server.
 * Serves: public website (/), admin dashboard (/dashboard.html), login (/login.html), and API.
 * Content and users are stored in data/ (single source of truth).
 */
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const fs = require('fs').promises;
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const CONTENT_FILE = path.join(DATA_DIR, 'content.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

// Multer: store uploads in /uploads with safe filenames
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, UPLOADS_DIR);
  },
  filename: function (req, file, cb) {
    const mime = (file.mimetype || '').toLowerCase();
    const ext = mime.includes('png') ? '.png' : mime.includes('gif') ? '.gif' : mime.includes('webp') ? '.webp' : '.jpg';
    cb(null, 'img-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8) + ext);
  }
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 }, fileFilter: (req, file, cb) => {
  const ok = /^image\/(jpeg|jpg|png|gif|webp)$/i.test(file.mimetype);
  cb(null, !!ok);
} });

// Security: Helmet for secure headers
app.use(helmet({
  contentSecurityPolicy: false // Allow inline scripts for HTML files
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'change-this-secret-in-production-use-env-file',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: 'strict'
  }
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
});

// Default content when data/content.json is missing (e.g. first run or gitignored)
let DEFAULT_CONTENT;
try {
  DEFAULT_CONTENT = require('./data/content.json');
} catch (e) {
  DEFAULT_CONTENT = {
    siteInfo: { title: 'Comprehensive Cancer Center', tagline: 'Science That Heals. Care That Connects.', heroHeading: 'Science That Heals. Care That Connects.', heroSubheading: 'Advanced Cancer Treatment', heroDescription: 'Where cutting-edge oncology meets personalized patient care.', heroCtaPrimary: 'Schedule a Consultation', heroCtaSecondary: 'Learn More' },
    contact: { phone: '01120800011', address: '644 طريق الحرية، جناكليس، الإسكندرية', email: 'info@comprehensivecancercenter.com', emergencyPhone: '03-5865843' },
    stats: { patientsServed: 5000, successRate: 95, specialists: 50, yearsExperience: 20 },
    sectionsOrder: ['hero', 'services', 'team', 'about', 'contact', 'cta'],
    sectionVisibility: { hero: true, services: true, team: true, about: true, contact: true, cta: true },
    services: [{ icon: 'science', title: 'Advanced Diagnostics', description: 'State-of-the-art imaging and molecular testing.' }, { icon: 'medication', title: 'Precision Medicine', description: 'Targeted therapies tailored to your profile.' }, { icon: 'support', title: 'Holistic Support', description: 'Nutrition, mental health, survivorship programs.' }],
    aboutSection: { heading: 'Leading Cancer Care', paragraphs: ['At Comprehensive Cancer Center we address not just the disease, but the whole person.'], highlights: ['Nationally recognized specialists', 'Clinical trials', 'Supportive care'] },
    footer: { copyright: '© 2024 Comprehensive Cancer Center.', hours: 'Mon - Fri: 8:00 AM - 6:00 PM', emergencyText: '24/7 Emergency Support' },
    teamSection: { heading: 'World-Class Specialists', subheading: 'Our team combines decades of experience with cutting-edge research and compassionate care.' },
    experts: [
      { name: 'Dr. Sarah Chen', title: 'Chief Oncologist', imageUrl: '', bio: '25+ years specializing in precision oncology and immunotherapy.', icon: 'medical_services', visible: true },
      { name: 'Dr. Michael Torres', title: 'Radiation Specialist', imageUrl: '', bio: 'Expert in advanced radiation therapy and treatment planning.', icon: 'radiology', visible: true },
      { name: 'Dr. Priya Patel', title: 'Genetic Counselor', imageUrl: '', bio: 'Leading researcher in cancer genetics and hereditary screening.', icon: 'genetics', visible: true },
      { name: 'Dr. James Wilson', title: 'Surgical Oncologist', imageUrl: '', bio: 'Pioneer in minimally invasive surgical techniques.', icon: 'surgical', visible: true }
    ]
  };
}

const DEFAULT_USERS = {
  admin: {
    username: 'admin',
    password: '$2b$10$YourHashedPasswordHere'
  }
};

const DEFAULT_EXPERTS = [
  { name: 'Dr. Sarah Chen', title: 'Chief Oncologist', imageUrl: '', bio: '25+ years specializing in precision oncology and immunotherapy.', icon: 'medical_services', visible: true },
  { name: 'Dr. Michael Torres', title: 'Radiation Specialist', imageUrl: '', bio: 'Expert in advanced radiation therapy and treatment planning.', icon: 'radiology', visible: true },
  { name: 'Dr. Priya Patel', title: 'Genetic Counselor', imageUrl: '', bio: 'Leading researcher in cancer genetics and hereditary screening.', icon: 'genetics', visible: true },
  { name: 'Dr. James Wilson', title: 'Surgical Oncologist', imageUrl: '', bio: 'Pioneer in minimally invasive surgical techniques.', icon: 'surgical', visible: true }
];

function ensureExperts(content) {
  if (!content || typeof content !== 'object') return content;
  if (!content.teamSection) content.teamSection = { heading: 'World-Class Specialists', subheading: 'Our team combines decades of experience with cutting-edge research and compassionate care.' };
  if (!Array.isArray(content.experts) || content.experts.length === 0) content.experts = DEFAULT_EXPERTS.map(e => ({ ...e }));
  return content;
}

async function ensureDataDir() {
  try {
    await fs.mkdir(DATA_DIR, { recursive: true });
  } catch (e) {
    if (e.code !== 'EEXIST') throw e;
  }
}

async function ensureUploadsDir() {
  try {
    await fs.mkdir(UPLOADS_DIR, { recursive: true });
  } catch (e) {
    if (e.code !== 'EEXIST') throw e;
  }
}

async function initializeFiles() {
  try {
    await ensureDataDir();
    await ensureUploadsDir();

    try {
      await fs.access(USERS_FILE);
    } catch {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      DEFAULT_USERS.admin.password = hashedPassword;
      await fs.writeFile(USERS_FILE, JSON.stringify(DEFAULT_USERS, null, 2));
      console.log('✓ Users file created. Default credentials: admin / admin123');
      console.log('⚠ CHANGE PASSWORD IMMEDIATELY IN PRODUCTION!');
    }

    try {
      await fs.access(CONTENT_FILE);
      console.log('✓ Content file found');
    } catch {
      await fs.writeFile(CONTENT_FILE, JSON.stringify(DEFAULT_CONTENT, null, 2));
      console.log('✓ Content file created with default content');
    }
  } catch (error) {
    console.error('Error initializing files:', error);
    process.exit(1);
  }
}

function requireAuth(req, res, next) {
  if (req.session && req.session.userId) {
    next();
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
}

// ----- Routes (defined before static so they take precedence) -----

// Public website (single page)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'website', 'index.html'));
});

app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin', 'login.html'));
});

app.get('/dashboard.html', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin', 'dashboard.html'));
});

app.get('/referral.html', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin', 'referral.html'));
});

// Login
app.post('/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    const usersData = await fs.readFile(USERS_FILE, 'utf8');
    const users = JSON.parse(usersData);
    const user = users[username];
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) return res.status(401).json({ error: 'Invalid credentials' });
    req.session.userId = user.username;
    res.json({ success: true, message: 'Login successful', redirect: '/dashboard.html' });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ error: 'Logout failed' });
    res.json({ success: true });
  });
});

app.get('/api/auth/check', (req, res) => {
  if (req.session && req.session.userId) {
    res.json({ authenticated: true, username: req.session.userId });
  } else {
    res.json({ authenticated: false });
  }
});

// Public API – get content (no auth)
app.get('/api/public/content', async (req, res) => {
  try {
    const contentData = await fs.readFile(CONTENT_FILE, 'utf8');
    const content = ensureExperts(JSON.parse(contentData));
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.json(content);
  } catch (error) {
    console.error('Error reading content:', error);
    res.status(500).json({ error: 'Failed to read content' });
  }
});

// Admin API – get content (auth required)
app.get('/api/admin/content', requireAuth, async (req, res) => {
  try {
    const contentData = await fs.readFile(CONTENT_FILE, 'utf8');
    const content = ensureExperts(JSON.parse(contentData));
    res.json(content);
  } catch (error) {
    console.error('Error reading content:', error);
    res.status(500).json({ error: 'Failed to read content' });
  }
});

// Admin API – update content (auth required, instant save)
app.post('/api/admin/content', requireAuth, async (req, res) => {
  try {
    const content = req.body;
    if (!content || typeof content !== 'object') {
      return res.status(400).json({ error: 'Invalid content format' });
    }
    try {
      const currentContent = await fs.readFile(CONTENT_FILE, 'utf8');
      const backupFile = path.join(DATA_DIR, `content.backup.${Date.now()}.json`);
      await fs.writeFile(backupFile, currentContent);
      console.log(`✓ Backup: ${path.basename(backupFile)}`);
    } catch (e) {
      console.warn('Backup skip:', e.message);
    }
    await fs.writeFile(CONTENT_FILE, JSON.stringify(content, null, 2));
    console.log('✓ Content updated');
    res.json({ success: true, message: 'Content updated successfully' });
  } catch (error) {
    console.error('Error updating content:', error);
    res.status(500).json({ error: 'Failed to update content' });
  }
});

// Admin API – image upload (auth required)
app.post('/api/admin/upload', requireAuth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const url = '/uploads/' + path.basename(req.file.path);
  res.json({ success: true, url });
});

// Serve uploaded images
app.use('/uploads', express.static(UPLOADS_DIR));

// Static files (images, etc.) from project root so /image.jpg works for website
app.use(express.static(__dirname));

// Start
async function startServer() {
  await initializeFiles();
  app.listen(PORT, () => {
    console.log('\n' + '='.repeat(60));
    console.log('  CANCER CENTER – WEBSITE & ADMIN DASHBOARD');
    console.log('='.repeat(60));
    console.log(`\n  Website:    http://localhost:${PORT}/`);
    console.log(`  Login:      http://localhost:${PORT}/login.html`);
    console.log(`  Dashboard:  http://localhost:${PORT}/dashboard.html`);
    console.log(`  Public API: http://localhost:${PORT}/api/public/content`);
    console.log('\n  Default admin: admin / admin123');
    console.log('='.repeat(60) + '\n');
  });
}

startServer();
