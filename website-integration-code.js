// ========================================
// DYNAMIC CONTENT LOADER FOR CANCER CENTER WEBSITE
// Add this code to your Test.html file before the closing </script> tag
// ========================================

// Configuration
const CONTENT_API_URL = '/api/public/content';
let websiteContent = null;

// Load content from API
async function loadDynamicContent() {
    try {
        const response = await fetch(CONTENT_API_URL);
        if (!response.ok) {
            throw new Error('Failed to load content');
        }
        
        websiteContent = await response.json();
        updatePageContent();
        console.log('✓ Dynamic content loaded successfully');
    } catch (error) {
        console.error('Error loading dynamic content:', error);
        console.warn('Using default static content as fallback');
    }
}

// Update all page elements with dynamic content
function updatePageContent() {
    if (!websiteContent) return;

    // Update page title and meta
    if (websiteContent.siteInfo) {
        document.title = websiteContent.siteInfo.title + ' - ' + websiteContent.siteInfo.tagline;
    }

    // Update Hero Section
    updateHeroSection();

    // Update Contact Information
    updateContactInfo();

    // Update Stats
    updateStats();

    // Update Services
    updateServices();

    // Update About Section
    updateAboutSection();

    // Update Footer
    updateFooter();
}

// Update Hero Section
function updateHeroSection() {
    const hero = websiteContent.siteInfo;
    if (!hero) return;

    // Hero heading
    const heroHeading = document.querySelector('.text-6xl.lg\\:text-8xl.font-extrabold');
    if (heroHeading && hero.heroHeading) {
        heroHeading.textContent = hero.heroHeading;
    }

    // Hero subheading
    const heroSubheading = document.querySelector('.text-2xl.lg\\:text-4xl.font-bold.text-\\[var\\(--brand-blue-dark\\)\\]');
    if (heroSubheading && hero.heroSubheading) {
        heroSubheading.textContent = hero.heroSubheading;
    }

    // Hero description
    const heroDescription = document.querySelector('.text-lg.lg\\:text-xl.text-gray-700.leading-relaxed.max-w-3xl');
    if (heroDescription && hero.heroDescription) {
        heroDescription.textContent = hero.heroDescription;
    }

    // CTA buttons
    const ctaPrimary = document.querySelector('a[href="#contact"]');
    if (ctaPrimary && hero.heroCtaPrimary) {
        ctaPrimary.innerHTML = `
            <span class="material-symbols-outlined mr-2">event</span>
            ${hero.heroCtaPrimary}
        `;
    }

    const ctaSecondary = document.querySelectorAll('a[href="#about"]')[0];
    if (ctaSecondary && hero.heroCtaSecondary) {
        ctaSecondary.innerHTML = `
            ${hero.heroCtaSecondary}
            <span class="material-symbols-outlined ml-2">arrow_forward</span>
        `;
    }
}

// Update Contact Information
function updateContactInfo() {
    const contact = websiteContent.contact;
    if (!contact) return;

    // Phone numbers
    const phoneLinks = document.querySelectorAll('a[href^="tel:"]');
    phoneLinks.forEach(link => {
        if (link.textContent.includes('011') && contact.phone) {
            link.href = `tel:${contact.phone}`;
            link.textContent = contact.phone;
        }
        if (link.textContent.includes('03-') && contact.emergencyPhone) {
            link.href = `tel:${contact.emergencyPhone}`;
            link.textContent = contact.emergencyPhone;
        }
    });

    // Email
    const emailLinks = document.querySelectorAll('a[href^="mailto:"]');
    if (emailLinks.length > 0 && contact.email) {
        emailLinks.forEach(link => {
            link.href = `mailto:${contact.email}`;
            const emailText = link.querySelector('[data-cfemail]') || link;
            if (emailText.textContent) {
                emailText.textContent = contact.email;
            }
        });
    }

    // Address
    const addressElements = document.querySelectorAll('.text-gray-600');
    addressElements.forEach(el => {
        if (el.textContent.includes('طريق الحرية') && contact.address) {
            el.textContent = contact.address;
        }
    });
}

// Update Statistics
function updateStats() {
    const stats = websiteContent.stats;
    if (!stats) return;

    // Find all stat counters and update them
    const statElements = document.querySelectorAll('[data-count]');
    
    // Map stats to their elements based on current values
    statElements.forEach(el => {
        const currentValue = parseInt(el.dataset.count);
        
        if (currentValue === 5000 && stats.patientsServed) {
            el.dataset.count = stats.patientsServed;
            el.textContent = stats.patientsServed + (el.dataset.suffix || '');
        } else if (currentValue === 95 && stats.successRate) {
            el.dataset.count = stats.successRate;
            el.textContent = stats.successRate + (el.dataset.suffix || '');
        } else if (currentValue === 50 && stats.specialists) {
            el.dataset.count = stats.specialists;
            el.textContent = stats.specialists + (el.dataset.suffix || '');
        } else if (currentValue === 20 && stats.yearsExperience) {
            el.dataset.count = stats.yearsExperience;
            el.textContent = stats.yearsExperience + (el.dataset.suffix || '');
        }
    });
}

// Update Services Section
function updateServices() {
    const services = websiteContent.services;
    if (!services || !Array.isArray(services)) return;

    const serviceCards = document.querySelectorAll('.card-glow');
    
    serviceCards.forEach((card, index) => {
        if (services[index]) {
            const service = services[index];
            
            // Update icon
            const iconEl = card.querySelector('.material-symbols-outlined');
            if (iconEl && service.icon) {
                iconEl.textContent = service.icon;
            }

            // Update title
            const titleEl = card.querySelector('h3');
            if (titleEl && service.title) {
                titleEl.textContent = service.title;
            }

            // Update description
            const descEl = card.querySelector('p');
            if (descEl && service.description) {
                descEl.textContent = service.description;
            }
        }
    });
}

// Update About Section
function updateAboutSection() {
    const about = websiteContent.aboutSection;
    if (!about) return;

    // Update heading
    const aboutHeading = document.querySelector('#about h2');
    if (aboutHeading && about.heading) {
        aboutHeading.textContent = about.heading;
    }

    // Update paragraphs
    if (about.paragraphs && Array.isArray(about.paragraphs)) {
        const paragraphs = document.querySelectorAll('#about .text-lg.text-gray-700');
        about.paragraphs.forEach((text, index) => {
            if (paragraphs[index]) {
                paragraphs[index].textContent = text;
            }
        });
    }

    // Update highlights list
    if (about.highlights && Array.isArray(about.highlights)) {
        const highlightsList = document.querySelector('#about ul');
        if (highlightsList) {
            highlightsList.innerHTML = about.highlights.map(highlight => `
                <li class="flex items-start gap-3">
                    <span class="material-symbols-outlined text-[var(--brand-blue-light)] text-2xl flex-shrink-0 mt-1">
                        check_circle
                    </span>
                    <span class="text-gray-700">${highlight}</span>
                </li>
            `).join('');
        }
    }
}

// Update Footer
function updateFooter() {
    const footer = websiteContent.footer;
    if (!footer) return;

    // Update copyright
    const copyrightEl = document.querySelector('footer p');
    if (copyrightEl && footer.copyright) {
        copyrightEl.textContent = footer.copyright;
    }

    // Update hours
    const hoursElements = document.querySelectorAll('footer .text-gray-300');
    if (hoursElements.length > 0 && footer.hours) {
        hoursElements.forEach(el => {
            if (el.textContent.includes('Mon - Fri')) {
                el.textContent = footer.hours;
            }
        });
    }

    // Update emergency text
    if (footer.emergencyText) {
        const emergencyElements = document.querySelectorAll('.text-red-400');
        emergencyElements.forEach(el => {
            if (el.textContent.includes('Emergency')) {
                el.textContent = footer.emergencyText;
            }
        });
    }
}

// Auto-refresh content every 30 seconds (optional)
function enableAutoRefresh(intervalSeconds = 30) {
    setInterval(async () => {
        console.log('Checking for content updates...');
        await loadDynamicContent();
    }, intervalSeconds * 1000);
}

// Initialize dynamic content loading
document.addEventListener('DOMContentLoaded', () => {
    loadDynamicContent();
    // Uncomment the line below to enable auto-refresh every 30 seconds
    // enableAutoRefresh(30);
});

// Expose refresh function globally for manual refresh
window.refreshContent = loadDynamicContent;

console.log('✓ Dynamic content loader initialized');
console.log('💡 Call window.refreshContent() to manually reload content');
