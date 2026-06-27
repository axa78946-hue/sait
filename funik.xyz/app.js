/**
 * Funik Client — Interactive Frontend Logic
 * Implements smooth easing cursor spotlight, 3D parallax tilt, and scroll reveals.
 */

document.addEventListener('DOMContentLoaded', () => {
    // --------------------------------------------------------------------------
    // 0. Dynamic Navbar / Notice Header Height Calculation
    // --------------------------------------------------------------------------
    const topWrapper = document.querySelector('.top-navigation-wrapper');
    function updateNavHeightVar() {
        if (topWrapper) {
            document.documentElement.style.setProperty('--nav-wrapper-height', `${topWrapper.offsetHeight}px`);
        }
    }
    updateNavHeightVar();
    window.addEventListener('resize', updateNavHeightVar);
    setTimeout(updateNavHeightVar, 100);
    setTimeout(updateNavHeightVar, 300);

    // --------------------------------------------------------------------------
    // 1. Smooth Easing Cursor Spotlight Glow
    // --------------------------------------------------------------------------
    const cursorGlow = document.getElementById('cursorGlow');
    let mouseX = window.innerWidth / 2;
    let mouseY = window.innerHeight / 2;
    let currentX = mouseX;
    let currentY = mouseY;
    const easeSpeed = 0.08; // Easing speed (lower = smoother/slower lag)

    // Track mouse coordinates
    document.addEventListener('mousemove', (e) => {
        mouseX = e.clientX;
        mouseY = e.clientY;
    });

    // Animation loop using requestAnimationFrame for 60fps fluid performance
    function animateSpotlight() {
        // Easing interpolation formula: current = current + (target - current) * speed
        currentX += (mouseX - currentX) * easeSpeed;
        currentY += (mouseY - currentY) * easeSpeed;

        if (cursorGlow) {
            // Using translate3d for hardware acceleration
            cursorGlow.style.transform = `translate3d(${currentX}px, ${currentY}px, 0) translate(-50%, -50%)`;
        }

        requestAnimationFrame(animateSpotlight);
    }
    animateSpotlight();

    // --------------------------------------------------------------------------
    // 2. 3D Interactive Parallax Tilt for Gameplay Showcase
    // --------------------------------------------------------------------------
    const showcaseWrapper = document.querySelector('.showcase-viewport-wrapper');
    const showcaseWindow = document.querySelector('.showcase-window');

    if (showcaseWrapper && showcaseWindow) {
        showcaseWrapper.addEventListener('mousemove', (e) => {
            const rect = showcaseWrapper.getBoundingClientRect();
            
            // Calculate mouse coordinates relative to the element (from 0 to width/height)
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            
            // Convert to a coordinate system from -0.5 to 0.5
            const calcX = (x / rect.width) - 0.5;
            const calcY = (y / rect.height) - 0.5;
            
            // Tilt calculations (maximum rotation of 6 degrees)
            const rotateX = (calcY * -12).toFixed(2);
            const rotateY = (calcX * 12).toFixed(2);
            
            // Apply 3D transform rotation and a subtle translate3d shift
            showcaseWindow.style.transform = `rotateX(${rotateX}deg) rotateY(${rotateY}deg) translate3d(0, -4px, 10px)`;
        });

        // Reset transform smoothly when mouse leaves the showcase area
        showcaseWrapper.addEventListener('mouseleave', () => {
            showcaseWindow.style.transform = 'rotateX(0deg) rotateY(0deg) translate3d(0, 0, 0)';
        });
    }

    // --------------------------------------------------------------------------
    // 3. Mobile Navigation Menu & Hamburger Animation
    // --------------------------------------------------------------------------
    const mobileToggle = document.getElementById('mobileToggle');
    const navMenu = document.getElementById('navMenu');
    
    if (mobileToggle && navMenu) {
        mobileToggle.addEventListener('click', () => {
            const isActive = navMenu.classList.toggle('active');
            mobileToggle.classList.toggle('active');
            
            // Toggle body scrolling when menu is open to prevent background scrolling
            document.body.style.overflow = isActive ? 'hidden' : '';
        });
    }

    // --------------------------------------------------------------------------
    // 4. Smooth Anchor Scrolling & Active State Observer
    // --------------------------------------------------------------------------
    const navItems = document.querySelectorAll('.nav-item');
    
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const targetId = this.getAttribute('href');
            if (targetId === '#') return;
            
            const targetElement = document.querySelector(targetId);
            if (targetElement) {
                // Close mobile menu panel if open
                if (navMenu && navMenu.classList.contains('active')) {
                    navMenu.classList.remove('active');
                    if (mobileToggle) mobileToggle.classList.remove('active');
                    document.body.style.overflow = '';
                }
                
                // Calculate header offset including notices/banners
                const topWrapper = document.querySelector('.top-navigation-wrapper');
                const headerOffset = topWrapper ? topWrapper.offsetHeight : (document.getElementById('header').offsetHeight || 80);
                const elementPosition = targetElement.getBoundingClientRect().top;
                const offsetPosition = elementPosition + window.scrollY - headerOffset;
                
                window.scrollTo({
                    top: offsetPosition,
                    behavior: 'smooth'
                });
            }
        });
    });

    // Intersection Observer to highlight active navigation link based on current section
    const sections = document.querySelectorAll('section[id]');
    const observerOptions = {
        root: null,
        rootMargin: '-20% 0px -60% 0px', // Trigger when section occupies the middle of screen
        threshold: 0
    };

    const sectionObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const activeId = entry.target.getAttribute('id');
                navItems.forEach(item => {
                    item.classList.remove('active');
                    if (item.getAttribute('href') === `#${activeId}`) {
                        item.classList.add('active');
                    }
                });
            }
        });
    }, observerOptions);

    sections.forEach(section => {
        sectionObserver.observe(section);
    });

    // --------------------------------------------------------------------------
    // 5. Scroll Reveal Animations (Intersection Observer)
    // --------------------------------------------------------------------------
    const revealElements = document.querySelectorAll('.feature-card, .showcase-viewport-wrapper, .pricing-card, .hero-badge, .hero-title, .hero-description, .hero-buttons, .hero-metrics');
    
    // Set initial opacity and offset in JS to ensure clean fallback if JS is disabled
    revealElements.forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(30px)';
        el.style.transition = 'opacity 1s cubic-bezier(0.16, 1, 0.3, 1), transform 1s cubic-bezier(0.16, 1, 0.3, 1)';
    });

    const revealObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                // Apply final active state
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
                revealObserver.unobserve(entry.target); // Run only once
            }
        });
    }, {
        root: null,
        threshold: 0.05,
        rootMargin: '0px 0px -50px 0px' // Trigger slightly before element enters viewport
    });

    // Delay initialization slightly to let browser layout stabilize
    setTimeout(() => {
        revealElements.forEach(el => {
            revealObserver.observe(el);
        });
    }, 100);

    // --------------------------------------------------------------------------
    // 6. Premium Console Logging
    // --------------------------------------------------------------------------
    console.log(
        "%cFUNIK CLIENT %cv2.4.0",
        "color: #38bdf8; font-family: 'Outfit', sans-serif; font-size: 2.2rem; font-weight: 900; text-shadow: 0 0 15px rgba(56,189,248,0.4);",
        "color: #64748b; font-family: sans-serif; font-size: 1.2rem; font-weight: 500; margin-left: 10px;"
    );
    console.log(
        "%c[System] Авторизация и защита запущены. Приватное игровое ядро активно.",
        "color: #94a3b8; font-size: 1rem; line-height: 1.5;"
    );
});
