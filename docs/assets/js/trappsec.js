// ── Language Switcher ────────────────────────────────
function switchLang(lang) {
  document.querySelectorAll('.lang-btn').forEach(btn => {
    btn.classList.toggle('active', btn.textContent.toLowerCase().includes(lang));
  });

  document.querySelectorAll('.lang-content').forEach(el => {
    el.classList.toggle('active', el.getAttribute('data-lang') === lang);
  });

  localStorage.setItem('trappsec_lang', lang);

  if (document.querySelector('.lang-switcher')) {
    const url = new URL(window.location);
    url.searchParams.set('lang', lang);
    window.history.replaceState({}, '', url);
  }
}

// ── Copy Button ──────────────────────────────────────
function copyCode(btn) {
  const pre = btn.closest('.code-block-wrap').querySelector('pre');
  navigator.clipboard.writeText(pre.innerText).then(() => {
    btn.textContent = 'copied';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = 'copy'; btn.classList.remove('copied'); }, 2000);
  });
}

// ── TOC Builder ──────────────────────────────────────
function buildToc() {
  const tocList = document.getElementById('toc-list');
  if (!tocList) return;

  const headings = document.querySelectorAll('article.content h2, article.content h3');
  if (!headings.length) return;

  headings.forEach((h, i) => {
    if (!h.id) h.id = 'heading-' + i;

    const li = document.createElement('li');
    li.className = 'toc-item' + (h.tagName === 'H3' ? ' toc-item-sub' : '');
    li.dataset.id = h.id;

    const a = document.createElement('a');
    a.href = '#' + h.id;
    a.textContent = h.textContent;
    li.appendChild(a);
    tocList.appendChild(li);
  });
}

// ── Scroll Spy ───────────────────────────────────────
function initScrollSpy() {
  const tocList = document.getElementById('toc-list');
  if (!tocList) return;

  const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      const id = entry.target.id;
      const link = tocList.querySelector(`[data-id="${id}"]`);
      if (link) link.classList.toggle('active', entry.isIntersecting);
    });
  }, { rootMargin: '-52px 0px -70% 0px', threshold: 0 });

  tocList.querySelectorAll('.toc-item').forEach(item => {
    const el = document.getElementById(item.dataset.id);
    if (el) observer.observe(el);
  });
}

// ── Mobile Nav Drawer ────────────────────────────────
function initMobileNav() {
  const toggle  = document.getElementById('nav-toggle');
  const sidebar = document.getElementById('sidebar');
  const overlay = document.getElementById('nav-overlay');
  if (!toggle || !sidebar || !overlay) return;

  function openNav() {
    sidebar.classList.add('open');
    overlay.classList.add('open');
    document.body.classList.add('nav-open');
    toggle.setAttribute('aria-expanded', 'true');
  }

  function closeNav() {
    sidebar.classList.remove('open');
    overlay.classList.remove('open');
    document.body.classList.remove('nav-open');
    toggle.setAttribute('aria-expanded', 'false');
  }

  toggle.addEventListener('click', () =>
    sidebar.classList.contains('open') ? closeNav() : openNav()
  );

  overlay.addEventListener('click', closeNav);

  // Close drawer when a nav link is tapped on mobile
  sidebar.querySelectorAll('.nav-item').forEach(item =>
    item.addEventListener('click', () => {
      if (window.innerWidth < 768) closeNav();
    })
  );
}

// ── Init ─────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Language preference
  const urlParams = new URLSearchParams(window.location.search);
  const lang = urlParams.get('lang') || localStorage.getItem('trappsec_lang') || 'python';
  switchLang(lang);

  // TOC
  buildToc();
  initScrollSpy();

  // Mobile nav
  initMobileNav();
});
