// VAOL Auditor — Hash-Based SPA Router

const routes = new Map();
let currentDestroy = null;
let containerEl = null;

export function register(pattern, renderFn, destroyFn = null) {
  routes.set(pattern, { render: renderFn, destroy: destroyFn });
}

export function init(container) {
  containerEl = container;
  window.addEventListener('hashchange', () => resolve());
  resolve();
}

export function navigate(hash) {
  window.location.hash = hash;
}

export function currentRoute() {
  return window.location.hash.slice(1) || '/dashboard';
}

function resolve() {
  const hash = currentRoute();

  // Clean up previous page
  if (currentDestroy) {
    currentDestroy();
    currentDestroy = null;
  }

  // Try exact match first
  if (routes.has(hash)) {
    const route = routes.get(hash);
    containerEl.innerHTML = '';
    route.render(containerEl, {});
    currentDestroy = route.destroy;
    updateNav(hash);
    return;
  }

  // Try parameterized match (e.g., /records/:id)
  for (const [pattern, route] of routes) {
    const params = matchPattern(pattern, hash);
    if (params) {
      containerEl.innerHTML = '';
      route.render(containerEl, params);
      currentDestroy = route.destroy;
      updateNav(pattern);
      return;
    }
  }

  // Default to dashboard
  if (hash !== '/dashboard') {
    navigate('/dashboard');
  }
}

function matchPattern(pattern, path) {
  const patternParts = pattern.split('/');
  const pathParts = path.split('/');

  if (patternParts.length !== pathParts.length) return null;

  const params = {};
  for (let i = 0; i < patternParts.length; i++) {
    if (patternParts[i].startsWith(':')) {
      params[patternParts[i].slice(1)] = decodeURIComponent(pathParts[i]);
    } else if (patternParts[i] !== pathParts[i]) {
      return null;
    }
  }
  return params;
}

function updateNav(activePattern) {
  // Determine the base route for nav highlighting
  const base = '/' + activePattern.split('/').filter(Boolean)[0];
  document.querySelectorAll('nav a').forEach(a => {
    const href = a.getAttribute('href')?.replace('#', '');
    a.classList.toggle('active', href === base || activePattern === href);
  });
}
