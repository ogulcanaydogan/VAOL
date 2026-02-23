// VAOL Auditor — Collapsible JSON Viewer Component

export function renderJsonViewer(container, data) {
  const html = renderValue(data, 0, true);
  container.innerHTML = `<div class="json-viewer">${html}</div>`;

  // Wire toggle buttons
  container.querySelectorAll('.json-toggle').forEach(toggle => {
    toggle.addEventListener('click', () => {
      const target = toggle.nextElementSibling;
      const collapsed = toggle.querySelector('.json-collapsed');
      if (target && collapsed) {
        const isHidden = target.style.display === 'none';
        target.style.display = isHidden ? '' : 'none';
        collapsed.style.display = isHidden ? 'none' : '';
      }
    });
  });
}

function renderValue(value, indent, expanded = false) {
  if (value === null) return '<span class="json-null">null</span>';
  if (typeof value === 'boolean') return `<span class="json-boolean">${value}</span>`;
  if (typeof value === 'number') return `<span class="json-number">${value}</span>`;
  if (typeof value === 'string') {
    const escaped = value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    return `<span class="json-string">"${escaped}"</span>`;
  }

  if (Array.isArray(value)) {
    if (value.length === 0) return '[]';
    const items = value.map(v => `${pad(indent + 1)}${renderValue(v, indent + 1)}`).join(',\n');
    const display = expanded ? '' : 'style="display:none"';
    const collapsedDisplay = expanded ? 'style="display:none"' : '';
    return `<span class="json-toggle">[<span class="json-collapsed" ${collapsedDisplay}>...${value.length} items]</span></span><span ${display}>\n${items}\n${pad(indent)}]</span>`;
  }

  if (typeof value === 'object') {
    const keys = Object.keys(value);
    if (keys.length === 0) return '{}';
    const items = keys.map(k => {
      const escaped = k.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      return `${pad(indent + 1)}<span class="json-key">"${escaped}"</span>: ${renderValue(value[k], indent + 1)}`;
    }).join(',\n');
    const display = expanded ? '' : 'style="display:none"';
    const collapsedDisplay = expanded ? 'style="display:none"' : '';
    return `<span class="json-toggle">{<span class="json-collapsed" ${collapsedDisplay}>...${keys.length} keys}</span></span><span ${display}>\n${items}\n${pad(indent)}}</span>`;
  }

  return String(value);
}

function pad(level) {
  return '  '.repeat(level);
}
