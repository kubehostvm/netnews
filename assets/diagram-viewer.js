// Same-origin SVG objects preserve text selection, source links and node lookup.
function resizeDiagram(image, action) {
  const fit = image.parentElement.clientWidth;
  const current = image.getBoundingClientRect().width || fit;
  const natural = Number(image.dataset.width) || fit;
  const width = action === 'fit' ? fit : action === 'actual' ? natural : current * (action === 'in' ? 1.25 : 0.8);
  const bounded = Math.max(240, Math.min(12000, width));
  image.style.width = bounded + 'px';
  image.style.height = bounded * Number(image.dataset.ratio || 1) + 'px';
}

function findNodes(nodes, query) {
  const text = query.trim().toLowerCase();
  return text ? nodes.filter(node => node.textContent.toLowerCase().includes(text)) : [];
}

if (typeof document !== 'undefined') {
  document.querySelectorAll('.viewport object').forEach(image => {
    function initialize() {
      const svg = image.contentDocument?.documentElement;
      if (!svg || svg.localName !== 'svg') return;
      const box = svg.viewBox.baseVal;
      image.dataset.width = box.width * 4 / 3;
      image.dataset.ratio = box.height / box.width;
      svg.style.width = '100%';
      svg.style.height = '100%';
      const style = image.contentDocument.createElementNS('http://www.w3.org/2000/svg', 'style');
      style.textContent = '.search-match polygon,.search-match path,.search-match ellipse {stroke:#dc2626;stroke-width:4px;fill:#fef08a;}';
      svg.append(style);
      resizeDiagram(image, 'fit');
    }
    image.addEventListener('load', initialize);
    initialize();
  });
  document.querySelectorAll('[data-zoom]').forEach(button => {
    button.addEventListener('click', () => resizeDiagram(document.getElementById(button.dataset.target), button.dataset.zoom));
  });
  document.querySelectorAll('[data-search]').forEach(form => {
    let previous = '', index = -1;
    form.addEventListener('submit', event => {
      event.preventDefault();
      const image = document.getElementById(form.dataset.search);
      const nodes = [...(image.contentDocument?.querySelectorAll('g.node') || [])];
      const query = form.querySelector('input').value.trim();
      const matches = findNodes(nodes, query);
      nodes.forEach(node => node.classList.remove('search-match'));
      matches.forEach(node => node.classList.add('search-match'));
      index = query === previous ? (index + 1) % Math.max(1, matches.length) : 0;
      previous = query;
      form.querySelector('output').textContent = matches.length ? `${index + 1} / ${matches.length}` : '无匹配节点';
      if (!matches.length) return;
      resizeDiagram(image, 'actual');
      const rect = matches[index].getBoundingClientRect();
      const viewport = image.parentElement;
      viewport.scrollTo({ left: Math.max(0, rect.x + rect.width / 2 - viewport.clientWidth / 2), top: Math.max(0, rect.y + rect.height / 2 - viewport.clientHeight / 2) });
    });
  });
}

if (typeof module !== 'undefined') module.exports = { findNodes, resizeDiagram };
