const assert = require('node:assert/strict');
const { findNodes, resizeDiagram } = require('../assets/diagram-viewer.js');
const nodes = [{ textContent: 'tcp_filter()' }, { textContent: 'TC egress' }, { textContent: 'INPUT ipt_do_table()' }];
assert.deepEqual(findNodes(nodes, ' TCP_FILTER '), [nodes[0]]);
assert.deepEqual(findNodes(nodes, 'missing'), []);
assert.deepEqual(findNodes(nodes, ''), []);
assert.equal(findNodes(nodes, 'tc').length, 2);
const image = { parentElement: { clientWidth: 800 }, getBoundingClientRect: () => ({ width: 800 }), dataset: { width: '4000', ratio: '2' }, style: {} };
for (const [action, width] of [['fit', 800], ['in', 1000], ['out', 640], ['actual', 4000]]) {
  resizeDiagram(image, action);
  assert.equal(image.style.width, width + 'px');
  assert.equal(image.style.height, width * 2 + 'px');
}
console.log('Diagram search and zoom checks passed.');
