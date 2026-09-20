const test = require('node:test');
const assert = require('node:assert/strict');

test('application retains the baseline contract', () => {
  assert.equal(require('example-package')(), 'baseline');
});
