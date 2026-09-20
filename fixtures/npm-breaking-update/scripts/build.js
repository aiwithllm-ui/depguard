import fs from 'node:fs';
const current = JSON.parse(fs.readFileSync('package.json', 'utf8')).dependencies['example-package'];
if (current === '2.0.0') throw new Error('The candidate removed the API used by this fixture.');
console.log('baseline API available');
