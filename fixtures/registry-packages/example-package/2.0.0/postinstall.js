const fs = require('node:fs');
fs.writeFileSync('/tmp/depguard-postinstall-marker', 'installed\n');
