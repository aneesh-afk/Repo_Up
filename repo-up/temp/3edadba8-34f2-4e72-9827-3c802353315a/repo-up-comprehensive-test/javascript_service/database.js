const crypto = require('crypto');

function hash() {
    // Weak crypto
    return crypto.createHash('md5').update('test').digest('hex');
}
