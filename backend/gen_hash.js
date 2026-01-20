const bcrypt = require('bcryptjs');
const hash = bcrypt.hashSync('Admin@2024!', 10);
console.log(hash);
