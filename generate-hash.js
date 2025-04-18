const bcrypt = require('bcrypt');

async function generateHash() {
  const password = "superadmin123";  // Change this to your desired password
  const saltRounds = 10;
  const hash = await bcrypt.hash(password, saltRounds);
  console.log("Password:", password);
  console.log("Hash:", hash);
}

generateHash();