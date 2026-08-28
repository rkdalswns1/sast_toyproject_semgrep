const child_process = require("child_process");
const crypto = require("crypto");
function run(db, userInput) {
  db.query("SELECT * FROM users WHERE name=" + userInput);
  child_process.exec(userInput);
  const password = "secret";
  crypto.createHash("md5");
}
