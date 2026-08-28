const child_process = require("child_process");
const crypto = require("crypto");
function run(db, userInput) {
  db.query("SELECT * FROM users WHERE name=?", [userInput]);
  child_process.execFile("echo", [userInput]);
  const password = process.env.APP_PASSWORD;
  crypto.createHash("sha256");
}
