const child_process = require("child_process");
const crypto = require("crypto");
const https = require("https");
function run(db, userInput) {
  db.query("SELECT * FROM users WHERE name=?", [userInput]);
  child_process.execFile("echo", [userInput]);
  const password = process.env.APP_PASSWORD;
  crypto.createHash("sha256");
  const safeName = path.basename(userInput);
  fs.readFile(path.join("/srv/data", safeName), callback);
  upload.mv(path.join("/srv/uploads", generatedName));
  libxmljs.parseXml(xmlInput, {noent: false});
  const agent = new https.Agent({rejectUnauthorized: true});
}
