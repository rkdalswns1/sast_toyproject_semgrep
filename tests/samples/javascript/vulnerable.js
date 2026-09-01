const child_process = require("child_process");
const crypto = require("crypto");
const https = require("https");
function run(db, userInput, res) {
  db.query("SELECT * FROM users WHERE name=" + userInput);
  child_process.exec(userInput);
  const password = "secret";
  crypto.createHash("md5");
  res.send(userInput);
  fs.readFile("/srv/data/" + userInput, callback);
  upload.mv("/srv/uploads/" + upload.name);
  libxmljs.parseXml(xmlInput, {noent: true});
  const agent = new https.Agent({rejectUnauthorized: false});
}
