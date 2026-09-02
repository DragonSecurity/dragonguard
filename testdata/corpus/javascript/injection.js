// Never imported. Fixtures for the JavaScript rules.
const crypto = require("crypto");
const cp = require("child_process");

// dragon-js-sql-string-concat
function find(db, id) {
  return db.query("SELECT * FROM users WHERE id = " + id);
}

// dragon-js-command-injection
function remove(name) {
  cp.exec("rm -rf " + name);
}

// dragon-js-eval-on-variable
function evaluate(input) {
  return eval(input);
}

// dragon-js-weak-hash-for-passwords
function hash(pw) {
  return crypto.createHash("md5").update(pw).digest("hex");
}

// dragon-js-insecure-random-for-secrets
// The rule keys on the variable NAME as well as the call, so this fixture has
// to assign to something that reads like a secret -- a bare Math.random() is
// not the finding, using it for a token is.
function token() {
  const sessionToken = Math.random().toString(36);
  return sessionToken;
}
