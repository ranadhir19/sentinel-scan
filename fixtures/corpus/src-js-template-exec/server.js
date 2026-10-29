const { exec } = require("child_process");
function convert(name, cb) {
  exec(`convert ${name} out.png`, cb);
}
