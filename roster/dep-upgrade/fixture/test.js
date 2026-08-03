// Trivial passing test for the fixture package — plain node, no framework.
// Exercises the dependency so a broken lodash install would actually fail.
const _ = require("lodash");

if (_.add(1, 2) !== 3) {
  console.error("fixture test FAILED: lodash.add(1, 2) !== 3");
  process.exit(1);
}
if (_.chunk(["a", "b", "c", "d"], 2).length !== 2) {
  console.error("fixture test FAILED: lodash.chunk misbehaved");
  process.exit(1);
}
console.log(`fixture test ok (lodash ${_.VERSION})`);
