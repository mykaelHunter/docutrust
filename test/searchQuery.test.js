const test = require("node:test");
const assert = require("node:assert");
const { parseSearchQuery } = require("../src/lib/searchQuery");

test("regression: unclosed quote + newline (Project 7 fuzzer input) terminates", { timeout: 2000 }, () => {
  // Exact input found by Jazzer.js: bytes 0x22 0x0a
  assert.deepStrictEqual(parseSearchQuery('"\n'), [{ type: "phrase", value: "\n" }]);
});

test("unclosed quote keeps the rest of the input as the phrase", { timeout: 2000 }, () => {
  assert.deepStrictEqual(parseSearchQuery('"never closed'), [{ type: "phrase", value: "never closed" }]);
});

test("lone quote terminates", { timeout: 2000 }, () => {
  assert.deepStrictEqual(parseSearchQuery('"'), [{ type: "phrase", value: "" }]);
});

test("closed phrases and prefixes still parse", () => {
  assert.deepStrictEqual(parseSearchQuery('"quarterly report" budget*'), [
    { type: "phrase", value: "quarterly report" },
    { type: "prefix", value: "budget" },
  ]);
});

test("text after an unclosed quote is not parsed as separate tokens", { timeout: 2000 }, () => {
  assert.deepStrictEqual(parseSearchQuery('a "b c'), [
    { type: "word", value: "a" },
    { type: "phrase", value: "b c" },
  ]);
});

test("phrase-prefix: short phrase followed by * parses", () => {
  assert.deepStrictEqual(
    parseSearchQuery('"quarterly rep"*').map((t) => [t.type, t.value]),
    [["phrase-prefix", "quarterly rep"]]
  );
});
