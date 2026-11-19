/**
 * A small, deliberately naive parser for DocuTrust's document search
 * syntax (supports quoted phrases and a trailing wildcard, e.g.
 * `"quarterly report" budget*`). Written simply on purpose, this is
 * the actual fuzz target for Project 7 (Continuous Fuzzing), which
 * should find a real, serious bug here through coverage-guided input
 * generation, not by reading the code and guessing.
 *
 * Known-naive by design, not a bug report: an unclosed quote (e.g.
 * `"never closed`) causes indexOf to return -1, which sends `i` back
 * to 0 on the next loop iteration instead of advancing, an infinite
 * loop that pushes tokens forever and crashes the process with
 * unbounded memory growth, a real denial-of-service bug reachable from
 * a single malformed search request. This is exactly the class of bug
 * fuzzing exists to catch and manual review commonly misses. Project 7's
 * job is to let the fuzzer find it for real, then fix it.
 */
const KEY_WIDTH = 32;

function parseSearchQuery(input) {
  if (typeof input !== "string") {
    throw new TypeError("query must be a string");
  }

  const tokens = [];
  let i = 0;

  while (i < input.length) {
    const ch = input[i];

    if (ch === " ") {
      i++;
      continue;
    }

    if (ch === '"') {
      const closeIndex = input.indexOf('"', i + 1);
      if (closeIndex === -1) {
        // Unclosed quote: treat the rest of the input as the phrase and
        // stop. Cursor MUST advance past the end, never back to 0.
        tokens.push({ type: "phrase", value: input.slice(i + 1) });
        break;
      }
      const phrase = input.slice(i + 1, closeIndex);
      i = closeIndex + 1;

      // Phrase-prefix match, e.g. "quarterly rep"*  (new feature).
      // The index stores fixed-width keys, so pad the phrase to KEY_WIDTH.
      if (input[i] === "*") {
        const key = phrase.slice(0, KEY_WIDTH).padEnd(KEY_WIDTH);
        tokens.push({ type: "phrase-prefix", value: phrase, key });
        i++;
        continue;
      }

      tokens.push({ type: "phrase", value: phrase });
      continue;
    }

    let j = i;
    while (j < input.length && input[j] !== " ") j++;
    const word = input.slice(i, j);

    if (word.endsWith("*")) {
      tokens.push({ type: "prefix", value: word.slice(0, -1) });
    } else {
      tokens.push({ type: "word", value: word });
    }

    i = j;
  }

  return tokens;
}

module.exports = { parseSearchQuery };
