/**
 * raspMiddleware.js — hand-built RASP-style request-blocking middleware
 * for DocuTrust.
 *
 * SCOPE, STATED HONESTLY (per Project 3's brief): this is illustrative
 * infrastructure demonstrating the real underlying RASP mechanism —
 * inspecting requests at runtime and blocking ones that match known
 * attack signatures before they reach vulnerable application code. It is
 * NOT a production-grade RASP product. Real RASP tools (e.g. Contrast,
 * Sqreen) hook deep into the runtime (bytecode/AST instrumentation) to
 * catch attacks based on actual data flow into dangerous sinks, not just
 * pattern-matching on the request surface. This middleware uses simple,
 * targeted signature matching against the two seeded vulnerability
 * classes in this app (SQL injection via the `q` search param, XSS via
 * document title/body), which is enough to prove the real mechanism —
 * intercept-and-block before the vulnerable code runs — without
 * pretending to be a general-purpose product.
 *
 * Disable with the RASP_ENABLED=false environment variable — documented
 * here explicitly since a security control with no visible off-switch is
 * its own operational risk.
 */

const SQLI_PATTERNS = [
  /'\s*or\s*'?\d*'?\s*=\s*'?\d*'?/i, // ' OR '1'='1
  /'\s*or\s*1\s*=\s*1/i, // ' OR 1=1
  /--/, // SQL comment, used to truncate the rest of a query
  /;\s*(drop|delete|insert|update)\s/i, // stacked destructive statements
  /union\s+select/i,
];

const XSS_PATTERNS = [
  /<script[\s>]/i,
  /on\w+\s*=\s*['"]/i, // onerror=, onload=, etc.
  /javascript:/i,
  /<iframe[\s>]/i,
];

function matchesAny(value, patterns) {
  if (typeof value !== "string") return null;
  for (const pattern of patterns) {
    if (pattern.test(value)) return pattern.toString();
  }
  return null;
}

/**
 * Inspects query params and JSON body fields for known SQLi/XSS
 * signatures. Blocks with 403 and logs the match before the request
 * reaches any route handler.
 */
function raspMiddleware(req, res, next) {
  if (process.env.RASP_ENABLED === "false") {
    return next();
  }

  const fieldsToCheck = [
    ...Object.entries(req.query || {}),
    ...Object.entries(req.body || {}),
  ];

  for (const [field, value] of fieldsToCheck) {
    const sqliMatch = matchesAny(value, SQLI_PATTERNS);
    if (sqliMatch) {
      console.warn(
        `[RASP] BLOCKED SQLi attempt\n` +
          `  field:   ${field}\n` +
          `  value:   ${JSON.stringify(value)}\n` +
          `  pattern: ${sqliMatch}\n` +
          `  path:    ${req.method} ${req.originalUrl}\n`
      );
      return res.status(403).json({ error: "Request blocked by RASP: SQL injection pattern detected" });
    }

    const xssMatch = matchesAny(value, XSS_PATTERNS);
    if (xssMatch) {
      console.warn(
        `[RASP] BLOCKED XSS attempt\n` +
          `  field:   ${field}\n` +
          `  value:   ${JSON.stringify(value)}\n` +
          `  pattern: ${xssMatch}\n` +
          `  path:    ${req.method} ${req.originalUrl}\n`
      );
      return res.status(403).json({ error: "Request blocked by RASP: XSS pattern detected" });
    }
  }

  next();
}

module.exports = { raspMiddleware };
