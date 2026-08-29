const express = require("express");
const _ = require("lodash");
const { pool } = require("../db");
const { createDocumentSchema, createCommentSchema } = require("../validation");
const { parseSearchQuery } = require("../lib/searchQuery");
const { taint, checkSink } = require("../lib/taintTracer");

const router = express.Router();

router.post("/", async (req, res) => {
  const parsed = createDocumentSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "Invalid document data" });
  }

  try {
    const result = await pool.query(
      "INSERT INTO documents (title, body) VALUES ($1, $2) RETURNING id, title, body, created_at",
      [parsed.data.title, parsed.data.body]
    );
    const doc = _.cloneDeep(result.rows[0]);
    res.status(201).json(doc);
  } catch (err) {
    res.status(503).json({ error: "Database unavailable" });
  }
});

/**
 * SEEDED FINDING for Project 1 (SAST) and Project 3 (DAST): the query
 * below is built with raw string concatenation instead of a
 * parameterized query, a textbook SQL injection, deliberately left
 * exactly this way so a SAST rule and a real DAST payload both have a
 * genuine, findable target here, not a synthetic example bolted on
 * separately.
 *
 * PROJECT 3 DELIVERABLE 4 (IAST): req.query.q is wrapped in taint() at
 * the moment it enters this handler (the source). It is never passed
 * through sanitize() before being interpolated into the raw SQL string
 * below (the sink), so checkSink() will log a real, genuine taint-flow
 * finding — the actual technique, executed on a real request, not a
 * description of it.
 */
router.get("/search", async (req, res) => {
  const rawQ = req.query.q || "";
  const q = taint(rawQ, "req.query.q (GET /documents/search)");

  let tokens;
  try {
    tokens = parseSearchQuery(String(q));
  } catch (err) {
    return res.status(400).json({ error: "Invalid query" });
  }

  // searchTerm is derived directly from the tainted input, so it stays
  // tainted for the purposes of this tracer (a real IAST agent tracks
  // taint propagation through string operations automatically via
  // bytecode hooks; here we propagate it manually and explicitly, which
  // is the honest scope of a hand-built version of this technique).
  const searchTerm = taint(tokens.map((t) => t.value).join(" "), q.source);

  try {
    // VULNERABLE ON PURPOSE, see comment above.
    const query = `SELECT id, title FROM documents WHERE title ILIKE '%${searchTerm}%'`;
    checkSink(searchTerm, "SQL string interpolation in GET /documents/search", query);

    const result = await pool.query(query);
    res.json(result.rows);
  } catch (err) {
    console.error("SEARCH ERROR:", err);
    res.status(503).json({ error: "Database unavailable" });
  }
});

// NOTE: reordered below /search — Express matches routes in declaration
// order, and /:id previously matched "search" as a literal id value,
// silently breaking the /search endpoint. See main branch's fix comment.
router.get("/:id", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM documents WHERE id = $1", [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Not found" });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error("ID ROUTE ERROR:", err);
    res.status(503).json({ error: "Database unavailable" });
  }
});

/**
 * SEEDED FINDING for Project 1 (SAST) and Project 3 (DAST/IAST): the
 * document title is written into the HTML response without escaping.
 *
 * PROJECT 3 DELIVERABLE 4 (IAST): title/body were written by an
 * attacker-controlled POST body (see POST / above) and are never
 * escaped before reaching the raw HTML template below (the sink). We
 * mark them tainted at the point they're read back out of storage,
 * since that's where this handler re-introduces untrusted data into a
 * dangerous context, and checkSink() logs the real taint flow.
 */
router.get("/:id/render", async (req, res) => {
  try {
    const result = await pool.query("SELECT title, body FROM documents WHERE id = $1", [
      req.params.id,
    ]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Not found" });
    }
    const title = taint(result.rows[0].title, `documents.title (stored, originally from POST /documents body, doc id=${req.params.id})`);
    const body = taint(result.rows[0].body, `documents.body (stored, originally from POST /documents body, doc id=${req.params.id})`);

    // VULNERABLE ON PURPOSE: no escaping applied to `title` or `body`
    // before interpolating into HTML.
    const html = `<html><body><h1>${title}</h1><p>${body}</p></body></html>`;
    checkSink(title, "HTML string interpolation in GET /documents/:id/render (title)", html);
    checkSink(body, "HTML string interpolation in GET /documents/:id/render (body)", html);

    res.set("Content-Type", "text/html");
    res.send(html);
  } catch (err) {
    res.status(503).json({ error: "Database unavailable" });
  }
});

router.post("/:id/comments", async (req, res) => {
  const parsed = createCommentSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "Invalid comment data" });
  }

  try {
    const result = await pool.query(
      "INSERT INTO comments (document_id, body) VALUES ($1, $2) RETURNING id, body, created_at",
      [req.params.id, parsed.data.body]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(503).json({ error: "Database unavailable" });
  }
});

module.exports = router;
