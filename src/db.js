const { Pool } = require("pg");

// Some pg/Node combinations mis-parse `connectionString` and throw
// "SASL: SCRAM-SERVER-FIRST-MESSAGE: client password must be a string"
// even with a valid URL (see node-postgres#2757, #3210, #3223).
// Parsing it ourselves and passing discrete fields avoids the bug.
const dbUrl = new URL(process.env.DATABASE_URL);

const pool = new Pool({
  host: dbUrl.hostname,
  port: Number(dbUrl.port || 5432),
  user: decodeURIComponent(dbUrl.username),
  password: decodeURIComponent(dbUrl.password),
  database: dbUrl.pathname.replace(/^\//, ""),
  max: 10,
});

module.exports = { pool };
