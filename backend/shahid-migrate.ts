import { readFile } from "node:fs/promises";
import { Pool } from "pg";

const url = process.env.DATABASE_URL;
if (!url) throw new Error("DATABASE_URL is required");
const pool = new Pool({ connectionString: url, max: 5 });

async function main() {
  await pool.query("CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())");
  const base = "001_initial";
  const existing = await pool.query("SELECT 1 FROM schema_migrations WHERE version=$1",[base]);
  if (!existing.rowCount) {
    await pool.query(await readFile("database/schema.sql","utf8"));
    await pool.query("INSERT INTO schema_migrations(version) VALUES($1)",[base]);
    console.log("applied 001_initial");
  }
  const security = "002_security_runtime";
  const done = await pool.query("SELECT 1 FROM schema_migrations WHERE version=$1",[security]);
  if (!done.rowCount) {
    await pool.query(await readFile("database/migrations/002_security_runtime.sql","utf8"));
    await pool.query("INSERT INTO schema_migrations(version) VALUES($1)",[security]);
    console.log("applied 002_security_runtime");
  }
}
main().finally(()=>pool.end()).catch(e=>{console.error(e);process.exit(1);});
