import { readFile } from "node:fs/promises";
import { Pool } from "pg";

const url = process.env.DATABASE_URL;
if (!url) throw new Error("DATABASE_URL is required");
const pool = new Pool({ connectionString: url, max: 5 });
try {
  const files = ["database/schema.sql", "database/migrations/002_security_runtime.sql"];
  for (const file of files) {
    const sql = await readFile(file, "utf8");
    await pool.query(sql);
    console.log(`applied ${file}`);
  }
} finally {
  await pool.end();
}
