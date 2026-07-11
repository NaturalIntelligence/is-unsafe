/**
 * specs/sql-strict.spec.js
 *
 * Tests for the SQL-STRICT context.
 *
 * SQL-STRICT = all SQL rules + three extra noisy ones:
 *   sql-line-comment   (--\s or --)
 *   sql-stacked-query  (; SELECT / ; DROP etc.)
 *   sql-hex-encoding   (0x41414141)
 *
 * Also covers the SQL vs SQL-STRICT distinction — strings that should be
 * safe in SQL (high-precision) but flagged in SQL-STRICT (exhaustive).
 */

import { isUnsafe, allUnsafe, SQL, SQL_STRICT } from '../src/index.js';

const strictUnsafe = (v) => expect(isUnsafe(v, SQL_STRICT)).toBe(true,  `expected UNSAFE in SQL-STRICT: ${v}`);
const strictSafe   = (v) => expect(isUnsafe(v, SQL_STRICT)).toBe(false, `expected SAFE in SQL-STRICT:   ${v}`);
const baseUnsafe   = (v) => expect(isUnsafe(v, SQL)).toBe(true,  `expected UNSAFE in SQL: ${v}`);
const baseSafe     = (v) => expect(isUnsafe(v, SQL)).toBe(false, `expected SAFE in SQL:   ${v}`);

// ─── Rules shared with base SQL ─────────────────────────────────────────────

describe('SQL-STRICT context — inherits all base SQL rules', () => {
  it('flags UNION SELECT', () => {
    strictUnsafe('UNION SELECT * FROM users');
    strictUnsafe('1 UNION ALL SELECT null,null--');
  });

  it('flags DROP TABLE / DATABASE', () => {
    strictUnsafe('DROP TABLE users');
    strictUnsafe('DROP DATABASE production');
  });

  it('flags INSERT INTO / DELETE FROM / UPDATE SET', () => {
    strictUnsafe('INSERT INTO users VALUES (1,"admin")');
    strictUnsafe('DELETE FROM logs WHERE 1=1');
    strictUnsafe('UPDATE users SET password="x" WHERE id=1');
  });

  it('flags tautologies', () => {
    strictUnsafe("' OR '1'='1");
    strictUnsafe('OR 1=1');
    strictUnsafe('OR 0=0');
  });

  it('flags time-based blind injection', () => {
    strictUnsafe('AND SLEEP(5)');
    strictUnsafe('WAITFOR DELAY "0:0:5"');
    strictUnsafe('BENCHMARK(1000000,MD5(1))');
  });

  it('flags INFORMATION_SCHEMA and EXEC xp_', () => {
    strictUnsafe('INFORMATION_SCHEMA.TABLES');
    strictUnsafe('EXEC xp_cmdshell("whoami")');
  });
});

// ─── Rules exclusive to SQL-STRICT ──────────────────────────────────────────

describe('SQL-STRICT context — exclusive: sql-line-comment', () => {
  it('flags -- followed by whitespace', () => {
    strictUnsafe("' OR '1'='1' -- ");
    strictUnsafe('admin -- ');
  });

  it('flags -- at end of string', () => {
    strictUnsafe("' OR 1=1--");
    strictUnsafe('value--');
  });

  it('safe in base SQL context — "see note -- above"', () => {
    baseSafe('see note -- above');
    baseSafe('value-- ');
  });
});

describe('SQL-STRICT context — exclusive: sql-stacked-query', () => {
  it('flags semicolon followed by SQL keyword', () => {
    strictUnsafe('; SELECT * FROM users');
    strictUnsafe('; DROP TABLE users');
    strictUnsafe('; INSERT INTO admin VALUES (1)');
    strictUnsafe('; DELETE FROM logs');
    strictUnsafe('; UPDATE users SET admin=1');
    strictUnsafe('; EXEC xp_cmdshell("dir")');
  });

  it('safe in base SQL — normal prose with semicolons', () => {
    baseSafe('Hello; how are you?');
    baseSafe('First item; second item; third item');
  });
});

describe('SQL-STRICT context — exclusive: sql-hex-encoding', () => {
  it('flags 0x hex strings with 4+ hex digits', () => {
    strictUnsafe('0x61646d696e');
    strictUnsafe('0xDEADBEEF');
    strictUnsafe('0x41414141');
  });

  it('does not flag short hex values', () => {
    strictSafe('0xff');
    strictSafe('0x1a');
  });

  it('safe in base SQL — technical hex in docs/logs', () => {
    baseSafe('0xDEAD');
    baseSafe('0xCAFE');
    baseSafe('value 0xDEADBEEF in log');
  });
});

// ─── SQL vs SQL-STRICT comparison ─────────────────────────────────────────

describe('SQL vs SQL-STRICT — false-positive comparison', () => {
  const generalTextSamples = [
    'see note -- above',       // double dash in prose
    'value--',                 // double dash suffix
    '0xDEAD',                  // hex in technical text
    '0xCAFEBABE',              // hex constant
    'Paris; Lyon; Marseille',  // semicolons in list
    'Hello; how are you?',     // semicolons in prose
  ];

  it('base SQL passes all general-text strings', () => {
    for (const s of generalTextSamples) {
      baseSafe(s);
    }
  });

  it('SQL-STRICT flags some general-text strings (expected false positives)', () => {
    // These are the strings SQL-STRICT flags that SQL does not
    strictUnsafe('see note -- above');
    strictUnsafe('value--');
    strictUnsafe('0xCAFEBABE');
  });

  const realInjections = [
    "' OR 1=1--",
    'UNION SELECT * FROM users',
    'DROP TABLE users',
    '; DELETE FROM logs',
    'EXEC xp_cmdshell("whoami")',
  ];

  it('both SQL and SQL-STRICT catch real injection payloads', () => {
    for (const s of realInjections) {
      baseUnsafe(s);
      strictUnsafe(s);
    }
  });
});

// ─── SQL-STRICT safe strings ─────────────────────────────────────────────

describe('SQL-STRICT context — safe strings', () => {
  it('passes typical user input', () => {
    strictSafe('John Smith');
    strictSafe('john@example.com');
    strictSafe('New York');
    strictSafe('2024-01-15');
    strictSafe('product-category-name');
  });

  it('passes apostrophes in normal usage', () => {
    strictSafe("O'Brien");
    strictSafe("it's a fine day");
  });

  it('passes SQL keywords as standalone words', () => {
    strictSafe('select all options');
    strictSafe('drop the ball');
    strictSafe('delete this message');
    strictSafe('update your status');
  });
});
