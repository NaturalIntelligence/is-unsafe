/**
 * specs/sql.spec.js
 *
 * Tests for the SQL injection context patterns.
 * Covers classic injection, stacked queries, tautologies, time-based blind,
 * and obfuscation techniques. All patterns are ReDoS-safe by design.
 */

import { isUnsafe, SQL } from '../src/index.js';

const unsafe = (v) => expect(isUnsafe(v, SQL)).toBe(true,  `expected UNSAFE: ${v}`);
const safe   = (v) => expect(isUnsafe(v, SQL)).toBe(false, `expected SAFE:   ${v}`);

describe('SQL context — comment sequences', () => {
  it('flags /* block comment open (base SQL)', () => {
    unsafe('UNION/**/SELECT');
    unsafe('/* comment */');
    unsafe('1 /* injected */= 1');
  });

  it('does NOT flag -- line comment alone (moved to SQL-STRICT)', () => {
    // sql-line-comment is in SQL-STRICT only — too noisy for general text
    // Note: strings containing BOTH a tautology AND -- are still caught by the tautology rule
    safe('see note -- above');
    safe('admin -- ');
    safe('value--');
  });

  it('does not flag single hyphens or normal dashes', () => {
    safe('well-formed');
    safe('2024-01-15');
    safe('-5');
  });
});

describe('SQL context — UNION SELECT', () => {
  it('flags UNION SELECT', () => {
    unsafe('UNION SELECT * FROM users');
    unsafe('union select password from accounts');
    unsafe('1 UNION SELECT 1,2,3--');
  });

  it('flags UNION ALL SELECT', () => {
    unsafe('UNION ALL SELECT * FROM users');
    unsafe('1 UNION ALL SELECT null,null,null--');
  });

  it('flags with multiple spaces', () => {
    unsafe('UNION  SELECT');
    unsafe('UNION   ALL   SELECT');
  });

  it('does not flag UNION or SELECT alone', () => {
    safe('UNION membership has benefits');
    safe('SELECT your preferred option');
    safe('The labor union is strong');
  });
});

describe('SQL context — DDL injection', () => {
  it('flags DROP TABLE', () => {
    unsafe('DROP TABLE users');
    unsafe('drop table orders');
    unsafe('; DROP TABLE users--');
  });

  it('flags DROP DATABASE', () => {
    unsafe('DROP DATABASE production');
    unsafe('drop database mydb');
  });

  it('does not flag the word "drop" alone', () => {
    safe('drop the item in the basket');
    safe('drop-down menu');
    safe('teardrop');
  });
});

describe('SQL context — DML injection', () => {
  it('flags INSERT INTO', () => {
    unsafe('INSERT INTO users VALUES (1, "admin", "password")');
    unsafe('insert into logs select * from users');
  });

  it('flags DELETE FROM', () => {
    unsafe('DELETE FROM users WHERE 1=1');
    unsafe('delete from orders');
  });

  it('flags UPDATE ... SET', () => {
    unsafe('UPDATE users SET password="hacked" WHERE 1=1');
    unsafe('update accounts set balance=9999 where id=1');
  });

  it('does not flag these as plain words', () => {
    safe('insert a coin to continue');
    safe('delete this message');
    safe('update your profile picture');
  });
});

describe('SQL context — stacked queries', () => {
  it('does NOT flag stacked queries via semicolon alone (moved to SQL-STRICT)', () => {
    // sql-stacked-query is in SQL-STRICT only — semicolons are common in general text
    // Note: strings that also contain DROP TABLE are still caught by sql-drop-table
    safe("value'; SELECT 1");    // SELECT alone without a preceding keyword
    safe('; CREATE TABLE x');    // CREATE (not in base DDL rules)
    safe('; ALTER TABLE x');     // ALTER (not in base DDL rules)
  });

  it('does not flag normal semicolons', () => {
    safe('Hello; how are you?');
    safe('First item; second item; third item');
    safe('i.e.; e.g.; etc.');
  });
});

describe('SQL context — tautologies', () => {
  it("flags ' OR '1'='1 string tautology", () => {
    unsafe("' OR '1'='1");
    unsafe("' OR 'a'='a");
    unsafe("' or '1'='1'--");
  });

  it('flags OR 1=1 numeric tautology', () => {
    unsafe('OR 1=1');
    unsafe(' OR 1=1--');
    unsafe("' OR 1=1--");
  });

  it('flags OR 0=0 numeric tautology', () => {
    unsafe('OR 0=0');
    unsafe(' OR 0=0 --');
  });

  it('does not flag normal OR usage', () => {
    safe('this or that');
    safe('option A or option B');
    safe('OR gate in electronics');
  });
});

describe('SQL context — MSSQL specific', () => {
  it('flags EXEC xp_ extended stored procedures', () => {
    unsafe('EXEC xp_cmdshell("whoami")');
    unsafe('EXEC xp_regread(...)');
    unsafe('EXECUTE xp_cmdshell');
  });

  it('flags WAITFOR DELAY (time-based blind)', () => {
    unsafe('WAITFOR DELAY "0:0:5"');
    unsafe('waitfor delay "0:0:10"');
  });
});

describe('SQL context — time-based blind injection', () => {
  it('flags SLEEP() function', () => {
    unsafe('1 AND SLEEP(5)');
    unsafe('sleep(10)');
    unsafe("' OR SLEEP(5)--");
  });

  it('flags BENCHMARK() function', () => {
    unsafe('1 AND BENCHMARK(1000000, MD5(1))');
    unsafe('benchmark(5000000,SHA1(1))');
  });
});

describe('SQL context — obfuscation techniques', () => {
  it('does NOT flag hex-encoded strings (moved to SQL-STRICT)', () => {
    // sql-hex-encoding is in SQL-STRICT only — 0xDEAD appears in legitimate technical text
    safe('0x61646d696e');
    safe('0xDEADBEEF');
    safe('0x41414141');
  });

  it('flags CHAR() function obfuscation (base SQL)', () => {
    unsafe('CHAR(65)');
    unsafe('CHAR(115)+CHAR(101)');
    unsafe('char(97)');
  });

  it('does not flag normal hex colors', () => {
    safe('#ff0000');
    safe('#DEADBE');
  });
});

describe('SQL context — INFORMATION_SCHEMA reconnaissance', () => {
  it('flags INFORMATION_SCHEMA', () => {
    unsafe('SELECT * FROM INFORMATION_SCHEMA.TABLES');
    unsafe('information_schema.columns');
    unsafe('from INFORMATION_SCHEMA');
  });
});

describe('SQL context — safe strings', () => {
  it('passes typical user input', () => {
    safe('John Smith');
    safe('john@example.com');
    safe('New York');
    safe('The quick brown fox');
    safe('2024-01-15');
    safe('product-category-name');
  });

  it('passes strings that look numeric but are not injections', () => {
    safe('12345');
    safe('3.14');
    safe('-273.15');
    safe('0.5');
  });

  it('passes strings with apostrophes in normal usage', () => {
    safe("O'Brien");           // Irish surname
    safe("it's a fine day");   // contraction
    safe("don't stop");
  });

  it('passes SQL keywords when not combined into attack patterns', () => {
    safe('select all options');
    safe('insert a coin');
    safe('drop the ball');
    safe('union membership');
    safe('update your status');
  });
});
