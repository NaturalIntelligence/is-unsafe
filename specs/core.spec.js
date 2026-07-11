/**
 * specs/core.spec.js
 *
 * Tests for the core isUnsafe / whyUnsafe / allUnsafe API surface:
 * argument validation, multi-context arrays, custom RegExp, and exports.
 */

import { isUnsafe, whyUnsafe, allUnsafe, VALID_CONTEXTS, HTML, XML, SQL, SHELL } from '../src/index.js';

describe('isUnsafe — input validation', () => {
  it('throws TypeError when value is not a string', () => {
    expect(() => isUnsafe(null, HTML)).toThrowError(TypeError);
    expect(() => isUnsafe(undefined, HTML)).toThrowError(TypeError);
    expect(() => isUnsafe(42, HTML)).toThrowError(TypeError);
    expect(() => isUnsafe({}, HTML)).toThrowError(TypeError);
    expect(() => isUnsafe([], HTML)).toThrowError(TypeError);
  });

  it('throws TypeError for empty array context', () => {
    expect(() => isUnsafe('hello', [])).toThrowError(TypeError);
  });

  it('throws TypeError when context is a number, string, or plain object', () => {
    expect(() => isUnsafe('hello', 42)).toThrowError(TypeError);
    expect(() => isUnsafe('hello', {})).toThrowError(TypeError);
    // Strings no longer valid — must pass a PatternList
    expect(() => isUnsafe('hello', 'HTML')).toThrowError(TypeError);
  });

  it('returns false for empty string in any context', () => {
    for (const ctx of Object.values(VALID_CONTEXTS)) {
      expect(isUnsafe('', ctx)).toBe(false);
    }
  });

  it('returns false for benign strings in all built-in contexts', () => {
    const safe = 'Hello, world! This is a perfectly normal sentence.';
    for (const [name, ctx] of Object.entries(VALID_CONTEXTS)) {
      expect(isUnsafe(safe, ctx)).toBe(false, `expected safe in context ${name}`);
    }
  });
});

describe('isUnsafe — custom RegExp context', () => {
  it('returns true when custom pattern matches', () => {
    expect(isUnsafe('foobar', /foo/)).toBe(true);
  });

  it('returns false when custom pattern does not match', () => {
    expect(isUnsafe('hello', /xyz/)).toBe(false);
  });

  it('respects regex flags on custom pattern', () => {
    expect(isUnsafe('FOO', /foo/i)).toBe(true);
    expect(isUnsafe('FOO', /foo/)).toBe(false);
  });
});

describe('isUnsafe — multi-context array', () => {
  it('returns true if unsafe in any listed context', () => {
    const xssPayload = '<script>alert(1)</script>';
    expect(isUnsafe(xssPayload, [HTML, SQL])).toBe(true);
  });

  it('returns false if safe in all listed contexts', () => {
    expect(isUnsafe('hello world', [HTML, SQL, SHELL])).toBe(false);
  });

  it('returns true for a value unsafe in second context but not first', () => {
    const sqlPayload = "' OR 1=1 --";
    expect(isUnsafe(sqlPayload, [HTML, SQL])).toBe(true);
  });

  it('accepts a single-item array', () => {
    expect(isUnsafe('<script>x</script>', [HTML])).toBe(true);
    expect(isUnsafe('safe', [HTML])).toBe(false);
  });
});

describe('whyUnsafe', () => {
  it('returns null for safe strings', () => {
    expect(whyUnsafe('hello world', HTML)).toBeNull();
  });

  it('returns a MatchResult object for unsafe strings', () => {
    const result = whyUnsafe('<script>alert(1)</script>', HTML);
    expect(result).not.toBeNull();
    expect(result.context).toBe('HTML');
    expect(typeof result.id).toBe('string');
    expect(typeof result.description).toBe('string');
    expect(result.pattern).toBeInstanceOf(RegExp);
  });

  it('returns the first matching rule', () => {
    const result = whyUnsafe('<script>alert(1)</script>', HTML);
    expect(result.id).toBe('html-script-open');
  });

  it('works with custom RegExp', () => {
    const result = whyUnsafe('danger', /danger/);
    expect(result.context).toBe('CUSTOM');
    expect(result.id).toBe('custom-regex');
  });

  it('returns null for custom RegExp that does not match', () => {
    expect(whyUnsafe('safe string', /never-matches-xyz/)).toBeNull();
  });

  it('works with multi-context array', () => {
    const result = whyUnsafe("' OR 1=1--", [HTML, SQL]);
    expect(result).not.toBeNull();
    expect(result.context).toBe('SQL');
  });
});

describe('allUnsafe', () => {
  it('returns empty array for safe string', () => {
    expect(allUnsafe('hello', HTML)).toEqual([]);
  });

  it('returns multiple matches when multiple rules fire', () => {
    const payload = '<script onload="x"></script>';
    const results = allUnsafe(payload, HTML);
    expect(results.length).toBeGreaterThan(1);
    const ids = results.map(r => r.id);
    expect(ids).toContain('html-script-open');
    expect(ids).toContain('html-script-close');
  });

  it('aggregates results across multiple contexts', () => {
    const payload = '<script>alert(1)</script>; DROP TABLE users--';
    const results = allUnsafe(payload, [HTML, SQL]);
    const contexts = results.map(r => r.context);
    expect(contexts).toContain('HTML');
    expect(contexts).toContain('SQL');
  });

  it('returns MatchResult objects with correct shape', () => {
    const results = allUnsafe('<script>x</script>', HTML);
    for (const r of results) {
      expect(typeof r.context).toBe('string');
      expect(typeof r.id).toBe('string');
      expect(typeof r.description).toBe('string');
      expect(r.pattern).toBeInstanceOf(RegExp);
    }
  });
});

describe('VALID_CONTEXTS export', () => {
  it('exports pattern arrays (PatternList) for each context', () => {
    for (const ctx of Object.values(VALID_CONTEXTS)) {
      expect(Array.isArray(ctx)).toBe(true);
      expect(ctx.length).toBeGreaterThan(0);
    }
  });

  it('includes all built-in contexts', () => {
    expect(Array.isArray(VALID_CONTEXTS.HTML)).toBe(true);
    expect(Array.isArray(VALID_CONTEXTS.XML)).toBe(true);
    expect(Array.isArray(VALID_CONTEXTS.SVG)).toBe(true);
    expect(Array.isArray(VALID_CONTEXTS.SQL)).toBe(true);
    expect(Array.isArray(VALID_CONTEXTS['SQL-STRICT'])).toBe(true);
    expect(Array.isArray(VALID_CONTEXTS.SHELL)).toBe(true);
    expect(Array.isArray(VALID_CONTEXTS.REDOS)).toBe(true);
    expect(Array.isArray(VALID_CONTEXTS.NOSQL)).toBe(true);
    expect(Array.isArray(VALID_CONTEXTS.LOG)).toBe(true);
  });

  it('has exactly the expected number of contexts', () => {
    expect(Object.keys(VALID_CONTEXTS).length).toBe(9);
  });

  it('named exports match VALID_CONTEXTS entries', () => {
    expect(VALID_CONTEXTS.HTML).toBe(HTML);
    expect(VALID_CONTEXTS.XML).toBe(XML);
    expect(VALID_CONTEXTS.SQL).toBe(SQL);
  });
});

describe('named context exports', () => {
  it('HTML is a usable PatternList', () => {
    expect(isUnsafe('<script>x</script>', HTML)).toBe(true);
  });

  it('XML is a usable PatternList', () => {
    expect(isUnsafe('<!DOCTYPE foo>', XML)).toBe(true);
  });

  it('context label in MatchResult matches the export name', () => {
    const result = whyUnsafe('<script>x</script>', HTML);
    expect(result.context).toBe('HTML');

    const xmlResult = whyUnsafe('<!DOCTYPE foo>', XML);
    expect(xmlResult.context).toBe('XML');
  });
});
