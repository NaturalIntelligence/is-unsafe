/**
 * specs/core.spec.js
 *
 * Tests for the core isUnsafe / whyUnsafe / allUnsafe API surface:
 * argument validation, multi-context arrays, custom RegExp, and exports.
 */

import { isUnsafe, whyUnsafe, allUnsafe, VALID_CONTEXTS } from '../src/index.js';

describe('isUnsafe — input validation', () => {
  it('throws TypeError when value is not a string', () => {
    expect(() => isUnsafe(null, 'HTML')).toThrowError(TypeError);
    expect(() => isUnsafe(undefined, 'HTML')).toThrowError(TypeError);
    expect(() => isUnsafe(42, 'HTML')).toThrowError(TypeError);
    expect(() => isUnsafe({}, 'HTML')).toThrowError(TypeError);
    expect(() => isUnsafe([], 'HTML')).toThrowError(TypeError);
  });

  it('throws TypeError for unknown context string', () => {
    expect(() => isUnsafe('hello', 'UNKNOWN')).toThrowError(TypeError);
    expect(() => isUnsafe('hello', 'html')).toThrowError(TypeError); // case-sensitive
    expect(() => isUnsafe('hello', '')).toThrowError(TypeError);
  });

  it('throws TypeError for empty context array', () => {
    expect(() => isUnsafe('hello', [])).toThrowError(TypeError);
  });

  it('throws TypeError for unknown context inside array', () => {
    expect(() => isUnsafe('hello', ['HTML', 'NOTACONTEXT'])).toThrowError(TypeError);
  });

  it('throws TypeError when context is a number or object', () => {
    expect(() => isUnsafe('hello', 42)).toThrowError(TypeError);
    expect(() => isUnsafe('hello', {})).toThrowError(TypeError);
  });

  it('returns false for empty string in any context', () => {
    for (const ctx of VALID_CONTEXTS) {
      expect(isUnsafe('', ctx)).toBe(false);
    }
  });

  it('returns false for benign strings in all built-in contexts', () => {
    const safe = 'Hello, world! This is a perfectly normal sentence.';
    for (const ctx of VALID_CONTEXTS) {
      expect(isUnsafe(safe, ctx)).toBe(false, `expected safe in context ${ctx}`);
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
    expect(isUnsafe(xssPayload, ['HTML', 'SQL'])).toBe(true);
  });

  it('returns false if safe in all listed contexts', () => {
    expect(isUnsafe('hello world', ['HTML', 'SQL', 'SHELL'])).toBe(false);
  });

  it('returns true for a value unsafe in second context but not first', () => {
    const sqlPayload = "' OR 1=1 --";
    expect(isUnsafe(sqlPayload, ['HTML', 'SQL'])).toBe(true);
  });

  it('accepts a single-item array', () => {
    expect(isUnsafe('<script>x</script>', ['HTML'])).toBe(true);
    expect(isUnsafe('safe', ['HTML'])).toBe(false);
  });
});

describe('whyUnsafe', () => {
  it('returns null for safe strings', () => {
    expect(whyUnsafe('hello world', 'HTML')).toBeNull();
  });

  it('returns a MatchResult object for unsafe strings', () => {
    const result = whyUnsafe('<script>alert(1)</script>', 'HTML');
    expect(result).not.toBeNull();
    expect(result.context).toBe('HTML');
    expect(typeof result.id).toBe('string');
    expect(typeof result.description).toBe('string');
    expect(result.pattern).toBeInstanceOf(RegExp);
  });

  it('returns the first matching rule', () => {
    const result = whyUnsafe('<script>alert(1)</script>', 'HTML');
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
    const result = whyUnsafe("' OR 1=1--", ['HTML', 'SQL']);
    expect(result).not.toBeNull();
    expect(result.context).toBe('SQL');
  });
});

describe('allUnsafe', () => {
  it('returns empty array for safe string', () => {
    expect(allUnsafe('hello', 'HTML')).toEqual([]);
  });

  it('returns multiple matches when multiple rules fire', () => {
    const payload = '<script onload="x"></script>';
    const results = allUnsafe(payload, 'HTML');
    expect(results.length).toBeGreaterThan(1);
    const ids = results.map(r => r.id);
    expect(ids).toContain('html-script-open');
    expect(ids).toContain('html-script-close');
  });

  it('aggregates results across multiple contexts', () => {
    const payload = '<script>alert(1)</script>; DROP TABLE users--';
    const results = allUnsafe(payload, ['HTML', 'SQL']);
    const contexts = results.map(r => r.context);
    expect(contexts).toContain('HTML');
    expect(contexts).toContain('SQL');
  });

  it('returns MatchResult objects with correct shape', () => {
    const results = allUnsafe('<script>x</script>', 'HTML');
    for (const r of results) {
      expect(typeof r.context).toBe('string');
      expect(typeof r.id).toBe('string');
      expect(typeof r.description).toBe('string');
      expect(r.pattern).toBeInstanceOf(RegExp);
    }
  });
});

describe('VALID_CONTEXTS export', () => {
  it('exports an array of string context names', () => {
    expect(Array.isArray(VALID_CONTEXTS)).toBe(true);
    for (const c of VALID_CONTEXTS) {
      expect(typeof c).toBe('string');
    }
  });

  it('includes all built-in contexts', () => {
    expect(VALID_CONTEXTS).toContain('HTML');
    expect(VALID_CONTEXTS).toContain('XML');
    expect(VALID_CONTEXTS).toContain('SVG');
    expect(VALID_CONTEXTS).toContain('SQL');
    expect(VALID_CONTEXTS).toContain('SQL-STRICT');
    expect(VALID_CONTEXTS).toContain('SHELL');
    expect(VALID_CONTEXTS).toContain('REDOS');
    expect(VALID_CONTEXTS).toContain('NOSQL');
    expect(VALID_CONTEXTS).toContain('LOG');
  });

  it('has exactly the expected number of contexts', () => {
    expect(VALID_CONTEXTS.length).toBe(9);
  });
});
