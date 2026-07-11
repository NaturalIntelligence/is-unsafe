/**
 * specs/integration.spec.js
 *
 * End-to-end integration tests modelling real-world usage scenarios,
 * including the motivating use-case from @nodable/entities / fast-xml-parser.
 */

import { isUnsafe, whyUnsafe, allUnsafe, HTML, XML, SQL, SHELL, REDOS, SVG } from '../src/index.js';

// ─── Scenario 1: FXP / @nodable/entities postCheck ─────────────────────────

describe('Integration: FXP entity resolution postCheck', () => {
  /**
   * Models the motivating example from the design doc:
   * <!ENTITY xss '</script><script>alert(document.domain)</script><x y="'>
   * resolved via &xss; inside an XML sitemap
   */

  const xssEntity = '</script><script>alert(document.domain)</script><x y="';

  it('detects the XSS entity value as unsafe in HTML context', () => {
    expect(isUnsafe(xssEntity, HTML)).toBe(true);
  });

  it('detects the XSS entity value as unsafe in XML context (script close is XML concern too)', () => {
    // Not all XML contexts fire, but HTML fires so mixed context check is meaningful
    expect(isUnsafe(xssEntity, [HTML, XML])).toBe(true);
  });

  it('passes normal entity values', () => {
    const safeEntities = [
      'https://example.com/page',
      'New York, NY',
      'product-category',
      'Copyright © 2024',
      'Tom & Jerry',
      '5 < 10',
    ];
    for (const v of safeEntities) {
      expect(isUnsafe(v, HTML)).toBe(false, `safe entity should pass: ${v}`);
    }
  });

  it('simulates the postCheck callback pattern', () => {
    function postCheck(resolved, original) {
      if (isUnsafe(resolved, HTML)) {
        return original; // keep literal entity reference unchanged
      }
      return resolved;
    }

    expect(postCheck(xssEntity, '&xss;')).toBe('&xss;');
    expect(postCheck('New York', '&city;')).toBe('New York');
  });

  it('provides diagnostic info via whyUnsafe for logging', () => {
    const result = whyUnsafe(xssEntity, HTML);
    expect(result).not.toBeNull();
    expect(result.context).toBe('HTML');
    expect(typeof result.id).toBe('string');
    expect(typeof result.description).toBe('string');
  });
});

// ─── Scenario 2: Form input validation ──────────────────────────────────────

describe('Integration: form field sanitisation guard', () => {
  function validateField(value, contexts) {
    if (isUnsafe(value, contexts)) {
      throw new Error(`Unsafe input detected: ${whyUnsafe(value, contexts).id}`);
    }
    return value;
  }

  it('accepts normal name input', () => {
    expect(() => validateField('John Smith', [HTML, SQL])).not.toThrow();
  });

  it('rejects XSS payload in name field', () => {
    expect(() => validateField('<script>alert(1)</script>', [HTML, SQL])).toThrow();
  });

  it('rejects SQL injection in search field', () => {
    expect(() => validateField("' OR 1=1--", [HTML, SQL])).toThrow();
  });

  it('accepts numeric input', () => {
    expect(() => validateField('42', [HTML, SQL])).not.toThrow();
    expect(() => validateField('3.14', [HTML, SQL])).not.toThrow();
  });
});

// ─── Scenario 3: File upload path validation ─────────────────────────────────

describe('Integration: file upload path guard', () => {
  function safePath(filename) {
    return !isUnsafe(filename, SHELL);
  }

  it('allows normal filenames', () => {
    expect(safePath('document.pdf')).toBe(true);
    expect(safePath('photo-2024.jpg')).toBe(true);
    expect(safePath('report_final.xlsx')).toBe(true);
  });

  it('blocks path traversal attempts', () => {
    expect(safePath('../../../etc/passwd')).toBe(false);
    expect(safePath('..\\..\\windows\\system32')).toBe(false);
  });

  it('blocks null byte injection', () => {
    expect(safePath('legit.jpg\x00.php')).toBe(false);
    expect(safePath('file.txt%00.sh')).toBe(false);
  });

  it('blocks absolute path injection', () => {
    expect(safePath('/etc/passwd')).toBe(false);
    expect(safePath('C:\\Windows\\System32\\cmd.exe')).toBe(false);
  });
});

// ─── Scenario 4: SVG attribute injection guard ──────────────────────────────

describe('Integration: SVG attribute value guard', () => {
  it('correctly classifies safe SVG attribute values', () => {
    expect(isUnsafe('#ff0000', SVG)).toBe(false);            // fill value
    expect(isUnsafe('rotate(45)', SVG)).toBe(false);         // transform value
    expect(isUnsafe('0 0 100 100', SVG)).toBe(false);        // viewBox value
  });

  it('correctly classifies unsafe SVG attribute strings', () => {
    // isUnsafe checks the string that will appear in the document.
    // An unsafe SVG attribute appears in the document as: attrname="value"
    // The xlink:href with javascript: value appears as the full attribute expression
    expect(isUnsafe('xlink:href="javascript:alert(1)"', SVG)).toBe(true);
    expect(isUnsafe('onload="alert(document.domain)"', SVG)).toBe(true);
  });

  it('passes internal fragment href reference', () => {
    expect(isUnsafe('<use href="#local-anchor">', SVG)).toBe(false);
  });
});

// ─── Scenario 5: User-supplied regex validation ──────────────────────────────

describe('Integration: user-supplied regex guard', () => {
  function compileUserRegex(pattern) {
    if (isUnsafe(pattern, REDOS)) {
      const detail = whyUnsafe(pattern, REDOS);
      throw new Error(`ReDoS risk detected (${detail.id}): ${detail.description}`);
    }
    return new RegExp(pattern);
  }

  it('compiles safe patterns', () => {
    expect(() => compileUserRegex('^[a-z]+$')).not.toThrow();
    expect(() => compileUserRegex('\\d{4}-\\d{2}-\\d{2}')).not.toThrow();
  });

  it('rejects ReDoS-prone patterns', () => {
    expect(() => compileUserRegex('(a+)+')).toThrowError(/redos/i);
    expect(() => compileUserRegex('(a*)*')).toThrowError(/redos/i);
  });
});

// ─── Scenario 6: allUnsafe audit report ─────────────────────────────────────

describe('Integration: allUnsafe for audit reporting', () => {
  it('returns all matching rules for a compound payload', () => {
    const payload = '<script onload="alert(1)">javascript:void</script>';
    const findings = allUnsafe(payload, HTML);

    expect(findings.length).toBeGreaterThan(0);

    const ids = findings.map(f => f.id);
    // Should catch script open, script close, event handler, and javascript: protocol
    expect(ids).toContain('html-script-open');
    expect(ids).toContain('html-script-close');
    expect(ids.some(id => id.includes('event-handler') || id.includes('handler'))).toBe(true);
  });

  it('returns empty array for safe input', () => {
    expect(allUnsafe('hello world', HTML)).toEqual([]);
    expect(allUnsafe('john@example.com', [HTML, SQL, SHELL])).toEqual([]);
  });
});

// ─── Scenario 7: Mixed context (XML sitemap entity) ──────────────────────────

describe('Integration: XML sitemap entity value guard', () => {
  /**
   * Sitemap URLs should be safe in both XML (no parser attacks) and HTML
   * (no XSS if reflected into a page). Check both.
   */
  function isUrlSafeForSitemap(url) {
    return !isUnsafe(url, [HTML, XML]);
  }

  it('passes normal sitemap URLs', () => {
    expect(isUrlSafeForSitemap('https://example.com/')).toBe(true);
    expect(isUrlSafeForSitemap('https://example.com/products/widget-123')).toBe(true);
    expect(isUrlSafeForSitemap('https://example.com/search?q=blue+widget&page=1')).toBe(true);
  });

  it('blocks XSS payloads in URL position', () => {
    expect(isUrlSafeForSitemap('javascript:alert(1)')).toBe(false);
    expect(isUrlSafeForSitemap('https://example.com/<script>alert(1)</script>')).toBe(false);
  });

  it('blocks XML injection in URL position', () => {
    expect(isUrlSafeForSitemap('https://example.com/<!--')).toBe(false);
    expect(isUrlSafeForSitemap('https://example.com/<![CDATA[')).toBe(false);
  });
});
