/**
 * specs/entity-decoding.spec.js
 *
 * Regression tests for the entity-encoded scheme bypass
 * (javascript&#58;, &#x3a;, &colon;, &Tab; …) in markup contexts.
 */

import { isUnsafe, whyUnsafe, allUnsafe, HTML, XML, SVG, SQL, SHELL, LOG } from '../src/index.js';
import decodeEntities from '../src/util/decode-entities.js';

const unsafe = (v) => expect(isUnsafe(v, HTML)).toBe(true,  `expected UNSAFE: ${v}`);
const safe   = (v) => expect(isUnsafe(v, HTML)).toBe(false, `expected SAFE:   ${v}`);

// ─── decoder unit tests ─────────────────────────────────────────────────────

describe('decodeEntities — decoder', () => {
  it('returns input untouched when there is no ampersand', () => {
    const s = 'plain text: no entities';
    expect(decodeEntities(s)).toBe(s);
  });

  it('decodes decimal references (with/without ;, with padding)', () => {
    expect(decodeEntities('&#58;')).toBe(':');
    expect(decodeEntities('&#058;')).toBe(':');
    expect(decodeEntities('&#00000058;')).toBe(':');
    expect(decodeEntities('&#58x')).toBe(':x');
  });

  it('decodes hex references (any case, with/without ;, with padding)', () => {
    expect(decodeEntities('&#x3a;')).toBe(':');
    expect(decodeEntities('&#x3A;')).toBe(':');
    expect(decodeEntities('&#X3a;')).toBe(':');
    expect(decodeEntities('&#x0000003a;')).toBe(':');
    expect(decodeEntities('&#x3a ')).toBe(': ');
  });

  it('decodes &colon;, &Tab; and &NewLine;', () => {
    expect(decodeEntities('&colon;')).toBe(':');
    expect(decodeEntities('&Tab;')).toBe('\t');
    expect(decodeEntities('&NewLine;')).toBe('\n');
  });

  it('named references are case-sensitive and need a semicolon (like browsers)', () => {
    expect(decodeEntities('&COLON;')).toBe('&COLON;');
    expect(decodeEntities('&tab;')).toBe('&tab;');
    expect(decodeEntities('&colon')).toBe('&colon');
    expect(decodeEntities('&newline;')).toBe('&newline;');
  });

  it('leaves out-of-range code points alone', () => {
    expect(decodeEntities('&#xFFFFFFF;')).toBe('&#xFFFFFFF;');
    expect(decodeEntities('&#99999999;')).toBe('&#99999999;');
    expect(decodeEntities('&#x110000;')).toBe('&#x110000;');
  });

  it('does not decode &amp; and does not double-decode', () => {
    expect(decodeEntities('&amp;')).toBe('&amp;');
    expect(decodeEntities('&amp;#58;')).toBe('&amp;#58;');
    expect(decodeEntities('&#38;#58;')).toBe('&#58;');   // one pass only
  });

  it('does not decode unknown named references', () => {
    expect(decodeEntities('&copy; &lt; &gt;')).toBe('&copy; &lt; &gt;');
  });

  it('does not decode inherited Object.prototype names', () => {
    expect(decodeEntities('&constructor;')).toBe('&constructor;');
    expect(decodeEntities('&toString;')).toBe('&toString;');
  });

  it('handles pathological input quickly (no ReDoS)', () => {
    const t = Date.now();
    decodeEntities('&' + '#0'.repeat(50000));
    decodeEntities('&#x' + '0'.repeat(100000));
    decodeEntities('&'.repeat(100000));
    expect(Date.now() - t).toBeLessThan(500);
  });
});

// ─── reported bypass: HTML context ──────────────────────────────────────────

describe('HTML — entity-encoded colon in javascript:', () => {
  it('flags decimal colon', () => {
    unsafe('javascript&#58;alert(1)');
    unsafe('javascript&#058;alert(1)');
    unsafe('javascript&#58alert(1)');            // no semicolon
  });

  it('flags hex colon', () => {
    unsafe('javascript&#x3a;alert(1)');
    unsafe('javascript&#x3A;alert(1)');
    unsafe('javascript&#X3a;alert(1)');
    unsafe('javascript&#x3a alert(1)');          // no semicolon
  });

  it('flags named colon', () => {
    unsafe('javascript&colon;alert(1)');
    unsafe('JaVaScRiPt&colon;alert(1)');
  });

  it('flags leading-zero padded colon', () => {
    unsafe('javascript&#x0000003a;alert(1)');
    unsafe('javascript&#00000058;alert(1)');
    unsafe('javascript&#X00003A;alert(1)');
  });

  it('flags letters AND colon encoded', () => {
    unsafe('java&#115;cript&#58;alert(1)');
    unsafe('&#106;avascript&#58;alert(1)');
    unsafe('&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;alert(1)');
  });

  it('flags vbscript: with encoded colon', () => {
    unsafe('vbscript&#58;msgbox(1)');
    unsafe('vbscript&#x3a;msgbox(1)');
    unsafe('vbscript&colon;msgbox(1)');
  });

  it('flags the exact PoC strings from the report', () => {
    for (const v of [
      'javascript&#58;alert(1)',
      'javascript&#x3a;alert(1)',
      'javascript&#x0000003a;alert(1)',
      'javascript&colon;alert(1)',
      'java&#115;cript&#58;alert(1)',
      'JaVaScRiPt&#58;alert(1)',
      'vbscript&#x3a;msgbox(1)',
    ]) unsafe(v);
  });

  it('flags full attribute context', () => {
    unsafe('<a href="javascript&#58;alert(1)">x</a>');
    unsafe('<a href=javascript&colon;alert(1)>x</a>');
  });
});

describe('HTML — &Tab; / &NewLine; inside the scheme', () => {
  it('flags &Tab; between letters', () => {
    unsafe('java&Tab;script:alert(1)');
    unsafe('j&Tab;a&Tab;v&Tab;a&Tab;s&Tab;c&Tab;r&Tab;i&Tab;p&Tab;t:alert(1)');
  });

  it('flags &NewLine; between letters', () => {
    unsafe('java&NewLine;script:alert(1)');
  });

  it('flags numeric tab/newline between letters', () => {
    unsafe('java&#9;script:alert(1)');
    unsafe('java&#10;script:alert(1)');
    unsafe('java&#x0A;script:alert(1)');
  });

  it('flags &Tab; combined with an encoded colon', () => {
    unsafe('java&Tab;script&colon;alert(1)');
  });

  it('does not decode wrong-case names (a browser would not either)', () => {
    safe('java&tab;script:alert(1)');            // &tab; is not a valid reference
  });
});

// ─── false-positive guards ──────────────────────────────────────────────────

describe('HTML — entity decoding does not add false positives', () => {
  it('stays safe for ordinary entity-bearing text', () => {
    safe('Price: 5 &amp; up, see note');
    safe('I am learning javascript');
    safe('the ratio is 3&#58;1');                // colon entity, no scheme
    safe('tom &amp; jerry');
    safe('New York, NY');
    safe('https://example.com/path');
    safe('Copyright &copy; 2024');
    safe('Time&#58; 10&#58;30');
  });

  it('stays safe for double-encoded markup (rendered as text)', () => {
    safe('&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;');
    safe('javascript&amp;#58;alert(1)');         // &amp; not decoded → text
  });

  it('stays safe for escaped non-script markup', () => {
    safe('&lt;b&gt;hello&lt;/b&gt;');
  });

  it('stays safe for out-of-range numeric references', () => {
    safe('javascript&#xFFFFFFF;alert(1)');
    safe('javascript&#99999999;alert(1)');
  });

  it('stays safe for &colon without semicolon (not decoded by browsers)', () => {
    safe('javascript&colonalert(1)');
  });
});

// ─── other contexts / API behaviour ─────────────────────────────────────────

describe('entity decoding — scope and API', () => {
  it('also applies to the SVG context', () => {
    expect(isUnsafe('href="javascript&#58;alert(1)"', SVG)).toBe(true);
    expect(isUnsafe('xlink:href="javascript&colon;alert(1)"', SVG)).toBe(true);
    expect(isUnsafe('href="javascript&amp;#58;alert(1)"', SVG)).toBe(false);
  });

  it('also applies to the XML context', () => {
    expect(isUnsafe('&#60;!--', XML)).toBe(true);        // decodes to <!--
    expect(isUnsafe('&#93;&#93;&#62;', XML)).toBe(true); // decodes to ]]>
    expect(isUnsafe('Tom &amp; Jerry', XML)).toBe(false);
    expect(isUnsafe('5 &lt; 10', XML)).toBe(false);
  });

  it('does NOT apply to non-markup contexts (matched byte-for-byte)', () => {
    expect(isUnsafe('&#124 ls', SHELL)).toBe(false);           // would decode to '|'
    expect(isUnsafe('&#37;0a', LOG)).toBe(false);             // would decode to %0a
    expect(isUnsafe('&#85;NION &#83;ELECT', SQL)).toBe(false);
    expect(HTML.decodeEntities).toBe(true);
    expect(SHELL.decodeEntities).toBeUndefined();
    expect(SQL.decodeEntities).toBeUndefined();
    expect(LOG.decodeEntities).toBeUndefined();
  });

  it('whyUnsafe reports the rule that matched the decoded copy', () => {
    const r = whyUnsafe('javascript&#58;alert(1)', HTML);
    expect(r).not.toBeNull();
    expect(r.context).toBe('HTML');
    expect(r.id).toBe('html-javascript-protocol');
  });

  it('allUnsafe also reports matches on the decoded copy', () => {
    const ids = allUnsafe('javascript&#58;alert(1)', HTML).map(r => r.id);
    expect(ids).toContain('html-javascript-protocol');
  });

  it('works inside a multi-context array', () => {
    expect(isUnsafe('javascript&#58;alert(1)', [HTML, SQL])).toBe(true);
    expect(isUnsafe('tom &amp; jerry', [HTML, XML, SVG])).toBe(false);
  });

  it('never removes an existing detection', () => {
    for (const v of ['javascript:alert(1)', '<script>', 'onclick=x', '&#x3C;script']) {
      expect(isUnsafe(v, HTML)).toBe(true, v);
    }
  });
});

// ─── concatenation guidance ─────────────────────────────────────────────────

describe('check the FINAL concatenated string', () => {
  it('two safe parts can become unsafe only after joining', () => {
    const a = 'java';
    const b = 'script&#58;alert(1)';
    expect(isUnsafe(a, HTML)).toBe(false);
    expect(isUnsafe(b, HTML)).toBe(false);
    expect(isUnsafe(a + b, HTML)).toBe(true);
  });

  it('works for entity-split schemes too', () => {
    const a = 'java&#115;';
    const b = 'cript&colon;alert(1)';
    expect(isUnsafe(a, HTML)).toBe(false);
    expect(isUnsafe(b, HTML)).toBe(false);
    expect(isUnsafe(a + b, HTML)).toBe(true);
  });
});
