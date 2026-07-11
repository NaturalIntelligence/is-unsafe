/**
 * specs/xml.spec.js
 *
 * Tests for the XML context patterns.
 * Covers XXE, CDATA injection, DOCTYPE injection, namespace confusion,
 * and parser-level attacks distinct from HTML XSS.
 */

import { isUnsafe, XML } from '../src/index.js';

const unsafe = (v) => expect(isUnsafe(v, XML)).toBe(true,  `expected UNSAFE: ${v}`);
const safe   = (v) => expect(isUnsafe(v, XML)).toBe(false, `expected SAFE:   ${v}`);

describe('XML context — CDATA injection', () => {
  it('flags <![CDATA[ opening sequence', () => {
    unsafe('<![CDATA[injected content]]>');
    unsafe('<![CDATA[');
    unsafe('prefix<![CDATA[suffix');
  });

  it('flags ]]> CDATA close sequence', () => {
    unsafe(']]>');
    unsafe('content]]>');
    unsafe(']]><evil/>');
  });

  it('does not flag normal bracket sequences', () => {
    safe('[array content]');
    safe(']]');    // two brackets, no >
    safe('![CDAT'); // incomplete
  });
});

describe('XML context — processing instructions', () => {
  it('flags <?xml-stylesheet processing instruction', () => {
    unsafe('<?xml-stylesheet type="text/xsl" href="evil.xsl"?>');
    unsafe('<?xml-stylesheet');
  });

  it('flags <?xml  (with space — version declaration injection)', () => {
    unsafe('<?xml version="1.1"?>');
    unsafe('<?xml ');
  });

  it('flags <?php processing instruction', () => {
    unsafe('<?php echo "evil"; ?>');
    unsafe('<?PHP');
  });

  it('flags <?asp processing instruction', () => {
    unsafe('<?asp code ?>');
  });

  it('flags ?> closing a processing instruction', () => {
    unsafe('?>');
    unsafe('injected content?>');
  });

  it('does not flag normal question marks', () => {
    safe('Is this a question?');
    safe('What time is it?');
    safe('a=1&b=2');
  });
});

describe('XML context — DOCTYPE injection', () => {
  it('flags <!DOCTYPE declaration', () => {
    unsafe('<!DOCTYPE urlset [<!ENTITY xss "evil">]>');
    unsafe('<!DOCTYPE foo SYSTEM "evil.dtd">');
    unsafe('<!DOCTYPE');
  });

  it('does not flag the word DOCTYPE in text', () => {
    safe('The DOCTYPE declaration defines the document type');
    safe('use DOCTYPE for validation');
  });
});

describe('XML context — XXE (external entity references)', () => {
  it('flags SYSTEM keyword in entity context', () => {
    unsafe('<!ENTITY xxe SYSTEM "file:///etc/passwd">');
    unsafe('SYSTEM "http://evil.com/xxe"');
    unsafe("SYSTEM 'file:///etc/shadow'");
  });

  it('flags PUBLIC keyword in entity context', () => {
    unsafe('<!ENTITY pub PUBLIC "-//W3C//DTD" "http://evil.com">');
    unsafe('PUBLIC "-//foo" "http://evil.com"');
  });

  it('flags <!ENTITY declaration', () => {
    unsafe('<!ENTITY xss "evil value">');
    unsafe('<!ENTITY % xss SYSTEM "evil.dtd">');
    unsafe('<!ENTITY ');
  });

  it('does not flag SYSTEM or PUBLIC as plain words in text', () => {
    safe('The system is running');
    safe('This is a public API');
    safe('PUBLIC SYSTEM'); // no quote following
  });
});

describe('XML context — entity expansion (billion laughs)', () => {
  it('flags repeated entity references (3+)', () => {
    unsafe('&e1;&e2;&e3;');
    unsafe('&lol;&lol;&lol;&lol;');
    unsafe('&a;&b;&c;&d;&e;');
  });

  it('does not flag one or two entity references', () => {
    safe('&amp;');
    safe('&lt;&gt;');
    safe('&copy; 2024');
  });

  it('does not flag standard entity usage', () => {
    safe('Tom &amp; Jerry');
    safe('5 &lt; 10');
  });
});

describe('XML context — namespace injection', () => {
  it('flags xmlns= attribute injection', () => {
    unsafe('xmlns="http://evil.com"');
    unsafe('xmlns:evil="http://evil.com"');
    unsafe('xmlns:xlink="http://www.w3.org/1999/xlink"');
  });

  it('does not flag the word xmlns in text', () => {
    safe('The xmlns attribute declares namespaces');
  });
});

describe('XML context — comment injection', () => {
  it('flags <!-- opening comment', () => {
    unsafe('<!-- injected comment -->');
    unsafe('<!--');
    unsafe('text <!-- hidden content --> text');
  });

  it('flags --> closing comment', () => {
    unsafe('-->');
    unsafe('injected-->');
    unsafe('--><evil/>');
  });

  it('does not flag single hyphens or normal dashes', () => {
    safe('value is 5 - 3 = 2');
    safe('a well-formed sentence');
    safe('em—dash usage');
  });
});

describe('XML context — safe strings', () => {
  it('passes typical text node content', () => {
    safe('Hello, World!');
    safe('https://example.com/path');
    safe('The price is $9.99');
    safe('Temperature: -20°C');
    safe('Standard & normal text');  // & alone is safe (single entity ref)
  });

  it('passes normal XML attribute values', () => {
    safe('en-US');
    safe('utf-8');
    safe('2024-01-15');
    safe('user@example.com');
  });

  it('passes the FXP motivating example — safe entity value', () => {
    safe('https://example.com/page');
    safe('New York, NY');
    safe('product-category');
  });
});
