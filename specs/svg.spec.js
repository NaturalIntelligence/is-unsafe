/**
 * specs/svg.spec.js
 *
 * Tests for the SVG context patterns.
 * SVG has a unique attack surface: XML-based but browser-rendered.
 * These tests cover vectors that bypass HTML sanitizers (DOMPurify documented bypasses).
 */

import { isUnsafe, SVG } from '../src/index.js';

const unsafe = (v) => expect(isUnsafe(v, SVG)).toBe(true,  `expected UNSAFE: ${v}`);
const safe   = (v) => expect(isUnsafe(v, SVG)).toBe(false, `expected SAFE:   ${v}`);

describe('SVG context — <script> element', () => {
  it('flags <script element in SVG', () => {
    unsafe('<script>alert(1)</script>');
    unsafe('<script type="text/javascript">');
    unsafe('<SCRIPT>');
  });

  it('does not flag the word script', () => {
    safe('this is a script reference');
    safe('noscript');
  });
});

describe('SVG context — xlink:href javascript:', () => {
  it('flags xlink:href with javascript: protocol', () => {
    unsafe('xlink:href="javascript:alert(1)"');
    unsafe("xlink:href='javascript:void(0)'");
    unsafe('xlink : href = "javascript:alert(1)"');
  });

  it('flags xlink:href with JAVASCRIPT: (case insensitive)', () => {
    unsafe('xlink:href="JAVASCRIPT:alert(1)"');
    unsafe('XLINK:HREF="javascript:alert(1)"');
  });

  it('does not flag xlink:href with safe http:// URL', () => {
    // NOTE: svg-use-external catches http:// hrefs on <use>, but xlink:href alone with http is okay
    // The xlink:href-javascript rule only matches javascript: protocol
    safe('xlink:href="#local-symbol"');  // internal fragment reference
  });
});

describe('SVG context — href="javascript:"', () => {
  it('flags href= with javascript: value', () => {
    unsafe('href="javascript:alert(1)"');
    unsafe("href='javascript:void(0)'");
    unsafe('href =javascript:alert(1)');
  });

  it('does not flag href with safe URL', () => {
    safe('href="#anchor"');
    safe('href="https://example.com"');
  });
});

describe('SVG context — <foreignObject>', () => {
  it('flags <foreignObject element', () => {
    unsafe('<foreignObject width="100%" height="100%"><body xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></body></foreignObject>');
    unsafe('<foreignObject>');
    unsafe('<FOREIGNOBJECT>');
  });

  it('does not flag the word foreignObject in text', () => {
    safe('foreignObject is an SVG element');
    safe('using foreignobject for HTML embedding');
  });
});

describe('SVG context — <use> with external reference', () => {
  it('flags <use> with external http href', () => {
    unsafe('<use href="https://evil.com/sprite.svg#icon">');
    unsafe('<use xlink:href="http://evil.com/x.svg#y">');
  });

  it('flags <use> with javascript: href', () => {
    unsafe('<use href="javascript:alert(1)">');
  });

  it('does not flag <use> with internal fragment reference', () => {
    safe('<use href="#local-icon">');
    safe('<use xlink:href="#sprite-icon">');
  });
});

describe('SVG context — <animate> attributeName href attacks', () => {
  it('flags <animate attributeName="href"', () => {
    unsafe('<animate attributeName="href" values="javascript:alert(1)">');
    unsafe('<animate attributeName="href" from="#safe" to="javascript:alert(1)">');
  });

  it('flags <animate attributeName="xlink:href"', () => {
    unsafe('<animate attributeName="xlink:href" to="javascript:alert(1)">');
  });

  it('does not flag animate with safe attributeName', () => {
    safe('<animate attributeName="opacity" from="0" to="1">');
    safe('<animate attributeName="cx" values="10;50;10">');
    safe('<animate attributeName="fill" values="red;blue">');
  });
});

describe('SVG context — <set> element to="javascript:"', () => {
  it('flags <set to="javascript:..."', () => {
    unsafe('<set attributeName="href" to="javascript:alert(1)">');
    unsafe('<set to="javascript:void(0)">');
  });

  it('does not flag <set> with safe value', () => {
    safe('<set attributeName="visibility" to="visible">');
    safe('<set attributeName="fill" to="red">');
  });
});

describe('SVG context — event handler attributes', () => {
  it('flags SVG-specific onload, onerror, onactivate', () => {
    unsafe('onload="alert(1)"');
    unsafe('onerror="alert(1)"');
    unsafe('onactivate="alert(1)"');
  });

  it('flags SVG animation event handlers', () => {
    unsafe('onbegin="alert(1)"');
    unsafe('onend="alert(1)"');
    unsafe('onrepeat="alert(1)"');
  });

  it('flags generic mouse event handlers', () => {
    unsafe('onmouseover="alert(1)"');
    unsafe('onclick="alert(1)"');
    unsafe('onfocus="alert(1)"');
  });

  it('flags uppercase event handlers', () => {
    unsafe('ONLOAD="alert(1)"');
    unsafe('OnError="alert(1)"');
  });
});

describe('SVG context — <feImage> external reference', () => {
  it('flags <feImage href= with external URL', () => {
    unsafe('<feImage href="https://evil.com/track.png">');
    unsafe('<feImage xlink:href="http://evil.com/pixel.gif">');
  });
});

describe('SVG context — <image> external', () => {
  it('flags <image> with javascript: protocol', () => {
    unsafe('<image xlink:href="javascript:alert(1)">');
    unsafe('<image href="javascript:void(0)">');
  });

  it('flags <image> with http/https external URL', () => {
    unsafe('<image xlink:href="https://tracker.evil.com/pixel.gif">');
    unsafe('<image href="http://evil.com/image.png">');
  });
});

describe('SVG context — style= containing javascript:', () => {
  it('flags style attribute with javascript: value', () => {
    unsafe('style="background:url(javascript:alert(1))"');
    unsafe('style="fill: javascript:alert(1)"');
  });

  it('does not flag normal style attributes', () => {
    safe('style="fill: red; stroke: blue;"');
    safe('style="opacity: 0.5"');
  });
});

describe('SVG context — safe strings', () => {
  it('passes normal SVG attribute values', () => {
    safe('M 10 10 L 100 100');        // SVG path data
    safe('0 0 100 100');              // viewBox
    safe('#ff0000');                  // color
    safe('translate(10, 20)');        // transform
    safe('rotate(45)');
    safe('1em');
    safe('50%');
  });

  it('passes normal text content', () => {
    safe('Chart Title');
    safe('Q1 Revenue: $1.2M');
    safe('10:30 AM');
  });
});
