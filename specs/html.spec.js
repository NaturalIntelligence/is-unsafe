/**
 * specs/html.spec.js
 *
 * Comprehensive tests for the HTML context patterns.
 * Each rule has at least one true positive and one true negative.
 */

import { isUnsafe, HTML } from '../src/index.js';

const unsafe = (v) => expect(isUnsafe(v, HTML)).toBe(true, `expected UNSAFE: ${v}`);
const safe = (v) => expect(isUnsafe(v, HTML)).toBe(false, `expected SAFE:   ${v}`);

describe('HTML context — <script> tags', () => {
  it('flags <script opening tag', () => {
    unsafe('<script>');
    unsafe('<script ');
    unsafe('<script/');
    unsafe('<script>alert(1)</script>');
    unsafe('<SCRIPT>');
    unsafe('<Script>');
  });

  it('flags </script> closing tag', () => {
    unsafe('</script>');
    unsafe('</SCRIPT>');
    unsafe('</script >');
  });

  it('does not flag the word "script" without <', () => {
    safe('This is a script for the play');
    safe('noscript');
    safe('manuscript');
    safe('typescript');
  });
});

describe('HTML context — javascript: protocol', () => {
  it('flags bare javascript:', () => {
    unsafe('javascript:alert(1)');
    unsafe('JAVASCRIPT:alert(1)');
    unsafe('JavaScript:alert(1)');
  });

  it('flags javascript: with whitespace between characters', () => {
    unsafe('j a v a s c r i p t :');
    unsafe('j\ta\tv\ta\ts\tc\tr\ti\tp\tt\t:');
    unsafe('j\na\nv\na\ns\nc\nr\ni\np\nt\n:');
  });

  it('does not flag the word "javascript" without colon protocol', () => {
    safe('I am learning javascript');
    safe('javascript frameworks are popular');
  });
});

describe('HTML context — vbscript: protocol', () => {
  it('flags vbscript: protocol', () => {
    unsafe('vbscript:MsgBox("XSS")');
    unsafe('VBSCRIPT:alert');
    unsafe('vbscript :alert');
  });

  it('does not flag the word vbscript without colon', () => {
    safe('vbscript is a legacy language');
  });
});

describe('HTML context — data: URIs', () => {
  it('flags data:text/html', () => {
    unsafe('data:text/html,<script>alert(1)</script>');
    unsafe('data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==');
    unsafe('DATA:TEXT/HTML,x');
  });

  it('flags data:application/xhtml', () => {
    unsafe('data:application/xhtml+xml,<script>alert(1)</script>');
    unsafe('data:application/xhtml;base64,x');
  });

  it('flags data:image/svg+xml', () => {
    unsafe('data:image/svg+xml,<svg onload=alert(1)>');
  });

  it('does not flag safe data URIs', () => {
    safe('data:image/png;base64,iVBORw0KGgo=');
    safe('data:image/jpeg;base64,/9j/4AAQ=');
    safe('data:text/plain,hello');
  });
});

describe('HTML context — inline event handlers', () => {
  it('flags common event handlers', () => {
    unsafe('onclick=alert(1)');
    unsafe('onerror=alert(1)');
    unsafe('onload=alert(1)');
    unsafe('onmouseover=alert(1)');
    unsafe('onfocus=alert(1)');
    unsafe('onblur=alert(1)');
    unsafe('onkeydown=alert(1)');
    unsafe('onsubmit=alert(1)');
  });

  it('bug test', () => {
    unsafe('<img src=x onerror=alert(1)>');
  });

  it('flags event handlers with spaces around =', () => {
    unsafe('onclick = alert(1)');
    unsafe('onerror  =  alert(1)');
  });

  it('flags uppercase event handlers', () => {
    unsafe('ONCLICK=alert(1)');
    unsafe('OnError=alert(1)');
  });

  it('does not flag normal words starting with "on"', () => {
    safe('only one thing matters');
    safe('ongoing process');
    safe('online shopping');
    // "on" followed by non-word-boundary is safe — "online=" would be flagged
    // but we only test no-= variants here
  });

  it('does not flag "on" without the handler pattern', () => {
    safe('turn it on');
    safe('the show must go on');
  });
});

describe('HTML context — HTML entity obfuscation', () => {
  it('flags &#x3C;script (hex entity for <)', () => {
    unsafe('&#x3C;script');
    unsafe('&#X3C;script');
    unsafe('&#x3c;script');
  });

  it('flags &#60;script (decimal entity for <)', () => {
    unsafe('&#60;script');
  });

  it('flags &lt;script', () => {
    unsafe('&lt;script');
    unsafe('&LT;script');
  });
});

describe('HTML context — CSS expression()', () => {
  it('flags style attribute with expression()', () => {
    unsafe('style=width:expression(alert(1))');
    unsafe('style="xss:expression(alert(1))"');
  });
});

describe('HTML context — <object> and <embed>', () => {
  it('flags <object tag', () => {
    unsafe('<object data="evil.swf">');
    unsafe('<OBJECT>');
  });

  it('flags <embed tag', () => {
    unsafe('<embed src="evil.swf">');
    unsafe('<EMBED>');
  });

  it('does not flag the words object or embed as text', () => {
    safe('this is a JavaScript object');
    safe('you can embed content');
  });
});

describe('HTML context — <iframe>', () => {
  it('flags <iframe', () => {
    unsafe('<iframe src="evil.html">');
    unsafe('<IFRAME>');
  });

  it('does not flag the word iframe without <', () => {
    safe('use an iframe for this');
  });
});

describe('HTML context — <base> and <meta refresh>', () => {
  it('flags <base> tag', () => {
    unsafe('<base href="https://evil.com/">');
    unsafe('<BASE href="x">');
  });

  it('flags meta http-equiv refresh', () => {
    unsafe('<meta http-equiv="refresh" content="0;url=evil.com">');
    unsafe('<META HTTP-EQUIV="REFRESH">');
  });
});

describe('HTML context — srcdoc', () => {
  it('flags srcdoc= attribute', () => {
    unsafe('srcdoc="<script>alert(1)</script>"');
    unsafe('<iframe srcdoc="evil">');
  });

  it('does not flag the word srcdoc without =', () => {
    safe('the srcdoc attribute allows embedding');
  });
});

describe('HTML context — safe strings', () => {
  it('passes typical text content', () => {
    safe('Hello, World!');
    safe('Price: $9.99');
    safe('Visit https://example.com for details');
    safe('Use code SAVE10 at checkout');
    safe('1 + 1 = 2');
    safe('The temperature is -5°C');
    safe('John\'s article about web development');
    safe('<br> is a line break'); // This would be flagged by some, but we're conservative
  });

  it('passes URLs without javascript: scheme', () => {
    safe('https://example.com/path?q=hello&page=1');
    safe('http://example.com');
    safe('ftp://files.example.com');
  });

  it('passes XML-looking but HTML-safe content', () => {
    safe('<?xml version="1.0"?>'); // XML PI — unsafe for XML context, safe for HTML
  });
});
