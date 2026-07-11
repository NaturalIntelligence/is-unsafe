/**
 * specs/redos.spec.js
 *
 * Tests for the REDOS context.
 * Detects strings that, when compiled as RegExp, could cause catastrophic
 * backtracking (ReDoS — Regular Expression Denial of Service).
 */

import { isUnsafe, REDOS } from '../src/index.js';

const unsafe = (v) => expect(isUnsafe(v, REDOS)).toBe(true,  `expected UNSAFE: ${v}`);
const safe   = (v) => expect(isUnsafe(v, REDOS)).toBe(false, `expected SAFE:   ${v}`);

describe('REDOS context — nested quantifiers (classic ReDoS forms)', () => {
  it('flags (a+)+ pattern', () => {
    unsafe('(a+)+');
    unsafe('([a-z]+)+');
    unsafe('(\\w+)+');
  });

  it('flags (a*)* pattern', () => {
    unsafe('(a*)*');
    unsafe('([0-9]*)*');
  });

  it('flags (a+)* pattern', () => {
    unsafe('(a+)*');
    unsafe('([a-zA-Z]+)*');
  });

  it('flags (a*)+ pattern', () => {
    unsafe('(a*)+');
    unsafe('(\\d*)+');
  });

  it('flags (.+b)* — quantifier not at end of group', () => {
    unsafe('(.+b)*');
    unsafe('(a+b)+');
    unsafe('(x+yz)*');
  });

  it('flags doubly nested ((a+)+)', () => {
    unsafe('((a+)+)');
    unsafe('(([a-z]+)+)');
  });

  it('does not flag simple quantifiers', () => {
    safe('a+');
    safe('[a-z]*');
    safe('\\d{3}');
    safe('\\w+\\s');
  });

  it('does not flag non-nested groups', () => {
    safe('(abc)+');        // fixed string group — no inner quantifier
    safe('(foo){2,5}');    // fixed string, bounded repeat
  });
});

describe('REDOS context — overlapping alternation under quantifier', () => {
  it('flags (a|a)+ repeated identical alternatives', () => {
    unsafe('(a|a)+');
    unsafe('(foo|foo)+');
    unsafe('(x|x)*');
  });
});

describe('REDOS context — (x*x)+ star-concat patterns', () => {
  it('flags (a*a)+ pattern', () => {
    unsafe('(a*a)+');
    unsafe('(x*x)*');
  });

  it('flags (.*x)+ greedy dot variants', () => {
    unsafe('(.*a)+');
    unsafe('(.+b)*');
  });
});

describe('REDOS context — repeated greedy dot quantifiers', () => {
  it('flags (.*){n} patterns', () => {
    unsafe('(.*){2}');
    unsafe('(.+){3}');
    unsafe('(.*){10}');
  });
});

describe('REDOS context — very large repetition counts', () => {
  it('flags {1000,} or larger', () => {
    unsafe('a{1000,}');
    unsafe('\\w{9999}');
    unsafe('[a-z]{5000,10000}');
  });

  it('does not flag reasonable repetition counts', () => {
    safe('a{1,100}');
    safe('\\d{3,6}');
    safe('\\w{1,50}');
    safe('[a-z]{2,4}');
    safe('a{999}');
  });
});

describe('REDOS context — catastrophic alternation', () => {
  it('flags patterns with 10+ pipe alternatives', () => {
    unsafe('(a|b|c|d|e|f|g|h|i|j)+');
    unsafe('(one|two|three|four|five|six|seven|eight|nine|ten|eleven)');
  });

  it('does not flag short alternation groups', () => {
    safe('(cat|dog)');
    safe('(yes|no|maybe)');
    safe('(red|green|blue|yellow)');
    safe('(mon|tue|wed|thu|fri|sat|sun)');
    safe('(jan|feb|mar|apr|may|jun|jul|aug)');
  });
});

describe('REDOS context — safe regex strings', () => {
  it('passes typical simple patterns', () => {
    safe('^[a-z]+$');
    safe('\\d{4}-\\d{2}-\\d{2}');
    safe('[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}');
    safe('^https?://[\\w.-]+');
    safe('\\b\\w+\\b');
  });

  it('passes bounded quantifier patterns', () => {
    safe('[a-z]{3,10}');
    safe('\\w{1,20}');
    safe('[0-9]{4}');
  });

  it('passes alternation without nesting or excessive branches', () => {
    safe('cat|dog|bird');
    safe('(GET|POST|PUT|DELETE)');
    safe('(jpg|jpeg|png|gif|webp)');
  });

  it('passes plain strings (no regex metacharacters)', () => {
    safe('hello world');
    safe('john@example.com');
    safe('2024-01-15');
  });
});
