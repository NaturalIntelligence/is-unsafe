/**
 * specs/nosql.spec.js
 *
 * Tests for the NOSQL context.
 * Covers MongoDB query operator injection and prototype pollution.
 */

import { isUnsafe, whyUnsafe, NOSQL } from '../src/index.js';

const unsafe = (v) => expect(isUnsafe(v, NOSQL)).toBe(true,  `expected UNSAFE: ${v}`);
const safe   = (v) => expect(isUnsafe(v, NOSQL)).toBe(false, `expected SAFE:   ${v}`);

// ─── MongoDB $ operator injection ───────────────────────────────────────────

describe('NOSQL context — $where operator', () => {
  it('flags $where: (server-side JS execution)', () => {
    unsafe('{"$where": "this.password == \'admin\'"}');
    unsafe('$where: "sleep(5000)"');
    unsafe('"$where":"this.credits > 0"');
  });

  it('does not flag "where" without $ prefix', () => {
    safe('where clause');
    safe('WHERE id = 1');
    safe('somewhere');
  });
});

describe('NOSQL context — comparison operator bypass ($ne, $gt, $gte, $lt)', () => {
  it('flags $ne: — not-equal authentication bypass', () => {
    unsafe('{"password": {"$ne": null}}');
    unsafe('"$ne": ""');
    unsafe('$ne:""');
  });

  it('flags $gt: / $gte:', () => {
    unsafe('{"age": {"$gt": 0}}');
    unsafe('"$gte": ""');
    unsafe('$gt: ""');
  });

  it('flags $lt: / $lte:', () => {
    unsafe('{"value": {"$lt": 999}}');
    unsafe('"$lte": 1000');
    unsafe('$lt:0');
  });

  it('does not flag these as plain words', () => {
    safe('$net income');    // $ followed by different word
    safe('$gross');
    safe('greater than zero');
  });
});

describe('NOSQL context — $regex operator (blind injection)', () => {
  it('flags $regex: — character-by-character data extraction', () => {
    unsafe('{"password": {"$regex": "^a"}}');
    unsafe('"$regex": ".*"');
    unsafe('$regex:"^admin"');
  });

  it('does not flag the word regex without $ prefix', () => {
    safe('regex pattern');
    safe('use a regex here');
  });
});

describe('NOSQL context — logical operators ($or, $and, $nor)', () => {
  it('flags $or: [ — always-true bypass', () => {
    unsafe('{"$or": [{}, {"a": "b"}]}');
    unsafe('"$or": [{"username": "admin"}]');
    unsafe('$or: [{}, {}]');
  });

  it('flags $and: [', () => {
    unsafe('{"$and": [{"a": 1}]}');
    unsafe('"$and": [{}]');
  });

  it('flags $nor: [', () => {
    unsafe('{"$nor": [{"valid": true}]}');
    unsafe('"$nor": [{}]');
  });

  it('does not flag "or", "and", "nor" without $ prefix', () => {
    safe('this or that');
    safe('cats and dogs');
    safe('nor here nor there');
  });
});

describe('NOSQL context — $exists, $in operators', () => {
  it('flags $exists: — field enumeration', () => {
    unsafe('{"password": {"$exists": true}}');
    unsafe('"$exists": true');
    unsafe('$exists:false');
  });

  it('flags $in: [ — value enumeration', () => {
    unsafe('{"role": {"$in": ["admin", "root"]}}');
    unsafe('"$in": ["a", "b"]');
    unsafe('$in:["x"]');
  });
});

describe('NOSQL context — JavaScript execution operators', () => {
  it('flags $expr: — aggregation expression injection', () => {
    unsafe('{"$expr": {"$gt": ["$balance", 0]}}');
    unsafe('"$expr": {"$eq": ["$secret", "value"]}');
  });

  it('flags $function: — arbitrary JS in MongoDB 4.4+', () => {
    unsafe('{"$function": {"body": "function() { return true; }", "args": [], "lang": "js"}}');
    unsafe('"$function": {"body": "evil()", "lang": "js"}');
  });

  it('flags $accumulator: — custom aggregation with JS', () => {
    unsafe('{"$accumulator": {"init": "function(){}", "accumulate": "function(){}", "lang": "js"}}');
    unsafe('"$accumulator": {"lang": "js"}');
  });
});

describe('NOSQL context — prototype pollution', () => {
  it('flags __proto__ property access', () => {
    unsafe('{"__proto__": {"isAdmin": true}}');
    unsafe('__proto__');
    unsafe('user[__proto__][isAdmin]=true');
  });

  it('flags constructor.prototype', () => {
    unsafe('constructor.prototype.isAdmin=true');
    unsafe('{"constructor": {"prototype": {"evil": true}}}');
    unsafe('obj.constructor.prototype');
  });

  it('flags ["__proto__"] bracket notation', () => {
    unsafe('["__proto__"]["isAdmin"]');
    unsafe('obj["__proto__"]["admin"] = true');
  });

  it('does not flag "proto" or "prototype" alone', () => {
    safe('prototype chain');
    safe('The prototype pattern');
    safe('proto file');
    safe('constructor function');
    safe('Object.prototype methods');  // no dot before prototype here...
    // Note: 'constructor.prototype' IS flagged — that's intentional
  });
});

describe('NOSQL context — safe strings', () => {
  it('passes typical user input', () => {
    safe('John Smith');
    safe('john@example.com');
    safe('2024-01-15');
    safe('New York');
    safe('product-123');
  });

  it('passes JSON without $ operators', () => {
    safe('{"name": "Alice", "age": 30}');
    safe('{"status": "active", "role": "user"}');
    safe('{"email": "test@example.com"}');
  });

  it('passes normal JavaScript variable names', () => {
    safe('userId');
    safe('productName');
    safe('orderTotal');
  });

  it('passes $ in non-MongoDB contexts', () => {
    safe('$100');
    safe('$USD');
    safe('price: $9.99');
  });
});

describe('NOSQL context — whyUnsafe reporting', () => {
  it('identifies the specific operator rule that fired', () => {
    const result = whyUnsafe('{"$ne": null}', NOSQL);
    expect(result).not.toBeNull();
    expect(result.id).toBe('nosql-ne-operator');
    expect(result.context).toBe('NOSQL');
  });

  it('identifies prototype pollution rule', () => {
    const result = whyUnsafe('__proto__', NOSQL);
    expect(result).not.toBeNull();
    expect(result.id).toBe('nosql-proto-pollution');
  });
});
