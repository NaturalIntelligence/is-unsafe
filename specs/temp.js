import { isUnsafe } from '../src/index.js';

describe('TEMP', () => {
  it('check', () => {
    console.log(isUnsafe("SELECT * FROM users WHERE id = 1", 'SQL'));

    console.log(isUnsafe("It's 100% safe", 'SQL'));

    console.log(isUnsafe("--comments are fine", 'SQL'));
  });


});