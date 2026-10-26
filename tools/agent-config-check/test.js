'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { analyze, MAX_LENGTH, MAX_FINDINGS } = require('./scanner.js');
const ids = input => new Set(analyze(input).findings.map(item => item.ruleId));
const random = 'Q8f3N9a2W7k4R1v6Y0m5D8p3H2z9C4s1';

for (const [name, input, expected] of [
  ['OpenAI', `key: "sk-proj-${random}"`, 'secret'],
  ['Anthropic', `key: "sk-ant-api03-${random}"`, 'secret'],
  ['GitHub classic', `key: ghp_${random}`, 'secret'],
  ['GitHub fine-grained', `key: github_pat_${random}`, 'secret'],
  ['AWS access key', 'key: AKIA1234567890ABCDEF', 'secret'],
  ['AWS session key', 'key: ASIA1234567890ABCDEF', 'secret'],
  ['AWS secret field', `AWS_SECRET_ACCESS_KEY=${random}`, 'secret'],
  ['Slack', `key: xoxb-1234567890-${random}`, 'secret'],
  ['low-entropy hardcoded password', 'PASSWORD=not-so-secret', 'secret'],
  ['custom high-entropy value', `CUSTOM_ID=${random}`, 'entropy'],
  ['PEM private key', '-----BEGIN PRIVATE KEY-----', 'secret'],
  ['IPv4 binding', 'host = "0.0.0.0"', 'bind'],
  ['IPv6 binding', 'host = "::"', 'bind'],
  ['dotenv debug', 'DEBUG=true', 'debug'],
  ['YAML debug', 'debug_enabled: yes', 'debug'],
  ['compact JSON debug', '{"server":{"debug":true}}', 'debug'],
  ['disabled auth', 'authentication: none', 'auth'],
  ['disabled required auth', 'auth_required = false', 'auth'],
  ['anonymous access', 'allow_anonymous: true', 'auth'],
  ['CORS env', 'CORS_ORIGINS="*"', 'cors'],
  ['CORS JSON list', '{"allowedOrigins":["*"]}', 'cors'],
  ['CORS YAML list', 'cors:\n  origins:\n    - "*"', 'cors'],
  ['root user', 'user: root', 'permission'],
  ['numeric root uid', '{"runAsUser":0}', 'permission'],
  ['root uid and group', 'user: "0:0"', 'permission'],
  ['privileged', 'privileged: true', 'permission'],
  ['root requirement disabled', 'runAsNonRoot: false', 'permission'],
  ['IAM wildcard', '{"Action":"*", "Resource":"*"}', 'permission'],
  ['agent allow', '{"permissions":{"allow":["Bash(*)"]}}', 'permission'],
  ['unbounded filesystem', 'allowed_paths: ["/**"]', 'permission'],
  ['YAML permission list', 'permissions:\n  allow:\n    - "*"', 'permission'],
  ['Docker capabilities', 'cap_add: [ALL]', 'permission'],
  ['TOML full access', '[agent]\nsandbox_mode = "danger-full-access"', 'permission'],
  ['MCP arguments', '{"mcpServers":{"agent":{"args":["--no-auth","--debug","--yolo"]}}}', 'auth'],
  ['published port', 'ports:\n  - "8080:80"', 'port'],
  ['unindented YAML port list', 'ports:\n- "8080:80"', 'port'],
  ['public host port', 'ports: ["0.0.0.0:8080:80"]', 'port'],
  ['port range', 'ports: ["8000-8002:80-82/tcp"]', 'port'],
  ['bare public port', 'ports:\n  - 8080', 'port'],
  ['long port syntax', 'ports:\n  - target: 80\n    published: "8080"', 'port']
]) {
  test(`detects ${name}`, () => assert.ok(ids(input).has(expected)));
}

for (const [name, input] of [
  ['empty input', ''],
  ['safe config', 'HOST=127.0.0.1\nDEBUG=false\nAUTH_ENABLED=true\nuser: app'],
  ['dotenv comments', '# DEBUG=true\n# TOKEN=sk-proj-' + random],
  ['JSON comments', '// "debug": true\n/* HOST=0.0.0.0\nDEBUG=true */\nDEBUG=false'],
  ['interpolated environment variable', 'API_KEY=${OPENAI_API_KEY}\nTOKEN=$TOKEN'],
  ['template placeholders', 'API_KEY={{ secrets.API_KEY }}\nTOKEN="<your-token>"'],
  ['sample placeholders', 'API_KEY=your_api_key_here\nPASSWORD=changeme123\nTOKEN=REDACTED'],
  ['loopback port', 'ports:\n  - "127.0.0.1:8080:80"'],
  ['IPv6 loopback port', 'ports: ["[::1]:8080:80"]'],
  ['internal expose', 'expose:\n  - "8080"'],
  ['deny wildcard', 'permissions:\n  deny:\n    - "*"'],
  ['JSON deny access', '{"permissions":{"deny":["Read(/**)"]}}'],
  ['limited access', 'allowed_paths: ["./project"]'],
  ['non-secret URL', 'URL=https://example.com/aLongPath1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ'],
  ['UUID', 'ID=7ec3b049-04de-44ab-b9b4-c1d38a1bd32c'],
  ['hex digest', 'HASH=9b2d43c0ab8e1d358f30cfda88018235'],
  ['disabled flags', 'args: ["--no-auth=false", "--yolo=false", "--debug=false"]'],
  ['comment after value', 'DEBUG=false # DEBUG=true'],
  ['unrelated debug word', 'description: "debug=true is disabled"']
]) {
  test(`does not flag ${name}`, () => assert.equal(analyze(input).findings.length, 0));
}

test('keeps quoted comment markers and detects secrets without returning any source value', () => {
  const value = `${random}#//suffix`;
  const result = analyze(`TOKEN="${value}" # comment`);
  assert.ok(result.findings.some(item => item.ruleId === 'secret'));
  const serialized = JSON.stringify(result);
  assert.ok(!serialized.includes(random));
  assert.ok(!serialized.includes('suffix'));
  assert.ok(!serialized.includes('TOKEN'));
  for (const item of result.findings) assert.match(item.maskedValue, /^•+（\d+文字）$/);
});

test('reports line numbers across CRLF and deduplicates a rule on the same line', () => {
  const result = analyze('# comment\r\nDEBUG=true\r\nTOKEN=sk-proj-' + random);
  assert.deepEqual(result.findings.map(item => [item.ruleId, item.line]), [['debug', 2], ['secret', 3]]);
});

test('does not carry a YAML permissions section into a sibling', () => {
  assert.equal(analyze('permissions:\n  allow: ["./src"]\nother:\n  - "*"').findings.length, 0);
});

test('limits input size and finding count', () => {
  assert.throws(() => analyze('a'.repeat(MAX_LENGTH + 1)), RangeError);
  const result = analyze('DEBUG=true\n'.repeat(MAX_FINDINGS + 3));
  assert.equal(result.findings.length, MAX_FINDINGS);
  assert.equal(result.truncated, true);
});

test('malicious markup stays data and is absent from the returned findings', () => {
  const attack = '<img src=x onerror=alert(1)>';
  const result = analyze(`PASSWORD="${attack}"`);
  assert.ok(!JSON.stringify(result).includes(attack));
});
