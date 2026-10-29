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

for (const [name, input, expected] of [
  ['MCP filesystem root', '{"mcpServers":{"files":{"args":["-y","@modelcontextprotocol/server-filesystem","/"]}}}', 'permission'],
  ['MCP filesystem home', 'args: ["server-filesystem", "~"]', 'permission'],
  ['MCP filesystem multiline args', 'args: [\n  "@modelcontextprotocol/server-filesystem",\n  "/"\n]', 'permission'],
  ['agent Read home glob', 'allow: ["Read(~/**)"]', 'permission'],
  ['agent Write home glob', '{"permissions":{"allow":["Write(~/**)"]}}', 'permission'],
  ['agent YAML Read home glob', 'permissions:\n  allow:\n    - "Read(~/**)"', 'permission'],
  ['filesystem home glob', 'allowed_paths: ["~/**"]', 'permission'],
  ['filesystem YAML home glob', 'allowed_paths:\n  - "~/**"', 'permission'],
  ['IPv6 endpoint', 'listen: "[::]:8080"', 'bind'],
  ['IPv6 bind address', 'BIND_ADDRESS="::"', 'bind'],
  ['IPv6 command flag', 'args: ["--listen=[::]:8080"]', 'bind'],
  ['IPv4 command flag', 'command: "serve --host 0.0.0.0"', 'bind'],
  ['Docker host network', 'services:\n  agent:\n    network_mode: host', 'network']
]) {
  test(`detects regression: ${name}`, () => assert.ok(ids(input).has(expected)));
}

for (const [name, input] of [
  ['description containing IPv4', 'description: "Bind to 0.0.0.0 when needed"'],
  ['description containing IPv6', 'description: "Example endpoint [::]:8080"'],
  ['description containing bind flag', 'description: "Use --host 0.0.0.0 for remote access"'],
  ['plain explanatory text', 'Use 0.0.0.0 to listen on all interfaces.'],
  ['commented binding', '# host: 0.0.0.0\n// listen: "[::]:8080"'],
  ['IPv6 loopback host', 'host: "::1"'],
  ['IPv6 loopback endpoint', 'listen: "[::1]:8080"'],
  ['other MCP server args', 'args: ["server-example", "/"]'],
  ['limited MCP filesystem', 'args: ["@modelcontextprotocol/server-filesystem", "./workspace"]'],
  ['separate MCP server arguments', '{"files":{"args":["server-filesystem","./workspace"]},"other":{"args":["other-server","/"]}}'],
  ['commented MCP filesystem', '# args: ["server-filesystem", "/"]'],
  ['limited Read glob', 'allow: ["Read(~/project/**)"]'],
  ['denied home glob', 'permissions:\n  deny: ["Read(~/**)"]'],
  ['Docker bridge network', 'network_mode: bridge'],
  ['certificate PEM body', `certificate: |\n  -----BEGIN CERTIFICATE-----\n  ${random}Ab3D\n  -----END CERTIFICATE-----`],
  ['public key PEM body', `-----BEGIN PUBLIC KEY-----\n${random}Ab3D\n-----END PUBLIC KEY-----`],
  ['base64 certificate field', `certificate: "${random}Ab3D"`]
]) {
  test(`does not flag regression: ${name}`, () => assert.equal(analyze(input).findings.length, 0));
}

test('CORS allow_origins produces only a CORS warning', () => {
  for (const input of ['cors:\n  allow_origins: "*"', 'cors:\n  allow_origins:\n    - "*"', '{"cors":{"allow_origins":"*"}}']) {
    assert.deepEqual([...ids(input)], ['cors']);
  }
  assert.ok(ids('allow: ["*"]').has('permission'));
});

test('PEM end restores entropy detection and does not hide private key headers', () => {
  assert.ok(ids(`-----BEGIN CERTIFICATE-----\n${random}\n-----END CERTIFICATE-----\nCUSTOM_ID=${random}`).has('entropy'));
  assert.ok(ids(`-----BEGIN PRIVATE KEY-----\n${random}\n-----END PRIVATE KEY-----`).has('secret'));
  assert.ok(ids(`TOKEN=${random}`).has('secret'));
});

test('binding, flags, and filesystem argument masks use actual value lengths', () => {
  for (const [input, ruleId, value] of [
    ['host: "::"', 'bind', '::'],
    ['listen: "[::]:8080"', 'bind', '[::]:8080'],
    ['HOST=0.0.0.0', 'bind', '0.0.0.0'],
    ['args: ["--bind=[::]:8080"]', 'bind', '[::]:8080'],
    ['args: ["--debug"]', 'debug', '--debug'],
    ['args: ["--no-auth=true"]', 'auth', '--no-auth=true'],
    ['args: ["--yolo"]', 'permission', '--yolo'],
    ['args: ["server-filesystem", "/"]', 'permission', '/']
  ]) {
    const result = analyze(input);
    assert.equal(result.findings.find(item => item.ruleId === ruleId).maskedValue, `••••（${value.length}文字）`);
    assert.ok(!JSON.stringify(result).includes('args:'));
  }
});

test('bare port masks use the configured port length', () => {
  for (const input of ['ports:\n - 8080', 'ports: [8080]', 'published: "8080"']) {
    assert.equal(analyze(input).findings.find(item => item.ruleId === 'port').maskedValue, '••••（4文字）');
  }
});

test('MCP filesystem finding reports the root argument line', () => {
  assert.deepEqual(analyze('args: [\n "server-filesystem",\n "/"\n]').findings.map(item => [item.ruleId, item.line]), [['permission', 3]]);
});
