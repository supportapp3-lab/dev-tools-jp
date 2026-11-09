'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const api = require('./checker');
let passed = 0;
function test(name, fn) { fn(); passed += 1; console.log(`ok ${passed} - ${name}`); }
function config(text) { return `services:\n  example:\n${text.split('\n').map((line) => `    ${line}`).join('\n')}\n`; }
function ids(text) { return api.analyze(config(text)).findings.map((f) => f.id); }

for (const [name, input, expected] of [
  ['privileged', 'privileged: true', ['privileged']],
  ['privileged quoted', 'privileged: "true" # note', ['privileged']],
  ['privileged disabled', 'privileged: false', []],
  ['socket short readonly', 'volumes:\n  - "/var/run/docker.sock:/run/docker.sock:ro"', ['socket']],
  ['socket flow list', 'volumes: ["/var/run/docker.sock:/run/docker.sock"]', ['socket']],
  ['socket long', 'volumes:\n  - type: bind\n    source: /var/run/docker.sock\n    target: /run/docker.sock', ['socket']],
  ['other volume', 'volumes:\n  - /data:/data', []],
  ['host network', "network_mode: 'host'", ['host']],
  ['isolated network', 'network_mode: bridge', []],
  ['all capability', 'cap_add: [ALL]', ['capability']],
  ['SYS_ADMIN block', 'cap_add:\n  - SYS_ADMIN', ['capability']],
  ['capability scalar heuristic', 'cap_add: ALL', ['capability']],
  ['cap_drop is not cap_add', 'cap_drop: [ALL]\ncap_add: [NET_BIND_SERVICE]', []],
  ['secret map', 'environment:\n  POSTGRES_PASSWORD: DUMMY_VALUE', ['secret']],
  ['secret list', 'environment:\n  - API_KEY=DUMMY_VALUE\n  - PASSWORD=DUMMY_TWO', ['secret', 'secret']],
  ['secret flow map', 'environment: {API_KEY: "DUMMY_VALUE"}', ['secret']],
  ['secret flow list', 'environment: ["API_KEY=DUMMY_VALUE"]', ['secret']],
  ['empty/reference environment', 'environment:\n  - PASSWORD\n  - PASSWORD=\n  - API_KEY=${API_KEY}\n  - TOKEN=$TOKEN\n  - MODE=production\n  - PASSWORD=null', []],
  ['empty/null map environment', 'environment:\n  PASSWORD: ""\n  TOKEN:\n  API_KEY: null', []],
  ['latest image', 'image: registry.invalid/team/app:latest', ['latest']],
  ['fixed image', 'image: registry.invalid:5000/team/app:1.2.3', []],
  ['digest latest is pinned', 'image: example:latest@sha256:1234', []],
  ['root user', 'user: root', ['root']],
  ['root uid and group', 'user: "0:1000"', ['root']],
  ['non-root user', 'user: "1000:1000"', []],
  ['seccomp list', 'security_opt:\n  - seccomp:unconfined', ['seccomp']],
  ['seccomp flow', 'security_opt: ["seccomp=unconfined"]', ['seccomp']],
  ['seccomp default', 'security_opt:\n  - no-new-privileges:true', []],
  ['comments ignored', '# privileged: true\n# user: root\nimage: app:1', []],
  ['quoted hash retained', 'environment:\n  API_KEY: "#DUMMY_VALUE"', ['secret']],
  ['command shell text not settings', 'command: |\n  user: root\n  privileged: true\n\n  cap_add: ALL\nimage: app:1', []],
  ['unrelated nested settings not service properties', 'labels:\n  privileged: true\n  user: root', []],
]) test(name, () => { assert.deepEqual(ids(input), expected); });

for (const port of [3306, 5432, 6379, 27017, 9200]) {
  test(`DB port ${port} with omitted IP`, () => assert.deepEqual(ids(`ports:\n  - "${port}:${port}"`), ['db']));
  test(`DB port ${port} localhost`, () => assert.deepEqual(ids(`ports:\n  - "127.0.0.1:${port}:${port}"`), []));
}
for (const [name, input, expected] of [
  ['all IPv4', 'ports: ["0.0.0.0:12345:5432/tcp"]', ['db']],
  ['all IPv6', 'ports:\n  - "[::]:12345:5432"', ['db']],
  ['IPv6 loopback', 'ports:\n  - "[::1]:12345:5432"', []],
  ['container only ephemeral published port', 'ports:\n  - 5432', ['db']],
  ['container target is DB even with changed host port', 'ports:\n  - "15432:5432"', ['db']],
  ['host DB number with nonDB container', 'ports:\n  - "5432:8080"', []],
  ['port range', 'ports:\n  - "5300-5500:5300-5500"', ['db']],
  ['normal web port', 'ports:\n  - "8080:80"', []],
  ['ports long omitted IP', 'ports:\n  - target: 5432\n    published: "15432"\n    protocol: tcp', ['db']],
  ['ports long automatically assigned host port', 'ports:\n  - target: 5432', ['db']],
  ['ports long explicit all', 'ports:\n  - target: 3306\n    published: 13306\n    host_ip: 0.0.0.0', ['db']],
  ['ports long localhost', 'ports:\n  - target: 3306\n    published: 13306\n    host_ip: "127.0.0.1"', []],
  ['ports flow object', 'ports:\n  - {target: 6379, published: 16379, host_ip: "0.0.0.0"}', ['db']],
  ['expose only', 'expose: [5432]', []],
]) test(name, () => assert.deepEqual(ids(input), expected));

test('dangerous sample detects all nine categories and safe sample has zero', () => {
  assert.deepEqual([...new Set(api.analyze(api.unsafeSample).findings.map((f) => f.id))].sort(),
    ['privileged', 'socket', 'host', 'db', 'capability', 'secret', 'latest', 'root', 'seccomp'].sort());
  assert.deepEqual(api.analyze(api.safeSample), { findings: [], incomplete: false, truncated: false });
});
test('separate services do not leak section context', () => {
  const result = api.analyze('services:\n  one:\n    environment:\n      PASSWORD: DUMMY\n  two:\n    labels:\n      TOKEN: DUMMY\n    ports:\n      - "127.0.0.1:5432:5432"\n');
  assert.deepEqual(result.findings.map((f) => [f.id, f.line]), [['secret', 4]]);
});
test('secret values, service names and source snippets never appear in results', () => {
  const value = 'DUMMY_COMPOSE_PRIVATE_VALUE';
  const result = api.analyze(`services:\n  PRIVATE_SERVICE_NAME:\n    environment:\n      API_KEY: "${value}"\n    privileged: true\n`);
  assert.equal(result.findings.length, 2);
  const serialized = JSON.stringify(result);
  for (const forbidden of [value, 'PRIVATE_SERVICE_NAME', `API_KEY: "${value}"`]) assert.ok(!serialized.includes(forbidden));
  for (const finding of result.findings) {
    assert.ok(finding.line >= 1 && ['危険', '注意'].includes(finding.severity));
    assert.ok(finding.advice && finding.maskedValue === '[設定値は非表示]');
  }
});
test('masked input hides values in mappings/lists/comments/unsupported lines', () => {
  const value = 'DUMMY_COMPOSE_PRIVATE_VALUE';
  const input = `# ${value}\nservices:\n  app:\n    image: '${value}'\n    environment:\n      API_KEY: "${value}" # ${value}\n      - PASSWORD=${value}\n${value}\n`;
  const masked = api.maskInput(input);
  assert.ok(!masked.includes(value));
  assert.ok(masked.includes('services:') && masked.includes('API_KEY: [マスク]'));
});
for (const input of ['not yaml', 'services: {}', 'services:\n  app: {privileged: true}',
  'services:\n  app: &base\n    privileged: true', config('env_file: private.env'),
  config('extends:\n  file: other.yml'), config('command: |\n  something'),
  config('ports: ["5432:5432",'), 'services:\n\tapp:\n  user: root',
  'include:\n  - other.yml\nservices:\n  app:\n    image: demo:1']) {
  test('unsupported/reference syntax explicitly remains incomplete', () => assert.equal(api.analyze(input).incomplete, true));
}
test('bounded input and capped results', () => {
  assert.throws(() => api.analyze('x'.repeat(api.MAX_LENGTH + 1)));
  assert.throws(() => api.analyze(null));
  const result = api.analyze(config('environment:\n' + Array.from({ length: 220 }, (_, i) => `  API_KEY_${i}: DUMMY_${i}`).join('\n')));
  assert.equal(result.findings.length, 200);
  assert.equal(result.truncated, true);
});

class Element {
  constructor() { this.value = ''; this.textContent = ''; this.children = []; this.listeners = {}; this.hidden = false; this.readOnly = false; }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren() { this.children = []; this.textContent = ''; }
  focus() {}
  get innerHTML() { throw Error('unsafe HTML rendering'); }
  set innerHTML(_) { throw Error('unsafe HTML rendering'); }
}
test('browser app: samples, private paste/masking, locked editing, re-paste, clear and no APIs', () => {
  const elements = new Map();
  for (const id of ['config', 'findings', 'status', 'count', 'empty', 'check', 'unsafe-sample', 'safe-sample', 'clear']) elements.set(id, new Element());
  const windowEvents = {};
  const forbidden = () => assert.fail('network or persistence API used');
  const context = { window: { ComposeCheck: api, addEventListener: (name, fn) => { windowEvents[name] = fn; } },
    document: { getElementById: (id) => elements.get(id), createElement: () => new Element() },
    fetch: forbidden, XMLHttpRequest: forbidden, WebSocket: forbidden, localStorage: { setItem: forbidden }, sessionStorage: { setItem: forbidden } };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8'), context);
  const click = (id) => elements.get(id).listeners.click();
  click('unsafe-sample');
  assert.equal(elements.get('findings').children.length, 9);
  assert.ok(!elements.get('config').value.includes('DUMMY_COMPOSE_ONLY'));
  click('safe-sample');
  assert.equal(elements.get('findings').children.length, 0);
  assert.match(elements.get('status').textContent, /安全の保証ではありません/);
  const value = 'DUMMY_COMPOSE_PRIVATE_VALUE';
  let prevented = false;
  elements.get('config').listeners.paste({ preventDefault() { prevented = true; }, clipboardData: { getData: () => config(`environment:\n  API_KEY: ${value}`) } });
  assert.equal(prevented, true);
  assert.equal(elements.get('config').readOnly, true);
  assert.ok(!elements.get('config').value.includes(value));
  click('check');
  assert.equal(elements.get('findings').children.length, 1);
  click('clear');
  assert.equal(elements.get('config').value, '');
  assert.equal(elements.get('config').readOnly, false);
  elements.get('config').value = config('user: root');
  elements.get('config').listeners.input();
  click('check');
  assert.equal(elements.get('findings').children.length, 1);
  windowEvents.pagehide();
  assert.equal(elements.get('config').value, '');
});
test('HTML uses local assets, strict no-connect CSP, text rendering and no tracking/forms', () => {
  const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
  assert.match(html, /connect-src 'none'/);
  assert.match(html, /form-action 'none'/);
  assert.ok(!/<form|<iframe|<img|<script[^>]+src=["']https?:/i.test(html));
  assert.ok(!/analytics|affiliate|googletagmanager/i.test(html));
});
console.log(`${passed} tests passed`);
