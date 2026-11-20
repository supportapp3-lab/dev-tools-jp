'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const api = require('./checker');

function ids(yaml) { return api.analyze(yaml).findings.map((item) => item.id); }
function workflow(trigger, permissions, steps, runner = 'ubuntu-latest') {
  return `name: test\non: ${trigger}\n${permissions}\njobs:\n  test:\n    runs-on: ${runner}\n    steps:\n${steps}`;
}
const sha = '0123456789abcdef0123456789abcdef01234567';

test('dangerous sample detects the main high and medium risks; normal sample has no high/medium findings', () => {
  const dangerous = api.analyze(api.unsafeSample);
  assert.equal(dangerous.error, null);
  for (const id of ['targetInfo', 'targetCheckout', 'writeAll', 'injection', 'unpinnedMain', 'curlPipe']) assert.ok(ids(api.unsafeSample).includes(id), id);
  const normal = api.analyze(api.safeSample);
  assert.equal(normal.error, null);
  assert.deepEqual(normal.findings.filter((item) => ['high', 'medium'].includes(item.severity)), []);
});

test('workflow trigger scalar, array and map forms are recognized', () => {
  for (const trigger of ['pull_request_target', '[push, pull_request_target]', '{pull_request_target: {}, workflow_dispatch: {}}']) {
    assert.ok(ids(workflow(trigger, 'permissions: {}', '      - run: echo ok\n')).includes('targetInfo'), trigger);
  }
  assert.ok(ids(workflow('[push, pull_request]', 'permissions: {}', '      - run: echo ok\n')).includes('selfHosted') === false);
});

test('dangerous head checkout is limited to privileged triggers and line numbers point at ref', () => {
  const steps = '      - uses: actions/checkout@' + sha + '\n        with:\n          persist-credentials: false\n          ref: ${{ github.event.pull_request.head.ref }}\n';
  const target = api.analyze(workflow('pull_request_target', 'permissions: {}', steps));
  assert.equal(target.findings.find((item) => item.id === 'targetCheckout')?.line, 11);
  assert.ok(!ids(workflow('pull_request', 'permissions: {}', steps)).includes('targetCheckout'));
});

test('run injection checks untrusted values in block scalars and ignores comments', () => {
  const unsafe = workflow('pull_request', 'permissions: {}', '      - run: |\n          echo "${{ github.event.pull_request.title }}"\n          echo "${{ github.event.comment.body }}"\n');
  const findings = api.analyze(unsafe).findings.filter((item) => item.id === 'injection');
  assert.deepEqual(findings.map((item) => item.line), [9, 10]);
  assert.deepEqual(ids(workflow('pull_request', 'permissions: {}', '      - run: echo ok # ${{ github.event.issue.title }}\n')), []);
});

test('run injection covers workflow_run and other externally controlled event fields while env remains safe', () => {
  const expressions = [
    'github.event.workflow_run.head_commit.message',
    'github.event.workflow_run.head_commit.author.name',
    'github.event.workflow_run.head_commit.author.email',
    'github.event.workflow_run.head_branch',
    'github.event.workflow_run.display_title',
    'github.event.workflow_run.pull_requests[0].head.ref',
    'github.event.discussion.title',
    'github.event.discussion.body',
    'github.event.discussion_comment.body',
    'github.event.pages[0].page_name',
    'github.event.pull_request.head.label',
    'github.event.pull_request.head.repo.default_branch',
  ];
  for (const expression of expressions) {
    const interpolation = '${{ ' + expression + ' }}';
    const direct = workflow('push', 'permissions: {}', `      - run: echo "${interpolation}"\n`);
    const directResult = api.analyze(direct);
    assert.equal(directResult.findings.find((item) => item.id === 'injection')?.severity, 'high', expression);
    const viaEnv = workflow('push', 'permissions: {}', `      - env:\n          VALUE: ${interpolation}\n        run: printf '%s' "$VALUE"\n`);
    assert.ok(!ids(viaEnv).includes('injection'), expression);
  }
});

test('multiple jobs, step mappings, quoted strings, and folded block scalars parse', () => {
  const yaml = `on: [pull_request]\npermissions: {}\njobs:\n  first:\n    runs-on: ubuntu-latest\n    steps:\n      - name: quoted # is not a comment\n        run: >\n          echo "${'${{'} github.event.issue.body }}"\n  second:\n    runs-on: [ubuntu-latest, self-hosted]\n    steps:\n      - uses: vendor/action@v1\n`;
  const result = api.analyze(yaml);
  assert.equal(result.error, null);
  assert.ok(result.findings.some((item) => item.id === 'injection'));
  assert.ok(result.findings.some((item) => item.id === 'selfHosted'));
  assert.ok(result.findings.some((item) => item.id === 'unpinnedAction'));
});

test('permissions, unpinned actions, checkout persistence, and curl-to-shell rules are classified', () => {
  const yaml = `on: pull_request_target\njobs:\n  test:\n    permissions:\n      contents: write\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: vendor/action@v1\n      - uses: vendor/moving@master\n      - run: curl https://example.invalid/setup.sh | sh\n`;
  const findings = api.analyze(yaml).findings;
  assert.ok(findings.some((item) => item.id === 'targetWrite' && item.severity === 'high'));
  assert.ok(findings.some((item) => item.id === 'checkout' && item.severity === 'low'));
  assert.ok(findings.some((item) => item.id === 'unpinnedAction' && item.severity === 'low'));
  assert.ok(findings.some((item) => item.id === 'unpinnedMain' && item.severity === 'medium'));
  assert.ok(findings.some((item) => item.id === 'curlPipe' && item.severity === 'medium'));
  const official = api.analyze(workflow('push', 'permissions: {}', '      - uses: actions/checkout@v4\n        with:\n          persist-credentials: false\n'));
  assert.ok(official.findings.some((item) => item.id === 'unpinnedAction' && item.severity === 'info'));
  assert.deepEqual(ids(workflow('push', 'permissions: {}', '      - uses: actions/checkout@' + sha + '\n        with:\n          persist-credentials: false\n')), []);
});

test('workflow_run with PR head checkout is flagged and pull_request self-hosted runners are warned', () => {
  const headCheckout = '      - uses: actions/checkout@' + sha + '\n        with:\n          persist-credentials: false\n          ref: ${{ github.event.pull_request.head.sha }}\n';
  assert.ok(ids(workflow('{workflow_run: {}, workflow_dispatch: {}}', 'permissions: {}', headCheckout)).includes('targetCheckout'));
  const runner = api.analyze(workflow('pull_request', 'permissions: {}', '      - run: echo ok\n', '[ubuntu-latest, self-hosted]'));
  assert.ok(runner.findings.some((item) => item.id === 'selfHosted' && item.severity === 'medium'));
});

test('workflow_run head SHA or repository checkout is high risk, while checkout without either is not', () => {
  const shaCheckout = '      - uses: actions/checkout@' + sha + '\n        with:\n          ref: ${{ github.event.workflow_run.head_sha }}\n';
  const repoCheckout = '      - uses: actions/checkout@' + sha + '\n        with:\n          repository: ${{ github.event.workflow_run.head_repository.full_name }}\n';
  const trigger = '{workflow_run: {workflows: [CI], types: [completed]}}';
  const permissions = 'permissions: {}';
  assert.ok(ids(workflow(trigger, permissions, shaCheckout)).includes('targetCheckout'));
  assert.ok(ids(workflow(trigger, permissions, repoCheckout)).includes('targetCheckout'));
  const safe = workflow(trigger, permissions, '      - uses: actions/checkout@' + sha + '\n        with:\n          persist-credentials: false\n');
  assert.ok(!ids(safe).includes('targetCheckout'));
});

test('every high and medium finding includes a YAML remediation example', () => {
  const idsWithExamples = ['targetCheckout', 'injection', 'noPermissions', 'writeAll', 'targetWrite', 'broadWrite', 'unpinnedMain', 'echoSecret', 'insecure', 'selfHosted', 'curlPipe'];
  for (const id of idsWithExamples) assert.ok(api.examples[id]?.trim(), id);
  const result = api.analyze(api.unsafeSample);
  for (const finding of result.findings.filter((item) => ['high', 'medium'].includes(item.severity))) {
    assert.ok(finding.yamlExample?.trim(), finding.id);
  }
});

test('secret echo, insecure commands, and hardcoded credentials are found without reflecting values', () => {
  const secret = 'ghp_DUMMYTOKEN1234567890';
  const yaml = `on: push\npermissions: {}\njobs:\n  test:\n    runs-on: ubuntu-latest\n    env:\n      ACTIONS_ALLOW_UNSECURE_COMMANDS: true\n      TOKEN_VALUE: ${secret}\n    steps:\n      - run: echo "${'${{'} secrets.TEST_TOKEN }}"\n`;
  const result = api.analyze(yaml);
  const text = JSON.stringify(result);
  for (const id of ['insecure', 'token', 'echoSecret']) assert.ok(result.findings.some((item) => item.id === id), id);
  assert.ok(!text.includes(secret));
});

test('permissions absence and overbroad write are reported', () => {
  assert.ok(ids(workflow('push', '', '      - run: echo ok\n')).includes('noPermissions'));
  assert.ok(ids(workflow('push', 'permissions:\n  contents: write\n', '      - run: echo ok\n')).includes('broadWrite'));
  assert.ok(!ids(workflow('push', 'permissions: {}\n', '      - run: echo ok\n')).includes('noPermissions'));
});

test('malformed and empty YAML produce a visible error instead of throwing', () => {
  for (const yaml of ['', 'on: [push', 'on: push\non: pull_request', 'jobs:\n\tbad: value', 'not a mapping']) {
    assert.doesNotThrow(() => api.analyze(yaml));
    assert.ok(api.analyze(yaml).error, JSON.stringify(yaml));
  }
});

test('results expose no source text and are bounded', () => {
  const value = 'DUMMY_SECRET_CONTENT';
  const result = api.analyze(`on: push\npermissions: {}\njobs:\n  t:\n    runs-on: ubuntu-latest\n    env:\n      PASSWORD: ${value}\n    steps:\n      - run: echo ok\n`);
  assert.ok(!JSON.stringify(result).includes(value));
  assert.ok(api.analyze('x'.repeat(api.MAX_LENGTH + 1)).error);
});

class Element {
  constructor(tagName = '') { this.tagName = tagName.toUpperCase(); this.value = ''; this.textContent = ''; this.children = []; this.listeners = {}; this.hidden = false; }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren() { this.children = []; this.textContent = ''; }
  focus() {}
}
test('browser app uses text nodes and makes no network or storage calls', () => {
  const elements = new Map();
  for (const id of ['workflow', 'findings', 'status', 'count', 'empty', 'check', 'unsafe-sample', 'safe-sample', 'clear']) elements.set(id, new Element());
  const forbidden = () => assert.fail('network or persistence API used');
  const context = { window: { GhaCheck: api, addEventListener() {} }, document: { getElementById: (id) => elements.get(id), createElement: (tag) => new Element(tag) }, fetch: forbidden, XMLHttpRequest: forbidden, WebSocket: forbidden, localStorage: { setItem: forbidden }, sessionStorage: { setItem: forbidden } };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8'), context);
  elements.get('unsafe-sample').listeners.click();
  assert.ok(elements.get('findings').children.length > 0);
  const examples = elements.get('findings').children.flatMap((item) => item.children.filter((child) => child.tagName === 'PRE'));
  assert.ok(examples.length > 0);
  assert.equal(examples[0].children[0].tagName, 'CODE');
  assert.ok(examples.some((item) => item.children[0].textContent.includes('actions/checkout')));
  elements.get('safe-sample').listeners.click();
  assert.equal(elements.get('findings').children.filter((item) => item.className.includes('finding-high') || item.className.includes('finding-medium')).length, 0);
  elements.get('clear').listeners.click();
  assert.equal(elements.get('workflow').value, '');
});

test('HTML has strict CSP, local assets, Japanese metadata, and no form or external resource', () => {
  const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
  assert.match(html, /connect-src 'none'/); assert.match(html, /script-src 'self'/); assert.match(html, /style-src 'self'/); assert.match(html, /form-action 'none'/);
  assert.match(html, /GitHub Actions ワークフロー安全チェッカー/); assert.match(html, /name="description"/);
  assert.ok(!/<form|<iframe|<(?:script|link)[^>]+(?:src|href)=["']https?:/i.test(html));
});

test('top page links to the new checker', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', '..', 'index.html'), 'utf8');
  assert.match(html, /tools\/gha-check\//);
});
