'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const api = require('./checker');

function analyze(body) { return api.analyze(body); }
function ids(body) { return analyze(body).findings.map((item) => item.id); }
function has(body, id) { return analyze(body).findings.some((item) => item.id === id); }

test('final stage without USER and final root/UID 0 are medium findings', () => {
  assert.equal(has('FROM alpine:3.20\nUSER app\nFROM alpine:3.20', 'final-user-root'), true);
  assert.equal(analyze('FROM alpine:3.20\nUSER app\nFROM alpine:3.20').findings.find((x) => x.id === 'final-user-root').line, 3);
  assert.equal(has('FROM alpine:3.20\nUSER root', 'final-user-root'), true);
  assert.equal(has('FROM alpine:3.20\nUSER 0:0', 'final-user-root'), true);
  assert.equal(has('FROM alpine:3.20\nUSER app', 'final-user-root'), false);
});

test('HEALTHCHECK is evaluated for the final image stage and NONE counts as missing', () => {
  assert.equal(has('FROM alpine:3.20 AS build\nHEALTHCHECK CMD true\nFROM alpine:3.20 AS app\nUSER app', 'missing-healthcheck'), true);
  assert.equal(has('FROM alpine:3.20\nHEALTHCHECK NONE\nUSER app', 'missing-healthcheck'), true);
  assert.equal(has('FROM alpine:3.20\nHEALTHCHECK CMD true\nUSER app', 'missing-healthcheck'), false);
});

test('ENV and ARG secret-like names with values are high without exposing values', () => {
  const secret = 'DUMMY_PRIVATE_SENTINEL_123';
  const result = analyze(`FROM alpine:3.20\nENV API_KEY ${secret}\nARG ACCESS_TOKEN=${secret}`);
  assert.equal(result.findings.filter((x) => x.id === 'secret-variable').length, 2);
  assert.ok(!JSON.stringify(result).includes(secret));
  assert.equal(has('FROM alpine:3.20\nARG PASSWORD', 'secret-variable'), false);
  assert.equal(has('FROM alpine:3.20\nENV MODE=production', 'secret-variable'), false);
});

test('literal token patterns are detected without displaying them', () => {
  const tokens = ['ghp_DUMMYTOKEN1234567890', 'github_pat_DUMMYTOKEN1234567890',
    'AKIA1234567890ABCDEF', 'sk-DUMMYTOKEN1234567890', 'xoxb-DUMMYTOKEN1234567890'];
  for (const token of tokens) {
    const result = analyze(`FROM alpine:3.20\nRUN printf '%s' '${token}'`);
    assert.ok(has(`FROM alpine:3.20\nRUN printf '%s' '${token}'`, 'hardcoded-token'), token);
    assert.ok(!JSON.stringify(result).includes(token));
  }
});

test('COPY/ADD sensitive paths and full build context are reported', () => {
  const body = 'FROM alpine:3.20\nCOPY .env .\nCOPY id_rsa /root/.ssh/id_rsa\nADD cert.pem /etc/cert.pem\nCOPY . .';
  assert.equal(ids(body).filter((id) => id === 'copy-sensitive-path').length, 3);
  assert.equal(has(body, 'copy-all-context'), true);
  assert.equal(has('FROM alpine:3.20\nCOPY app.js /app/', 'copy-sensitive-path'), false);
});

test('ADD URL and local files both recommend safer alternatives', () => {
  const result = analyze('FROM alpine:3.20\nADD https://example.invalid/a.tgz /tmp/a.tgz\nADD app.conf /etc/app.conf');
  assert.equal(result.findings.filter((x) => x.id === 'add-url').length, 1);
  assert.equal(result.findings.filter((x) => x.id === 'add-local').length, 1);
});

test('FROM tagless/latest and missing digest findings are distinct', () => {
  assert.equal(has('FROM alpine\nUSER app', 'mutable-base-tag'), true);
  assert.equal(has('FROM alpine:latest\nUSER app', 'mutable-base-tag'), true);
  assert.equal(has('FROM alpine:3.20\nUSER app', 'mutable-base-tag'), false);
  assert.equal(has('FROM alpine:3.20\nUSER app', 'unpinned-base-digest'), true);
  assert.equal(has('FROM alpine:3.20@sha256:abcdef\nUSER app', 'unpinned-base-digest'), false);
  assert.equal(has('FROM scratch\nUSER app', 'mutable-base-tag'), false);
});

test('shell and JSON forms, lower-case instructions and line continuations are supported', () => {
  const body = 'from --platform=linux/amd64 alpine:3.20 as base\n' +
    'arg API_KEY="DUMMY_PRIVATE_VALUE"\n' +
    'run curl https://example.invalid/a \\\n+      | sh\n' +
    'copy [".env", "/app/.env"]\n' +
    'user ["app"]\n' +
    'healthcheck CMD true';
  const result = analyze(body);
  assert.equal(result.incomplete, false);
  assert.equal(has(body, 'secret-variable'), true);
  assert.equal(has(body, 'pipe-to-shell'), true);
  assert.equal(has(body, 'copy-sensitive-path'), true);
  assert.equal(has(body, 'final-user-root'), false);
  assert.ok(result.findings.every((item) => Number.isInteger(item.line) && item.line > 0));
});

test('JSON and shell ENV forms detect only values assigned to secret-like names', () => {
  assert.equal(has('FROM alpine:3.20\nENV ["TOKEN", "DUMMY"]', 'secret-variable'), true);
  assert.equal(has('FROM alpine:3.20\nENV API_KEY=DUMMY MODE=production', 'secret-variable'), true);
  assert.equal(has('FROM alpine:3.20\nENV API_KEY', 'secret-variable'), false);
});

test('comments are ignored, multi-stage USER checks only the final stage', () => {
  const body = '# RUN curl x | sh\nFROM alpine:3.20 AS build\nUSER root\nFROM alpine:3.20 AS final\nUSER app\nHEALTHCHECK CMD true';
  assert.equal(has(body, 'pipe-to-shell'), false);
  assert.equal(has(body, 'final-user-root'), false);
  const continued = 'FROM alpine:3.20\nRUN curl https://example.invalid/a \\\n# ignored Dockerfile comment\n  | sh\nUSER app\nHEALTHCHECK CMD true';
  assert.equal(has(continued, 'pipe-to-shell'), true);
});

test('requested permission, sudo, apt, SSH and healthcheck checks are available', () => {
  const body = 'FROM ubuntu:24.04\nRUN chmod 777 /app && sudo apt-get install curl && apt-get upgrade -y\nEXPOSE 22';
  for (const id of ['world-writable', 'sudo', 'apt-recommends', 'apt-cache-cleanup', 'apt-upgrade', 'expose-ssh', 'missing-healthcheck']) {
    assert.ok(has(body, id), id);
  }
  assert.equal(has('FROM ubuntu:24.04\nRUN apt-get install --no-install-recommends curl && rm -rf /var/lib/apt/lists/*\nRUN apk add openssh-server\nHEALTHCHECK CMD true', 'apt-recommends'), false);
  assert.equal(has('FROM alpine:3.20\nRUN apk add openssh-server\nHEALTHCHECK CMD true', 'install-sshd'), true);
});

test('ordinary sample has no high or medium findings; unsafe sample demonstrates checks', () => {
  const safe = analyze(api.safeSample);
  assert.deepEqual(safe.findings.filter((item) => ['高', '中'].includes(item.severity)), []);
  const unsafe = analyze(api.unsafeSample);
  for (const id of ['final-user-root', 'secret-variable', 'hardcoded-token', 'copy-sensitive-path',
    'mutable-base-tag', 'pipe-to-shell', 'world-writable', 'install-sshd', 'expose-ssh']) assert.ok(has(api.unsafeSample, id), id);
  assert.ok(unsafe.findings.some((item) => item.id === 'copy-all-context' && item.severity === '情報'));
});

test('heredoc is reported as incomplete and its body is not parsed as Docker instructions', () => {
  const result = analyze('FROM alpine:3.20\nRUN <<EOF\nFROM bad:latest\nEOF\nUSER app\nHEALTHCHECK CMD true');
  assert.equal(result.incomplete, true);
  assert.equal(result.findings.some((item) => item.id === 'mutable-base-tag' && item.line === 3), false);
});

test('malformed, empty, and oversized input do not throw', () => {
  for (const input of ['', 'not a dockerfile', 'FROM', 'FROM alpine:3.20\nCOPY [broken', 'FROM alpine:3.20\nRUN <<EOF\nnever closed']) {
    assert.doesNotThrow(() => analyze(input));
  }
  assert.ok(analyze('not a dockerfile').incomplete);
  assert.ok(analyze('x'.repeat(api.MAX_LENGTH + 1)).error);
  assert.ok(analyze(null).error);
});

test('result cap, masked values, and static page security', () => {
  const many = 'FROM alpine:3.20\n' + Array.from({ length: 220 }, (_, i) => `ENV API_KEY_${i}=DUMMY_${i}`).join('\n');
  const result = analyze(many);
  assert.equal(result.findings.length, api.MAX_FINDINGS);
  assert.equal(result.truncated, true);
  const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
  assert.match(html, /connect-src 'none'/);
  assert.ok(!/<form|<iframe|<img|<script[^>]+src=["']https?:/i.test(html));
  assert.ok(!/analytics|affiliate|googletagmanager/i.test(html));
  assert.ok(!/<script\b(?![^>]*\bsrc=)/i.test(html));
});

test('browser app uses textContent only and clears data on navigation without network or storage', () => {
  class Element {
    constructor() { this.value = ''; this.textContent = ''; this.children = []; this.listeners = {}; this.hidden = false; }
    addEventListener(name, fn) { this.listeners[name] = fn; }
    append(...nodes) { this.children.push(...nodes); }
    replaceChildren() { this.children = []; }
    focus() {}
    set innerHTML(_) { assert.fail('unsafe HTML rendering'); }
  }
  const elements = new Map();
  for (const id of ['dockerfile', 'findings', 'status', 'count', 'empty', 'check', 'unsafe-sample', 'safe-sample', 'clear']) elements.set(id, new Element());
  const windowEvents = {};
  const forbidden = () => assert.fail('network or persistence API used');
  const context = { window: { DockerfileCheck: api, addEventListener: (name, fn) => { windowEvents[name] = fn; } },
    document: { getElementById: (id) => elements.get(id), createElement: () => new Element() },
    fetch: forbidden, XMLHttpRequest: forbidden, WebSocket: forbidden,
    localStorage: { setItem: forbidden }, sessionStorage: { setItem: forbidden } };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8'), context);
  elements.get('unsafe-sample').listeners.click();
  assert.ok(elements.get('findings').children.length > 0);
  const secret = 'DUMMY_APP_SECRET_777';
  elements.get('dockerfile').value = `FROM alpine:3.20\nENV API_KEY=${secret}`;
  elements.get('check').listeners.click();
  assert.ok(!JSON.stringify(elements.get('findings')).includes(secret));
  elements.get('clear').listeners.click();
  assert.equal(elements.get('dockerfile').value, '');
  windowEvents.pagehide();
  assert.equal(elements.get('dockerfile').value, '');
});
