'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const api = require('./checker');
let passed = 0;
function test(name, fn) { fn(); passed += 1; console.log(`ok ${passed} - ${name}`); }
function encode(value) { return Buffer.from(JSON.stringify(value)).toString('base64url'); }
function token(header, payload, signature = 'dummy-signature') { return `${encode(header)}.${encode(payload)}.${signature}`; }
const now = Date.parse('2026-11-12T00:00:00Z');
const seconds = Math.floor(now / 1000);
function ids(header, payload) { return api.analyze(token(header, payload), now).findings.map((item) => item.title); }

test('Bearer prefix and surrounding whitespace/newlines are accepted', () => {
  const result = api.analyze(` \nBearer ${token({ alg: 'RS256' }, { exp: seconds + 3600 })}\n `, now);
  assert.equal(result.ok, true);
});
test('alg none is case-insensitive and high severity', () => {
  const result = api.analyze(token({ alg: 'NoNe' }, { exp: seconds + 3600 }), now);
  assert.equal(result.findings[0].severity, 'high');
  assert.equal(result.findings[0].title, 'alg: none');
});
test('ordinary claims do not trigger an algorithm warning', () => {
  assert.deepEqual(ids({ alg: 'RS256' }, { exp: seconds + 3600 }), []);
});
test('missing exp is medium severity', () => {
  const result = api.analyze(token({ alg: 'RS256' }, {}), now);
  assert.equal(result.findings[0].severity, 'medium');
  assert.equal(result.findings[0].title, 'exp がありません');
});
test('expired exp is an informational finding', () => {
  const result = api.analyze(token({ alg: 'RS256' }, { exp: seconds - 120 }), now);
  assert.equal(result.findings.find((item) => item.title === '期限切れ').severity, 'low');
  assert.match(result.dates.find((item) => item.claim === 'exp').text, /2分前に期限切れ/);
});
test('long validity, future nbf, and JST conversion are reported', () => {
  const result = api.analyze(token({ alg: 'RS256' }, { iat: seconds, nbf: seconds + 3600, exp: seconds + 31 * 86400 }), now);
  assert.ok(result.findings.some((item) => item.title === '有効期間が長い可能性'));
  assert.ok(result.findings.some((item) => item.title === 'まだ有効ではありません'));
  assert.equal(result.dates.find((item) => item.claim === 'iat').text, '発行: 2026-11-12 09:00:00 JST');
  assert.match(result.dates.find((item) => item.claim === 'nbf').text, /あと1時間から有効/);
});
test('sensitive keys and PII values are reported without exposing values', () => {
  const secret = 'DO_NOT_PRINT_THIS_TOKEN';
  const result = api.analyze(token({ alg: 'RS256' }, { api_key: secret, contact: 'user@example.com' }), now);
  const finding = result.findings.find((item) => item.title === '機微情報らしき内容');
  assert.ok(finding);
  assert.match(finding.message, /暗号化ではなく/);
  assert.ok(!JSON.stringify(result.findings).includes(secret));
  assert.ok(!JSON.stringify(result.findings).includes('user@example.com'));
});
test('HS256, kid, and jku/x5u warnings are covered', () => {
  const result = api.analyze(token({ alg: 'HS256', kid: 'key-1', jku: 'https://example.invalid/keys' }, { exp: seconds + 3600 }), now);
  assert.deepEqual(result.findings.map((item) => item.title), ['kid ヘッダー', '外部鍵参照ヘッダー', '共有鍵アルゴリズム']);
});
test('signature content is not exposed; only its encoded length is returned', () => {
  const result = api.analyze(token({ alg: 'RS256' }, { exp: seconds + 3600 }, 'SECRET_SIGNATURE_VALUE'), now);
  assert.equal(result.signatureLength, 'SECRET_SIGNATURE_VALUE'.length);
  assert.ok(!JSON.stringify(result).includes('SECRET_SIGNATURE_VALUE'));
});
test('invalid segment count, malformed Base64URL/JSON, and JWE show friendly errors', () => {
  assert.match(api.analyze('nope').error, /3パート/);
  assert.match(api.analyze('a.b.c.d.e').error, /JWE/);
  assert.match(api.analyze('@@.e30.sig').error, /ヘッダーをBase64URL\/JSON/);
  assert.match(api.analyze(`${encode({ alg: 'RS256' })}.${Buffer.from('not json').toString('base64url')}.sig`).error, /ペイロードをBase64URL\/JSON/);
  assert.match(api.analyze(`.${encode({})}.sig`).error, /ヘッダーをBase64URL\/JSON/);
});
test('a token with internal whitespace is rejected', () => {
  assert.match(api.analyze(`Bearer ${token({ alg: 'RS256' }, {})}\nextra`).error, /途中に空白/);
});
test('danger sample uses dummy content and exercises risk checks', () => {
  const result = api.analyze(api.dangerSample, now);
  assert.equal(result.ok, true);
  assert.ok(result.findings.some((item) => item.title === 'alg: none'));
  assert.ok(result.findings.some((item) => item.title === '機微情報らしき内容'));
  assert.ok(result.findings.some((item) => item.title === '期限切れ'));
});
test('normal sample has no high-severity findings', () => {
  const result = api.analyze(api.normalSample, now);
  assert.equal(result.ok, true);
  assert.ok(!result.findings.some((item) => item.severity === 'high'));
});
test('top-level input limit is enforced', () => {
  assert.match(api.analyze('x'.repeat(api.MAX_LENGTH + 1)).error, /長すぎます/);
});
test('browser app uses text rendering and no network or storage APIs', () => {
  class Element {
    constructor() { this.value = ''; this.textContent = ''; this.children = []; this.listeners = {}; this.hidden = false; this.className = ''; }
    addEventListener(name, fn) { this.listeners[name] = fn; }
    append(...items) { this.children.push(...items); }
    replaceChildren() { this.children = []; }
    focus() {}
    set innerHTML(_) { assert.fail('HTML injection API must not be used'); }
  }
  const ids = ['jwt', 'status', 'header', 'payload', 'signature', 'dates', 'findings', 'empty', 'decode', 'danger-sample', 'normal-sample', 'clear'];
  const elements = new Map(ids.map((id) => [id, new Element()]));
  const fail = () => assert.fail('network or persistence API must not be used');
  const context = {
    window: { JwtCheck: api },
    document: { getElementById: (id) => elements.get(id), createElement: () => new Element() },
    fetch: fail,
    XMLHttpRequest: fail,
    WebSocket: fail,
    localStorage: { setItem: fail },
    sessionStorage: { setItem: fail }
  };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8'), context);
  elements.get('danger-sample').listeners.click();
  assert.match(elements.get('status').textContent, /署名は検証していません/);
  assert.ok(elements.get('findings').children.length > 0);
  elements.get('normal-sample').listeners.click();
  assert.ok(!elements.get('findings').children.some((item) => item.className === 'severity-high'));
  elements.get('clear').listeners.click();
  assert.equal(elements.get('jwt').value, '');
  assert.equal(elements.get('header').textContent, '');
});
test('HTML has strict CSP, local assets, and no form/tracker/remote dependency', () => {
  const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
  assert.match(html, /connect-src 'none'/);
  assert.match(html, /form-action 'none'/);
  assert.match(html, /<script src="checker\.js" defer>/);
  assert.ok(!/<form|<iframe|<script[^>]+src=["']https?:|googletagmanager|analytics/i.test(html));
});
console.log(`${passed} tests passed`);
