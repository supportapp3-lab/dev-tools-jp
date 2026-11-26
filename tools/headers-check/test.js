'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const api = require('./checker');

function result(input) { return api.analyze(input); }
function findings(input) { return result(input).findings; }
function has(input, id) { return findings(input).some((finding) => finding.id === id); }

test('empty and malformed input never throws and reports ignored lines', () => {
  assert.equal(api.parseHeaders('').headers.size, 0);
  assert.equal(result('not a header\n: missing name\n').ignoredLines, 2);
  assert.doesNotThrow(() => result('HTTP/2 200\n\u0000\n???\n: bad'));
});

test('accepts status lines, headers without status, and case-insensitive names', () => {
  assert.equal(result('HTTP/1.1 200 OK\nStrict-Transport-Security: max-age=31536000; includeSubDomains').responseCount, 1);
  assert.ok(!has('strict-transport-security: max-age=31536000; includeSubDomains\nX-Content-Type-Options: nosniff\nX-Frame-Options: DENY\nReferrer-Policy: no-referrer\nPermissions-Policy: camera=()\nContent-Security-Policy: default-src \'self\'; object-src \'none\'; frame-ancestors \'none\'', 'Strict-Transport-Security:HSTS がありません'));
  const lower = result('hTtP/2 200\nx-content-type-options: nosniff\nx-frame-options: DENY\nreferrer-policy: no-referrer\npermissions-policy: camera=()\nstrict-transport-security: max-age=20000000; includeSubDomains\ncontent-security-policy: default-src \'self\'; object-src \'none\'; frame-ancestors \'none\'');
  assert.equal(lower.ignoredLines, 0);
  assert.equal(lower.findings.length, 0);
});

test('when curl output has multiple status blocks, only the last response is analyzed', () => {
  const input = 'HTTP/1.1 301 Moved\nServer: nginx/1.18.0\n\nHTTP/2 200\nStrict-Transport-Security: max-age=31536000; includeSubDomains\nX-Content-Type-Options: nosniff\nX-Frame-Options: DENY\nReferrer-Policy: no-referrer\nPermissions-Policy: camera=()\nContent-Security-Policy: default-src \'self\'; object-src \'none\'; frame-ancestors \'none\'\n\n';
  const parsed = result(input);
  assert.equal(parsed.responseCount, 2);
  assert.equal(parsed.selectedLast, true);
  assert.ok(!parsed.findings.some((finding) => finding.header === 'Server'));
});

test('HSTS absence, short max-age, zero, and includeSubDomains are distinguished', () => {
  assert.ok(findings('').some((finding) => finding.header === 'Strict-Transport-Security' && finding.severity === 'medium'));
  assert.ok(findings('Strict-Transport-Security: max-age=1000').some((finding) => finding.severity === 'low'));
  const zero = findings('Strict-Transport-Security: max-age=0');
  assert.ok(zero.some((finding) => finding.header === 'Strict-Transport-Security' && finding.severity === 'medium'));
  assert.ok(!zero.some((finding) => finding.header === 'Strict-Transport-Security' && finding.severity === 'low'));
  assert.ok(findings('Strict-Transport-Security: max-age=31536000').some((finding) => finding.title.includes('includeSubDomains')));
  assert.ok(!findings('Strict-Transport-Security: max-age=31536000; includeSubDomains').some((finding) => finding.header === 'Strict-Transport-Security'));
});

test('CSP missing and report-only-only policies have different severity', () => {
  assert.ok(findings('').some((finding) => finding.header === 'Content-Security-Policy' && finding.severity === 'medium'));
  const reportOnly = findings('Content-Security-Policy-Report-Only: default-src \'self\'');
  assert.ok(reportOnly.some((finding) => finding.severity === 'low' && finding.header === 'Content-Security-Policy-Report-Only'));
  assert.ok(!reportOnly.some((finding) => finding.severity === 'medium' && finding.header === 'Content-Security-Policy'));
});

test('CSP script-src falls back to default-src and recognizes unsafe-inline, nonce, and hash', () => {
  assert.ok(findings("Content-Security-Policy: default-src 'unsafe-inline'").some((finding) => finding.title.includes('unsafe-inline')));
  assert.ok(!findings("Content-Security-Policy: script-src 'unsafe-inline' 'nonce-AbCd123'; default-src 'self'").some((finding) => finding.title.includes('unsafe-inline')));
  assert.ok(!findings("Content-Security-Policy: script-src 'unsafe-inline' 'sha256-AbCd123='; default-src 'self'").some((finding) => finding.title.includes('unsafe-inline')));
  assert.ok(findings("Content-Security-Policy: script-src 'unsafe-eval'; default-src 'self'").some((finding) => finding.title.includes('unsafe-eval')));
});

test('CSP identifies broad-only script sources, missing object policy, and frame ancestors', () => {
  assert.ok(findings('Content-Security-Policy: script-src https:').some((finding) => finding.title.includes('広すぎます')));
  const fallback = findings("Content-Security-Policy: default-src 'self'");
  assert.ok(!fallback.some((finding) => finding.title.includes('object-src')));
  assert.ok(fallback.some((finding) => finding.header === 'Content-Security-Policy' && finding.title.includes('frame-ancestors')));
  assert.ok(findings("Content-Security-Policy: script-src 'self'").some((finding) => finding.title.includes('object-src')));
});

test('clickjacking protection accepts X-Frame-Options or CSP frame-ancestors', () => {
  assert.ok(findings('').some((finding) => finding.title.includes('クリックジャッキング')));
  assert.ok(!findings("Content-Security-Policy: default-src 'self'; frame-ancestors 'none'").some((finding) => finding.title.includes('クリックジャッキング')));
  assert.ok(findings('X-Frame-Options: ALLOW-FROM https://example.test').some((finding) => finding.severity === 'low'));
});

test('nosniff, Referrer-Policy, and Permissions-Policy checks accept safe values', () => {
  const missing = findings('');
  assert.ok(missing.some((finding) => finding.header === 'X-Content-Type-Options' && finding.severity === 'low'));
  assert.ok(missing.some((finding) => finding.header === 'Referrer-Policy' && finding.severity === 'low'));
  assert.ok(missing.some((finding) => finding.header === 'Permissions-Policy' && finding.severity === 'info'));
  assert.ok(findings('X-Content-Type-Options: nosniff').every((finding) => finding.header !== 'X-Content-Type-Options'));
  assert.ok(findings('X-Content-Type-Options: sniff').some((finding) => finding.header === 'X-Content-Type-Options'));
  assert.ok(findings('Referrer-Policy: unsafe-url').some((finding) => finding.severity === 'medium'));
  assert.ok(!findings('Referrer-Policy: strict-origin-when-cross-origin\nPermissions-Policy: camera=()').some((finding) => ['Referrer-Policy', 'Permissions-Policy'].includes(finding.header)));
});

test('each Set-Cookie is checked and cookie values are never returned', () => {
  const input = 'Set-Cookie: session_token=SUPER-SECRET; SameSite=None\nSet-Cookie: theme=purple';
  const parsed = result(input);
  assert.equal(parsed.cookies.length, 2);
  assert.deepEqual(parsed.cookies.map((cookie) => cookie.value), ['••••', '••••']);
  assert.ok(parsed.findings.some((finding) => finding.severity === 'high' && finding.cookieIndex === 1));
  assert.ok(parsed.findings.some((finding) => finding.header === 'Set-Cookie' && finding.title.includes('HttpOnly') && finding.severity === 'medium'));
  assert.ok(parsed.findings.some((finding) => finding.title.includes('SameSite がありません')));
  assert.ok(!JSON.stringify(parsed).includes('SUPER-SECRET'));
});

test('cookie Secure, HttpOnly, and SameSite checks accept complete attributes', () => {
  assert.ok(!findings('Set-Cookie: sessionid=redact-me; Path=/; Secure; HttpOnly; SameSite=Lax').some((finding) => finding.header === 'Set-Cookie'));
  assert.ok(findings('Set-Cookie: preference=x').some((finding) => finding.severity === 'low' && finding.title.includes('HttpOnly')));
  assert.ok(findings('Set-Cookie: auth_token=x; Secure').some((finding) => finding.severity === 'medium' && finding.title.includes('HttpOnly')));
  assert.ok(findings('Set-Cookie: a=b; SameSite=None; Secure; HttpOnly').every((finding) => !finding.title.includes('Secure がありません')));
});

test('CORS wildcard with credentials is high, null is medium, and public wildcard is info', () => {
  assert.ok(findings('Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true').some((finding) => finding.severity === 'high'));
  assert.ok(findings('Access-Control-Allow-Origin: null').some((finding) => finding.severity === 'medium'));
  assert.ok(findings('Access-Control-Allow-Origin: *').some((finding) => finding.severity === 'info'));
  assert.ok(!findings('Access-Control-Allow-Origin: https://app.example.com\nAccess-Control-Allow-Credentials: true').some((finding) => finding.header.startsWith('Access-Control')));
});

test('version disclosure and deprecated headers are reported without reflecting values', () => {
  const input = 'Server: nginx/1.18.0 (Ubuntu)\nX-Powered-By: PHP/8.2\nX-AspNet-Version: 4.0\nX-AspNetMvc-Version: 5.2\nX-XSS-Protection: 1; mode=block\nPublic-Key-Pins: demo';
  const found = findings(input);
  assert.ok(found.some((finding) => finding.header === 'Server' && finding.severity === 'low'));
  assert.equal(found.filter((finding) => ['x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version'].includes(finding.header)).length, 3);
  assert.ok(found.some((finding) => finding.header === 'X-XSS-Protection' && finding.severity === 'info'));
  assert.ok(found.some((finding) => finding.header === 'Public-Key-Pins' && finding.severity === 'low'));
  assert.ok(!JSON.stringify(found).includes('PHP/8.2'));
  assert.ok(!findings('Server: nginx').some((finding) => finding.header === 'Server'));
  assert.ok(!findings('X-XSS-Protection: 0').some((finding) => finding.header === 'X-XSS-Protection'));
});

test('Cache-Control hint is conditional on Set-Cookie', () => {
  assert.ok(findings('Set-Cookie: a=b; Secure').some((finding) => finding.title.includes('Cache-Control')));
  assert.ok(!findings('Set-Cookie: a=b; Secure\nCache-Control: no-store').some((finding) => finding.title.includes('Cache-Control')));
});

test('unparseable header lines are ignored and counted without stopping analysis', () => {
  const parsed = result('HTTP/2 200\nbad line\nX-Content-Type-Options: nosniff\n@bad: value\n');
  assert.equal(parsed.ignoredLines, 2);
  assert.ok(!parsed.findings.some((finding) => finding.header === 'X-Content-Type-Options'));
});

test('ordinary sample has no high or medium finding and unsafe sample exercises headline checks', () => {
  const safe = result(api.safeSample);
  assert.ok(!safe.findings.some((finding) => ['high', 'medium'].includes(finding.severity)));
  const unsafe = result(api.unsafeSample);
  assert.ok(unsafe.findings.some((finding) => finding.header === 'Strict-Transport-Security'));
  assert.ok(unsafe.findings.some((finding) => finding.title.includes('unsafe-inline')));
  assert.ok(unsafe.findings.some((finding) => finding.header === 'Set-Cookie' && finding.title.includes('Secure')));
  assert.ok(unsafe.findings.some((finding) => finding.header.startsWith('Access-Control')));
  assert.ok(unsafe.findings.some((finding) => finding.header === 'Server'));
  assert.ok(!JSON.stringify(unsafe).includes('DEMO-SECRET-123'));
});
