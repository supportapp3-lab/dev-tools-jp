'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const api = require('./checker');
let passed = 0;
function test(name, fn) { fn(); passed += 1; console.log(`ok ${passed} - ${name}`); }
function config(body, before = 'server_tokens off; add_header X-Content-Type-Options nosniff; add_header X-Frame-Options DENY; add_header Strict-Transport-Security max-age=31536000;') { return `http {\n${before}\nserver {\n listen 8080;\n location ~ /. { deny all; }\n ${body}\n}\n}\n`; }
function ids(input) { return api.analyze(input).findings.map((finding) => finding.id); }

for (const [name, body, expected] of [
  ['autoindex on', 'autoindex on;', ['autoindex']], ['autoindex off', 'autoindex off;', []],
  ['old TLS protocols', 'listen 443 ssl; ssl_protocols TLSv1 TLSv1.1 TLSv1.2;', ['oldTls']],
  ['current TLS protocols', 'listen 443 ssl; ssl_protocols TLSv1.2 TLSv1.3; add_header Strict-Transport-Security x; add_header X-Content-Type-Options nosniff; add_header X-Frame-Options DENY;', []],
  ['unlimited body size', 'client_max_body_size 0;', ['bodySize']], ['body size over 1g', 'client_max_body_size 2g;', ['bodySize']],
  ['body size at 1g', 'client_max_body_size 1g;', []],
  ['wide root', 'root /;', ['rootPath']], ['root user home', 'root /home/devuser/site;', ['rootPath']],
  ['normal document root', 'root /var/www/site;', []],
  ['include noted', 'include /etc/nginx/conf.d/site.conf;', ['include']],
  ['secret key marker is flagged without reflecting content', 'ssl_certificate_key /private/location;\n# -----BEGIN PRIVATE KEY-----\nDUMMY_PRIVATE_MATERIAL', ['privateKey']],
  ['encrypted private key marker is flagged', '# -----BEGIN ENCRYPTED PRIVATE KEY-----', ['privateKey']],
]) test(name, () => assert.deepEqual(ids(config(body)), expected));

test('server_tokens defaults to on and explicit on is flagged', () => {
  assert.deepEqual([...new Set(ids('http { server { listen 80; } }'))].sort(), ['contentType', 'frame', 'hidden', 'serverTokens'].sort());
  assert.ok(ids(config('server_tokens on;')).includes('serverTokens'));
  assert.ok(!ids(config('server_tokens off;')).includes('serverTokens'));
});
test('HTTPS checks HSTS and security headers, but accepts inherited headers', () => {
  const safe = `http {\n server_tokens off;\n add_header X-Content-Type-Options nosniff;\n add_header Content-Security-Policy "frame-ancestors 'none'";\n add_header Strict-Transport-Security max-age=31536000;\n server { listen 443 ssl; ssl_protocols TLSv1.2 TLSv1.3; location ~ /\\. { deny all; } }\n}`;
  assert.deepEqual(api.analyze(safe).findings, []);
  const unsafe = 'http { server { listen 443 ssl; } }';
  assert.deepEqual([...new Set(ids(unsafe))].sort(), ['contentType', 'frame', 'hidden', 'hsts', 'serverTokens'].sort());
});
test('HTTP redirect requires a 443 TLS server and is checked only at server scope', () => {
  const secure = 'http { server { listen 80; return 301 https://$host$request_uri; } server { listen 443 ssl; } }';
  assert.ok(!ids(secure).includes('redirect'));
  const noRedirect = 'http { server { listen 80; location / { return 301 https://example.com; } } server { listen 443 ssl; } }';
  assert.ok(ids(noRedirect).includes('redirect'));
  assert.ok(!ids('http { server { listen 80; } }').includes('redirect'));
  assert.ok(!ids('http { server { return 301 https://example.com; } server { listen 443 ssl; } }').includes('redirect'));
  assert.ok(ids('http { server { } server { listen 443 ssl; } }').includes('redirect'));
});
test('non-serving redirect and forwarding/deny-only servers skip response checks', () => {
  const input = `http {
    server_tokens off;
    server {
      listen 80;
      return 301 https://$host$request_uri;
    }
    server {
      listen 443 ssl;
      ssl_protocols TLSv1.2 TLSv1.3;
      add_header Strict-Transport-Security max-age=31536000;
      root /var/www/example;
      location / { proxy_set_header Host $host; proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; proxy_pass http://app; }
      location ~ /\\. { deny all; }
    }
  }`;
  const result = api.analyze(input);
  assert.ok(!result.incomplete);
  assert.deepEqual(result.findings.map((finding) => finding.id), []);

  const idsOnRedirect = ids('http { server_tokens off; server { listen 80; return 301 https://example.com; } }');
  assert.ok(!idsOnRedirect.some((id) => ['hidden', 'contentType', 'frame'].includes(id)));

  const forwardingOnly = ids('http { server_tokens off; server { listen 8080; location / { proxy_pass http://app; } location /private/ { deny all; } } }');
  assert.ok(!forwardingOnly.some((id) => ['hidden', 'contentType', 'frame'].includes(id)));
  const partialForwarding = ids('http { server_tokens off; server { listen 8080; location /api/ { proxy_pass http://app; } } }');
  for (const id of ['hidden', 'contentType', 'frame']) assert.ok(partialForwarding.includes(id), id);
});
test('a serving server without a server-level return still reports missing response protections', () => {
  const result = ids('http { server_tokens off; server { listen 8080; root /var/www/site; } }');
  for (const id of ['hidden', 'contentType', 'frame']) assert.ok(result.includes(id), id);
});
test('hidden file location requires deny all; comments do not count', () => {
  assert.ok(!ids('http { server_tokens off; server { listen 80; location ~ /\\. { deny all; } } }').includes('hidden'));
  assert.ok(!ids('http { server_tokens off; server { listen 80; location ~ /\\. { deny all; } } }').includes('hidden'));
  assert.ok(ids('http { server_tokens off; server { listen 80; # location ~ /\\. { deny all; }\n} }').includes('hidden'));
  const multiple = 'http { server_tokens off; server { listen 8080; location ~ /\\. { deny all; } } server { listen 8081; } }';
  assert.equal(api.analyze(multiple).findings.filter((item) => item.id === 'hidden').length, 1);
});
test('top-level include is reported as an unchecked external file', () => {
  const result = api.analyze('include /etc/nginx/conf.d/*.conf; http { server_tokens off; server { listen 8080; } }');
  assert.equal(result.findings.filter((item) => item.id === 'include').length, 1);
});
test('nested locations, multiple servers, and ignored comments are parsed by block', () => {
  const input = `http { server_tokens off; server { listen 80; # autoindex on;\n location /outer/ { location /inner/ { autoindex on; } } } server { listen 8080; } }`;
  const findings = api.analyze(input).findings;
  assert.equal(findings.filter((item) => item.id === 'autoindex').length, 1);
  assert.equal(findings.find((item) => item.id === 'autoindex').line, 2);
  assert.equal(findings.filter((item) => item.id === 'serverTokens').length, 0);
});
test('proxy headers are checked and inherited from the nearest context', () => {
  const missing = config('location /app/ { proxy_pass http://app; }');
  assert.ok(ids(missing).includes('proxyHeaders'));
  const present = config('proxy_set_header Host $host; proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; location /app/ { proxy_pass http://app; }');
  assert.ok(!ids(present).includes('proxyHeaders'));
});
test('add_header inside a location warns when it replaces parent header inheritance', () => {
  const input = 'http { server_tokens off; server { listen 80; add_header X-Content-Type-Options nosniff; location / { add_header Cache-Control no-store; } } }';
  assert.ok(ids(input).includes('headerInheritance'));
  assert.ok(!ids(config('location / { add_header Cache-Control no-store; }', 'server_tokens off;')).includes('headerInheritance'));
});
test('alias/location slash mismatch is flagged; matching suffix is accepted', () => {
  assert.ok(ids(config('location /files { alias /srv/files/; }')).includes('aliasSlash'));
  assert.ok(!ids(config('location /files/ { alias /srv/files/; }')).includes('aliasSlash'));
  assert.ok(!ids(config('location ~ \.php$ { alias /srv/files/; }')).includes('aliasSlash'));
});
test('malformed braces and empty/non-http input do not throw and are marked incomplete', () => {
  for (const input of ['', 'not nginx config', 'http { server { listen 80;', 'http }', 'http { server { listen 80; } } }']) {
    assert.doesNotThrow(() => api.analyze(input));
    assert.equal(api.analyze(input).incomplete, true);
  }
});
test('unsafe and safe examples behave as documented', () => {
  const unsafeIds = new Set(api.analyze(api.unsafeSample).findings.map((finding) => finding.id));
  for (const id of ['serverTokens', 'autoindex', 'oldTls', 'hsts', 'redirect', 'hidden', 'contentType', 'frame', 'bodySize', 'proxyHeaders', 'headerInheritance', 'aliasSlash', 'rootPath']) assert.ok(unsafeIds.has(id), id);
  assert.deepEqual(api.analyze(api.safeSample), { findings: [], incomplete: false, truncated: false });
});
test('finding output never contains config values, paths, or source snippets', () => {
  const secret = 'DUMMY_SECRET_MATERIAL';
  const result = api.analyze(`http { server_tokens off; server { listen 443 ssl; root /root/${secret}; ssl_certificate_key /secret/path/${secret}; } }`);
  const json = JSON.stringify(result);
  for (const value of [secret, '/root/', '/secret/path/', 'ssl_certificate_key']) assert.ok(!json.includes(value));
  for (const finding of result.findings) assert.ok(finding.line >= 1 && finding.title && finding.why && finding.fix);
});
test('input and findings are bounded', () => {
  assert.throws(() => api.analyze('x'.repeat(api.MAX_LENGTH + 1)));
  assert.throws(() => api.analyze(null));
  const result = api.analyze(`http { server_tokens off; server { listen 80;\n${Array.from({ length: 350 }, () => 'autoindex on;').join('\n')}\n} }`);
  assert.equal(result.findings.length, api.MAX_FINDINGS);
  assert.equal(result.truncated, true);
});

class Element {
  constructor() { this.value = ''; this.textContent = ''; this.children = []; this.listeners = {}; this.hidden = false; }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren() { this.children = []; this.textContent = ''; }
  focus() {}
  get innerHTML() { throw new Error('unsafe HTML rendering'); }
  set innerHTML(_) { throw new Error('unsafe HTML rendering'); }
}
test('browser app uses samples and text nodes only, clears input, and makes no network/storage calls', () => {
  const elements = new Map();
  for (const id of ['config', 'findings', 'status', 'count', 'empty', 'check', 'unsafe-sample', 'safe-sample', 'clear']) elements.set(id, new Element());
  const windowEvents = {};
  const forbidden = () => assert.fail('network or persistence API used');
  const context = { window: { NginxCheck: api, addEventListener: (name, fn) => { windowEvents[name] = fn; } },
    document: { getElementById: (id) => elements.get(id), createElement: () => new Element() }, fetch: forbidden, XMLHttpRequest: forbidden, WebSocket: forbidden,
    localStorage: { setItem: forbidden }, sessionStorage: { setItem: forbidden } };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8'), context);
  const click = (id) => elements.get(id).listeners.click();
  click('unsafe-sample'); assert.ok(elements.get('findings').children.length > 0);
  click('safe-sample'); assert.equal(elements.get('findings').children.length, 0);
  assert.match(elements.get('status').textContent, /安全の保証ではありません/);
  elements.get('config').value = config('<img src=x onerror=alert(1)>'); click('check');
  assert.ok(!elements.get('findings').children.some((node) => node.innerHTML));
  click('clear'); assert.equal(elements.get('config').value, '');
  windowEvents.pagehide(); assert.equal(elements.get('config').value, '');
});
test('HTML has strict CSP, local assets and Japanese SEO metadata', () => {
  const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
  assert.match(html, /connect-src 'none'/); assert.match(html, /script-src 'self'/); assert.match(html, /style-src 'self'/); assert.match(html, /form-action 'none'/);
  assert.match(html, /<title>nginx設定セキュリティチェッカー/); assert.match(html, /name="description"/);
  assert.match(html, /aria-label="メインナビゲーション"/);
  assert.ok(!/<form|<iframe|<img|<(?:script|link)[^>]+(?:src|href)=["']https?:/i.test(html));
});
console.log(`\n${passed} tests passed`);
