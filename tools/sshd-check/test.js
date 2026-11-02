'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { analyze, durationSeconds } = require('./checker.js');
let passed = 0;
function test(name, run) { run(); passed++; console.log(`✓ ${name}`); }
function has(result, text, category) {
  return result.findings.find(item => item.title.includes(text) && (!category || item.category === category));
}

test('empty input returns no findings', () => {
  const result = analyze('  \n # comment only');
  assert.equal(result.empty, true);
  assert.deepEqual(result.findings, []);
});

test('keywords and yes values ignore case and comments are removed', () => {
  const result = analyze('pErMiTrOoTlOgIn YES # comment\nPasswordAuthentication YES');
  assert(has(result, 'root', '危険'));
  assert(has(result, 'パスワード認証', '危険'));
  assert.equal(result.findings.some(item => item.reason.includes('comment')), false);
});

test('first duplicate value is used and later duplicate is explained', () => {
  const result = analyze('PasswordAuthentication no\nPasswordAuthentication yes');
  assert(has(result, '無効', '良い'));
  assert.equal(has(result, 'パスワード認証が許可', '危険'), undefined);
  assert(has(result, '重複', '注意'));
  assert.equal(result.duplicates[0].first.value, 'no');
});

test('legacy challenge response name shares first-value semantics', () => {
  const result = analyze('ChallengeResponseAuthentication no\nKbdInteractiveAuthentication yes');
  assert.equal(result.duplicates.length, 1);
  assert.equal(result.duplicates[0].first.value, 'no');
  assert.equal(has(result, 'キーボード対話認証'), undefined);
});

test('Match block is listed separately and does not affect global judgment', () => {
  const result = analyze('PasswordAuthentication no\nMatch User guest\n PasswordAuthentication yes\n PermitRootLogin yes');
  assert(has(result, 'パスワード認証が無効', '良い'));
  assert.equal(has(result, 'パスワード認証が許可', '危険'), undefined);
  assert.equal(has(result, 'root の直接ログインが許可'), undefined);
  assert.equal(result.matchLines.length, 3);
  assert.equal(result.matchLines[0].isHeader, true);
});

test('Include is displayed without reading or evaluating its contents', () => {
  const result = analyze('Include /etc/ssh/sshd_config.d/*.conf\n');
  assert.equal(result.includes.length, 1);
  assert.equal(result.includes[0].value, '/etc/ssh/sshd_config.d/*.conf');
  assert.equal(has(result, 'Include'), undefined);
});

test('root, empty-password, and protocol 1 risks are detected', () => {
  const result = analyze('PermitRootLogin yes\nPermitEmptyPasswords yes\nProtocol 1');
  assert(has(result, 'root', '危険'));
  assert(has(result, '空パスワード', '危険'));
  assert(has(result, 'Protocol 1', '危険'));
});

test('missing root and password settings explain version defaults', () => {
  const result = analyze('PubkeyAuthentication yes');
  assert.match(has(result, 'PermitRootLogin').reason, /バージョン/);
  assert.match(has(result, 'PasswordAuthentication').reason, /既定はyes/);
});

test('keyboard interactive aliases and X11 forwarding are reported', () => {
  const result = analyze('KbdInteractiveAuthentication yes\nX11Forwarding yes');
  assert(has(result, 'キーボード対話', '注意'));
  assert(has(result, 'X11転送', '注意'));
});

test('high MaxAuthTries is warned only above six', () => {
  assert(has(analyze('MaxAuthTries 7'), '6 を超え', '注意'));
  assert.equal(has(analyze('MaxAuthTries 6'), '6 を超え'), undefined);
});

test('AllowTcpForwarding yes and its missing default are cautioned', () => {
  assert(has(analyze('AllowTcpForwarding yes'), 'TCP転送', '注意'));
  assert(has(analyze('Port 2222'), 'AllowTcpForwarding が未指定', '注意'));
});

test('missing ClientAliveInterval and PermitUserEnvironment yes are covered', () => {
  const result = analyze('PermitUserEnvironment yes');
  assert(has(result, 'ClientAliveInterval が未設定', '注意'));
  assert(has(result, 'ユーザー環境設定', '注意'));
});

test('LoginGraceTime handles units and warns over 120 seconds', () => {
  assert.equal(durationSeconds('2m'), 120);
  assert.equal(durationSeconds('1h'), 3600);
  assert(has(analyze('LoginGraceTime 121'), '120 秒を超', '注意'));
  assert.equal(has(analyze('LoginGraceTime 2m'), '120 秒を超'), undefined);
});

test('old ciphers, MACs, and key exchanges are identified', () => {
  const result = analyze('Ciphers aes128-cbc,aes256-ctr\nMACs hmac-sha1\nKexAlgorithms diffie-hellman-group1-sha1');
  assert.equal(result.findings.filter(item => item.title.includes('古い暗号')).length, 3);
});

test('PAM and password authentication combination is explained', () => {
  const result = analyze('UsePAM yes\nPasswordAuthentication yes');
  assert.match(has(result, 'UsePAM と PasswordAuthentication').reason, /PAM設定/);
});

test('Port 22 is information, not a security warning', () => {
  const result = analyze('Port 22');
  assert(has(result, '標準ポート 22', '情報'));
  assert.equal(result.findings.some(item => item.category === '危険'), false);
});

test('good root, key, and allowlist settings are shown', () => {
  const result = analyze('PermitRootLogin prohibit-password\nPubkeyAuthentication yes\nAllowUsers deploy\nAllowGroups ssh-users');
  assert(has(result, 'root の直接ログインが制限', '良い'));
  assert(has(result, 'PubkeyAuthentication', '良い'));
  assert(has(result, 'AllowUsers', '良い'));
  assert(has(result, 'AllowGroups', '良い'));
});

test('one megabyte input does not throw', () => {
  const result = analyze(`Port 22 #${'x'.repeat(1024 * 1024 - 9)}`);
  assert.equal(result.empty, false);
  assert(has(result, '標準ポート 22', '情報'));
});

test('assets, CSP, safe DOM use, and Pages-relative paths are present', () => {
  const base = 'https://supportapp3-lab.github.io/dev-tools-jp/tools/sshd-check/';
  const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
  for (const asset of ['style.css', 'checker.js', 'app.js']) {
    assert(html.includes(`"${asset}"`));
    assert.equal(new URL(asset, base).pathname, `/dev-tools-jp/tools/sshd-check/${asset}`);
    assert(fs.existsSync(path.join(__dirname, asset)));
  }
  assert.match(html, /connect-src 'none'/);
  assert.equal(new URL('../../', base).pathname, '/dev-tools-jp/');
  const home = fs.readFileSync(path.join(__dirname, '../../index.html'), 'utf8');
  assert(home.includes('href="tools/sshd-check/"'));
  const app = fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8');
  assert.doesNotMatch(app, /\.innerHTML\s*=/);
});

console.log(`${passed} tests passed`);
