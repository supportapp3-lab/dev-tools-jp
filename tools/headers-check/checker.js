(function (root) {
  'use strict';

  const MAX_LENGTH = 200000;
  const MAX_FINDINGS = 300;
  const LEVELS = { high: '高', medium: '中', low: '低', info: '情報' };
  const HEADER_TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

  const unsafeSample = `HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
X-Powered-By: PHP/8.2
Content-Security-Policy: default-src *; script-src 'unsafe-inline' 'unsafe-eval' https:; object-src 'none'
Set-Cookie: sessionid=DEMO-SECRET-123; SameSite=None
Set-Cookie: theme=dark
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Referrer-Policy: unsafe-url
X-Frame-Options: ALLOW-FROM https://example.test
X-XSS-Protection: 1; mode=block
Public-Key-Pins: pin-sha256="DEMO"`;

  const safeSample = `HTTP/2 200
Server: nginx
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-demo'; object-src 'none'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=()
Set-Cookie: sessionid=DEMO-SECRET-456; Path=/; Secure; HttpOnly; SameSite=Lax
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Credentials: true
Cache-Control: no-store`;

  function add(findings, severity, header, title, why, fix, extra = {}) {
    if (findings.length >= MAX_FINDINGS) return;
    findings.push({ id: extra.id || `${header}:${title}`, severity, severityLabel: LEVELS[severity], header, title, why, fix, ...extra });
  }

  function parseHeaders(input) {
    const text = String(input ?? '').slice(0, MAX_LENGTH);
    const lines = text.replace(/\r\n?/g, '\n').split('\n');
    const statusIndexes = [];
    for (let i = 0; i < lines.length; i += 1) {
      if (/^\s*HTTP\/\d(?:\.\d)?\s+\d{3}(?:\s|$)/i.test(lines[i])) statusIndexes.push(i);
    }
    const responseCount = statusIndexes.length || (text.trim() ? 1 : 0);
    const selectedStart = statusIndexes.length ? statusIndexes[statusIndexes.length - 1] + 1 : 0;
    const headers = new Map();
    let ignoredLines = 0;
    let endedAtBlank = false;

    for (let i = selectedStart; i < lines.length; i += 1) {
      const line = lines[i];
      if (/^\s*HTTP\/\d(?:\.\d)?\s+\d{3}(?:\s|$)/i.test(line)) break;
      if (!line.trim()) {
        if (statusIndexes.length) { endedAtBlank = true; break; }
        continue;
      }
      const colon = line.indexOf(':');
      if (colon <= 0) { ignoredLines += 1; continue; }
      const rawName = line.slice(0, colon).trim();
      if (!HEADER_TOKEN.test(rawName)) { ignoredLines += 1; continue; }
      const name = rawName.toLowerCase();
      const value = line.slice(colon + 1).trim();
      if (!headers.has(name)) headers.set(name, []);
      headers.get(name).push(value);
    }
    return {
      headers,
      responseCount,
      selectedLast: statusIndexes.length > 1,
      ignoredLines,
      truncated: String(input ?? '').length > MAX_LENGTH,
      endedAtBlank
    };
  }

  function hasToken(value, token) {
    return value.split(/[\t ]+/).some((part) => part.toLowerCase() === token);
  }

  function parseCsp(value) {
    const directives = new Map();
    for (const part of value.split(';')) {
      const tokens = part.trim().split(/[\t ]+/).filter(Boolean);
      if (!tokens.length) continue;
      const name = tokens.shift().toLowerCase();
      if (!directives.has(name)) directives.set(name, tokens.map((token) => token.toLowerCase()));
    }
    return directives;
  }

  function parseCookie(value, index) {
    const parts = value.split(';');
    const first = parts.shift().trim();
    const equals = first.indexOf('=');
    const name = equals > 0 ? first.slice(0, equals).trim() : '';
    const attrs = new Map();
    for (const part of parts) {
      const at = part.trim();
      if (!at) continue;
      const split = at.indexOf('=');
      const key = (split < 0 ? at : at.slice(0, split)).trim().toLowerCase();
      if (key) attrs.set(key, split < 0 ? '' : at.slice(split + 1).trim());
    }
    return { index, name: name || `Cookie ${index}`, redacted: '••••', attrs };
  }

  function examples(header, setting) {
    const value = setting || '適切な値';
    const nginx = `add_header ${header} "${value}" always;`;
    const apache = `Header always set ${header} "${value}"`;
    if (header.toLowerCase() === 'set-cookie') {
      return 'nginx: proxy_cookie_flags ~ secure httponly samesite=lax; / Apache: Header edit Set-Cookie "^(.*)$" "$1; Secure; HttpOnly; SameSite=Lax"（重複を避けるため、まずアプリ側で設定）';
    }
    return `nginx: ${nginx} / Apache: ${apache}`;
  }

  function analyze(input) {
    const parsed = parseHeaders(input);
    const headers = parsed.headers;
    const findings = [];
    const get = (name) => headers.get(name.toLowerCase()) || [];
    const has = (name) => get(name).length > 0;
    const cookies = get('set-cookie').map(parseCookie);
    const cspValues = get('content-security-policy');
    const reportOnly = get('content-security-policy-report-only');
    const policies = cspValues.map(parseCsp);

    if (!has('strict-transport-security')) {
      add(findings, 'medium', 'Strict-Transport-Security', 'HSTS がありません', 'HTTPS接続後も、利用者のブラウザがHTTPへ戻る余地があります。', examples('Strict-Transport-Security', 'max-age=31536000; includeSubDomains'));
    } else {
      const hsts = get('strict-transport-security').join(';');
      const age = hsts.match(/(?:^|;)\s*max-age\s*=\s*"?(\d+)/i);
      if (age && Number(age[1]) === 0) {
        add(findings, 'medium', 'Strict-Transport-Security', 'HSTS の max-age が 0 です', 'max-age=0 はブラウザに保存済みのHSTSポリシーを削除する指定です。', examples('Strict-Transport-Security', 'max-age=31536000'));
      } else if (!age || Number(age[1]) < 15552000) {
        add(findings, 'low', 'Strict-Transport-Security', 'HSTS の max-age が180日未満か未指定です', '短い期間ではHSTSによる保護が途切れやすくなります。', examples('Strict-Transport-Security', 'max-age=31536000'));
      }
      if (!/\bincludeSubDomains\b/i.test(hsts)) add(findings, 'info', 'Strict-Transport-Security', 'HSTS に includeSubDomains がありません', 'サブドメインはこのポリシーの対象外です。全サブドメインがHTTPS対応済みか確認してください。', examples('Strict-Transport-Security', 'max-age=31536000; includeSubDomains'));
    }

    if (!cspValues.length) {
      if (reportOnly.length) add(findings, 'low', 'Content-Security-Policy-Report-Only', 'CSP は Report-Only のみです', 'Report-Only は違反を報告するだけで、ブラウザによる制限を強制しません。', examples('Content-Security-Policy', "default-src 'self'; object-src 'none'; frame-ancestors 'none'"));
      else add(findings, 'medium', 'Content-Security-Policy', 'CSP がありません', 'Content Security Policyがないため、読み込めるスクリプトなどを制限できません。', examples('Content-Security-Policy', "default-src 'self'; object-src 'none'; frame-ancestors 'none'"));
    } else {
      const cspFlags = new Set();
      for (const policy of policies) {
        const script = policy.get('script-src') || policy.get('default-src') || [];
        const hasNonceOrHash = script.some((token) => /^'nonce-[^']+'$/.test(token) || /^'sha(?:256|384|512)-[^']+'$/.test(token));
        if (script.includes("'unsafe-inline'") && !hasNonceOrHash) cspFlags.add('unsafeInline');
        if (script.includes("'unsafe-eval'")) cspFlags.add('unsafeEval');
        const broad = new Set(['*', 'http:', 'https:', 'data:']);
        if (script.length > 0 && script.every((token) => broad.has(token))) cspFlags.add('broadScript');
      }
      if (cspFlags.has('unsafeInline')) add(findings, 'medium', 'Content-Security-Policy', "script-src に 'unsafe-inline' があります", 'インラインスクリプトを許すと、HTMLへの注入がスクリプト実行につながりやすくなります。nonceまたはhashを使うとこの指定を無効化できます。', examples('Content-Security-Policy', "default-src 'self'; script-src 'self' 'nonce-{生成値}'; object-src 'none'"));
      if (cspFlags.has('unsafeEval')) add(findings, 'medium', 'Content-Security-Policy', "script-src に 'unsafe-eval' があります", '文字列からコードを実行する機能を許し、注入の影響を広げるおそれがあります。', examples('Content-Security-Policy', "default-src 'self'; script-src 'self'; object-src 'none'"));
      if (cspFlags.has('broadScript')) add(findings, 'medium', 'Content-Security-Policy', 'script-src の許可範囲が広すぎます', '* や scheme source だけの許可は、多くの場所からスクリプトを読み込める状態になります。', examples('Content-Security-Policy', "default-src 'self'; script-src 'self'; object-src 'none'"));
      const missingObject = policies.some((policy) => !policy.has('object-src') && !policy.has('default-src'));
      if (missingObject) add(findings, 'low', 'Content-Security-Policy', 'object-src と default-src がありません', 'プラグイン等の object 読込み先が制限されていません。', examples('Content-Security-Policy', "default-src 'self'; object-src 'none'"));
      if (policies.some((policy) => !policy.has('frame-ancestors'))) add(findings, 'info', 'Content-Security-Policy', 'CSP に frame-ancestors がありません', 'CSPによる埋め込み元制限は設定されていません。', examples('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'"));
    }

    const hasFrameAncestors = policies.some((policy) => policy.has('frame-ancestors'));
    if (!has('x-frame-options') && !hasFrameAncestors) add(findings, 'medium', 'X-Frame-Options / Content-Security-Policy: frame-ancestors', 'クリックジャッキング対策がありません', '別サイトにページを埋め込まれ、利用者が意図しない操作をする可能性があります。', examples('X-Frame-Options', 'DENY'));
    if (get('x-frame-options').some((value) => /^\s*ALLOW-FROM\b/i.test(value))) add(findings, 'low', 'X-Frame-Options', 'ALLOW-FROM は非推奨です', 'ALLOW-FROM は多くのブラウザでサポートされず、埋め込み制限として機能しない場合があります。', examples('X-Frame-Options', 'DENY'));
    if (!has('x-content-type-options') || !get('x-content-type-options').some((value) => /^\s*nosniff\s*$/i.test(value))) add(findings, 'low', 'X-Content-Type-Options', 'nosniff がありません', 'ブラウザによるMIME型の推測を抑止できていません。', examples('X-Content-Type-Options', 'nosniff'));

    if (!has('referrer-policy')) add(findings, 'low', 'Referrer-Policy', 'Referrer-Policy がありません', 'リンク先へ遷移するときに、元ページのURLが送られることがあります。', examples('Referrer-Policy', 'strict-origin-when-cross-origin'));
    else if (get('referrer-policy').some((value) => value.split(',').some((item) => item.trim().toLowerCase() === 'unsafe-url'))) add(findings, 'medium', 'Referrer-Policy', 'unsafe-url は送信情報が多すぎます', '別サイトへの遷移でも元URL全体がRefererとして送られる設定です。', examples('Referrer-Policy', 'strict-origin-when-cross-origin'));
    if (!has('permissions-policy')) add(findings, 'info', 'Permissions-Policy', 'Permissions-Policy がありません', 'カメラやマイク等のブラウザ機能の利用範囲をこの応答では制限していません。', examples('Permissions-Policy', 'camera=(), microphone=()'));

    cookies.forEach((cookie, index) => {
      const attrs = cookie.attrs;
      const sessionLike = /(session|sid|token|auth)/i.test(cookie.name);
      const secure = attrs.has('secure');
      const sameSite = (attrs.get('samesite') || '').toLowerCase();
      if (sameSite === 'none' && !secure) add(findings, 'high', 'Set-Cookie', `Cookie ${index + 1}: SameSite=None に Secure がありません`, 'SameSite=NoneのCookieはSecure属性も必要で、暗号化されていない接続へ送られるおそれがあります。', examples('Set-Cookie', 'アプリ側で Secure; HttpOnly; SameSite=Lax を設定'), { cookieIndex: index + 1 });
      else if (!secure) add(findings, 'medium', 'Set-Cookie', `Cookie ${index + 1}: Secure がありません`, 'HTTPS以外の接続にもCookieが送られる可能性があります。', examples('Set-Cookie'), { cookieIndex: index + 1 });
      if (!attrs.has('httponly')) add(findings, sessionLike ? 'medium' : 'low', 'Set-Cookie', `Cookie ${index + 1}: HttpOnly がありません`, 'JavaScriptからCookieを読み取れる状態です。セッション用Cookieでは特に影響が大きくなります。', examples('Set-Cookie'), { cookieIndex: index + 1 });
      if (!attrs.has('samesite')) add(findings, 'low', 'Set-Cookie', `Cookie ${index + 1}: SameSite がありません`, 'クロスサイトリクエストにCookieを含めるかどうかが明示されていません。', examples('Set-Cookie'), { cookieIndex: index + 1 });
    });

    const origins = get('access-control-allow-origin').map((value) => value.trim().toLowerCase());
    const credentials = get('access-control-allow-credentials').some((value) => /^\s*true\s*$/i.test(value));
    if (origins.includes('*') && credentials) add(findings, 'high', 'Access-Control-Allow-Origin / Access-Control-Allow-Credentials', 'CORS が全オリジンと認証情報を同時に許可しています', '任意のサイトから、利用者の認証情報を伴う応答へアクセスできる設定の組合せです。', examples('Access-Control-Allow-Origin', 'https://app.example.com'));
    else if (origins.includes('null')) add(findings, 'medium', 'Access-Control-Allow-Origin', 'CORS が null origin を許可しています', 'sandbox化された文書など、予期しないページからのアクセスを許す可能性があります。', examples('Access-Control-Allow-Origin', 'https://app.example.com'));
    else if (origins.includes('*')) add(findings, 'info', 'Access-Control-Allow-Origin', 'CORS がすべてのオリジンを許可しています', '公開情報でない場合は、必要なサイトだけを許可する設定を検討してください。', examples('Access-Control-Allow-Origin', 'https://app.example.com'));

    if (get('server').some((value) => /\b[a-z][\w.-]*\/\d+(?:\.\d+)+/i.test(value))) add(findings, 'low', 'Server', 'Server にバージョン番号があります', 'ソフトウェア名とバージョンから、対象を絞った攻撃を受けやすくなる場合があります。', 'nginx: server_tokens off; / Apache: ServerTokens Prod（完全な隠蔽は保証しません）');
    for (const name of ['x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version']) {
      if (has(name)) add(findings, 'low', name, `${name} が公開されています`, 'アプリケーションの種類やバージョン情報が推測されることがあります。', 'nginx: proxy_hide_header X-Powered-By; / Apache: Header always unset X-Powered-By');
    }
    if (get('x-xss-protection').some((value) => /^\s*1(?:\s*;|\s*$)/i.test(value))) add(findings, 'info', 'X-XSS-Protection', 'X-XSS-Protection: 1 系が設定されています', 'この旧式のブラウザ機能はCSPの代わりになりません。無効化するか、CSPを設定してください。', examples('X-XSS-Protection', '0'));
    if (has('public-key-pins')) add(findings, 'low', 'Public-Key-Pins', 'Public-Key-Pins は非推奨です', 'HPKPは設定ミスでサイトへ接続できなくなる危険があり、現行ブラウザでは非推奨です。', 'nginx: add_header Public-Key-Pins "" always; / Apache: Header always unset Public-Key-Pins');
    if (cookies.length && !has('cache-control')) add(findings, 'info', 'Cache-Control / Set-Cookie', 'Cookie がある応答に Cache-Control がありません', '認証後のページを共有キャッシュへ保存しないよう、no-storeを検討してください。', examples('Cache-Control', 'no-store'));

    return {
      findings,
      responseCount: parsed.responseCount,
      selectedLast: parsed.selectedLast,
      ignoredLines: parsed.ignoredLines,
      truncated: parsed.truncated,
      cookies: cookies.map(({ index, name, redacted, attrs }) => ({ index, name, value: redacted, attributes: [...attrs.keys()] }))
    };
  }

  const api = { analyze, parseHeaders, unsafeSample, safeSample, MAX_LENGTH };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root) root.HeadersCheck = api;
}(typeof window !== 'undefined' ? window : globalThis));
