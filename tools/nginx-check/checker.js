(function (root) {
  'use strict';

  const MAX_LENGTH = 200000;
  const MAX_FINDINGS = 300;
  const LEVELS = { high: '高', medium: '中', low: '低', info: '情報' };
  const RULES = {
    privateKey: ['high', '秘密鍵らしい内容', '貼り付けた設定に秘密鍵の開始マーカーがあります。秘密鍵は公開・共有しないでください。', '秘密鍵を削除し、漏えいした可能性がある場合は鍵を交換してください。'],
    serverTokens: ['low', 'server_tokensが未設定またはon', 'nginxのバージョン情報が応答に含まれ、対象バージョンを推測されやすくなることがあります。', 'httpまたはserverで server_tokens off; を検討してください。'],
    autoindex: ['high', 'autoindex on', 'ディレクトリ内のファイル一覧を公開する可能性があります。', '不要な一覧表示を避けるため、autoindex off; にしてください。'],
    oldTls: ['high', '古いTLSプロトコル', 'SSLv2/SSLv3/TLSv1/TLSv1.1 は現在のTLS設定として推奨されません。', '利用環境を確認し、TLSv1.2 TLSv1.3 など現在サポートされる方式に限定してください。'],
    hsts: ['medium', 'HTTPSのHSTSヘッダーが未確認', 'HTTPS接続後もブラウザがHTTPへ戻る可能性があります。', 'HTTPS応答で Strict-Transport-Security を設定し、max-ageやincludeSubDomainsの適用範囲を検討してください。'],
    redirect: ['low', 'HTTPからHTTPSへの転送が未確認', 'HTTPで受けたリクエストが暗号化接続へ転送されない可能性があります。', '80番serverに return 301 https://...; などの転送を設定してください。'],
    hidden: ['medium', '隠しファイルへのdenyが未確認', '.git、.envなどの隠しファイルを配信しない設定が確認できません。', 'location ~ /\\. に deny all; を設定するなど、公開範囲を確認してください。'],
    contentType: ['low', 'X-Content-Type-Optionsが未確認', 'ブラウザが応答内容を別のMIME型として解釈する場合があります。', 'X-Content-Type-Options: nosniff を設定してください。'],
    frame: ['low', 'クリックジャッキング対策が未確認', '別サイトにページを埋め込まれ、利用者が意図しない操作をする可能性があります。', 'X-Frame-Options または Content-Security-Policy の frame-ancestors を設定してください。'],
    bodySize: ['low', '大きすぎるリクエスト本文上限', 'client_max_body_size が無制限または1gを超える設定です。大容量リクエストが資源を消費する可能性があります。', '用途に必要な上限まで小さくしてください。'],
    proxyHeaders: ['info', 'proxy_set_headerが未確認', '上流へ元のHostや接続元情報が渡らず、アプリのURL生成やログに影響することがあります。', '必要に応じて proxy_set_header Host $host; と X-Forwarded-For を設定してください。'],
    headerInheritance: ['medium', 'location内のadd_headerによる継承上書き', 'location内にadd_headerを書くと、通常は上位レベルのadd_headerが継承されなくなります。', '必要なヘッダーをlocation側にも設定するか、設定を共通化してください。'],
    aliasSlash: ['high', 'aliasとlocationの末尾スラッシュ不一致', 'aliasとlocationの末尾スラッシュが一致せず、意図しないパス解決につながる可能性があります。', '通常のprefix locationでは、両方に末尾スラッシュを付けるか、両方から外してください。'],
    rootPath: ['high', '公開rootが広すぎる可能性', 'root がシステム全体やユーザーのホームディレクトリを公開範囲に含める設定です。', '公開する専用ディレクトリ（例: /var/www/example）に限定してください。'],
    include: ['info', 'include先は未確認', 'include先のファイル内容はこのツールから読み込めないため、検査対象外です。', 'include先も手元で個別に確認してください。']
  };

  const safeSample = `http {
server_tokens off;
add_header X-Content-Type-Options nosniff always;
add_header Content-Security-Policy "frame-ancestors 'none'" always;
server {
    listen 80;
    server_name example.com;
    return 301 https://$host$request_uri;
    location ~ /\\. { deny all; }
}
server {
    listen 443 ssl;
    server_name example.com;
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Content-Type-Options nosniff always;
    add_header Content-Security-Policy "frame-ancestors 'none'" always;
    client_max_body_size 20m;
    root /var/www/example;
    location ~ /\\. { deny all; }
    location /api/ {
        proxy_pass http://app;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
}`;

  const unsafeSample = `http {
    server_tokens on;
    server {
        listen 80;
        server_name example.com;
        root /;
        autoindex on;
        client_max_body_size 2g;
        location /files {
            alias /srv/files/;
            add_header X-Content-Type-Options nosniff;
        }
    }
    server {
        listen 443 ssl;
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
        proxy_pass http://app;
    }
}`;

  function tokenize(input) {
    const tokens = [];
    let value = '', tokenLine = 1, line = 1, quote = '', escaped = false, comment = false, incomplete = false;
    const flush = () => {
      if (value) tokens.push({ value, line: tokenLine });
      value = '';
    };
    for (let i = 0; i < input.length; i += 1) {
      const c = input[i];
      if (comment) {
        if (c === '\n') { comment = false; line += 1; }
        else if (c === '\r' && input[i + 1] !== '\n') line += 1;
        continue;
      }
      if (quote) {
        value += c;
        if (escaped) escaped = false;
        else if (quote === '"' && c === '\\') escaped = true;
        else if (c === quote) quote = '';
        if ((c === '\n' || c === '\r') && !quote) line += 1;
        continue;
      }
      if (c === '#') { flush(); comment = true; continue; }
      if (c === '"' || c === "'") {
        if (!value) tokenLine = line;
        quote = c; value += c; continue;
      }
      if (c === '\n' || c === '\r' || /\s/.test(c)) {
        flush();
        if (c === '\n' || c === '\r' && input[i + 1] !== '\n') line += 1;
        continue;
      }
      if ('{};'.includes(c)) {
        flush(); tokens.push({ value: c, line }); continue;
      }
      if (!value) tokenLine = line;
      value += c;
    }
    flush();
    if (quote) incomplete = true;
    return { tokens, incomplete };
  }

  function unquote(value) {
    if (value.length >= 2 && ((value[0] === '"' && value.at(-1) === '"') || (value[0] === "'" && value.at(-1) === "'"))) {
      const body = value.slice(1, -1);
      return value[0] === '"' ? body.replace(/\\(["\\])/g, '$1') : body;
    }
    return value;
  }

  function parse(input) {
    const { tokens, incomplete: lexicalError } = tokenize(input);
    const top = { name: '', args: [], line: 1, parent: null, blocks: [], directives: [] };
    const stack = [top];
    let statement = [], incomplete = lexicalError;
    function directive(parts) {
      if (!parts.length) return;
      const parent = stack.at(-1);
      parent.directives.push({ name: unquote(parts[0].value).toLowerCase(), args: parts.slice(1).map((t) => unquote(t.value)), line: parts[0].line });
    }
    for (const token of tokens) {
      if (token.value === ';') { directive(statement); statement = []; continue; }
      if (token.value === '{') {
        if (!statement.length) { incomplete = true; continue; }
        const parent = stack.at(-1);
        const block = { name: unquote(statement[0].value).toLowerCase(), args: statement.slice(1).map((t) => unquote(t.value)), line: statement[0].line, parent, blocks: [], directives: [] };
        parent.blocks.push(block); stack.push(block); statement = []; continue;
      }
      if (token.value === '}') {
        if (statement.length) { directive(statement); statement = []; incomplete = true; }
        if (stack.length === 1) incomplete = true;
        else stack.pop();
        continue;
      }
      statement.push(token);
    }
    if (statement.length || stack.length !== 1) incomplete = true;
    if (statement.length) directive(statement);
    return { top, incomplete };
  }

  function blocksOf(block, out = []) {
    for (const child of block.blocks) { out.push(child); blocksOf(child, out); }
    return out;
  }
  function directives(block, name) { return block.directives.filter((item) => item.name === name); }
  function ancestors(block) { const out = []; for (let p = block.parent; p && p.name; p = p.parent) out.unshift(p); return out; }
  function addFinding(findings, seen, id, line) {
    const signature = `${id}:${line}`;
    if (seen.has(signature)) return;
    seen.add(signature);
    if (findings.length >= MAX_FINDINGS) { findings.truncated = true; return; }
    const [severity, title, why, fix] = RULES[id];
    findings.push({ id, line: Math.max(1, line), severity, severityLabel: LEVELS[severity], title, why, fix });
  }
  function hasHeader(block, header) {
    return effectiveServerHeaders(block).some((item) => (item.args[0] || '').toLowerCase() === header.toLowerCase());
  }
  function listenPort(server) {
    const entries = directives(server, 'listen');
    if (!entries.length) return [{ item: { line: server.line }, port: 80, ssl: false }];
    return entries.map((item) => {
      const first = item.args[0] || '';
      const match = /(?:^|:)(\d+)$/.exec(first);
      return { item, port: match ? Number(match[1]) : first === '' ? 80 : null, ssl: item.args.some((arg) => arg.toLowerCase() === 'ssl') };
    });
  }
  function effectiveServerTokens(server) {
    const chain = [...ancestors(server).filter((block) => block.name === 'http'), server];
    for (let i = chain.length - 1; i >= 0; i -= 1) {
      const entries = directives(chain[i], 'server_tokens');
      if (entries.length) return entries.at(-1);
    }
    return null;
  }
  function parseSize(raw) {
    const match = /^([0-9]+(?:\.[0-9]+)?)([kmg]?)$/i.exec(raw || '');
    if (!match) return null;
    const value = Number(match[1]);
    const power = { '': 0, k: 1, m: 2, g: 3 }[match[2].toLowerCase()];
    return value * (1024 ** power);
  }
  function blockLocation(block) {
    if (block.name !== 'location') return '';
    let args = block.args.slice();
    if (['=', '^~', '~', '~*'].includes(args[0])) args = args.slice(1);
    return args[0] || '';
  }
  function effectiveProxyHeaders(block) {
    const chain = [...ancestors(block), block];
    let active = [];
    for (const item of chain) {
      const local = directives(item, 'proxy_set_header');
      if (local.length) active = local;
    }
    return new Set(active.map((item) => (item.args[0] || '').toLowerCase()));
  }
  function effectiveServerHeaders(block) {
    const chain = [...ancestors(block), block];
    let active = [];
    for (const context of chain) {
      const local = directives(context, 'add_header');
      if (local.length) active = local;
    }
    return active;
  }

  function analyze(input) {
    if (typeof input !== 'string') throw new TypeError('設定を文字列で入力してください。');
    if (input.length > MAX_LENGTH) throw new RangeError('入力は20万文字以内にしてください。');
    const parsed = parse(input), findings = [], seen = new Set();
    const blocks = blocksOf(parsed.top);
    const servers = blocks.filter((block) => block.name === 'server');
    let incomplete = parsed.incomplete || !blocks.some((block) => block.name === 'http') || servers.length === 0;
    const includes = [...directives(parsed.top, 'include'), ...blocks.flatMap((block) => directives(block, 'include'))];
    for (const item of includes) addFinding(findings, seen, 'include', item.line);

    const privateKeyMarker = /-----BEGIN (?:(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----/i.exec(input);
    if (privateKeyMarker) {
      const prefix = input.slice(0, privateKeyMarker.index);
      const line = (prefix.match(/\n/g) || []).length + 1;
      addFinding(findings, seen, 'privateKey', line);
    }

    for (const item of blocks.flatMap((block) => directives(block, 'autoindex'))) {
      if ((item.args[0] || '').toLowerCase() === 'on') addFinding(findings, seen, 'autoindex', item.line);
    }
    for (const item of blocks.flatMap((block) => directives(block, 'ssl_protocols'))) {
      if (item.args.some((arg) => /^(?:sslv2|sslv3|tlsv1(?:\.0)?|tlsv1\.1)$/i.test(arg))) addFinding(findings, seen, 'oldTls', item.line);
    }
    for (const item of blocks.flatMap((block) => directives(block, 'client_max_body_size'))) {
      const size = parseSize(item.args[0]);
      if (size === 0 || size !== null && size > 1024 ** 3) addFinding(findings, seen, 'bodySize', item.line);
    }
    for (const item of blocks.flatMap((block) => directives(block, 'root'))) {
      const path = (item.args[0] || '').replace(/\\/g, '/').replace(/\/+$/, '') || '/';
      if (path === '/' || /^\/root(?:\/|$)/i.test(path) || /^\/home(?:\/|$)/i.test(path)) addFinding(findings, seen, 'rootPath', item.line);
    }

    for (const server of servers) {
      const listens = listenPort(server);
      const secure = listens.some(({ port, ssl }) => port === 443 && ssl);
      if (secure && !hasHeader(server, 'Strict-Transport-Security')) addFinding(findings, seen, 'hsts', server.line);
      const httpServer = listens.find(({ port }) => port === 80);
      if (httpServer && servers.some((other) => listenPort(other).some(({ port, ssl }) => port === 443 && ssl))) {
        const redirects = directives(server, 'return').some((item) => item.args[0] === '301' && /^https:\/\//i.test(item.args[1] || ''));
        if (!redirects) addFinding(findings, seen, 'redirect', httpServer.item.line);
      }
      const token = effectiveServerTokens(server);
      if (!token || (token.args[0] || '').toLowerCase() === 'on') addFinding(findings, seen, 'serverTokens', token?.line || server.line);
      if (!hasHeader(server, 'X-Content-Type-Options')) addFinding(findings, seen, 'contentType', server.line);
      const frame = hasHeader(server, 'X-Frame-Options') || effectiveServerHeaders(server).some((item) => {
        if ((item.args[0] || '').toLowerCase() !== 'content-security-policy') return false;
        return item.args.slice(1).join(' ').toLowerCase().includes('frame-ancestors');
      });
      if (!frame) addFinding(findings, seen, 'frame', server.line);
    }

    for (const server of servers) {
      const hiddenLocations = blocksOf(server).filter((block) => block.name === 'location'
        && (block.args.join(' ').includes('/\\.') || block.args.join(' ').includes('/.')));
      if (!hiddenLocations.some((block) => directives(block, 'deny').some((item) => (item.args[0] || '').toLowerCase() === 'all'))) {
        addFinding(findings, seen, 'hidden', server.line);
      }
    }

    for (const location of blocks.filter((block) => block.name === 'location')) {
      const localHeaders = directives(location, 'add_header');
      if (localHeaders.length && ancestors(location).some((parent) => directives(parent, 'add_header').length)) {
        addFinding(findings, seen, 'headerInheritance', localHeaders[0].line);
      }
      const path = blockLocation(location);
      for (const alias of directives(location, 'alias')) {
        if (/^(?:~|~\*|=|\^~)$/.test(location.args[0] || '') || !path) continue;
        const target = alias.args[0] || '';
        if (path.endsWith('/') !== target.endsWith('/')) addFinding(findings, seen, 'aliasSlash', alias.line);
      }
      if (directives(location, 'proxy_pass').length) {
        const headers = effectiveProxyHeaders(location);
        if (!headers.has('host') || !headers.has('x-forwarded-for')) addFinding(findings, seen, 'proxyHeaders', directives(location, 'proxy_pass')[0].line);
      }
    }

    findings.sort((a, b) => a.line - b.line || a.id.localeCompare(b.id));
    return { findings: findings.slice(0, MAX_FINDINGS), incomplete, truncated: findings.truncated === true };
  }

  const api = { MAX_LENGTH, MAX_FINDINGS, analyze, safeSample, unsafeSample };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.NginxCheck = api;
}(typeof globalThis !== 'undefined' ? globalThis : this));
