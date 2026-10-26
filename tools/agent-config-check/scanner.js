(function (root) {
  'use strict';

  const MAX_LENGTH = 200000;
  const MAX_FINDINGS = 200;
  const rules = {
    secret: ['high', 'キー・トークンなどの直書き', '認証情報らしい値があります。', '環境変数やシークレット管理へ移し、実際の秘密値なら失効・再発行も検討してください。'],
    entropy: ['medium', 'ランダムな文字列', '高エントロピーの値があります。認証情報の可能性を確認してください。', 'IDなどの無害な値の場合もあります。用途を確認し、秘密値なら設定ファイルから分離してください。'],
    bind: ['medium', '全インターフェースへのバインド', '0.0.0.0 または :: で待ち受ける設定があります。', 'ローカル専用ならループバックに限定し、外部公開する場合は認証とファイアウォールを確認してください。'],
    port: ['medium', 'ポートの公開', 'ホスト側へ公開するポート設定があります。', '必要なポートだけを公開し、ローカル専用ならホストIPをループバックに限定してください。'],
    debug: ['medium', 'デバッグが有効', 'デバッグ機能が有効になる設定があります。', '公開環境では無効にし、詳細なエラーや内部情報が表示されないことを確認してください。'],
    auth: ['high', '認証が無効', '認証を無効にする設定があります。', '外部から利用できるサービスには認証を設定してください。'],
    cors: ['medium', 'ワイルドカード CORS', '任意のオリジンを許可する設定があります。', '利用するオリジンを個別に指定してください。認証情報付き通信の設定も併せて確認してください。'],
    permission: ['high', '広すぎる権限・アクセス範囲', '全権限、root実行、または広いファイルアクセスを許可する設定があります。', '専用ユーザーと必要最小限の権限・ディレクトリに限定してください。']
  };

  function entropy(value) {
    const counts = new Map();
    for (const char of value) counts.set(char, (counts.get(char) || 0) + 1);
    let result = 0;
    for (const count of counts.values()) {
      const p = count / value.length;
      result -= p * Math.log2(p);
    }
    return result;
  }

  function placeholder(value) {
    return !value || /\$\{|\$[A-Z_][A-Z0-9_]*|\{\{|^<.*>$|^(?:example|sample|dummy|test|your[_-]|replace|redacted|change[_-]?me)/i.test(value) || /^(?:null|none|undefined|true|false)$/i.test(value) || /^(.)\1{7,}$/.test(value);
  }

  // This is a text heuristic, not a YAML/TOML parser. Keep quoted comment markers.
  function stripComments(line, state) {
    let result = '';
    let quote = '';
    let escaped = false;
    for (let i = 0; i < line.length; i += 1) {
      const char = line[i];
      const next = line[i + 1];
      if (state.block) {
        if (char === '*' && next === '/') { state.block = false; i += 1; result += ' '; }
        continue;
      }
      if (quote) {
        result += char;
        if (escaped) escaped = false;
        else if (char === '\\') escaped = true;
        else if (char === quote) quote = '';
        continue;
      }
      if (char === '"' || char === "'") { quote = char; result += char; }
      else if (char === '/' && next === '*') { state.block = true; i += 1; }
      else if (char === '#' || (char === '/' && next === '/' && (i === 0 || /\s/.test(line[i - 1])))) break;
      else result += char;
    }
    return result;
  }

  function scalar(raw) {
    const text = raw.trim();
    if (text[0] === '"') {
      try { return JSON.parse(text); } catch (_) { return text.slice(1, -1); }
    }
    if (text[0] === "'") return text.slice(1, -1);
    return text;
  }

  function values(text) {
    return (text.match(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,\[\]{}]+/g) || []).map(scalar);
  }

  function pairs(line) {
    const result = [];
    const pattern = /(?:^|[\s,{])(?:"([^"\n]+)"|'([^'\n]+)'|([A-Za-z_][\w.-]*))\s*[:=]\s*/g;
    let match;
    while ((match = pattern.exec(line)) !== null) {
      const rest = line.slice(match.index + match[0].length);
      if (rest[0] === '{') continue;
      const value = rest.match(/^("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\[[^\]]*\]|[^\s,}\]]+)/);
      if (value) {
        result.push({ key: match[1] || match[2] || match[3], raw: value[0], value: scalar(value[0]) });
        pattern.lastIndex += value[0].length;
      }
    }
    return result;
  }

  function normalize(key) { return key.toLowerCase().replace(/[^a-z0-9]/g, ''); }
  function enabled(value) { return /^(?:true|yes|on|1)$/i.test(value); }
  function disabled(value) { return /^(?:false|no|off|0|none|disabled)$/i.test(value); }
  function wildcard(value) { return /(?:^|[\s"',\[(])\*(?:$|[\s"',\])])/.test(value); }

  function analyze(input) {
    if (typeof input !== 'string') throw new TypeError('入力はテキストにしてください。');
    if (input.length > MAX_LENGTH) throw new RangeError('入力は20万文字以内にしてください。');
    const findings = [];
    const seen = new Set();
    const state = { block: false };
    const sections = [];
    let toml = '';
    let truncated = false;

    function add(ruleId, line, value) {
      const signature = `${ruleId}:${line}`;
      if (seen.has(signature)) return;
      seen.add(signature);
      if (findings.length >= MAX_FINDINGS) { truncated = true; return; }
      const [severity, title, message, advice] = rules[ruleId];
      // Never return the source, key name, or any characters of the value.
      findings.push({ ruleId, line, severity, title, message, advice, maskedValue: `••••（${String(value).length}文字）` });
    }

    const lines = input.split(/\r?\n/);
    lines.forEach((original, index) => {
      const lineNo = index + 1;
      const line = stripComments(original, state);
      if (!line.trim()) return;
      const indent = line.match(/^\s*/)[0].length;
      while (sections.length && (indent < sections[sections.length - 1].indent || (indent === sections[sections.length - 1].indent && !/^\s*-\s/.test(line)))) sections.pop();
      const header = line.match(/^\s*\[\[?([\w."'-]+)\]\]?\s*$/);
      if (header) toml = header[1];
      const section = line.match(/^\s*([\w.-]+)\s*:\s*$/);
      const context = `${toml} ${sections.map(item => item.key).join(' ')}`;
      const entries = pairs(line);
      const candidates = new Set(entries.flatMap(entry => values(entry.raw)));
      // Also find provider keys in arrays and command arguments.
      for (const token of values(line)) candidates.add(token);
      let hasSecret = false;
      for (const value of candidates) {
        if (placeholder(value)) continue;
        if (/\b(?:sk-(?:proj-|ant-api\d{2}-)?[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|(?:AKIA|ASIA)[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{20,})\b/.test(value)) {
          add('secret', lineNo, value); hasSecret = true;
        }
      }
      for (const entry of entries) {
        const key = normalize(entry.key);
        const value = String(entry.value);
        const scope = `${context} ${entry.key}`;
        if (/(?:apikey|accesskey|accesstoken|authtoken|authorization|password|passwd|secret|privatekey|credential|token)$/.test(key) && value.length >= 8 && !placeholder(value) && !/^\[|^\{/.test(value)) {
          add('secret', lineNo, value); hasSecret = true;
        }
        if (/(?:debug|debugmode|debugenabled|enabledebug)$/.test(key) && enabled(value)) add('debug', lineNo, value);
        if ((/^(?:auth|authentication|requireauth|authrequired|authenabled|authenticationenabled|enableauth|basicauth)$/.test(key) && disabled(value)) || (/^(?:disableauth|authdisabled|noauth|anonymousaccess|allowanonymous)$/.test(key) && enabled(value))) add('auth', lineNo, value);
        if (/(?:cors|allowedorigins|alloworigin|allowedhosts|accesscontrolalloworigin)/.test(normalize(scope)) && wildcard(entry.raw)) add('cors', lineNo, entry.raw);
        if (!/deny|disallow|exclude/i.test(scope) && (
          ((/^(?:user|runasuser|uid)$/.test(key)) && /^(?:root|0(?::0)?)$/.test(value)) ||
          (/^(?:privileged|allowprivilegeescalation|dangerouslyskippermissions)$/.test(key) && enabled(value)) ||
          (key === 'runasnonroot' && disabled(value)) ||
          (key === 'sandboxmode' && value === 'danger-full-access') ||
          (/(?:permissions|allow|actions?|resources?|scope|capadd)/i.test(entry.key) && wildcard(entry.raw)) ||
          (/allowedpaths|alloweddirectories|filesystem|fileaccess/.test(normalize(scope)) && /(?:^|["'\s\[(,])(?:\/\*\*|\*\*|\/|~\/?|[A-Za-z]:[\\/])(?:$|["'\s\]),])/.test(entry.raw)) ||
          (key === 'capadd' && /\bALL\b/.test(entry.raw)) ||
          (/allow/i.test(entry.key) && /Read\(\/\*\*\)|Write\(\/\*\*\)|Bash\(\*\)/i.test(entry.raw))
        )) add('permission', lineNo, entry.raw);
      }
      if (!hasSecret) {
        for (const value of candidates) {
          const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[_+-]/].filter(pattern => pattern.test(value)).length;
          if (value.length >= 24 && classes >= 3 && /^[A-Za-z0-9_+\/-]+=*$/.test(value) && !/[/:]/.test(value) && !placeholder(value) && entropy(value) >= 4.2) add('entropy', lineNo, value);
        }
      }
      if (/(?:^|[^\d.])0\.0\.0\.0(?:[^\d.]|$)|(?:"|'|=|\s)\[?::\]?(?:"|'|\s|$)/.test(line)) add('bind', lineNo, '0.0.0.0 / ::');
      if (/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(line)) add('secret', lineNo, '秘密鍵ヘッダー');
      const portScope = /\bports\b|\bpublished\b|\bpublic_ports\b/i.test(context) || entries.some(entry => /^(?:ports|published|publicports)$/.test(normalize(entry.key)));
      if (portScope && !/\bexpose\b/i.test(context)) {
        const mappings = line.match(/(?:\[::1\]|(?:\d{1,3}\.){3}\d{1,3}|localhost):\d+(?:-\d+)?:\d+(?:-\d+)?(?:\/(?:tcp|udp))?|\b\d+(?:-\d+)?:\d+(?:-\d+)?(?:\/(?:tcp|udp))?/g) || [];
        const publicMapping = mappings.find(value => !/^(?:127\.\d+\.\d+\.\d+|localhost|\[::1\]):/.test(value));
        const barePort = /^\s*-\s*["']?\d+(?:-\d+)?(?:\/(?:tcp|udp))?["']?\s*$/.test(line) || entries.some(entry => /^(?:ports|published)$/.test(normalize(entry.key)) && /\d/.test(entry.raw) && mappings.length === 0);
        if (publicMapping || barePort) add('port', lineNo, publicMapping || '公開ポート');
      }
      if (/--(?:dangerously-skip-permissions|yolo|allow-root|no-sandbox)(?=$|[\s"',\]]|=true)/.test(line)) add('permission', lineNo, '権限を広げるフラグ');
      if (/--(?:disable-auth|no-auth)(?=$|[\s"',\]]|=true)/.test(line)) add('auth', lineNo, '認証を無効にするフラグ');
      if (/--debug(?:\s|["',\]]|$)/.test(line)) add('debug', lineNo, 'デバッグフラグ');
      if (!/deny|disallow|exclude/i.test(context) && /permissions|allow|fileaccess|allowedpaths|alloweddirectories/.test(normalize(context)) && /^\s*-\s*["']?(?:\*|\/\*\*|\/|~\/?)['"]?\s*$/.test(line)) add('permission', lineNo, '広いアクセス範囲');
      if (/cors|origins/i.test(context) && /^\s*-\s*["']?\*['"]?\s*$/.test(line)) add('cors', lineNo, '*');
      if (section) sections.push({ indent, key: section[1] });
    });
    return { findings, truncated, lines: lines.length };
  }

  const api = { analyze, MAX_LENGTH, MAX_FINDINGS };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.AgentConfigCheck = api;
}(typeof globalThis !== 'undefined' ? globalThis : this));
