(function (root) {
  'use strict';
  const MAX_LENGTH = 200000;
  const MAX_FINDINGS = 200;
  const DB_PORTS = new Set([3306, 5432, 6379, 27017, 9200]);
  const rules = {
    privileged: ['危険', 'privileged が有効', 'コンテナに強いホスト権限を与える候補です。', 'privileged: true を外し、必要な機能だけ個別に許可してください。'],
    socket: ['危険', 'Dockerソケットのマウント', 'Dockerデーモンを操作できる可能性があります。読み取り専用マウントでもAPI操作の権限は制限できません。', '不要ならソケットのマウントを削除してください。必要な場合は権限を限定した仲介などを検討してください。'],
    host: ['危険', 'ホストネットワークの使用', 'ホストとのネットワーク分離が弱くなります。', 'network_mode: host を外し、Composeのネットワークと必要な公開ポートだけを使ってください。'],
    db: ['危険', 'DB用ポートを全インターフェースに公開', 'DB類のコンテナ側ポートを、IP未指定・0.0.0.0・::でホストに公開する候補です。', 'コンテナ間の通信だけならportsを削除。ローカル専用なら127.0.0.1に限定し、認証とアクセス制御も確認してください。'],
    capability: ['危険', '強いLinux capabilityの追加', 'ALL または SYS_ADMIN を追加する候補です。', 'cap_addから外し、本当に必要なcapabilityだけに限定してください。'],
    secret: ['危険', 'environment に認証情報らしい値を直書き', 'パスワード・APIキー・トークン等の名前に、空でない固定値があります。', '直書きを避け、Compose secretsや管理された実行時注入を検討してください。環境変数参照への変更だけで秘密が保護されるとは限りません。'],
    latest: ['注意', 'latest タグのイメージ', '更新で同じタグの内容が変わる可能性があります。', '動作確認済みのバージョンやdigestに固定し、更新は検証して取り込んでください。'],
    root: ['注意', 'root ユーザーを明示', 'コンテナ内の実行ユーザーがrootになる候補です。', 'イメージが対応する非rootユーザーを指定し、必要なファイル権限を調整してください。'],
    seccomp: ['危険', 'seccomp の制限を解除', 'seccomp:unconfined はシステムコールの制限を解除します。', 'unconfinedを外し、既定のseccompプロファイルまたは必要最小限の専用プロファイルを使ってください。']
  };
  const safeSample = `# 検出対象のパターンを避けた例です。安全性の保証ではありません。
services:
  app:
    image: nginx:1.28.0
    user: "1000:1000"
    privileged: false
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    ports:
      - "127.0.0.1:8080:80"
    environment:
      API_KEY: \${API_KEY}
  db:
    image: postgres:17.6
    ports:
      - "127.0.0.1:5432:5432"
    environment:
      POSTGRES_PASSWORD: \${POSTGRES_PASSWORD}
`;
  const unsafeSample = `# 架空の値だけを使った例です。実行しないでください。
services:
  app:
    image: example.invalid/demo:latest
    privileged: true
    user: root
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    ports:
      - "0.0.0.0:5432:5432"
    cap_add: [ALL, SYS_ADMIN]
    environment:
      API_KEY: DUMMY_COMPOSE_ONLY
    security_opt:
      - seccomp:unconfined
`;

  function stripComment(line) {
    let quote = '', escaped = false;
    for (let i = 0; i < line.length; i += 1) {
      const c = line[i];
      if (escaped) { escaped = false; continue; }
      if (quote === '"' && c === '\\') { escaped = true; continue; }
      if (quote && c === quote) {
        if (quote === "'" && line[i + 1] === "'") { i += 1; continue; }
        quote = '';
      } else if (!quote && (c === '"' || c === "'")) quote = c;
      else if (!quote && c === '#' && (i === 0 || /\s/.test(line[i - 1]))) return line.slice(0, i);
    }
    return line;
  }
  function splitFlow(text, delimiter = ',') {
    const values = [];
    let start = 0, quote = '', depth = 0;
    for (let i = 0; i < text.length; i += 1) {
      const c = text[i];
      if (quote === '"' && c === '\\') { i += 1; continue; }
      if (quote && c === quote) {
        if (quote === "'" && text[i + 1] === "'") { i += 1; continue; }
        quote = '';
      } else if (!quote && (c === '"' || c === "'")) quote = c;
      else if (!quote && (c === '[' || c === '{')) depth += 1;
      else if (!quote && (c === ']' || c === '}')) depth -= 1;
      else if (!quote && depth === 0 && c === delimiter) { values.push(text.slice(start, i).trim()); start = i + 1; }
    }
    values.push(text.slice(start).trim());
    return values;
  }
  function scalar(raw) {
    const s = raw.trim();
    if (s.startsWith('"') && s.endsWith('"')) { try { return JSON.parse(s); } catch (_) { return s.slice(1, -1); } }
    if (s.startsWith("'") && s.endsWith("'")) return s.slice(1, -1).replace(/''/g, "'");
    return s;
  }
  function pair(text) {
    const m = /^("[^"\n]+"|'[^'\n]+'|[A-Za-z_][\w.-]*)\s*:(?:[ \t]+(.*)|$)/.exec(text);
    return m ? { key: scalar(m[1]), raw: m[2] || '' } : null;
  }
  function inlineChildren(raw, line) {
    const s = raw.trim();
    if (s.startsWith('[') && s.endsWith(']')) return splitFlow(s.slice(1, -1)).filter(Boolean).map((value) => ({ key: null, raw: value, line, children: [] }));
    if (s.startsWith('{') && s.endsWith('}')) return splitFlow(s.slice(1, -1)).filter(Boolean).map((value) => {
      const p = pair(value);
      return { key: p?.key || null, raw: p?.raw || value, line, children: [] };
    });
    return [];
  }
  function children(node) { return node.children.length ? node.children : inlineChildren(node.raw, node.line); }
  function parse(input) {
    const rootNode = { indent: -1, children: [] }, stack = [rootNode];
    let uncertain = false, blockIndent = null;
    input.split(/\r\n?|\n/).forEach((raw, index) => {
      if (!raw.trim()) return;
      if (/^\s*\t/.test(raw)) { uncertain = true; return; }
      const indent = raw.length - raw.trimStart().length;
      if (blockIndent !== null && indent > blockIndent) return;
      blockIndent = null;
      const text = stripComment(raw).trim();
      if (!text || text === '---' || text === '...') return;
      if (/^[%]|(?:^|\s)[&*][\w-]+|^<<\s*:/.test(text)) uncertain = true;
      while (stack.length > 1 && indent <= stack.at(-1).indent) stack.pop();
      let node;
      const isList = /^-\s+/.test(text);
      const content = isList ? text.replace(/^-\s+/, '') : text;
      const p = pair(content);
      if (isList) {
        node = { key: null, raw: p ? '' : content, indent, line: index + 1, children: [] };
        if (p) node.children.push({ ...p, line: index + 1, children: [] });
      } else if (p) node = { ...p, indent, line: index + 1, children: [] };
      else { uncertain = true; return; }
      if (/^[|>][+-]?\d?$/.test(node.raw)) { blockIndent = indent; uncertain = true; }
      if ((node.raw.startsWith('[') && !node.raw.endsWith(']'))
          || (node.raw.startsWith('{') && !node.raw.endsWith('}'))
          || (node.raw.startsWith('"') && !node.raw.endsWith('"'))
          || (node.raw.startsWith("'") && !node.raw.endsWith("'"))) uncertain = true;
      stack.at(-1).children.push(node);
      stack.push(node);
    });
    return { rootNode, uncertain };
  }
  function field(node, name) { return children(node).find((child) => child.key === name); }
  function reference(value) { return /\$\{|\$[A-Za-z_]|^[&*]|\{\{/.test(value); }
  function secretName(name) { return /password|passwd|secret|token|api[_-]?key|private[_-]?key/i.test(name); }
  function literalSecret(raw) {
    const v = scalar(raw);
    return v !== '' && !/^(?:null|~)$/i.test(v) && !reference(v);
  }
  function dbTarget(value) {
    if (/^\d+$/.test(value)) return DB_PORTS.has(Number(value));
    const range = /^(\d+)-(\d+)$/.exec(value);
    return range && [...DB_PORTS].some((port) => Number(range[1]) <= port && port <= Number(range[2]));
  }
  function riskyPort(node) {
    const long = children(node);
    if (long.length) {
      const target = field(node, 'target'), published = field(node, 'published'), host = field(node, 'host_ip');
      return target && (!published || !reference(published.raw)) && dbTarget(scalar(target.raw))
        && (!host || ['', '0.0.0.0', '::', '[::]'].includes(scalar(host.raw)));
    }
    const value = scalar(node.raw).replace(/\/(?:tcp|udp)$/i, '');
    if (reference(value)) return false;
    // Bracketed IPv6 addresses contain colons but are one host component.
    const m = /^(?:\[([^\]]+)\]:|([^:]+):)?(\d+(?:-\d+)?):(\d+(?:-\d+)?)$/.exec(value);
    if (m) return (!m[1] && !m[2] || ['0.0.0.0', '::'].includes(m[1] || m[2])) && dbTarget(m[4]);
    // A container-only entry also publishes to an automatically chosen host port.
    return /^\d+(?:-\d+)?$/.test(value) && dbTarget(value);
  }

  function analyze(input) {
    if (typeof input !== 'string' || input.length > MAX_LENGTH) throw new Error('入力は20万文字以内にしてください。');
    const findings = [], seen = new Set();
    const parsed = parse(input);
    let incomplete = parsed.uncertain, truncated = false;
    const services = parsed.rootNode.children.filter((node) => node.key === 'services');
    if (services.length !== 1 || !services[0].children.length) incomplete = true;
    function add(id, node) {
      const signature = `${id}:${node.line}`;
      if (seen.has(signature)) return;
      seen.add(signature);
      if (findings.length === MAX_FINDINGS) { truncated = true; return; }
      const [severity, title, message, advice] = rules[id];
      findings.push({ id, line: node.line, severity, title, message, advice, maskedValue: '[設定値は非表示]' });
    }
    for (const service of services.flatMap((node) => node.children)) {
      if (service.key === null || service.raw.trim()) { incomplete = true; continue; }
      for (const node of service.children) {
        if (node.key === null) incomplete = true;
        const value = scalar(node.raw);
        if (['ports', 'volumes', 'environment'].includes(node.key) && node.raw.trim() && !children(node).length) incomplete = true;
        if (node.key === 'privileged' && /^(?:true|yes|on|1)$/i.test(value)) add('privileged', node);
        if (node.key === 'network_mode' && value === 'host') add('host', node);
        if (node.key === 'image' && /:latest$/.test(value)) add('latest', node);
        if (node.key === 'user' && /^(?:root|0)(?::[^\s]+)?$/.test(value)) add('root', node);
        if (node.key === 'volumes') for (const volume of children(node)) {
          const source = field(volume, 'source');
          const v = source ? scalar(source.raw) : scalar(volume.raw).split(':', 1)[0];
          if (v === '/var/run/docker.sock') add('socket', volume);
        }
        if (node.key === 'ports') for (const port of children(node)) if (riskyPort(port)) add('db', port);
        if (node.key === 'cap_add') {
          const caps = children(node).length ? children(node) : [{ ...node, raw: value }];
          for (const cap of caps) if (['ALL', 'SYS_ADMIN', 'CAP_SYS_ADMIN'].includes(scalar(cap.raw).toUpperCase())) add('capability', cap);
        }
        if (node.key === 'security_opt') {
          const options = children(node).length ? children(node) : [node];
          for (const option of options) if (/^seccomp[:=]unconfined$/.test(scalar(option.raw))) add('seccomp', option);
        }
        if (node.key === 'environment') for (const variable of children(node)) {
          const assignment = variable.key === null ? /^([^=]+)=(.*)$/.exec(scalar(variable.raw)) : null;
          const name = variable.key || assignment?.[1];
          const raw = variable.key ? variable.raw : assignment?.[2];
          if (name && secretName(name) && raw !== undefined && literalSecret(raw)) add('secret', variable);
        }
        if (['extends', 'include', 'env_file'].includes(node.key)) incomplete = true;
      }
    }
    if (parsed.rootNode.children.some((n) => ['include', 'extends'].includes(n.key))) incomplete = true;
    findings.sort((a, b) => a.line - b.line || a.id.localeCompare(b.id));
    return { findings, incomplete, truncated };
  }

  function maskInput(input) {
    return input.split(/\r\n?|\n/).map((line) => {
      const text = stripComment(line);
      const indent = /^\s*/.exec(line)[0];
      if (!text.trim()) return line.trim() ? `${indent}# コメントは非表示` : '';
      const match = /^(\s*(?:-\s+)?(?:"[^"\n]+"|'[^'\n]+'|[A-Za-z_][\w.-]*)\s*:\s*)(.*)$/.exec(text);
      return match ? match[1] + (match[2].trim() ? '[マスク]' : '') : `${indent}[マスク]`;
    }).join('\n');
  }
  const api = { analyze, maskInput, safeSample, unsafeSample, MAX_LENGTH, MAX_FINDINGS };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.ComposeCheck = api;
}(typeof globalThis !== 'undefined' ? globalThis : this));
