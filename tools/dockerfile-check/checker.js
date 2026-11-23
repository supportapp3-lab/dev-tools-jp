'use strict';

(function (root) {
  const MAX_LENGTH = 200000;
  const MAX_FINDINGS = 200;
  const INSTRUCTIONS = new Set(['ADD', 'ARG', 'CMD', 'COPY', 'ENTRYPOINT', 'ENV', 'EXPOSE', 'FROM',
    'HEALTHCHECK', 'LABEL', 'MAINTAINER', 'ONBUILD', 'RUN', 'SHELL', 'STOPSIGNAL', 'USER', 'VOLUME']);
  const severityOrder = { '高': 0, '中': 1, '低': 2, '情報': 3 };
  const SECRET_NAME = /(?:^|[^A-Z0-9])(?:PASSWORD|PASSWD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL)(?:$|[^A-Z0-9])/i;
  const TOKEN_PATTERNS = [
    /(?<![A-Za-z0-9])ghp_[A-Za-z0-9]{8,}/g,
    /(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{8,}/g,
    /(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![A-Za-z0-9])/g,
    /(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{8,}/g,
    /(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{8,}/g,
  ];

  function finding(id, severity, line, title, message, advice) {
    return { id, severity, line: Math.max(1, line || 1), title, message, advice, maskedValue: '[値は表示しません]' };
  }

  function tokenize(text) {
    const words = [];
    let word = '', quote = '', escaped = false, active = false;
    for (const char of text) {
      if (escaped) { word += char; escaped = false; active = true; continue; }
      if (char === '\\' && quote !== "'") { escaped = true; active = true; continue; }
      if (quote) {
        if (char === quote) quote = '';
        else word += char;
        active = true;
        continue;
      }
      if (char === '"' || char === "'") { quote = char; active = true; continue; }
      if (/\s/.test(char)) {
        if (active) words.push(word);
        word = ''; active = false;
      } else { word += char; active = true; }
    }
    if (escaped || quote) return { words: [], ok: false };
    if (active) words.push(word);
    return { words, ok: true };
  }

  function jsonWords(text) {
    try {
      const value = JSON.parse(text);
      if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) return { words: [], ok: false };
      return { words: value, ok: true };
    } catch (_) { return { words: [], ok: false }; }
  }

  function wordsFor(text) {
    const trimmed = text.trim();
    return trimmed.startsWith('[') ? jsonWords(trimmed) : tokenize(trimmed);
  }

  function logicalLines(text) {
    const physical = text.replace(/\r\n?/g, '\n').split('\n');
    const result = [];
    let value = '', start = 1, continuing = false;
    for (let i = 0; i < physical.length; i += 1) {
      let part = physical[i];
      if (!continuing) { start = i + 1; value = ''; }
      if (!part.trim() || part.trimStart().startsWith('#')) continue;
      const continued = /\\\s*$/.test(part);
      if (continued) part = part.replace(/\\\s*$/, ' ');
      value += (value ? ' ' : '') + part.trim();
      if (continued) { continuing = true; continue; }
      result.push({ text: value, line: start });
      continuing = false;
    }
    if (continuing) result.push({ text: value, line: start, unterminatedContinuation: true });
    return result;
  }

  function nameHasSecret(name) { return SECRET_NAME.test(name); }

  function addSecretFindings(words, instruction, line, add) {
    const entries = [];
    if (instruction === 'ARG') {
      if (words.length) {
        const index = words[0].indexOf('=');
        entries.push(index < 0 ? [words[0], ''] : [words[0].slice(0, index), words[0].slice(index + 1)]);
      }
    }
    if (instruction === 'ENV') {
      if (words.length >= 2 && !words.some((word) => word.includes('='))) {
        entries.push([words[0], words.slice(1).join(' ')]);
      } else for (const token of words) {
        const index = token.indexOf('=');
        if (index > 0) entries.push([token.slice(0, index), token.slice(index + 1)]);
      }
    }
    for (const [name, value] of entries) {
      if (nameHasSecret(name) && String(value).trim()) {
        add(finding('secret-variable', '高', line, '秘密情報らしい値の設定',
          'ENV / ARG に秘密情報らしい名前と値があります。値は表示していません。',
          '値をDockerfileへ書かず、BuildKitの --mount=type=secret でビルド時に渡してください。'));
      }
    }
  }

  function pathsFor(words) {
    const operands = [];
    for (const word of words) {
      if (word.startsWith('--')) continue;
      operands.push(word);
    }
    return operands.length >= 2 ? operands.slice(0, -1) : [];
  }

  function sensitivePath(path) {
    const normalized = path.replace(/\\/g, '/').replace(/^["']|["']$/g, '');
    const parts = normalized.split('/');
    return parts.some((part) => part === '.env' || /^\.env\.[^/]+$/.test(part)
      || part === '.git' || part === 'id_rsa' || /(?:^|\*)[^/]*\.pem$/i.test(part));
  }

  function analyze(input) {
    const result = { findings: [], incomplete: false, truncated: false };
    if (typeof input !== 'string') {
      result.incomplete = true; result.error = 'Dockerfileをテキストとして読み取れません。'; return result;
    }
    if (input.length > MAX_LENGTH) {
      result.incomplete = true; result.error = '入力が上限を超えています。20万文字以内に分けてください。'; return result;
    }
    if (!input.trim()) return result;

    let rows = logicalLines(input);
    const parsed = [];
    let heredocEnd = null;
    for (const row of rows) {
      if (heredocEnd) {
        if (row.text.trim() === heredocEnd) heredocEnd = null;
        continue;
      }
      const match = row.text.match(/^([A-Za-z]+)(?:\s+([\s\S]*))?$/);
      if (!match || !INSTRUCTIONS.has(match[1].toUpperCase())) {
        result.incomplete = true;
        result.findings.push(finding('parse-error', '情報', row.line, '一部を解釈できません',
          'Dockerfileの行を命令として解釈できませんでした。以降の結果は不完全な可能性があります。',
          '命令名と綴りを確認し、heredocなど未対応の構文はDocker公式の検証ツールでも確認してください。'));
        continue;
      }
      const instruction = match[1].toUpperCase();
      const args = (match[2] || '').trim();
      parsed.push({ instruction, args, line: row.line });
      if (/^(?:RUN|ADD|COPY)\b/i.test(row.text)) {
        const heredoc = row.text.match(/<<-?\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?/);
        if (heredoc) { result.incomplete = true; heredocEnd = heredoc[1]; }
      }
      if (row.unterminatedContinuation) {
        result.incomplete = true;
        result.findings.push(finding('parse-error', '情報', row.line, '継続行が完了していません',
          '行末の継続記号に続く行がありません。', '行末の \\ と次の行を確認してください。'));
      }
    }
    if (heredocEnd) {
      result.incomplete = true;
      result.findings.push(finding('heredoc-unclosed', '情報', Math.max(1, rows.at(-1)?.line || 1), 'heredocを確認できません',
        'heredocの終端を確認できませんでした。', '終端識別子を確認し、Docker公式の検証ツールでも確認してください。'));
    }
    if (!parsed.some((row) => row.instruction === 'FROM')) {
      result.incomplete = true;
      result.findings.push(finding('missing-from', '情報', 1, 'FROM 命令が見つかりません',
        'Dockerfileとしての構成を確認できませんでした。', '有効なFROM命令を含むDockerfileか確認してください。'));
    }

    const add = (item) => result.findings.push(item);
    const stages = [];
    let currentStage = null;
    for (const row of parsed) {
      const { instruction, args, line } = row;
      if (instruction === 'FROM') {
        const tokens = wordsFor(args);
        if (!tokens.ok || !tokens.words.length) {
          result.incomplete = true;
          add(finding('parse-error', '情報', line, 'FROM 命令を解釈できません', 'ベースイメージを解析できませんでした。', 'FROMの引数を確認してください。'));
          currentStage = { line, lastUser: null, image: null }; stages.push(currentStage); continue;
        }
        const image = tokens.words.find((word) => !word.startsWith('--'));
        if (!image) { result.incomplete = true; continue; }
        currentStage = { line, lastUser: null, image, hasHealthcheck: false };
        stages.push(currentStage);
        if (image.includes('$') || image.includes('${')) {
          result.incomplete = true;
          add(finding('dynamic-base-image', '情報', line, 'ベースイメージが動的です',
            '変数で指定されたイメージのタグやダイジェストを確認できません。', '利用するベースイメージを固定し、可能ならダイジェストを指定してください。'));
        } else if (image.toLowerCase() !== 'scratch') {
          const at = image.lastIndexOf('@');
          const nameAndTag = at < 0 ? image : image.slice(0, at);
          const slash = nameAndTag.lastIndexOf('/');
          const colon = nameAndTag.lastIndexOf(':');
          const tag = colon > slash ? nameAndTag.slice(colon + 1) : '';
          if (!tag || tag.toLowerCase() === 'latest') {
            add(finding('mutable-base-tag', '中', line, 'ベースイメージのタグが固定されていません',
              tag ? 'latestタグは更新で内容が変わる場合があります。' : 'タグが省略されるとlatest相当になります。',
              '検証済みのバージョンタグを指定してください。'));
          }
          if (!image.toLowerCase().includes('@sha256:')) {
            add(finding('unpinned-base-digest', '情報', line, 'ベースイメージにダイジェストがありません',
              '同じタグでも参照先イメージが更新される場合があります。', '再現性が必要なビルドでは検証済みの @sha256: ダイジェストを併記してください。'));
          }
        }
        continue;
      }
      if (instruction === 'USER' && currentStage) currentStage.lastUser = { args, line };
      if (instruction === 'HEALTHCHECK' && currentStage && !/^NONE\s*$/i.test(args)) currentStage.hasHealthcheck = true;
      if (instruction === 'ENV' || instruction === 'ARG') {
        const parsedWords = wordsFor(args);
        if (!parsedWords.ok) {
          result.incomplete = true;
          add(finding('parse-error', '情報', line, 'ENV / ARG を解釈できません', '設定値を安全に解析できませんでした。', '引用符・JSON形式の記述を確認してください。'));
        } else addSecretFindings(parsedWords.words, instruction, line, add);
      }
      const instructionForTokens = instruction === 'ONBUILD' ? args.replace(/^(ADD|COPY)\s+/i, '') : args;
      const effectiveInstruction = instruction === 'ONBUILD' ? (args.match(/^(ADD|COPY)\b/i)?.[1].toUpperCase() || '') : instruction;
      if (effectiveInstruction === 'COPY' || effectiveInstruction === 'ADD') {
        const parsedWords = wordsFor(instructionForTokens);
        if (!parsedWords.ok) {
          result.incomplete = true;
          add(finding('parse-error', '情報', line, 'COPY / ADD を解釈できません', 'コピー元を安全に解析できませんでした。', '引用符またはJSON形式の記述を確認してください。'));
        } else {
          const sources = pathsFor(parsedWords.words);
          if (effectiveInstruction === 'COPY' && sources.length === 1 && (sources[0] === '.' || sources[0] === './')) {
            add(finding('copy-all-context', '情報', line, 'ビルドコンテキスト全体をコピーしています',
              'COPY . . は意図しないファイルを含める場合があります。', '.dockerignoreで.env、秘密鍵、.gitなどを除外してください。'));
          }
          for (const source of sources) {
            if (sensitivePath(source)) add(finding('copy-sensitive-path', '高', line, '秘密情報らしいパスをコピーしています',
              'コピー元に.env、秘密鍵、証明書、または.gitが含まれています。', 'コピー対象を限定し、秘密情報はBuildKit secretで扱ってください。'));
            if (effectiveInstruction === 'ADD' && /^https?:\/\//i.test(source)) {
              add(finding('add-url', '低', line, 'ADD でURLを取得しています',
                'ADDによるURL取得は取得内容や展開動作が分かりにくくなります。', 'COPYで固定したファイルを使うか、検証・固定したcurl取得手順を使ってください。'));
            } else if (effectiveInstruction === 'ADD' && !/^https?:\/\//i.test(source) && !source.startsWith('<<')) {
              add(finding('add-local', '低', line, 'ローカルファイルに ADD を使っています',
                '通常のファイルコピーではADDの展開機能が不要です。', 'ローカルファイルにはCOPYを使ってください。'));
            }
          }
        }
      }
      if (instruction === 'EXPOSE' && /(?:^|\s)22(?:\/|\s|$)/.test(args)) {
        add(finding('expose-ssh', '中', line, 'SSHポートを公開しています',
          'コンテナ内のSSHサーバーは攻撃面を増やすことがあります。', 'SSHが必要か見直し、必要ならコンテナ外のアクセス制御を確認してください。'));
      }
      if (instruction === 'RUN') {
        if (/(?:curl|wget)\b[^|\n]*\|\s*(?:sh|bash)\b/i.test(args)) {
          add(finding('pipe-to-shell', '中', line, '取得した内容をそのままシェルへ渡しています',
            '取得先の変更や通信の改ざんがビルド時のコード実行につながります。', '取得元とチェックサムを検証してから実行してください。'));
        }
        if (/\bchmod\s+(?:-R\s+)?0?777\b/i.test(args)) {
          add(finding('world-writable', '中', line, '全ユーザーに書き込み権限を付けています',
            'chmod 777は必要以上の権限を与える場合があります。', '利用者と用途に必要な最小権限へ絞ってください。'));
        }
        if (/\bsudo\b/i.test(args)) {
          add(finding('sudo', '低', line, 'ビルド中に sudo を使っています',
            'DockerのRUNは通常rootで実行されるためsudoが不要なことがあります。', 'USER切替の位置と権限を確認し、不要ならsudoを外してください。'));
        }
        if (/\bapt-get\s+install\b/i.test(args)) {
          if (!/--no-install-recommends\b/i.test(args)) {
            add(finding('apt-recommends', '低', line, 'apt-get install の推奨パッケージを抑制していません',
              '不要な推奨パッケージがイメージに追加される場合があります。', 'apt-get install --no-install-recommends を検討してください。'));
          }
          if (!/\brm\s+-rf\s+\/var\/lib\/apt\/lists\//i.test(args)) {
            add(finding('apt-cache-cleanup', '低', line, 'aptの一覧キャッシュを削除していません',
              'パッケージ一覧がイメージレイヤーに残る場合があります。', '同じRUN内で rm -rf /var/lib/apt/lists/* を実行してください。'));
          }
        }
        if (/\bapt-get\s+upgrade\b/i.test(args)) {
          add(finding('apt-upgrade', '低', line, 'ビルド時に apt-get upgrade を実行しています',
            'ベースイメージの更新内容が意図せず変わり、再現性が下がる場合があります。', '更新済みのベースイメージを選び、必要なパッケージだけを指定してください。'));
        }
        if (/\b(?:apt-get\s+install\s+[^;&|]*openssh-server|apk\s+add\s+[^;&|]*openssh|sshd\b)/i.test(args)) {
          add(finding('install-sshd', '中', line, 'SSHサーバーを導入または起動しています',
            'コンテナ内のSSHサーバーは攻撃面を増やすことがあります。', 'SSHを使わず、コンテナ実行基盤の管理機能を利用できないか確認してください。'));
        }
      }
      for (const pattern of TOKEN_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(args)) add(finding('hardcoded-token', '高', line, 'トークンらしい文字列があります',
          'Dockerfileに認証情報らしい形式の文字列があります。値は表示していません。',
          '値を削除して漏えいとして扱い、必要なら無効化・更新してください。ビルド時はBuildKit secretを使ってください。'));
      }
    }

    const finalStage = stages.at(-1);
    if (finalStage) {
      const user = finalStage.lastUser;
      const value = user ? wordsFor(user.args) : null;
      const userName = value?.ok ? value.words[0]?.split(':')[0].toLowerCase() : '';
      if (!user || userName === 'root' || userName === '0') {
        add(finding('final-user-root', '中', user?.line || finalStage.line, '最終ステージがrootで実行される可能性があります',
          user ? '最終USERがrootまたはUID 0です。' : '最終ステージにUSERがなく、既定のrootで動く可能性があります。',
          '専用の非rootユーザーを作成し、最終ステージで USER app を指定してください。'));
      }
    }
    if (!finalStage?.hasHealthcheck) add(finding('missing-healthcheck', '情報', finalStage?.line || Math.max(1, rows.at(-1)?.line || 1),
      'HEALTHCHECK がありません', 'Dockerはコンテナのアプリケーション応答を自動判定できない場合があります。',
      '実行環境に応じて、軽量で安全なヘルスチェックを追加してください。'));

    const unique = new Map();
    for (const item of result.findings) unique.set(`${item.id}:${item.line}`, item);
    const findings = [...unique.values()].sort((a, b) => a.line - b.line || severityOrder[a.severity] - severityOrder[b.severity]);
    result.truncated = findings.length > MAX_FINDINGS;
    result.findings = findings.slice(0, MAX_FINDINGS);
    return result;
  }

  const unsafeSample = `FROM node:latest
ENV API_KEY=ghp_DUMMYTOKEN1234567890
COPY .env .
COPY . .
ADD https://example.invalid/install.sh /tmp/install.sh
RUN curl https://example.invalid/install.sh | sh && chmod -R 777 /app && apt-get install openssh-server
EXPOSE 22
USER root`;
  const safeSample = `FROM node:22.11.0 AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
FROM node:22.11.0-alpine AS app
WORKDIR /app
COPY --from=build /src/dist ./dist
USER node
HEALTHCHECK CMD node -e "process.exit(0)"
CMD ["node", "dist/server.js"]`;
  const api = { MAX_LENGTH, MAX_FINDINGS, analyze, unsafeSample, safeSample };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root) root.DockerfileCheck = api;
}(typeof window !== 'undefined' ? window : globalThis));
