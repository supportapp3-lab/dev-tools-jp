(function (root, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.SshdChecker = api;
})(typeof globalThis === 'object' ? globalThis : this, function () {
  'use strict';

  const ALIASES = new Map([
    ['challengeresponseauthentication', 'kbdinteractiveauthentication']
  ]);

  function canonical(keyword) {
    const lower = keyword.toLowerCase();
    return ALIASES.get(lower) || lower;
  }

  function analyze(source) {
    const input = String(source == null ? '' : source);
    const lines = input.split(/\r\n|\n|\r/);
    const settings = new Map();
    const duplicates = [];
    const matchLines = [];
    const includes = [];
    const empty = !lines.some(line => line.split('#', 1)[0].trim().length > 0);
    let inMatch = false;

    for (let index = 0; index < lines.length; index++) {
      const withoutComment = lines[index].split('#', 1)[0].trim();
      if (!withoutComment) continue;
      const directive = /^([^\s=]+)(?:\s*=\s*(.*)|\s+(.*))?$/.exec(withoutComment);
      if (!directive) continue;
      const keyword = directive[1];
      let value = directive[2] || directive[3] || '';
      if (value.length >= 2 && value[0] === '"' && value[value.length - 1] === '"') {
        value = value.slice(1, -1);
      }
      const lower = keyword.toLowerCase();
      const line = index + 1;

      if (lower === 'match') {
        inMatch = true;
        matchLines.push({ line, keyword, value, text: withoutComment, isHeader: true });
        continue;
      }

      if (lower === 'include') {
        includes.push({ line, value, inMatch });
      }

      if (inMatch) {
        matchLines.push({ line, keyword, value, text: withoutComment, isHeader: false });
        continue;
      }

      const key = canonical(keyword);
      if (!settings.has(key)) {
        settings.set(key, { keyword, value, line });
      } else {
        duplicates.push({ keyword, canonicalKeyword: key, value, line, first: settings.get(key) });
      }
    }

    const findings = [];
    const add = (category, title, item, reason, recommendation) => findings.push({
      category, title, line: item ? item.line : null,
      reason, recommendation, directive: item ? item.keyword : '', value: item ? item.value : ''
    });
    if (empty) return { findings, duplicates, matchLines, includes, empty, lineCount: lines.length };
    const get = keyword => settings.get(canonical(keyword));

    for (const duplicate of duplicates) {
      add('注意', `${duplicate.keyword} が重複しています（${duplicate.line}行目）`, duplicate,
        `OpenSSHでは同じ設定の最初の値が採用されます。後の値「${duplicate.value || '（値なし）'}」は反映されない可能性があります。`,
        `重複を整理し、採用したい値を最初の設定にしてください（例: ${duplicate.keyword} no）。`);
    }

    const rootLogin = get('PermitRootLogin');
    if (!rootLogin) {
      add('注意', 'PermitRootLogin が未指定です', null,
        '既定値はOpenSSHのバージョンによって異なります。rootでの直接ログイン可否を設定ファイルだけから断定できません。',
        'rootの直接ログインを止める例: PermitRootLogin no（鍵ログインだけ許す場合: prohibit-password）。');
    } else if (rootLogin.value.toLowerCase() === 'yes') {
      add('危険', 'root の直接ログインが許可されています', rootLogin,
        '侵害時に管理者アカウントへ直接ログインされる範囲が広がります。',
        '例: PermitRootLogin prohibit-password または PermitRootLogin no。');
    } else if (['no', 'prohibit-password', 'without-password'].includes(rootLogin.value.toLowerCase())) {
      const legacy = rootLogin.value.toLowerCase() === 'without-password';
      add('良い', 'root の直接ログインが制限されています', rootLogin,
        legacy
          ? 'rootへのパスワードログインを許可しない設定です。without-password は prohibit-password の旧名です。'
          : 'rootへのパスワードログインを許可しない設定です。',
        legacy
          ? '新しい設定例: PermitRootLogin prohibit-password。'
          : '現在の運用に合う値を維持し、別の管理者アカウントからのログインも確認してください。');
    }

    const password = get('PasswordAuthentication');
    if (!password) {
      add('注意', 'PasswordAuthentication が未指定です', null,
        'OpenSSHの既定はyesです。公開鍵だけにしたい場合、未指定のままでは意図と異なることがあります。',
        '公開鍵認証だけにする例: PasswordAuthentication no。');
    } else if (password.value.toLowerCase() === 'yes') {
      add('危険', 'パスワード認証が許可されています', password,
        'インターネットから到達できるSSHでは、弱いパスワードや再利用パスワードが攻撃対象になります。',
        '鍵認証だけにする例: PasswordAuthentication no。');
    } else if (password.value.toLowerCase() === 'no') {
      add('良い', 'パスワード認証が無効です', password,
        'パスワードでのSSHログインを許可しない設定です。',
        '鍵認証で別のログイン経路を確認してから維持してください。');
    }

    for (const directive of ['PermitEmptyPasswords', 'Protocol']) {
      const item = get(directive);
      if (item && item.value.toLowerCase().split(/\s+/).includes('yes') && directive === 'PermitEmptyPasswords') {
        add('危険', '空パスワードが許可されています', item,
          'パスワード未設定のアカウントでログインできるおそれがあります。',
          '例: PermitEmptyPasswords no。');
      }
      if (item && directive === 'Protocol' && item.value.split(/\s+/).includes('1')) {
        add('危険', '古いSSH Protocol 1 が指定されています', item,
          'Protocol 1は古く、現行の安全なSSH構成として使うべきではありません。',
          'Protocol 2へ移行し、対応状況を確認してください。');
      }
    }

    const kbd = get('KbdInteractiveAuthentication');
    if (kbd && kbd.value.toLowerCase() === 'yes') {
      add('注意', 'キーボード対話認証が有効です', kbd,
        'PAMや追加プロンプトを通じた認証経路が残る場合があります。PasswordAuthenticationだけでは判断できません。',
        '不要なら KbdInteractiveAuthentication no（旧名: ChallengeResponseAuthentication no）を検討してください。');
    }

    for (const [directive, title, reason, recommendation] of [
      ['X11Forwarding', 'X11転送が有効です', '不要な転送機能は利用可能な攻撃面を増やします。', '不要なら X11Forwarding no。'],
      ['PermitUserEnvironment', 'ユーザー環境設定の読込みが有効です', 'ユーザーが指定する環境変数による予期しない挙動につながる場合があります。', '不要なら PermitUserEnvironment no。']
    ]) {
      const item = get(directive);
      if (item && item.value.toLowerCase() === 'yes') add('注意', title, item, reason, recommendation);
    }

    const maxAuth = get('MaxAuthTries');
    if (maxAuth && /^\d+$/.test(maxAuth.value) && Number(maxAuth.value) > 6) {
      add('注意', 'MaxAuthTries が 6 を超えています', maxAuth,
        '1回の接続で許可する認証失敗回数が多めです。',
        '例: MaxAuthTries 6 以下。利用者の接続方法に合わせて調整してください。');
    }

    const forwarding = get('AllowTcpForwarding');
    if (!forwarding) {
      add('注意', 'AllowTcpForwarding が未指定です', null,
        'OpenSSHの既定ではTCP転送が許可されます。踏み台などで不要なら意図を明示してください。',
        '不要なら AllowTcpForwarding no。必要な場合は local / remote などに範囲を絞る方法があります。');
    } else if (forwarding.value.toLowerCase() === 'yes') {
      add('注意', 'TCP転送が許可されています', forwarding,
        '利用者がSSH接続を経由して別の宛先へ転送できる設定です。',
        '不要なら AllowTcpForwarding no。必要な場合は local または remote に制限してください。');
    }

    const interval = get('ClientAliveInterval');
    if (!interval) {
      add('注意', 'ClientAliveInterval が未設定です', null,
        '無通信接続をサーバー側から確認する間隔は明示されていません。',
        '運用に合わせた値を設定し、ClientAliveCountMax と組み合わせて切断時間を確認してください。');
    }

    const grace = get('LoginGraceTime');
    if (grace) {
      const seconds = durationSeconds(grace.value);
      if (seconds !== null && seconds > 120) {
        add('注意', 'LoginGraceTime が 120 秒を超えています', grace,
          '認証を完了しない接続が長く保持される設定です。',
          '例: LoginGraceTime 60。利用環境に合わせて調整してください。');
      }
    }

    for (const directive of ['Ciphers', 'MACs', 'KexAlgorithms']) {
      const item = get(directive);
      if (!item) continue;
      const algorithms = item.value.toLowerCase().split(',').map(value => value.trim());
      const weak = algorithms.filter(value => /cbc|arcfour|hmac-md5|hmac-sha1|diffie-hellman-group1-sha1/.test(value));
      if (weak.length) {
        add('注意', `${directive} に古い暗号・アルゴリズム候補があります`, item,
          `設定値に ${weak.join('、')} が含まれています。サーバーの対応状況とクライアント要件を確認してください。`,
          `古い候補を外した ${directive} の明示例を、利用環境で検証して設定してください。`);
      }
    }

    const usePam = get('UsePAM');
    if (usePam && password) {
      add('情報', 'UsePAM と PasswordAuthentication の組み合わせ', usePam,
        `UsePAM ${usePam.value}、PasswordAuthentication ${password.value} が最初のグローバル設定です。実際の認証可否はPAM設定やディストリビューションにも依存します。`,
        'PAMを使う場合も、PasswordAuthentication と PAM側の認証ポリシーを合わせて確認してください。');
    }

    const port = get('Port');
    if (port && port.value.split(/\s+/).includes('22')) {
      add('情報', '標準ポート 22 が含まれています', port,
        'Port 22の変更は任意で、ポート番号変更だけではSSHの本質的な安全性は高まりません。',
        '公開範囲、認証方式、更新、ファイアウォールを優先して確認してください。');
    }

    for (const directive of ['PubkeyAuthentication', 'AllowUsers', 'AllowGroups']) {
      const item = get(directive);
      if (!item) continue;
      if ((directive === 'PubkeyAuthentication' && item.value.toLowerCase() === 'yes') ||
          (directive !== 'PubkeyAuthentication' && item.value.trim())) {
        add('良い', `${directive} が指定されています`, item,
          directive === 'PubkeyAuthentication' ? '公開鍵認証が有効です。' : 'ログイン対象を明示的に制限しています。',
          '運用対象のアカウントやグループと設定内容が一致しているか確認してください。');
      }
    }

    return {
      findings,
      duplicates,
      matchLines,
      includes,
      empty,
      lineCount: lines.length
    };
  }

  function durationSeconds(value) {
    const match = /^(\d+)([smhd]?)$/i.exec(value.trim());
    if (!match) return null;
    const units = { '': 1, s: 1, m: 60, h: 3600, d: 86400 };
    const result = Number(match[1]) * units[match[2].toLowerCase()];
    return Number.isFinite(result) ? result : null;
  }

  return { analyze, durationSeconds };
});
