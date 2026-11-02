(function () {
  'use strict';
  const input = document.getElementById('config');
  const findings = document.getElementById('findings');
  const status = document.getElementById('status');
  const empty = document.getElementById('empty');
  const count = document.getElementById('count');
  const matchSection = document.getElementById('match-section');
  const matchList = document.getElementById('match-lines');
  const includeList = document.getElementById('includes');
  const includeSection = document.getElementById('include-section');

  function appendText(parent, tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    node.textContent = text;
    parent.append(node);
    return node;
  }

  function render() {
    findings.replaceChildren();
    matchList.replaceChildren();
    includeList.replaceChildren();
    const result = SshdChecker.analyze(input.value);
    empty.hidden = !result.empty;
    count.hidden = result.empty;
    count.textContent = `${result.findings.length}件の指摘`;
    status.textContent = result.empty
      ? '設定を貼り付けると、ブラウザ内で確認します。'
      : result.findings.length
        ? `確認が必要な項目: ${result.findings.length}件。実際の有効設定はInclude先や接続条件にも左右されます。`
        : '入力を解析しました。検出がなくても安全性を保証するものではありません。';

    for (const finding of result.findings) {
      const item = document.createElement('li');
      item.className = `finding finding-${finding.category}`;
      const header = document.createElement('div');
      header.className = 'finding-header';
      appendText(header, 'span', 'badge', finding.category);
      appendText(header, 'h3', '', finding.title);
      if (finding.line) appendText(header, 'span', 'line-number', `${finding.line}行目`);
      item.append(header);
      appendText(item, 'p', '', finding.reason);
      appendText(item, 'p', 'recommendation', `推奨例: ${finding.recommendation}`);
      findings.append(item);
    }

    for (const include of result.includes) {
      const item = document.createElement('li');
      const scope = include.inMatch ? 'Matchブロック内' : 'グローバル';
      item.textContent = `${include.line}行目（${scope}）: Include ${include.value || '（パス未指定）'} — 読み込まれるファイルの中身はこのツールでは確認できません。`;
      includeList.append(item);
    }
    includeSection.hidden = result.includes.length === 0;

    for (const match of result.matchLines) {
      const item = document.createElement('li');
      item.textContent = `${match.line}行目: ${match.text}`;
      matchList.append(item);
    }
    matchSection.hidden = result.matchLines.length === 0;
  }

  document.getElementById('check').addEventListener('click', render);
  document.getElementById('clear').addEventListener('click', () => {
    input.value = '';
    render();
    input.focus();
  });
  document.getElementById('unsafe-sample').addEventListener('click', () => {
    input.value = [
      '# 危険な例（環境により判定は異なります）',
      'PermitRootLogin yes',
      'PasswordAuthentication yes',
      'PermitEmptyPasswords yes',
      'X11Forwarding yes',
      'AllowTcpForwarding yes',
      'MaxAuthTries 10',
      'Ciphers aes128-cbc,aes256-ctr',
      'Match User guest',
      '  PasswordAuthentication yes'
    ].join('\n');
    render();
  });
  document.getElementById('safe-sample').addEventListener('click', () => {
    input.value = [
      '# 安全な例（実環境に合わせてください）',
      'PermitRootLogin prohibit-password',
      'PasswordAuthentication no',
      'PermitEmptyPasswords no',
      'KbdInteractiveAuthentication no',
      'PubkeyAuthentication yes',
      'AllowUsers deploy operator',
      'AllowTcpForwarding no',
      'X11Forwarding no',
      'ClientAliveInterval 300',
      'LoginGraceTime 60'
    ].join('\n');
    render();
  });

  render();
})();
