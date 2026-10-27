'use strict';

(function () {
  const input = document.getElementById('config');
  const list = document.getElementById('findings');
  const status = document.getElementById('status');
  const count = document.getElementById('count');
  const empty = document.getElementById('empty');
  const sample = `# 架空のサンプルです。実在する認証情報ではありません。
OPENAI_API_KEY=sk-proj-F7a2K9m4Q1s8V6c3N5r0D2h9L4p8B1w6
SESSION_ID=Q8f3N9a2W7k4R1v6Y0m5D8p3H2z9C4s1
HOST=0.0.0.0
DEBUG=true
AUTH_ENABLED=false
CORS_ORIGINS="*"

# Docker Compose の例
services:
  agent:
    user: root
    privileged: true
    ports:
      - "8080:80"

# エージェントのアクセス範囲の例
allowed_paths: ["/**"]`;

  function reset(message) {
    list.replaceChildren();
    count.hidden = true;
    empty.hidden = false;
    status.textContent = message;
  }

  function element(tag, className, text) {
    const item = document.createElement(tag);
    item.className = className;
    item.textContent = text;
    return item;
  }

  function check() {
    reset('');
    if (!input.value.trim()) {
      status.textContent = '設定を入力するか、「サンプル入力」を押してください。';
      return;
    }
    try {
      const result = window.AgentConfigCheck.analyze(input.value);
      empty.hidden = true;
      count.hidden = false;
      count.textContent = `${result.findings.length}件`;
      status.textContent = result.findings.length
        ? `${result.findings.length}件の見直し候補があります。${result.truncated ? '上限200件まで表示しています。入力を分けて再確認してください。' : '用途に合わせて各設定を確認してください。'}`
        : '該当するパターンは見つかりませんでした。安全を保証する結果ではありません。';
      for (const finding of result.findings) {
        const item = element('li', `finding ${finding.severity}`, '');
        const top = element('div', 'finding-top', '');
        top.append(element('span', 'badge', finding.severity === 'high' ? '要確認' : '注意'), element('span', 'line', `${finding.line}行目`));
        item.append(top, element('h3', '', finding.title), element('p', '', finding.message), element('span', 'masked', finding.maskedValue), element('p', '', finding.advice));
        list.append(item);
      }
    } catch (_) {
      status.textContent = 'チェックできませんでした。入力は20万文字以内に分けてください。';
    }
  }

  document.getElementById('check').addEventListener('click', check);
  document.getElementById('sample').addEventListener('click', function () { input.value = sample; check(); });
  document.getElementById('clear').addEventListener('click', function () {
    input.value = '';
    reset('入力と確認結果を消去しました。');
    input.focus();
  });
  input.addEventListener('input', function () { reset('入力が変更されました。「設定をチェック」を押してください。'); });
}());
