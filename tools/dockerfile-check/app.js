'use strict';
(function () {
  const api = window.DockerfileCheck;
  const input = document.getElementById('dockerfile');
  const list = document.getElementById('findings');
  const status = document.getElementById('status');
  const count = document.getElementById('count');
  const empty = document.getElementById('empty');

  function reset(message) {
    list.replaceChildren(); count.hidden = true; empty.hidden = false; status.textContent = message;
  }
  function element(tag, className, text) {
    const node = document.createElement(tag); node.className = className; node.textContent = text; return node;
  }
  function check() {
    reset('');
    if (input.value.length > api.MAX_LENGTH) { input.value = ''; reset('20万文字以内に分けてください。入力を消去しました。'); return; }
    if (!input.value.trim()) { status.textContent = 'Dockerfileを貼り付けるか、サンプルを選んでください。'; return; }
    const result = api.analyze(input.value);
    if (result.error) { status.textContent = result.error; return; }
    count.hidden = false; count.textContent = result.findings.length + '件'; empty.hidden = result.findings.length > 0;
    status.textContent = result.findings.length
      ? result.findings.length + '件の見直し候補があります。簡易チェックのため、安全の保証ではありません。' +
        (result.incomplete ? ' 未対応または解釈できない構文があります。結果は不完全です。' : '')
      : (result.incomplete ? '一部を解釈できませんでした。Dockerfile全体を確認してください。' :
        '対象のパターンは見つかりませんでした。安全の保証ではありません。');
    for (const finding of result.findings) {
      const item = element('li', 'finding finding-' + finding.severity, '');
      const header = element('div', 'finding-header', '');
      header.append(element('span', 'badge', finding.severity), element('span', 'line-number', finding.line + '行目'));
      item.append(header, element('h3', '', finding.title), element('p', '', finding.message));
      if (finding.maskedValue) item.append(element('p', 'hint', finding.maskedValue));
      item.append(element('p', 'recommendation', finding.advice));
      if (finding.fixSnippet) {
        const example = element('pre', 'fix-example', '');
        example.append(element('code', '', finding.fixSnippet));
        item.append(element('h4', 'fix-example-title', '修正例'), example);
      }
      list.append(item);
    }
  }
  document.getElementById('check').addEventListener('click', check);
  document.getElementById('unsafe-sample').addEventListener('click', () => { input.value = api.unsafeSample; check(); });
  document.getElementById('safe-sample').addEventListener('click', () => { input.value = api.safeSample; check(); });
  document.getElementById('clear').addEventListener('click', () => { input.value = ''; reset('入力と確認結果を消去しました。'); input.focus(); });
  window.addEventListener('pagehide', () => { input.value = ''; list.replaceChildren(); });
}());
