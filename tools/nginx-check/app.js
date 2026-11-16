'use strict';
(function () {
  const api = window.NginxCheck;
  const input = document.getElementById('config');
  const list = document.getElementById('findings');
  const status = document.getElementById('status');
  const count = document.getElementById('count');
  const empty = document.getElementById('empty');
  function reset(message) { list.replaceChildren(); count.hidden = true; empty.hidden = false; status.textContent = message; }
  function element(tag, className, text) { const node = document.createElement(tag); node.className = className; node.textContent = text; return node; }
  function check() {
    reset('');
    if (!input.value.trim()) { status.textContent = '設定を貼り付けるか、サンプルを選んでください。'; return; }
    try {
      const result = api.analyze(input.value);
      count.hidden = false; count.textContent = `${result.findings.length}件`; empty.hidden = true;
      status.textContent = `${result.findings.length ? `${result.findings.length}件の見直し候補があります。` : '対象のパターンは見つかりませんでした。安全の保証ではありません。'}${result.incomplete ? ' 未確認の書式や設定ブロックがあります。' : ''}${result.truncated ? ' 表示件数の上限に達しました。入力を分けてください。' : ''}`;
      for (const finding of result.findings) {
        const item = element('li', `finding finding-${finding.severity}`, '');
        const top = element('div', 'finding-header', '');
        top.append(element('span', `badge badge-${finding.severity}`, finding.severityLabel), element('span', 'line-number', `${finding.line}行目`));
        item.append(top, element('h3', '', finding.title), element('p', '', finding.why), element('p', 'recommendation', `修正案: ${finding.fix}`));
        list.append(item);
      }
    } catch (_) { reset('チェックできませんでした。入力サイズと設定の書式を確認してください。'); }
  }
  document.getElementById('check').addEventListener('click', check);
  document.getElementById('unsafe-sample').addEventListener('click', () => { input.value = api.unsafeSample; check(); });
  document.getElementById('safe-sample').addEventListener('click', () => { input.value = api.safeSample; check(); });
  document.getElementById('clear').addEventListener('click', () => { input.value = ''; reset('入力と確認結果を消去しました。'); input.focus(); });
  window.addEventListener('pagehide', () => { input.value = ''; list.replaceChildren(); });
}());
