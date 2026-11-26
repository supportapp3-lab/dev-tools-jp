'use strict';
(function () {
  const api = window.HeadersCheck;
  const input = document.getElementById('headers');
  const list = document.getElementById('findings');
  const status = document.getElementById('status');
  const count = document.getElementById('count');
  const empty = document.getElementById('empty');
  const cookieSummary = document.getElementById('cookie-summary');

  function reset(message) {
    list.replaceChildren();
    cookieSummary.replaceChildren();
    cookieSummary.hidden = true;
    count.hidden = true;
    empty.hidden = false;
    status.textContent = message;
  }
  function element(tag, className, text) {
    const node = document.createElement(tag);
    node.className = className;
    node.textContent = text;
    return node;
  }
  function check() {
    reset('');
    if (!input.value.trim()) {
      status.textContent = 'ヘッダーを貼り付けるか、サンプルを選んでください。';
      return;
    }
    try {
      const result = api.analyze(input.value);
      count.hidden = false;
      count.textContent = `${result.findings.length}件`;
      empty.hidden = true;
      status.textContent = `${result.selectedLast ? `${result.responseCount}件のレスポンスを検出し、最後のものを確認しました。` : 'ヘッダーを確認しました。'} ${result.findings.length ? `${result.findings.length}件の見直し候補があります。` : '高・中の指摘は見つかりませんでした。安全の保証ではありません。'}${result.ignoredLines ? ` 解釈できない行を${result.ignoredLines}件無視しました。` : ''}${result.truncated ? ' 入力が長いため先頭20万文字だけを確認しました。' : ''}`;
      if (result.cookies.length) {
        cookieSummary.hidden = false;
        cookieSummary.append(element('h3', '', 'Set-Cookie（値はマスク）'));
        const cookieList = document.createElement('ul');
        for (const cookie of result.cookies) cookieList.append(element('li', '', `${cookie.name}=${cookie.value}`));
        cookieSummary.append(cookieList);
      }
      for (const finding of result.findings) {
        const item = element('li', `finding finding-${finding.severity}`, '');
        const top = element('div', 'finding-header', '');
        top.append(
          element('span', `badge badge-${finding.severity}`, finding.severityLabel),
          element('span', 'header-name', finding.header)
        );
        item.append(
          top,
          element('h3', '', finding.title),
          element('p', '', finding.why),
          element('p', 'recommendation', `修正案: ${finding.fix}`)
        );
        list.append(item);
      }
    } catch (_) {
      reset('チェックできませんでした。入力サイズとヘッダーの書式を確認してください。');
    }
  }
  document.getElementById('check').addEventListener('click', check);
  document.getElementById('unsafe-sample').addEventListener('click', () => { input.value = api.unsafeSample; check(); });
  document.getElementById('safe-sample').addEventListener('click', () => { input.value = api.safeSample; check(); });
  document.getElementById('clear').addEventListener('click', () => {
    input.value = '';
    reset('入力と確認結果を消去しました。');
    input.focus();
  });
  window.addEventListener('pagehide', () => { input.value = ''; reset(''); });
}());
