'use strict';
(function () {
  const api = window.ComposeCheck;
  const input = document.getElementById('config');
  const list = document.getElementById('findings');
  const status = document.getElementById('status');
  const count = document.getElementById('count');
  const empty = document.getElementById('empty');
  let original = '';
  function reset(message) {
    list.replaceChildren(); count.hidden = true; empty.hidden = false; status.textContent = message;
  }
  function accept(text) {
    if (text.length > api.MAX_LENGTH) {
      original = ''; input.value = ''; input.readOnly = false;
      reset('20万文字以内に分けて貼り付けてください。入力と結果を消去しました。'); return;
    }
    original = text;
    input.value = api.maskInput(text);
    input.readOnly = true;
    reset('入力の値をマスクしました。「設定をチェック」を押してください。編集は元ファイル側で行い、全体を貼り直してください。');
  }
  function element(tag, className, text) {
    const node = document.createElement(tag); node.className = className; node.textContent = text; return node;
  }
  function check() {
    reset('');
    if (!original.trim()) { status.textContent = '設定を貼り付けるか、サンプルを選んでください。'; return; }
    try {
      const result = api.analyze(original);
      count.hidden = false; count.textContent = `${result.findings.length}件`;
      empty.hidden = true;
      status.textContent = `${result.findings.length ? `${result.findings.length}件の見直し候補があります。` : '対象のパターンは見つかりませんでした。安全の保証ではありません。'}${result.incomplete ? ' 未確認の書式・参照先があります。設定全体は確認できていません。' : ''}${result.truncated ? ' 表示は200件までです。入力を分けてください。' : ''}`;
      for (const finding of result.findings) {
        const item = element('li', `finding finding-${finding.severity}`, '');
        const top = element('div', 'finding-header', '');
        top.append(element('span', 'badge', finding.severity), element('span', 'line-number', `${finding.line}行目`));
        item.append(top, element('h3', '', finding.title), element('p', '', finding.message), element('p', 'hint', finding.maskedValue), element('p', 'recommendation', finding.advice));
        list.append(item);
      }
    } catch (_) { reset('チェックできませんでした。入力を分け、対応する書式を確認してください。'); }
  }
  input.addEventListener('paste', (event) => {
    event.preventDefault();
    const text = event.clipboardData?.getData('text/plain');
    if (typeof text === 'string') accept(text);
  });
  input.addEventListener('input', () => { accept(input.value); });
  input.addEventListener('drop', (event) => { event.preventDefault(); });
  document.getElementById('check').addEventListener('click', check);
  document.getElementById('unsafe-sample').addEventListener('click', () => { accept(api.unsafeSample); check(); });
  document.getElementById('safe-sample').addEventListener('click', () => { accept(api.safeSample); check(); });
  document.getElementById('clear').addEventListener('click', () => {
    original = ''; input.value = ''; input.readOnly = false; reset('入力と確認結果を消去しました。'); input.focus();
  });
  window.addEventListener('pagehide', () => { original = ''; input.value = ''; list.replaceChildren(); });
}());
