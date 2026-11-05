'use strict';

(function () {
  const input = document.getElementById('text-input');
  const status = document.getElementById('status');
  const copyStatus = document.getElementById('copy-status');
  const summary = document.getElementById('summary');
  let timer;

  function setValue(id, value) {
    document.getElementById(id).textContent = value;
  }

  function render() {
    const result = TokenCounter.countText(input.value);
    setValue('characters', result.characters.toLocaleString('ja-JP'));
    setValue('non-whitespace', result.nonWhitespaceCharacters.toLocaleString('ja-JP'));
    setValue('lines', result.lines.toLocaleString('ja-JP'));
    setValue('bytes', result.utf8Bytes.toLocaleString('ja-JP'));
    setValue('words', result.words.toLocaleString('ja-JP'));
    setValue('word-note', result.hasCjk ? '日本語など空白で区切らない文章では参考値です。' : '空白で区切った語の数です。');
    setValue('gpt-tokens', result.gptTokens.toLocaleString('ja-JP'));
    setValue('claude-tokens', result.claudeTokens.toLocaleString('ja-JP'));
    status.textContent = input.value.length ? '入力に合わせて更新しました。' : 'テキストを入力すると、ここに結果が表示されます。';
    summary.value = [
      `文字数（空白含む）: ${result.characters}`,
      `文字数（空白を除く）: ${result.nonWhitespaceCharacters}`,
      `行数: ${result.lines}`,
      `UTF-8バイト数: ${result.utf8Bytes}`,
      `空白区切りの語数: ${result.words}`,
      `GPT系トークン概算: 約${result.gptTokens}`,
      `Claude系トークン概算: 約${result.claudeTokens}`,
    ].join('\n');
  }

  function scheduleRender() {
    window.clearTimeout(timer);
    timer = window.setTimeout(render, 100);
  }

  document.getElementById('examples').addEventListener('click', (event) => {
    const button = event.target.closest('button[data-example]');
    if (!button) return;
    input.value = examples[button.dataset.example];
    render();
    input.focus();
  });

  const examples = {
    japanese: '今日は新しいツールを作っています。',
    english: 'A small tool that counts characters and estimates tokens.',
    mixed: '議事録 summary: 次の release は Friday です。',
    log: Array.from({ length: 48 }, (_, index) => `[2026-11-05T00:${String(index).padStart(2, '0')}:00Z] INFO worker-${index % 4} completed task duration=${120 + index}ms`).join('\n'),
  };

  input.addEventListener('input', scheduleRender);
  document.getElementById('clear').addEventListener('click', () => {
    input.value = '';
    render();
    input.focus();
  });
  document.getElementById('copy').addEventListener('click', async () => {
    copyStatus.textContent = '';
    try {
      if (!navigator.clipboard || !navigator.clipboard.writeText) throw new Error('Clipboard API unavailable');
      await navigator.clipboard.writeText(summary.value);
      copyStatus.textContent = '集計結果をコピーしました。';
    } catch (_) {
      summary.focus();
      summary.select();
      copyStatus.textContent = 'コピーできませんでした。選択した集計結果を手動でコピーしてください。';
    }
  });
  render();
})();
