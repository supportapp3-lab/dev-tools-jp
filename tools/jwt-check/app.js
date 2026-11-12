(function () {
  'use strict';
  const input = document.getElementById('jwt');
  const status = document.getElementById('status');
  const headerOutput = document.getElementById('header');
  const payloadOutput = document.getElementById('payload');
  const signatureOutput = document.getElementById('signature');
  const dateOutput = document.getElementById('dates');
  const findingsOutput = document.getElementById('findings');
  const empty = document.getElementById('empty');
  const api = window.JwtCheck;

  function clearResults() {
    headerOutput.textContent = '';
    payloadOutput.textContent = '';
    signatureOutput.textContent = '';
    dateOutput.replaceChildren();
    findingsOutput.replaceChildren();
    empty.hidden = false;
  }

  function render() {
    clearResults();
    const result = api.analyze(input.value);
    if (!result.ok) {
      status.textContent = result.error;
      status.className = 'status error';
      return;
    }
    status.textContent = `デコードしました。署名は検証していません。${result.findings.length ? `見直し候補 ${result.findings.length} 件。` : 'この簡易チェックで見つかった候補はありません。安全の保証ではありません。'}`;
    status.className = 'status';
    headerOutput.textContent = JSON.stringify(result.header, null, 2);
    payloadOutput.textContent = JSON.stringify(result.payload, null, 2);
    signatureOutput.textContent = `${result.signatureLength}文字（署名内容は表示しません）`;
    for (const date of result.dates) {
      const item = document.createElement('li');
      item.textContent = date.text;
      dateOutput.append(item);
    }
    for (const finding of result.findings) {
      const item = document.createElement('li');
      item.className = `finding severity-${finding.severity}`;
      const title = document.createElement('strong');
      title.textContent = `${finding.severityLabel}: ${finding.title}`;
      const message = document.createElement('p');
      message.textContent = finding.message;
      item.append(title, message);
      findingsOutput.append(item);
    }
    empty.hidden = result.findings.length !== 0;
  }

  document.getElementById('decode').addEventListener('click', render);
  document.getElementById('danger-sample').addEventListener('click', () => {
    input.value = api.dangerSample;
    render();
  });
  document.getElementById('normal-sample').addEventListener('click', () => {
    input.value = api.normalSample;
    render();
  });
  document.getElementById('clear').addEventListener('click', () => {
    input.value = '';
    clearResults();
    status.textContent = '入力と結果を消去しました。';
    status.className = 'status';
    input.focus();
  });
}());
