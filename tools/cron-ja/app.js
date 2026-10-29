(function () {
  'use strict';
  const byId = id => document.getElementById(id);
  const input = byId('expression'), zone = byId('zone');
  const error = byId('error'), description = byId('description'), list = byId('runs');
  function render() {
    list.replaceChildren();
    byId('expanded').textContent = '';
    byId('reference').textContent = '';
    byId('no-runs').hidden = true;
    const now = new Date();
    byId('zone-help').textContent = zone.value === 'utc'
      ? '式をUTCとして計算します。GitHub Actionsの既定はUTCです。'
      : `このブラウザのタイムゾーン: ${Intl.DateTimeFormat().resolvedOptions().timeZone}`;
    try {
      const cron = CronJa.parse(input.value);
      const dates = CronJa.nextRuns(cron, now, zone.value);
      description.textContent = CronJa.describe(cron);
      byId('expanded').textContent = cron.reboot ? '@reboot' : `5フィールド: ${cron.expression}`;
      byId('reference').textContent = `基準日時: ${CronJa.formatDate(now, zone.value)} より後`;
      for (const date of dates) {
        const item = document.createElement('li');
        const time = document.createElement('time');
        time.dateTime = date.toISOString();
        time.textContent = CronJa.formatDate(date, zone.value);
        item.append(time); list.append(item);
      }
      if (dates.length < 5) {
        byId('no-runs').textContent = cron.reboot
          ? '起動時刻はcron式だけでは決まらないため、日時を表示できません。'
          : `400年先までに見つかった候補は${dates.length}回です。日付が実在するか確認してください。`;
        byId('no-runs').hidden = false;
      }
      error.hidden = true; error.textContent = ''; input.removeAttribute('aria-invalid');
    } catch (problem) {
      description.textContent = '式を確認してください。';
      error.textContent = problem instanceof CronJa.CronError ? problem.message : '計算できませんでした。式を確認してください。';
      error.hidden = false; input.setAttribute('aria-invalid', 'true');
    }
  }
  input.addEventListener('input', render);
  zone.addEventListener('change', render);
  byId('refresh').addEventListener('click', render);
  for (const button of document.querySelectorAll('[data-cron]')) {
    button.addEventListener('click', () => { input.value = button.dataset.cron; render(); });
  }
  render();
})();
