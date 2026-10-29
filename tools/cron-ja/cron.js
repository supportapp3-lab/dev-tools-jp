(function (root) {
  'use strict';
  const MONTHS = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'];
  const DAYS = ['SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'];
  const JA_DAYS = ['日曜', '月曜', '火曜', '水曜', '木曜', '金曜', '土曜'];
  const SPECS = [
    { label: '分', min: 0, max: 59 }, { label: '時', min: 0, max: 23 },
    { label: '日', min: 1, max: 31 }, { label: '月', min: 1, max: 12, names: MONTHS },
    { label: '曜日', min: 0, max: 7, names: DAYS }
  ];
  const MACROS = { '@hourly': '0 * * * *', '@daily': '0 0 * * *', '@weekly': '0 0 * * 0', '@monthly': '0 0 1 * *', '@yearly': '0 0 1 1 *' };

  class CronError extends Error {
    constructor(field, reason) { super(`${field}: ${reason}`); this.name = 'CronError'; this.field = field; }
  }

  function parseField(raw, spec) {
    const fail = reason => { throw new CronError(spec.label, reason); };
    const number = token => {
      let value;
      if (/^\d+$/.test(token)) value = Number(token);
      else if (spec.names && spec.names.includes(token)) value = spec.names.indexOf(token) + spec.min;
      else fail('数値、または対応する3文字の英略称を指定してください。');
      if (!Number.isSafeInteger(value) || value < spec.min || value > spec.max) fail(`${spec.min}〜${spec.max}の範囲で指定してください。`);
      return value;
    };
    const selected = new Set();
    for (const item of raw.split(',')) {
      if (!item) fail('カンマの前後に値が必要です。');
      const parts = item.split('/');
      if (parts.length > 2) fail('ステップの「/」は各項目に1個までです。');
      const step = parts.length === 2 ? Number(parts[1]) : 1;
      if (parts.length === 2 && (!/^\d+$/.test(parts[1]) || !Number.isSafeInteger(step) || step < 1)) fail('ステップは1以上の整数にしてください。');
      const base = parts[0];
      let first, last;
      if (base === '*') { first = spec.min; last = spec.max; }
      else {
        const range = base.split('-');
        if (range.length > 2 || range.some(value => !value)) fail('範囲は開始値-終了値で指定してください。');
        first = number(range[0]);
        last = range.length === 2 ? number(range[1]) : parts.length === 2 ? spec.max : first;
        if (first > last) fail('範囲の開始値は終了値以下にしてください（逆順・週またぎの範囲は非対応）。');
      }
      for (let value = first; value <= last; value += step) selected.add(spec.label === '曜日' && value === 7 ? 0 : value);
    }
    return { raw, values: [...selected].sort((a, b) => a - b), star: raw.startsWith('*') };
  }

  function parse(expression) {
    if (typeof expression !== 'string' || !expression.trim()) throw new CronError('式全体', 'cron式を入力してください。');
    if (expression.length > 200) throw new CronError('式全体', '200文字以内で入力してください。');
    const input = expression.trim().toUpperCase();
    if (input === '@REBOOT') return { reboot: true, expression: '@reboot', fields: [] };
    const expanded = MACROS[input.toLowerCase()] || input;
    if (expanded.startsWith('@')) throw new CronError('式全体', '対応する省略形は @hourly / @daily / @weekly / @monthly / @yearly / @reboot です。');
    const parts = expanded.split(/\s+/);
    if (parts.length !== 5) throw new CronError('式全体', '分・時・日・月・曜日の5フィールドが必要です。秒や年、実行コマンドを含めないでください。');
    return { reboot: false, expression: expanded, fields: parts.map((raw, index) => parseField(raw, SPECS[index])) };
  }

  function orDays(cron) { return !cron.fields[2].star && !cron.fields[4].star; }
  function dayMatches(cron, year, month, day) {
    const fields = cron.fields;
    const dom = fields[2].values.includes(day);
    const dow = fields[4].values.includes(new Date(Date.UTC(year, month - 1, day)).getUTCDay());
    return fields[3].values.includes(month) && (orDays(cron) ? dom || dow : dom && dow);
  }

  function describe(cron) {
    if (cron.reboot) return 'システムの起動時（@reboot は説明のみ）';
    const [minute, hour, day, month, weekday] = cron.fields;
    const join = field => field.values.join('・');
    const dayText = `${join(day)}日`;
    const weekText = weekday.values.map(value => JA_DAYS[value]).join('・');
    let calendar;
    if (orDays(cron)) calendar = `日付が${dayText}、または曜日が${weekText}の日`;
    else if (day.raw === '*' && weekday.raw === '*') calendar = '毎日';
    else if (day.raw === '*') calendar = `毎週${weekText}`;
    else if (weekday.raw === '*') calendar = `毎月${dayText}`;
    else calendar = `日付が${dayText}、かつ曜日が${weekText}の日`;
    let time;
    if (minute.values.length === 1 && hour.values.length === 1) time = `${hour.values[0]}:${String(minute.values[0]).padStart(2, '0')}`;
    else if (minute.raw === '*' && hour.raw === '*') time = '毎分';
    else if (hour.raw === '*') time = `毎時${join(minute)}分`;
    else if (minute.raw === '*') time = `${join(hour)}時台は毎分`;
    else time = `${join(hour)}時の${join(minute)}分`;
    const prefix = month.raw === '*' ? '' : `対象月は${join(month)}月。`;
    return `${prefix}${calendar}の ${time}${orDays(cron) ? '（日と曜日は OR 条件）' : ''}`;
  }

  function nextRuns(cron, after = new Date(), mode = 'local', count = 5) {
    if (!(after instanceof Date) || !Number.isFinite(after.getTime())) throw new CronError('基準日時', '有効な日時が必要です。');
    if (!['local', 'utc'].includes(mode)) throw new CronError('時刻', 'local または utc を指定してください。');
    if (!Number.isInteger(count) || count < 1 || count > 100) throw new CronError('件数', '1〜100回で指定してください。');
    if (cron.reboot) return [];
    const utc = mode === 'utc';
    const year = utc ? after.getUTCFullYear() : after.getFullYear();
    const month = utc ? after.getUTCMonth() : after.getMonth();
    const day = utc ? after.getUTCDate() : after.getDate();
    const startCalendar = Date.UTC(year, month, day);
    const firstMinute = Math.floor(after.getTime() / 60000) * 60000 + 60000;
    const results = [];
    // Calendar-day pruning bounds impossible schedules without scanning millions of minutes.
    // Scan actual instants inside a matching day so DST gaps/folds remain correct.
    for (let offset = 0; offset <= 146097 && results.length < count; offset++) {
      const calendar = new Date(startCalendar + offset * 86400000);
      const y = calendar.getUTCFullYear(), m = calendar.getUTCMonth(), d = calendar.getUTCDate();
      if (!dayMatches(cron, y, m + 1, d)) continue;
      const start = utc ? Date.UTC(y, m, d) : new Date(y, m, d).getTime();
      const end = utc ? start + 86400000 : new Date(y, m, d + 1).getTime();
      for (let stamp = Math.max(start, firstMinute); stamp < end && results.length < count; stamp += 60000) {
        const date = new Date(stamp);
        const h = utc ? date.getUTCHours() : date.getHours();
        const min = utc ? date.getUTCMinutes() : date.getMinutes();
        if (cron.fields[1].values.includes(h) && cron.fields[0].values.includes(min)) results.push(date);
      }
    }
    return results;
  }

  function formatDate(date, mode) {
    const utc = mode === 'utc';
    const get = name => date[`${utc ? 'getUTC' : 'get'}${name}`]();
    const pad = value => String(value).padStart(2, '0');
    const offset = utc ? 0 : -date.getTimezoneOffset();
    const zone = `UTC${offset >= 0 ? '+' : '-'}${pad(Math.floor(Math.abs(offset) / 60))}:${pad(Math.abs(offset) % 60)}`;
    return `${get('FullYear')}/${pad(get('Month') + 1)}/${pad(get('Date'))}（${JA_DAYS[get('Day')]}）${pad(get('Hours'))}:${pad(get('Minutes'))} ${zone}`;
  }

  const api = { parse, describe, nextRuns, formatDate, CronError, orDays };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.CronJa = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
