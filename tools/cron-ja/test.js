'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { parse, describe, nextRuns, formatDate, CronError } = require('./cron.js');
let passed = 0;
function test(name, run) { run(); passed++; console.log(`✓ ${name}`); }
function runs(expr, after, mode = 'utc', count = 5) { return nextRuns(parse(expr), new Date(after), mode, count).map(date => date.toISOString()); }
function zone(name, run) { const prior = process.env.TZ; process.env.TZ = name; try { run(); } finally { if (prior === undefined) delete process.env.TZ; else process.env.TZ = prior; } }

test('Issue example is natural Japanese', () => assert.equal(describe(parse('0 9 * * 1,4')), '毎週月曜・木曜の 9:00'));
test('English names are case insensitive', () => assert.deepEqual(parse('0 9 * jan-mar mon,thu').fields.slice(3).map(field => field.values), [[1, 2, 3], [1, 4]]));
test('Sunday 0 and 7 deduplicate', () => assert.deepEqual(parse('0 0 * * 0,7,SUN').fields[4].values, [0]));
test('Lists, ranges and steps combine', () => assert.deepEqual(parse('1-8/3,20,30-32 * * * *').fields[0].values, [1, 4, 7, 20, 30, 31, 32]));
test('Numeric start with step runs through field end', () => assert.deepEqual(parse('20/15 * * * *').fields[0].values, [20, 35, 50]));
test('15-minute schedule excludes reference minute', () => assert.deepEqual(runs('*/15 * * * *', '2026-10-29T09:00:00Z'), ['2026-10-29T09:15:00.000Z','2026-10-29T09:30:00.000Z','2026-10-29T09:45:00.000Z','2026-10-29T10:00:00.000Z','2026-10-29T10:15:00.000Z']));
test('Range step starts at range beginning', () => assert.deepEqual(runs('5-20/5 9 * * *', '2026-10-29T09:04:59Z'), ['2026-10-29T09:05:00.000Z','2026-10-29T09:10:00.000Z','2026-10-29T09:15:00.000Z','2026-10-29T09:20:00.000Z','2026-10-30T09:05:00.000Z']));
test('31st skips short months', () => assert.deepEqual(runs('0 0 31 * *', '2026-01-31T00:00:00Z', 'utc', 3), ['2026-03-31T00:00:00.000Z','2026-05-31T00:00:00.000Z','2026-07-31T00:00:00.000Z']));
test('Leap year and century skip', () => assert.deepEqual(runs('0 0 29 FEB *', '2096-03-01T00:00:00Z', 'utc', 1), ['2104-02-29T00:00:00.000Z']));
test('Leap schedule still provides all five dates', () => assert.deepEqual(runs('0 0 29 FEB *', '2026-01-01T00:00:00Z'), ['2028-02-29T00:00:00.000Z','2032-02-29T00:00:00.000Z','2036-02-29T00:00:00.000Z','2040-02-29T00:00:00.000Z','2044-02-29T00:00:00.000Z']));
test('Rare leap-day weekday intersection provides five candidates', () => {
  const dates = runs('0 0 29 FEB */7', '2026-01-01T00:00:00Z');
  assert.equal(dates.length, 5);
  assert(dates.every(value => { const date = new Date(value); return date.getUTCMonth() === 1 && date.getUTCDate() === 29 && date.getUTCDay() === 0; }));
});
test('Day and weekday use OR, deduplicating overlaps', () => {
  assert.match(describe(parse('0 0 1 * MON')), /または.*OR 条件/);
  assert.deepEqual(runs('0 0 1 * MON', '2026-10-31T23:59:59Z'), ['2026-11-01T00:00:00.000Z','2026-11-02T00:00:00.000Z','2026-11-09T00:00:00.000Z','2026-11-16T00:00:00.000Z','2026-11-23T00:00:00.000Z']);
});
test('Wildcard day keeps weekday restriction', () => assert.equal(runs('0 0 * * MON', '2026-11-01T00:00:00Z')[0], '2026-11-02T00:00:00.000Z'));
test('Explicit full day range is restricted for OR', () => assert.equal(runs('0 0 1-31 * MON', '2026-11-02T00:00:00Z')[0], '2026-11-03T00:00:00.000Z'));
test('Star-step day uses AND, consistent with Cronie', () => {
  assert.match(describe(parse('0 0 */2 * MON')), /かつ/);
  assert.equal(runs('0 0 */2 * MON', '2026-11-01T00:00:00Z')[0], '2026-11-09T00:00:00.000Z');
});
test('Month constraint still applies to OR days', () => assert.equal(runs('0 0 1 JAN MON', '2026-02-01T00:00:00Z')[0], '2027-01-01T00:00:00.000Z'));
for (const [macro, expression] of Object.entries({ '@hourly':'0 * * * *', '@daily':'0 0 * * *', '@weekly':'0 0 * * 0', '@monthly':'0 0 1 * *', '@yearly':'0 0 1 1 *' })) {
  test(`${macro} expands and calculates`, () => assert.deepEqual(runs(macro, '2026-10-29T09:12:00Z'), runs(expression, '2026-10-29T09:12:00Z')));
}
test('@reboot is description only', () => { assert.match(describe(parse('@reboot')), /起動時/); assert.deepEqual(nextRuns(parse('@reboot')), []); });
test('Impossible February 30 returns no dates', () => assert.deepEqual(runs('0 0 30 2 *', '2026-01-01T00:00:00Z'), []));
test('Day/weekday OR can make February 30 schedule meaningful', () => assert.equal(runs('0 0 30 FEB MON', '2026-01-01T00:00:00Z')[0], '2026-02-02T00:00:00.000Z'));
test('Step is within field, not elapsed interval', () => assert.deepEqual(runs('*/35 * * * *', '2026-10-29T09:34:00Z', 'utc', 3), ['2026-10-29T09:35:00.000Z','2026-10-29T10:00:00.000Z','2026-10-29T10:35:00.000Z']));
test('Local and UTC interpret the same expression in different zones', () => zone('Asia/Tokyo', () => {
  assert.equal(runs('0 9 * * *', '2026-10-29T00:00:00Z', 'local')[0], '2026-10-30T00:00:00.000Z');
  assert.equal(runs('0 9 * * *', '2026-10-29T00:00:00Z', 'utc')[0], '2026-10-29T09:00:00.000Z');
  assert.match(formatDate(new Date('2026-10-29T00:00:00Z'), 'local'), /09:00 UTC\+09:00/);
}));
test('DST gap skips nonexistent local time', () => zone('America/New_York', () => assert.equal(runs('30 2 * * *', '2026-03-08T05:00:00Z', 'local')[0], '2026-03-09T06:30:00.000Z')));
test('DST fold includes both instants and distinguishes offsets', () => zone('America/New_York', () => {
  assert.deepEqual(runs('30 1 * * *', '2026-11-01T04:00:00Z', 'local', 2), ['2026-11-01T05:30:00.000Z','2026-11-01T06:30:00.000Z']);
  assert.deepEqual(runs('30 1 * * *', '2026-11-01T05:45:00Z', 'local', 1), ['2026-11-01T06:30:00.000Z']);
  assert.match(formatDate(new Date('2026-11-01T05:30:00Z'), 'local'), /UTC-04:00/);
  assert.match(formatDate(new Date('2026-11-01T06:30:00Z'), 'local'), /UTC-05:00/);
}));
for (const [expr, field] of [
  ['', '式全体'], ['0 0 * *', '式全体'], ['0 0 0 * * *', '式全体'], ['@unknown', '式全体'],
  ['60 0 * * *', '分'], ['0 24 * * *', '時'], ['0 0 0 * *', '日'], ['0 0 * 13 *', '月'], ['0 0 * * 8', '曜日'],
  ['*/0 * * * *', '分'], ['*/-2 * * * *', '分'], ['*/1.5 * * * *', '分'], ['1,,2 * * * *', '分'],
  ['9-2 * * * *', '分'], ['0 0 ? * *', '日'], ['0 0 L * *', '日'], ['0 0 * JANUARY MONDAY', '月'],
  ['0/ * * * *', '分'], ['0//2 * * * *', '分'], ['<script> * * * *', '分']
]) test(`Invalid input reports field: ${expr}`, () => assert.throws(() => parse(expr), error => error instanceof CronError && error.field === field && error.message.includes(':')));
test('Long input and invalid calculation parameters fail safely', () => {
  assert.throws(() => parse('0'.repeat(201)), CronError);
  assert.throws(() => nextRuns(parse('* * * * *'), new Date('invalid')), CronError);
  assert.throws(() => nextRuns(parse('* * * * *'), new Date(), 'wrong'), CronError);
});
test('Assets and navigation resolve under the GitHub Pages project prefix', () => {
  const base = 'https://supportapp3-lab.github.io/dev-tools-jp/tools/cron-ja/';
  const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
  for (const asset of ['style.css', 'cron.js', 'app.js']) {
    assert(html.includes(`"${asset}"`));
    assert.equal(new URL(asset, base).pathname, `/dev-tools-jp/tools/cron-ja/${asset}`);
    assert(fs.existsSync(path.join(__dirname, asset)));
  }
  assert.equal(new URL('../../', base).pathname, '/dev-tools-jp/');
  const home = fs.readFileSync(path.join(__dirname, '../../index.html'), 'utf8');
  assert(home.includes('href="tools/cron-ja/"'));
  assert.equal(new URL('tools/cron-ja/', 'https://supportapp3-lab.github.io/dev-tools-jp/').pathname, '/dev-tools-jp/tools/cron-ja/');
});
console.log(`${passed} tests passed`);
