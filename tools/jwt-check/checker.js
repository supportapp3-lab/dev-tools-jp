(function (root) {
  'use strict';

  const MAX_LENGTH = 100000;
  const DAY_SECONDS = 24 * 60 * 60;
  const THIRTY_DAYS = 30 * DAY_SECONDS;
  const risks = {
    high: '高',
    medium: '中',
    low: '低',
    info: '情報'
  };
  const dummySignature = 'ZHVtbXktc2lnbmF0dXJl';

  function sampleToken(header, payload) {
    const encode = (value) => {
      const bytes = new TextEncoder().encode(JSON.stringify(value));
      let binary = '';
      bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
      return btoa(binary).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    };
    return `${encode(header)}.${encode(payload)}.${dummySignature}`;
  }

  function makeNormalSample(now = Date.now()) {
    const iat = Math.floor(now / 1000);
    return sampleToken({ alg: 'RS256', typ: 'JWT' }, { sub: 'demo-user', iat, exp: iat + 3600 });
  }

  function makeDangerSample(now = Date.now()) {
    const nowSeconds = Math.floor(now / 1000);
    return sampleToken(
      { alg: 'NoNe', kid: 'demo-key' },
      { sub: 'demo', password: 'DUMMY_ONLY', exp: nowSeconds - 600, nbf: nowSeconds + DAY_SECONDS }
    );
  }

  const phonePattern = /^(?:\+81(?:[-\s]?\d{1,4})|0\d{1,4})(?:[-\s]?\d{1,4}){1,2}$/;

  function decodeBase64Url(segment) {
    if (!segment || !/^[A-Za-z0-9_-]+$/.test(segment)) {
      throw new Error('JWTのBase64URL部分に使えない文字があります。');
    }
    const base64 = segment.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - segment.length % 4) % 4);
    let bytes;
    if (typeof Buffer !== 'undefined' && typeof Buffer.from === 'function') {
      bytes = Uint8Array.from(Buffer.from(base64, 'base64'));
    } else {
      const binary = atob(base64);
      bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    }
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  }

  function decodeObject(segment, label) {
    let value;
    try {
      value = JSON.parse(decodeBase64Url(segment));
    } catch (_) {
      throw new Error(`${label}をBase64URL/JSONとして読み取れません。JWTの形式を確認してください。`);
    }
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new Error(`${label}はJSONオブジェクトである必要があります。`);
    }
    return value;
  }

  function normalizeInput(value) {
    if (typeof value !== 'string') throw new Error('JWTを文字列で入力してください。');
    if (value.length > MAX_LENGTH) throw new Error('入力が長すぎます。');
    let token = value.trim();
    token = token.replace(/^Bearer\s+/i, '').trim();
    if (!token) throw new Error('JWTを入力してください。');
    if (/\s/.test(token)) throw new Error('JWTの途中に空白や改行があります。');
    return token;
  }

  function formatJst(seconds) {
    const date = new Date(seconds * 1000);
    if (!Number.isFinite(date.getTime())) return '日時を表示できません';
    const parts = new Intl.DateTimeFormat('ja-JP', {
      timeZone: 'Asia/Tokyo',
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hourCycle: 'h23'
    }).formatToParts(date);
    const part = (type) => parts.find((item) => item.type === type)?.value || '';
    return `${part('year')}-${part('month')}-${part('day')} ${part('hour')}:${part('minute')}:${part('second')} JST`;
  }

  function relativeTime(seconds, nowSeconds) {
    const delta = Math.abs(seconds - nowSeconds);
    const minutes = Math.max(1, Math.round(delta / 60));
    if (minutes < 60) return `${minutes}分`;
    const hours = Math.round(minutes / 60);
    if (hours < 48) return `${hours}時間`;
    return `${Math.round(hours / 24)}日`;
  }

  function dateEntries(payload, nowSeconds) {
    const entries = [];
    for (const [claim, label] of [['iat', '発行'], ['nbf', '有効開始'], ['exp', '期限']]) {
      const value = payload[claim];
      if (value === undefined) continue;
      if (typeof value !== 'number' || !Number.isFinite(value)) {
        entries.push({ claim, label, valid: false, text: `${label}: 数値の日時ではありません` });
        continue;
      }
      let text = `${label}: ${formatJst(value)}`;
      if (claim === 'exp') {
        text += value <= nowSeconds
          ? `（${relativeTime(value, nowSeconds)}前に期限切れ）`
          : `（あと${relativeTime(value, nowSeconds)}）`;
      } else if (claim === 'nbf' && value > nowSeconds) {
        text += `（あと${relativeTime(value, nowSeconds)}から有効）`;
      }
      entries.push({ claim, label, valid: true, value, text });
    }
    return entries;
  }

  function walkPayload(value, visit, path = []) {
    if (Array.isArray(value)) {
      value.forEach((item, index) => walkPayload(item, visit, path.concat(String(index))));
      return;
    }
    if (!value || typeof value !== 'object') return;
    for (const [key, child] of Object.entries(value)) {
      const next = path.concat(key);
      visit(key, child, next);
      walkPayload(child, visit, next);
    }
  }

  function findingsFor(header, payload, nowSeconds) {
    const findings = [];
    const add = (severity, title, message) => findings.push({ severity, severityLabel: risks[severity], title, message });
    const alg = typeof header.alg === 'string' ? header.alg : '';
    if (alg.toLowerCase() === 'none') {
      add('high', 'alg: none', '署名なしを示すアルゴリズムです。署名を要求するシステムでは受け入れないでください。');
    }
    if (header.kid !== undefined) {
      add('low', 'kid ヘッダー', '鍵を識別する値です。信頼できる鍵管理元と照合してください。');
    }
    if (header.jku !== undefined || header.x5u !== undefined) {
      add('medium', '外部鍵参照ヘッダー', 'jku/x5u のURLを自動取得しません。外部URLを鍵として信頼する前に、送信元と取得先を検証してください。');
    }
    if (/^HS(256|384|512)$/i.test(alg)) {
      add('low', '共有鍵アルゴリズム', 'HS系は共有鍵を使います。短い鍵や推測しやすい鍵は総当たりされるおそれがあります。');
    }

    const dates = dateEntries(payload, nowSeconds);
    const exp = dates.find((entry) => entry.claim === 'exp' && entry.valid);
    const iat = dates.find((entry) => entry.claim === 'iat' && entry.valid);
    if (payload.exp === undefined) {
      add('medium', 'exp がありません', 'このトークンには有効期限のclaimがありません。受け入れる側の失効・有効期間ポリシーを確認してください。');
    } else if (exp && exp.value <= nowSeconds) {
      add('low', '期限切れ', 'exp の日時を過ぎています（情報）。');
    }
    if (exp && iat && exp.value - iat.value > THIRTY_DAYS) {
      add('medium', '有効期間が長い可能性', 'iatからexpまでが30日を超えています。用途に合った短い有効期間を検討してください。');
    }
    const nbf = dates.find((entry) => entry.claim === 'nbf' && entry.valid);
    if (nbf && nbf.value > nowSeconds) {
      add('info', 'まだ有効ではありません', 'nbf の日時より前です。');
    }

    let sensitiveKey = false;
    let personalValue = false;
    walkPayload(payload, (key, value) => {
      if (/password|passwd|secret|api[_-]?key|token|credit(?:[_-]?card)?/i.test(key)) sensitiveKey = true;
      if (typeof value === 'string' && (/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i.test(value) || phonePattern.test(value.trim()))) personalValue = true;
    });
    if (sensitiveKey || personalValue) {
      add('medium', '機微情報らしき内容', `ペイロードに${[sensitiveKey && '機微情報らしいキー', personalValue && 'メールアドレス・電話番号らしい値'].filter(Boolean).join('と')}があります。JWTは暗号化ではなく、内容は誰でもデコードできます。`);
    }
    return { findings, dates };
  }

  function analyze(value, now = Date.now()) {
    try {
      const token = normalizeInput(value);
      const parts = token.split('.');
      if (parts.length === 5) throw new Error('JWE（5パートの暗号化トークン）はこのツールでは読めません。');
      if (parts.length !== 3) throw new Error('JWTはヘッダー・ペイロード・署名の3パートである必要があります。');
      const header = decodeObject(parts[0], 'ヘッダー');
      const payload = decodeObject(parts[1], 'ペイロード');
      const nowSeconds = Math.floor(now / 1000);
      const analysis = findingsFor(header, payload, nowSeconds);
      return {
        ok: true,
        header,
        payload,
        signatureLength: parts[2].length,
        dates: analysis.dates,
        findings: analysis.findings
      };
    } catch (error) {
      return { ok: false, error: error instanceof Error ? error.message : 'JWTを読み取れませんでした。' };
    }
  }

  const api = { MAX_LENGTH, analyze, makeDangerSample, makeNormalSample, formatJst, normalizeInput, relativeTime };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root) root.JwtCheck = api;
}(typeof window !== 'undefined' ? window : globalThis));
