'use strict';

const CJK = /[\u2e80-\u2eff\u2f00-\u2fdf\u3000-\u303f\u3040-\u30ff\u3100-\u312f\u3130-\u318f\u31a0-\u31bf\u31f0-\u31ff\u3200-\u32ff\u3300-\u33ff\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\ufe30-\ufe4f\uff00-\uffef]/u;
const GPT_ASCII_CHARS_PER_TOKEN = 4;
const CLAUDE_ASCII_CHARS_PER_TOKEN = 3.5;
const GPT_CJK_TOKENS_PER_CHARACTER = 1.0;
const CLAUDE_CJK_TOKENS_PER_CHARACTER = 1.3;

function countText(text) {
  const value = String(text);
  const points = Array.from(value);
  const nonWhitespacePoints = points.filter((point) => !/\s/u.test(point));
  const lines = value.length === 0 ? 0 : value.split(/\r\n|\r|\n/u).length;
  const words = value.trim() ? value.trim().split(/\s+/u).length : 0;
  const cjkCount = nonWhitespacePoints.filter((point) => CJK.test(point)).length;
  const otherCount = nonWhitespacePoints.length - cjkCount;

  return {
    characters: points.length,
    nonWhitespaceCharacters: nonWhitespacePoints.length,
    lines,
    utf8Bytes: new TextEncoder().encode(value).length,
    words,
    gptTokens: Math.ceil(otherCount / GPT_ASCII_CHARS_PER_TOKEN + cjkCount * GPT_CJK_TOKENS_PER_CHARACTER),
    claudeTokens: Math.ceil(otherCount / CLAUDE_ASCII_CHARS_PER_TOKEN + cjkCount * CLAUDE_CJK_TOKENS_PER_CHARACTER),
    hasCjk: cjkCount > 0,
  };
}

const exported = { countText };
if (typeof module !== 'undefined' && module.exports) module.exports = exported;
if (typeof globalThis !== 'undefined') globalThis.TokenCounter = exported;
