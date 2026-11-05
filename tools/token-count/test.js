'use strict';

const assert = require('node:assert/strict');
const { countText } = require('./counter.js');

assert.deepEqual(countText(''), {
  characters: 0, nonWhitespaceCharacters: 0, lines: 0, utf8Bytes: 0,
  words: 0, gptTokens: 0, claudeTokens: 0, hasCjk: false,
});
assert.equal(countText('A い\n🙂').characters, 5);
assert.equal(countText('A い\n🙂').nonWhitespaceCharacters, 3);
assert.equal(countText('A い\n🙂').lines, 2);
assert.equal(countText('A い\n🙂').utf8Bytes, Buffer.byteLength('A い\n🙂', 'utf8'));
assert.equal(countText('one two\nthree').words, 3);
assert.equal(countText('日本語だけ').hasCjk, true);
assert.equal(countText('ordinary English').hasCjk, false);
assert.ok(countText('日本語と English').claudeTokens >= countText('日本語と English').gptTokens);

const large = 'x🙂'.repeat(524288);
const largeResult = countText(large);
assert.equal(largeResult.characters, 1048576);
assert.equal(largeResult.lines, 1);
assert.ok(largeResult.utf8Bytes > 1048576);

console.log('token-count tests passed');
