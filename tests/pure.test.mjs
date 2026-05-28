// Headless unit tests for the PURE logic in index.html.
//
// Design goal: NO copy-paste drift. We load the *actual* <script> block out of
// index.html into a sandboxed VM context with minimal browser stubs, then test
// the functions the app exposes on window._pure. If index.html changes, these
// tests run against the new code automatically.
//
// Run:  node --test tests/
//
// Coverage (pure logic only, per project spec):
//   - pkceVerifier / pkceChallenge        (PKCE verifier + S256 challenge)
//   - shouldTriggerSegment                (gap timing)
//   - mixQueue                            (heard/new ratio interleave)
//   - parseSuggestionsJson                (Claude JSON parser)
//   - trackInfo + dedupe semantics        (heard/new dedupe filter building block)
//   - clampInt, formatTime                (helpers)
//
// Browser-only functions (parseRssHeadlines needs DOMParser) are verified
// MANUALLY in the browser — see the P5 verification steps. We do NOT fake them here.

import { test } from 'node:test';
// NOTE: loose assert (not assert/strict). The pure functions run inside a VM
// realm, so objects they return have a different Object.prototype than this
// module's realm. deepStrictEqual would reject them on prototype identity even
// when the data is identical; loose deepEqual compares structure/values only.
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

// ---- Load the real pure functions from index.html ----
const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
const m = html.match(/<script>([\s\S]*?)<\/script>\s*<\/body>/);
if (!m) throw new Error('Could not locate the inline <script> block in index.html');
const scriptSrc = m[1];

// Minimal browser stubs so the module-level code runs without a DOM.
const noop = () => {};
const stubStorage = () => ({ getItem: () => null, setItem: noop, removeItem: noop, clear: noop, key: () => null, length: 0 });
const sandbox = {
  window: {},
  document: { addEventListener: noop, getElementById: () => null },
  localStorage: stubStorage(),
  sessionStorage: stubStorage(),
  location: { hostname: '127.0.0.1', href: 'http://127.0.0.1:5173/', origin: 'http://127.0.0.1:5173' },
  crypto: globalThis.crypto,          // Node 20+ webcrypto (getRandomValues + subtle)
  btoa: (s) => Buffer.from(s, 'binary').toString('base64'),
  atob: (s) => Buffer.from(s, 'base64').toString('binary'),
  TextEncoder,
  console,
  setInterval: () => 0,
  clearInterval: noop,
  setTimeout: () => 0,
  clearTimeout: noop,
  fetch: () => Promise.reject(new Error('network disabled in unit tests')),
};
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(scriptSrc, sandbox, { filename: 'index.html#script' });

const P = sandbox.window._pure;
assert.ok(P, 'window._pure should be exposed by index.html');

// ===========================================================================
// pkceVerifier
// ===========================================================================
test('pkceVerifier: length + charset (RFC 7636)', () => {
  const v = P.pkceVerifier(64);
  assert.equal(v.length, 64);
  assert.match(v, /^[A-Za-z0-9._~-]+$/, 'only unreserved characters');
});

test('pkceVerifier: rejects out-of-range lengths', () => {
  // Match on message, not constructor — the VM realm's RangeError !== host's.
  assert.throws(() => P.pkceVerifier(42), /length must be 43-128/);
  assert.throws(() => P.pkceVerifier(129), /length must be 43-128/);
  assert.doesNotThrow(() => P.pkceVerifier(43));
  assert.doesNotThrow(() => P.pkceVerifier(128));
});

test('pkceVerifier: high entropy (no repeats across calls)', () => {
  const a = P.pkceVerifier(64);
  const b = P.pkceVerifier(64);
  assert.notEqual(a, b);
});

// ===========================================================================
// pkceChallenge — base64url(SHA-256(verifier)), known test vector from RFC 7636
// ===========================================================================
test('pkceChallenge: matches RFC 7636 appendix B vector', async () => {
  const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
  const expected = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
  const challenge = await P.pkceChallenge(verifier);
  assert.equal(challenge, expected);
});

test('pkceChallenge: no base64 padding or url-unsafe chars', async () => {
  const c = await P.pkceChallenge(P.pkceVerifier(64));
  assert.doesNotMatch(c, /[+/=]/, 'must be base64url with padding stripped');
});

// ===========================================================================
// shouldTriggerSegment
// ===========================================================================
test('shouldTriggerSegment: fires within lead window', () => {
  assert.equal(P.shouldTriggerSegment(100000, 105000, 5000), true);   // 5s left
  assert.equal(P.shouldTriggerSegment(101000, 105000, 5000), true);   // 4s left
});

test('shouldTriggerSegment: does not fire when far from end', () => {
  assert.equal(P.shouldTriggerSegment(50000, 105000, 5000), false);
});

test('shouldTriggerSegment: refuses short tracks (< 2x lead)', () => {
  assert.equal(P.shouldTriggerSegment(3000, 4000, 5000), false);   // 4s track
  assert.equal(P.shouldTriggerSegment(9000, 9999, 5000), false);   // < 10s track
});

test('shouldTriggerSegment: guards invalid input', () => {
  assert.equal(P.shouldTriggerSegment(NaN, 200000, 5000), false);
  assert.equal(P.shouldTriggerSegment(100000, 0, 5000), false);
  assert.equal(P.shouldTriggerSegment(-1, 200000, 5000), false);
  assert.equal(P.shouldTriggerSegment(100000, NaN, 5000), false);
});

// ===========================================================================
// mixQueue — ratio correctness + tagging
// ===========================================================================
const mkPool = (prefix, n) =>
  Array.from({ length: n }, (_, i) => ({ uri: `spotify:track:${prefix}${i}`, name: `${prefix}${i}`, artist: 'X' }));

test('mixQueue: 0% new = all heard', () => {
  const q = P.mixQueue(mkPool('h', 10), mkPool('n', 10), 0, 10);
  assert.equal(q.length, 10);
  assert.ok(q.every(t => t.kind === 'heard'));
});

test('mixQueue: 100% new = all new', () => {
  const q = P.mixQueue(mkPool('h', 10), mkPool('n', 10), 100, 10);
  assert.equal(q.length, 10);
  assert.ok(q.every(t => t.kind === 'new'));
});

test('mixQueue: ~30% new over 10 slots = 3 new', () => {
  const q = P.mixQueue(mkPool('h', 50), mkPool('n', 50), 30, 10);
  const newCount = q.filter(t => t.kind === 'new').length;
  assert.equal(newCount, 3, `expected 3 new in 10, got ${newCount}`);
});

test('mixQueue: ~50% new over 10 slots = 5 new', () => {
  const q = P.mixQueue(mkPool('h', 50), mkPool('n', 50), 50, 10);
  const newCount = q.filter(t => t.kind === 'new').length;
  assert.equal(newCount, 5);
});

test('mixQueue: new tracks are spread out, not clustered at one end', () => {
  const q = P.mixQueue(mkPool('h', 50), mkPool('n', 50), 30, 20);
  const newIdx = q.map((t, i) => (t.kind === 'new' ? i : -1)).filter(i => i >= 0);
  // With even distribution the new tracks should not all sit in the first or last third.
  const first = newIdx.filter(i => i < q.length / 3).length;
  const last  = newIdx.filter(i => i >= (2 * q.length) / 3).length;
  assert.ok(first > 0 && last > 0, `new tracks clustered: idx=${JSON.stringify(newIdx)}`);
});

test('mixQueue: falls back when one pool is exhausted', () => {
  // 80% new but only 2 new available — should fill remainder from heard.
  const q = P.mixQueue(mkPool('h', 10), mkPool('n', 2), 80, 10);
  assert.equal(q.filter(t => t.kind === 'new').length, 2);
  assert.equal(q.length, 10);
});

test('mixQueue: respects maxLength', () => {
  const q = P.mixQueue(mkPool('h', 100), mkPool('n', 100), 50, 7);
  assert.equal(q.length, 7);
});

test('mixQueue: preserves track fields and adds kind', () => {
  const q = P.mixQueue([{ uri: 'spotify:track:h0', name: 'Halo', artist: 'Beyonce' }], [], 0, 1);
  assert.deepEqual(q[0], { uri: 'spotify:track:h0', name: 'Halo', artist: 'Beyonce', kind: 'heard' });
});

// ===========================================================================
// parseSuggestionsJson — the Claude JSON parser
// ===========================================================================
test('parseSuggestionsJson: plain JSON array', () => {
  const out = P.parseSuggestionsJson('[{"title":"A","artist":"B"},{"title":"C","artist":"D"}]');
  assert.deepEqual(out, [{ title: 'A', artist: 'B' }, { title: 'C', artist: 'D' }]);
});

test('parseSuggestionsJson: strips ```json fences', () => {
  const out = P.parseSuggestionsJson('```json\n[{"title":"A","artist":"B"}]\n```');
  assert.deepEqual(out, [{ title: 'A', artist: 'B' }]);
});

test('parseSuggestionsJson: strips bare ``` fences', () => {
  const out = P.parseSuggestionsJson('```\n[{"title":"A","artist":"B"}]\n```');
  assert.deepEqual(out, [{ title: 'A', artist: 'B' }]);
});

test('parseSuggestionsJson: tolerates prose around the array', () => {
  const out = P.parseSuggestionsJson('Here are some picks:\n[{"title":"A","artist":"B"}]\nEnjoy!');
  assert.deepEqual(out, [{ title: 'A', artist: 'B' }]);
});

test('parseSuggestionsJson: trims whitespace in fields', () => {
  const out = P.parseSuggestionsJson('[{"title":"  A  ","artist":" B "}]');
  assert.deepEqual(out, [{ title: 'A', artist: 'B' }]);
});

test('parseSuggestionsJson: drops malformed entries', () => {
  const out = P.parseSuggestionsJson('[{"title":"A","artist":"B"},{"title":"X"},{"artist":"Y"},42,null]');
  assert.deepEqual(out, [{ title: 'A', artist: 'B' }]);
});

test('parseSuggestionsJson: throws when no array present', () => {
  assert.throws(() => P.parseSuggestionsJson('I cannot help with that.'));
  assert.throws(() => P.parseSuggestionsJson(''));
  assert.throws(() => P.parseSuggestionsJson(42));
});

// ===========================================================================
// trackInfo + dedupe semantics (the building block of the heard/new filter)
// ===========================================================================
test('trackInfo: projects a Spotify track to {uri,name,artist}', () => {
  const t = { uri: 'spotify:track:abc', name: 'Song', artists: [{ name: 'A1' }, { name: 'A2' }] };
  assert.deepEqual(P.trackInfo(t), { uri: 'spotify:track:abc', name: 'Song', artist: 'A1, A2' });
});

test('trackInfo: rejects non-track URIs and missing data', () => {
  assert.equal(P.trackInfo(null), null);
  assert.equal(P.trackInfo({}), null);
  assert.equal(P.trackInfo({ uri: 'spotify:episode:xyz', name: 'Pod' }), null); // not a track
  assert.equal(P.trackInfo({ uri: 'spotify:track:x' }).name, '(untitled)');
});

test('dedupe filter: a "new" URI present in heard set is excluded', () => {
  // Mirrors buildNewPool's filter: keep only suggestions whose URI is not in heard.
  const heard = new Set(['spotify:track:h0', 'spotify:track:h1']);
  const candidates = ['spotify:track:h1', 'spotify:track:n0', 'spotify:track:n1'];
  const kept = candidates.filter(uri => !heard.has(uri));
  assert.deepEqual(kept, ['spotify:track:n0', 'spotify:track:n1']);
});

// ===========================================================================
// helpers
// ===========================================================================
test('clampInt', () => {
  assert.equal(P.clampInt('50', 0, 100), 50);
  assert.equal(P.clampInt('-5', 0, 100), 0);
  assert.equal(P.clampInt('150', 0, 100), 100);
  assert.equal(P.clampInt('abc', 0, 100), 0);
});

test('formatTime', () => {
  assert.equal(P.formatTime(0), '0:00');
  assert.equal(P.formatTime(65000), '1:05');
  assert.equal(P.formatTime(605000), '10:05');
  assert.equal(P.formatTime(-1), '0:00');
  assert.equal(P.formatTime(NaN), '0:00');
});
