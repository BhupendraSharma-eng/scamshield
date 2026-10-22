const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const store = { verdictCache: {
  old: { verdict: { verdict: 'SCAM' }, expiresAt: Date.now() + 60000 },
  v2: { version: 'url-v2', verdict: { verdict: 'SCAM' }, expiresAt: Date.now() + 60000 },
} };
const event = { addListener() {} };
const context = {
  importScripts() {}, ScamShieldHelpers: {}, console, URL, Date, Map,
  chrome: {
    runtime: { onInstalled: event, onMessage: event },
    webNavigation: { onBeforeNavigate: event }, tabs: { onRemoved: event },
    storage: { onChanged: event, session: {
      async get() { return store; }, async set(values) { Object.assign(store, values); },
    } },
  },
};
vm.createContext(context);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../background.js'), 'utf8'), context);
(async () => {
  assert.equal(await context.getCachedVerdict('old'), null);
  assert.equal(await context.getCachedVerdict('v2'), null);
  await context.putCachedVerdict('portal', { verdict: 'SAFE' });
  assert.equal((await context.getCachedVerdict('portal')).verdict, 'SAFE');
  console.log('verdict cache: legacy rejected, previous policy rejected, current verdict reused');
})().catch(error => { console.error(error); process.exitCode = 1; });
