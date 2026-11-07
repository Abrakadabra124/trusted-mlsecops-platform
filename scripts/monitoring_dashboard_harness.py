"""Controlled JavaScript contract harness, included in the gate method digest."""

SCRIPT = r"""// Controlled DOM/fetch contract tests. Real browser rendering is checked separately.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

assert(Number(process.versions.node.split('.')[0]) >= 20, 'Node.js 20 or newer required');
const input = JSON.parse(readFileSync(0, 'utf8'));
class Element {
  constructor(tag = '') { this.tag = tag; this.children = []; this.listeners = {}; this.attrs = {}; this.value = ''; this.textContent = ''; this.disabled = false; }
  append(child) { this.children.push(child); }
  replaceChildren(...children) { this.children = children; }
  setAttribute(key, value) { this.attrs[key] = value; }
  addEventListener(event, action) { this.listeners[event] = action; }
}
const elements = new Map(input.ids.map(id => [id, new Element()]));
const el = id => { assert(elements.has(id), `unknown element ${id}`); return elements.get(id); };
const timers = new Map(), requests = [], handlers = {}, replies = [];
let nextTimer = 0;
const context = {
  document: {getElementById: el, createElement: tag => new Element(tag)},
  window: {addEventListener: (name, handler) => { handlers[name] = handler; }},
  setTimeout: (action, delay) => { timers.set(++nextTimer, {action, delay}); return nextTimer; },
  clearTimeout: id => timers.delete(id),
  TextDecoder, Uint8Array, AbortController,
  fetch: async (url, options) => {
    assert.equal(url, '/monitoring'); assert.equal(options.method, 'GET');
    assert.equal(options.credentials, 'omit'); assert.equal(options.cache, 'no-store');
    assert.equal(options.redirect, 'error'); assert.match(options.headers.Authorization, /^Bearer [a-f0-9]{64}$/);
    requests.push(options); assert(replies.length, 'unexpected request');
    return await replies.shift()(options.signal);
  },
};
// No storage, cookies, HTML parsing or external network facilities exist in this harness.
vm.runInNewContext(input.script, context, {timeout: 1000});
const idle = async () => { for (let i = 0; i < 30; i++) await Promise.resolve(); };
const response = (state = input.state, status = 200) => new Response(JSON.stringify(state), {status, headers: {'content-type': 'application/json'}});
const answer = (state = input.state, status = 200) => replies.push(() => response(state, status));
const event = (id, kind = 'click') => el(id).listeners[kind]({preventDefault() {}});
const connect = async (key = '9'.repeat(64)) => { el('credential').value = key; event('connect', 'submit'); await idle(); assert.equal(el('credential').value, ''); };
const refresh = async () => { event('refresh'); await idle(); };
const disconnected = () => { assert.equal(el('observations').textContent, '-'); assert.equal(el('disconnect').disabled, true); assert.equal(el('refresh').disabled, true); assert.equal(timers.size, 0); };
const shown = () => { assert.match(el('connection').textContent, /Подключено/); assert.equal(el('psi').children.length, 7); };
const unavailable = () => { assert.equal(el('observations').textContent, '-'); assert.equal(el('psi').children.length, 0); assert.match(el('connection').textContent, /Не удалось/); };
const clone = () => JSON.parse(JSON.stringify(input.state));
const runTimer = async delay => { const entry = [...timers].find(([, item]) => item.delay === delay); assert(entry, `missing timer ${delay}`); timers.delete(entry[0]); entry[1].action(); await idle(); };

switch (input.scenario) {
  case 'success':
    answer(); await connect(); shown();
    assert.equal(el('recall').textContent, '84.5%');
    assert.match(el('quality-message').textContent, /ухудшения/);
    assert.equal(el('receipts').children.length, 1);
    assert.equal(el('receipts').children[0].textContent, 'Ухудшение качества');
    assert.equal(el('reference').textContent, input.state.reference_sha256);
    answer(); await refresh(); shown(); assert.equal(requests.length, 2);
    event('disconnect'); disconnected();
    break;
  case 'insufficient': {
    const state = clone(); state.reports = [input.partial]; state.data_status = 'insufficient'; state.label_reports = [];
    answer(state); await connect(); shown();
    for (const row of el('psi').children) { assert.equal(row.children[1].textContent, 'Недостаточно данных'); assert.equal(row.children[2].textContent, '-'); }
    assert.equal(el('quality-status').textContent, 'Нет данных');
    break;
  }
  case 'prediction-abstentions': {
    const state = clone(); state.reports = [input.abstained];
    answer(state); await connect(); shown();
    assert.equal(el('psi').children.at(-1).children[1].textContent, 'Недостаточно данных');
    assert.equal(el('psi').children[0].children[1].textContent, '0.0000');
    break;
  }
  case 'unhealthy': {
    const state = clone(); state.healthy = false; state.faults = ['delivery'];
    answer(state, 503); await connect(); shown(); assert.match(el('faults').textContent, /Доставка/);
    assert.match(el('connection').textContent, /проблеме/);
    break;
  }
  case 'authentication':
    await connect('invalid'); assert.equal(requests.length, 0); disconnected();
    answer(); await connect(); shown();
    replies.push(() => new Response('PRIVATE-CANARY', {status: 401})); await refresh(); disconnected();
    assert.match(el('connection').textContent, /Доступ отклонён/);
    break;
  case 'rate-limit':
    answer(); await connect(); shown();
    replies.push(() => new Response('', {status: 429})); await refresh();
    assert.equal(el('observations').textContent, '-'); assert.match(el('connection').textContent, /30 секунд/);
    answer(); await runTimer(30000); shown();
    break;
  case 'bad-data': {
    const changes = [s => { s.release_ready = true; }, s => { s.reference_sha256 = '<img src=x onerror=alert(1)>'; }, s => { s.observations = -1; }, s => { s.healthy = false; }, s => { s.reports[0].psi.prediction = null; }, s => { s.reports[0].psi.prediction = '0'; }, s => { s.reports[0].reference_sha256 = '0'.repeat(64); }, s => { s.label_reports[0].true_positives = 201; }, s => { s.receipts[0].received_at_ms = 8640000000000001; }, s => { s.faults = ['PRIVATE-CANARY']; }];
    for (const change of changes) { answer(); await connect(); shown(); const state = clone(); change(state); answer(state); await refresh(); unavailable(); }
    break;
  }
  case 'body-errors': {
    const variants = [() => new Response('PRIVATE-CANARY'), () => new Response('{', {headers: {'content-type': 'application/json'}}), () => new Response('x'.repeat(262145), {headers: {'content-type': 'application/json'}}), () => new Response(new Uint8Array([0xff]), {headers: {'content-type': 'application/json'}}), () => new Response('', {status: 500}), () => { throw Error('PRIVATE-CANARY'); }];
    for (const variant of variants) { answer(); await connect(); shown(); replies.push(variant); await refresh(); unavailable(); }
    break;
  }
  case 'timeout':
  case 'body-timeout':
    replies.push(signal => {
      const stalled = new Promise((resolve, reject) => signal.addEventListener('abort', () => reject(Error('aborted'))));
      return input.scenario === 'timeout' ? stalled : {status: 200, headers: new Headers({'content-type':'application/json'}), body: {getReader: () => ({read: () => stalled})}};
    });
    await connect(); await runTimer(5000); unavailable(); assert(requests[0].signal.aborted);
    answer(); await runTimer(10000); shown();
    break;
  case 'late-response': {
    let finish;
    replies.push(() => new Promise(resolve => { finish = resolve; })); await connect();
    await refresh(); assert.equal(requests.length, 1);
    event('disconnect'); disconnected(); assert(requests[0].signal.aborted);
    answer(); await connect(); shown();
    const old = clone(); old.observations = 99999; finish(response(old)); await idle();
    shown(); assert.notEqual(el('observations').textContent, '99 999');
    handlers.pagehide(); disconnected();
    break;
  }
  default: throw Error('unknown scenario');
}
for (const element of elements.values()) assert(!element.textContent.includes('PRIVATE-CANARY'));
event('disconnect'); disconnected();
process.stdout.write(JSON.stringify({scenario: input.scenario, status: 'pass', requests: requests.length}));
"""
