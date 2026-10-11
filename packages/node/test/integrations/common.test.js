'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createWatchLookup, trapMethods } = require('../../src/integrations/_common');

test('createWatchLookup normalises once per raw route and memoises the result', () => {
    let reads = 0;
    const watch = { path: '/items/:id/', query_fields: {}, body_fields: {} };
    const ts = { get watches() { reads++; return [watch]; } };
    const lookup = createWatchLookup(ts);
    assert.equal(lookup('/items/:id'), watch);
    assert.equal(lookup('/items/:id'), watch);
    assert.equal(lookup('/nope'), null);
    assert.equal(lookup(undefined), null);
    assert.equal(reads, 1); // the watch list is read once, at construction
});

test('trapMethods upper-cases and de-duplicates', () => {
    assert.deepEqual(trapMethods({ methods: ['get', 'GET', 'post'] }), ['GET', 'POST']);
});
