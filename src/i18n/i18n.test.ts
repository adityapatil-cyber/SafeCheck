import assert from 'node:assert/strict';
import test from 'node:test';
import { DICTIONARIES } from './index.tsx';

function collectKeys(obj: unknown, prefix = ''): string[] {
  if (typeof obj === 'string') return [prefix];
  if (Array.isArray(obj)) {
    return obj.flatMap((item, idx) => collectKeys(item, `${prefix}[${idx}]`));
  }
  if (obj && typeof obj === 'object') {
    return Object.entries(obj).flatMap(([k, v]) =>
      collectKeys(v, prefix ? `${prefix}.${k}` : k),
    );
  }
  return [];
}

test('English, Hindi, and Gujarati dictionaries share identical translation key structures', () => {
  const enKeys = collectKeys(DICTIONARIES.en).sort();
  const hiKeys = collectKeys(DICTIONARIES.hi).sort();
  const guKeys = collectKeys(DICTIONARIES.gu).sort();

  assert.deepEqual(hiKeys, enKeys);
  assert.deepEqual(guKeys, enKeys);
  assert.ok(enKeys.length > 50);
});
