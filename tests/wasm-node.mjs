import assert from 'node:assert/strict';
import test from 'node:test';

import {
  ParamsType,
  initialState,
  keygen,
  keypairLen,
  publicKeyFromKeypair,
  publicKeyLen,
  secretKeyFromKeypair,
  secretKeyLen,
  signStateful,
  signStateless,
  signStatelessPrepare,
  signStatelessWithPrepare,
  signatureFromStatefulSignResult,
  stateCounter,
  statefulSignatureMaxLen,
  stateFromStatefulSignResult,
  stateLen,
  statelessSignatureLen,
  preparedStatelessKeyLen,
  verify,
  verifyStateful,
} from '../pkg/shrincs.js';

test('SHRINCS-B stateless sign/verify works through wasm', () => {
  const params = ParamsType.B;
  const message = new TextEncoder().encode('hello from wasm-bindgen');

  const keypair = keygen(params);
  assert.equal(keypair.length, keypairLen());

  const publicKey = publicKeyFromKeypair(keypair);
  const secretKey = secretKeyFromKeypair(keypair);
  assert.equal(publicKey.length, publicKeyLen());
  assert.equal(secretKey.length, secretKeyLen());

  const signature = signStateless(params, message, secretKey);
  assert.equal(signature.length, statelessSignatureLen(params));
  assert.equal(verify(params, message, signature, publicKey), true);

  const tamperedMessage = new TextEncoder().encode('hello from wasm-bindgen!');
  assert.equal(verify(params, tamperedMessage, signature, publicKey), false);
});

test('SHRINCS-B prepared stateless signing works through wasm', () => {
  const params = ParamsType.B;
  const message = new TextEncoder().encode('prepared stateless signing from wasm-bindgen');
  const keypair = keygen(params);
  const publicKey = publicKeyFromKeypair(keypair);
  const secretKey = secretKeyFromKeypair(keypair);

  const preparedKey = signStatelessPrepare(params, secretKey);
  assert.equal(preparedKey.length, preparedStatelessKeyLen(params));

  const signature = signStateless(params, message, secretKey);
  const preparedSignature = signStatelessWithPrepare(params, message, secretKey, preparedKey);
  assert.deepEqual(preparedSignature, signature);
  assert.equal(verify(params, message, preparedSignature, publicKey), true);

  const malformedPreparedKey = new Uint8Array(preparedKey);
  malformedPreparedKey[0] ^= 1;
  assert.throws(() =>
    signStatelessWithPrepare(params, message, secretKey, malformedPreparedKey),
  );
});

test('SHRINCS-B stateful sign/verify works through wasm', () => {
  const params = ParamsType.B;
  const message = new TextEncoder().encode('stateful hello from wasm-bindgen');

  const keypair = keygen(params);
  const publicKey = publicKeyFromKeypair(keypair);
  const secretKey = secretKeyFromKeypair(keypair);
  const state = initialState();

  assert.equal(state.length, stateLen());
  assert.equal(stateCounter(state), 0);

  const result = signStateful(params, message, secretKey, state);
  const nextState = stateFromStatefulSignResult(result);
  const signature = signatureFromStatefulSignResult(result);

  assert.equal(nextState.length, stateLen());
  assert.equal(stateCounter(nextState), 1);
  assert.ok(signature.length <= statefulSignatureMaxLen(params));
  assert.equal(verifyStateful(params, message, signature, publicKey), true);
  assert.equal(verify(params, message, signature, publicKey), true);

  const tamperedSignature = new Uint8Array(signature);
  tamperedSignature[tamperedSignature.length - 1] ^= 1;
  assert.equal(verifyStateful(params, message, tamperedSignature, publicKey), false);
});
