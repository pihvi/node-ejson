import {after, before, test} from 'node:test'
import assert from 'node:assert/strict'
import {decrypt, defaultConfig, encrypt, parseEncryptedValue} from '../ejson.js'
import testEjson from './test.json' with {type: 'json'}

test('default config', (t) => {
  assert.equal(defaultConfig.envFileDir, '.')
})

test('parseEncryptedValue', (t) => {
  assert.equal(testEjson.test_secret, 'EJ[1:jeDOl5qTBwflgRuusXrqoT5eclnznLKuCp8fxbuHjGg=:fRVLp8YU/m9sb04HKAN9r8RVzLNWkdTu:uhoMKBnFTUDSO5nayF/Wx/D+d8dPBIlLUJq8KA==]')
  assert.equal(parsed.schemaVersion, 1)
  assert.equal(parsed.encrypterPublic, 'jeDOl5qTBwflgRuusXrqoT5eclnznLKuCp8fxbuHjGg=')
  assert.equal(parsed.nonce, 'fRVLp8YU/m9sb04HKAN9r8RVzLNWkdTu')
  assert.equal(parsed.box, 'uhoMKBnFTUDSO5nayF/Wx/D+d8dPBIlLUJq8KA==')
})

test('encrypt', (t) => {
  const secretKey = keys[testEjson._public_key]
  const box = encrypt(testSecretValue, parsed.nonce, parsed.encrypterPublic, secretKey)
  assert.deepEqual(box, parsed.box)
})

test('decrypt', (t) => {
  const secretKey = keys[testEjson._public_key]
  const box = decrypt(parsed.box, parsed.nonce, parsed.encrypterPublic, secretKey)
  assert.deepEqual(box, testSecretValue)
})

const keys = {
  af33e849c33dd190ba01b2d50c898190f8da09082fbf1a244e4af9d62479d932:
    'ddbd617e7826292966fe1b8686b32e2214fa3e8633881ae6a31edf6175b790a2'
}
const testSecretValue = 'Hello World!'
const parsed = parseEncryptedValue(testEjson.test_secret)

let originalEnv
before(() => {
  originalEnv = {...process.env}
})
after(() => {
  process.env = originalEnv
})
