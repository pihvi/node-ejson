import nacl from './lib/nacl-fast.js'
import * as fs from 'node:fs/promises'

export const parseEncryptedValue = (value) => {
  const ejsonRegex = /^EJ\[(\d):([A-Za-z0-9+=/]{44}):([A-Za-z0-9+=/]{32}):(.+)]$/
  const parts = value.match(ejsonRegex)
  if (!parts || parts.length !== 5) {
    throw new Error('Invalid EJSON: ' + value)
  } else {
    return {
      schemaVersion: parseInt(parts[1]),
      encrypterPublic: parts[2],
      nonce: parts[3],
      box: parts[4]
    }
  }
}

export const encrypt = (message, nonce, theirPublicKey, mySecretKey) => {
  const msgBuff = Buffer.from(message, 'utf8')
  const nonceBuff = Buffer.from(nonce, 'base64')
  const theirPubBuff = Buffer.from(theirPublicKey, 'base64')
  const privBuff = Buffer.from(mySecretKey, 'hex')
  const data = nacl.box(msgBuff, nonceBuff, theirPubBuff, privBuff)
  return Buffer.from(data).toString('base64')
}

export const decrypt = (message, nonce, theirPublicKey, mySecretKey) => {
  const msgBuff = Buffer.from(message, 'base64')
  const nonceBuff = Buffer.from(nonce, 'base64')
  const theirPubBuff = Buffer.from(theirPublicKey, 'base64')
  const privBuff = Buffer.from(mySecretKey, 'hex')
  const data = nacl.box.open(msgBuff, nonceBuff, theirPubBuff, privBuff)
  return Buffer.from(data).toString('utf8')
}

export const defaultConfig = {
  envFilePath: process.env.NODE_EJSON_FILE_PATH ?? undefined,
  envFileDir: '.',
  envFilePrefix: process.env.NODE_ENV ?? 'env',
  envFileSuffix: '.ejson',
  keysDir: '/opt/ejson/keys/',
  getPrivateKey: async (publicKey, conf) => {
    if (process.env.NODE_EJSON_PRIVATE_KEY) {
      return process.env.NODE_EJSON_PRIVATE_KEY
    } else {
      return await fs.readFile(conf.keysDir + publicKey, 'utf8')
    }
  }
}

const mergeConfigs = (config) => ({...defaultConfig, ...config})

const processObjectFields = (rawConf, privateKey) => {
  const configJson = structuredClone(rawConf)
  for (const key in configJson) {
    if (key.startsWith('_')) {
      const keyName = key.slice(1)
      if (!configJson[keyName]) {
        configJson[keyName] = configJson[key]
      }
    } else if (typeof configJson[key] === 'string' && configJson[key].startsWith('EJ[')) {
      const parsed = parseEncryptedValue(configJson[key])
      configJson[key] = decrypt(parsed.box, parsed.nonce, parsed.encrypterPublic, privateKey)
    } else if (typeof configJson[key] === 'object') {
      configJson[key] = processObjectFields(configJson[key], privateKey)
    }
  }
  return configJson
}

const getConfigJson = async (config) => {
  if (config.configJson) {
    return config.configJson
  } else {
    const filePath = config.envFilePath ?? `${config.envFileDir}/${config.envFilePrefix}${config.envFileSuffix}`
    const envFile = await fs.readFile(filePath, 'utf8')
    return JSON.parse(envFile)
  }
}

export const processEjson = async (config) => {
  const conf = mergeConfigs(config)
  const rawConf = await getConfigJson(conf)
  const privateKey = await conf.getPrivateKey(rawConf['_public_key'], conf)
  return processObjectFields(rawConf, privateKey)
}

export default processEjson
