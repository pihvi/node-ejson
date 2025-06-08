import processEjson from '../../ejson.js'

const ejsonContentString = `{
  "_public_key": "af33e849c33dd190ba01b2d50c898190f8da09082fbf1a244e4af9d62479d932",
  "API_KEY": "EJ[1:jeDOl5qTBwflgRuusXrqoT5eclnznLKuCp8fxbuHjGg=:fRVLp8YU/m9sb04HKAN9r8RVzLNWkdTu:uhoMKBnFTUDSO5nayF/Wx/D+d8dPBIlLUJq8KA==]",
  "DATABASE": {
    "USERNAME": "EJ[1:jeDOl5qTBwflgRuusXrqoT5eclnznLKuCp8fxbuHjGg=:fRVLp8YU/m9sb04HKAN9r8RVzLNWkdTu:yzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678901234==]",
    "PASSWORD": "EJ[1:jeDOl5qTBwflgRuusXrqoT5eclnznLKuCp8fxbuHjGg=:fRVLp8YU/m9sb04HKAN9r8RVzLNWkdTu:YZabcdefghijklmnopqrstuvwxyz012345678901234==]"
  }
}`

const privateKeyString = 'ddbd617e7826292966fe1b8686b32e2214fa3e8633881ae6a31edf6175b790a2'

async function main() {
  try {
    const config = await processEjson(ejsonContentString, {
      getPrivateKey: async (publicKey) => {
        // In a real application, you might have a map of public keys to private keys
        // or fetch from a secure store. For this example, we use the hardcoded one
        // if it matches the expected public key from the ejson content.
        if (publicKey === "af33e849c33dd190ba01b2d50c898190f8da09082fbf1a244e4af9d62479d932") {
          return privateKeyString
        }
        throw new Error("Private key not found for public key: " + publicKey)
      },
    })

    console.log('Decrypted configuration:')
    console.log('API Key:', config.API_KEY)
    console.log('Database Username:', config.DATABASE.USERNAME)
    console.log('Database Password:', config.DATABASE.PASSWORD)

    // Use the decrypted values in your application
    // For example:
    // const api = new API(config.API_KEY);
    // const db = new Database(config.DATABASE.USERNAME, config.DATABASE.PASSWORD);
  } catch (error) {
    console.error('Error processing EJSON:', error)
  }
}

main()
