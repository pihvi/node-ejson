import processEjson from 'node-ejson'
import * as path from 'path'
import {fileURLToPath} from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

async function main() {
  try {
    const config = await processEjson({
      envFilePath: path.join(__dirname, '.env.ejson'),
      keysDir: path.join(__dirname, 'keys/'),
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
