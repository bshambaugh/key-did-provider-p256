# p256 key did provider
This is a DID Provider which implements [EIP2844](https://eips.ethereum.org/EIPS/eip-2844) for `did:key:` using P256.

## Installation

```
npm install --save key-did-provider-p256
```

## Usage

```js
import { P256Provider } from 'key-did-provider-p256'
import KeyResolver from 'key-did-resolver'
import { DID } from 'dids'
import { fromString} from 'uint8arrays'

const privateKey = '040f1dbf0a2ca86875447a7c010b0fc6d39d76859c458fbe8f2bf775a40ad74a'
const provider = new P256Provider(fromString(privateKey,'hex'))
const did = new DID({ provider, resolver: KeyResolver.getResolver() })
await did.authenticate()

// log the DID
console.log(did.id)

// create JWS
const { jws, linkedBlock } = await did.createDagJWS({ hello: 'world' })

// verify JWS
await did.verifyJWS(jws)

// JWE is not yet implemented, so it is commented out.
// create JWE
//const jwe = await did.createDagJWE({ very: 'secret' }, [did.id])

// decrypt JWE
//const decrypted = await did.decryptDagJWE(jwe)
```

## License

Apache-2.0 OR MIT
