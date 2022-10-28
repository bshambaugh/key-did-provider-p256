import { createJWS, ES256Signer } from 'did-jwt'
// import { ecdhEsA256KwDecrypter } from 'did-jwt' // did-jwt/src/encrypters/ecdhEsA256Kw.ts
import { HandlerMethods, RPCError, RPCRequest, RPCResponse, createHandler, SendRequestFunc } from 'rpc-utils'
import type { AuthParams, CreateJWSParams, DIDMethodName, DIDProviderMethods, DIDProvider, GeneralJWS } from 'dids'
import stringify from 'fast-json-stable-stringify'
import * as u8a from 'uint8arrays'
import { ec as EC } from 'elliptic'
import { encodeDIDfromHexString } from 'did-key-creator'

//const B64 = 'base64pad'

const ec = new EC('p256')

function toStableObject(obj: Record<string, any>): Record<string, any> {
  return JSON.parse(stringify(obj)) as Record<string, any>
}

// import function encodeDIDfromBytes from key-did-creator, import as npm module ...
// https://github.com/bshambaugh/did-key-creator/blob/main/src/encodeDIDkey.ts#L14

function toGeneralJWS(jws: string): GeneralJWS {
  const [protectedHeader, payload, signature] = jws.split('.')
  return {
    payload,
    signatures: [{ protected: protectedHeader, signature }],
  }
}

interface Context {
  did: string
  privateKey: Uint8Array
}


const sign = async (
  payload: Record<string, any> | string,
  did: string,
  secretKey: Uint8Array, // need special function for remote signer, because private key is remote
  protectedHeader: Record<string, any> = {}
) => {
  const kid = `${did}#${did.split(':')[2]}`
  // need remote signer here as well: https://github.com/decentralized-identity/did-jwt/blob/cebf2e6f255e559a1275bb97b35146ce72ce27f5/docs/guides/index.md#creating-custom-signers-for-integrating-with-hsm
  //const signer = ES256Signer(u8a.toString(secretKey, B64)) // look at did-jwt tests to find what ES256Signer requires
  const signer = ES256Signer(secretKey)
  const header = toStableObject(Object.assign(protectedHeader, { kid, alg: 'ES256' }))
  return createJWS(typeof payload === 'string' ? payload : toStableObject(payload), signer, header)
}

const didMethods: HandlerMethods<Context, DIDProviderMethods> = {
  did_authenticate: async ({ did, privateKey }, params: AuthParams) => {
    const response = await sign(
      {
        did,
        aud: params.aud,
        nonce: params.nonce,
        paths: params.paths,
        exp: Math.floor(Date.now() / 1000) + 600, // expires 10 min from now
      },
      did,
      privateKey
    )
    return toGeneralJWS(response)
  },
  did_createJWS: async ({ did, privateKey }, params: CreateJWSParams & { did: string }) => {
    const requestDid = params.did.split('#')[0]
    if (requestDid !== did) throw new RPCError(4100, `Unknown DID: ${did}`)
    const jws = await sign(params.payload, did, privateKey, params.protected)
    return { jws: toGeneralJWS(jws) }
  },
  did_decryptJWE: async () => {
     // this needs to be implemented in the did-jwt library
     // const decrypter = ecdhEsA256KwDecrypter(params.jwe, decrypter)
     // instead of the 4100 Error, emulate the commented out code below...
     // this will be able to change when did-jwt supports ES256 for JWE 
     // https://github.com/decentralized-identity/did-jwt/issues/225
     throw new RPCError(4100, 'Decryption not supported')
  },
  /*
  did_decryptJWE: async ({ secretKey }, params: DecryptJWEParams) => {
    const decrypter = x25519Decrypter(convertSecretKeyToX25519(secretKey))
    try {
      const bytes = await decryptJWE(params.jwe, decrypter)
      return { cleartext: u8a.toString(bytes, B64) }
    } catch (e) {
      throw new RPCError(-32000, (e as Error).message)
    }
  },
  */
}

export class P256Provider implements DIDProvider {
  _handle: SendRequestFunc<DIDProviderMethods>

  constructor(seed: Uint8Array) {
    // just use the library elliptic to do this...
   // const kp = ec.genKeyPair();
    const kp = ec.keyFromPrivate(seed)
    // const { secretKey, publicKey } = generateKeyPairFromSeed(seed)
    const publicKey = String(kp.getPublic('hex'))
    //const publicKey = kp.getPublic()
    const secretKey = String(kp.getPrivate('hex'))
    const privateKey = u8a.fromString(secretKey,'hex')
    const did = encodeDIDfromHexString('p256-pub',publicKey) // replace with encodeDIDfromBytes from did-key-creator
    const handler = createHandler<Context, DIDProviderMethods>(didMethods)
    this._handle = async (msg) => await handler({ did, privateKey }, msg)
  }

  get isDidProvider(): boolean {
    return true
  }

  async send<Name extends DIDMethodName>(
    msg: RPCRequest<DIDProviderMethods, Name>
  ): Promise<RPCResponse<DIDProviderMethods, Name> | null> {
    return await this._handle(msg)
  }
}
