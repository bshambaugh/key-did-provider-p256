import { createJWS, decryptJWE, ES256Signer } from 'did-jwt'
import { HandlerMethods, RequestHandler, RPCConnection, RPCError, RPCRequest, RPCResponse, createHandler, SendRequestFunc } from 'rpc-utils'
import type { AuthParams, CreateJWSParams, DecryptJWEParams, DIDMethodName, DIDProviderMethods, DIDProvider, GeneralJWS } from 'dids'
import stringify from 'fast-json-stable-stringify'
import * as u8a from 'uint8arrays'
import { ec as EC } from 'elliptic'

const B64 = 'base64pad'

const ec = new EC('p256')

function toStableObject(obj: Record<string, any>): Record<string, any> {
  return JSON.parse(stringify(obj)) as Record<string, any>
}

// encodeDID from bytes from key-did-creator

function toGeneralJWS(jws: string): GeneralJWS {
  const [protectedHeader, payload, signature] = jws.split('.')
  return {
    payload,
    signatures: [{ protected: protectedHeader, signature }],
  }
}

interface Context {
  did: string
  secretKey: Uint8Array
}


const sign = async (
  payload: Record<string, any> | string,
  did: string,
  secretKey: Uint8Array, // need special function for remote signer, because private key is remote
  protectedHeader: Record<string, any> = {}
) => {
  const kid = `${did}#${did.split(':')[2]}`
  // need remote signer here as well: https://github.com/decentralized-identity/did-jwt/blob/cebf2e6f255e559a1275bb97b35146ce72ce27f5/docs/guides/index.md#creating-custom-signers-for-integrating-with-hsm
  const signer = ES256Signer(u8a.toString(secretKey, B64)) // look at did-jwt tests to find what ES256Signer requires
  const header = toStableObject(Object.assign(protectedHeader, { kid, alg: 'EdDSA' }))
  return createJWS(typeof payload === 'string' ? payload : toStableObject(payload), signer, header)
}

const didMethods: HandlerMethods<Context, DIDProviderMethods> = {
  did_authenticate: async ({ did, secretKey }, params: AuthParams) => {
    const response = await sign(
      {
        did,
        aud: params.aud,
        nonce: params.nonce,
        paths: params.paths,
        exp: Math.floor(Date.now() / 1000) + 600, // expires 10 min from now
      },
      did,
      secretKey
    )
    return toGeneralJWS(response)
  },
  did_createJWS: async ({ did, secretKey }, params: CreateJWSParams & { did: string }) => {
    const requestDid = params.did.split('#')[0]
    if (requestDid !== did) throw new RPCError(4100, `Unknown DID: ${did}`)
    const jws = await sign(params.payload, did, secretKey, params.protected)
    return { jws: toGeneralJWS(jws) }
  },
  did_decryptJWE: async ({ secretKey }, params: DecryptJWEParams) => {
      // this needs to be implemented in the did-jwt library
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
    const kp = ec.genKeyPair();
    // const { secretKey, publicKey } = generateKeyPairFromSeed(seed)
    const publicKey = String(kp.getPublic('hex'))
    const secretKey = String(kp.getPrivate('hex'))
    const did = encodeDID(publicKey)
    const handler = createHandler<Context, DIDProviderMethods>(didMethods)
    this._handle = async (msg) => await handler({ did, secretKey }, msg)
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
