import { createJWS } from 'did-jwt'
import type {
  AuthParams,
  CreateJWSParams,
  DIDMethodName,
  DIDProviderMethods,
  DIDProvider,
  GeneralJWS,
} from 'dids'
import stringify from 'fast-json-stable-stringify'
import { RPCError, createHandler } from 'rpc-utils'
import type { HandlerMethods, RPCRequest, RPCResponse, SendRequestFunc } from 'rpc-utils'
import { remoteP256Signer } from './remoteP256Signer' 
import { encodeDIDfromHexString, compressedKeyInHexfromRaw } from 'did-key-creator'

// see https://github.com/decentralized-identity/did-jwt/issues/226 ,https://github.com/decentralized-identity/did-jwt/issues/229

function toStableObject(obj: Record<string, any>): Record<string, any> {
  return JSON.parse(stringify(obj)) as Record<string, any>
}

function toGeneralJWS(jws: string): GeneralJWS {
  const [protectedHeader, payload, signature] = jws.split('.')
  return {
    payload,
    signatures: [{ protected: protectedHeader, signature }],
  }
}

interface Context {
  did: string
}

const sign = async (
  payload: Record<string, any> | string,
  did: string,
  protectedHeader: Record<string, any> = {}
) => {
  const kid = `${did}#${did.split(':')[2]}`
  const signer = remoteP256Signer() // see remoteP256Signer.ts
  const header = toStableObject(Object.assign(protectedHeader, { kid, alg: 'ES256' }))  /// see https://datatracker.ietf.org/doc/html/rfc7518
  return createJWS(typeof payload === 'string' ? payload : toStableObject(payload), signer, header)
}

const didMethods: HandlerMethods<Context, DIDProviderMethods> = {
  did_authenticate: async ({ did }, params: AuthParams) => {
    const response = await sign(
      {
        did,
        aud: params.aud,
        nonce: params.nonce,
        paths: params.paths,
        exp: Math.floor(Date.now() / 1000) + 600, // expires 10 min from now
      },
      did
    )
    return toGeneralJWS(response)
  },
  did_createJWS: async ({ did}, params: CreateJWSParams & { did: string }) => {
    const requestDid = params.did.split('#')[0]
    if (requestDid !== did) throw new RPCError(4100, `Unknown DID: ${did}`)
    const jws = await sign(params.payload, did,  params.protected)
    return { jws: toGeneralJWS(jws) }
  },
  did_decryptJWE: async () => {
    throw new RPCError(4100, 'Decryption not supported')
  },
}

//export class P256Provider 
export class P256Provider implements DIDProvider {
  _handle: SendRequestFunc<DIDProviderMethods>

  constructor() {
    const multicodecName = 'p256-pub';
    // this raw public key may be stored somewhere, but initially it needs to be pulled over the wire from the cryptochip ... see remotePublicKey.ts
    const rawPublicKey = 'f9c36f8964623378bdc068d4bce07ed17c8fa486f9ac0c2613ca3c8c306d7bb61cd36717b8ac5e4fea8ad23dc8d0783c2318ee4ad7a80db6e0026ad0b072a24f';
    const compressedKey = compressedKeyInHexfromRaw(rawPublicKey);
    const did = encodeDIDfromHexString(multicodecName ,compressedKey);
    const handler = createHandler<Context, DIDProviderMethods>(didMethods)
    this._handle = async (msg) => await handler({ did }, msg)
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
