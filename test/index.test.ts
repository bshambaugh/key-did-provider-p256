// create file like https://github.com/ceramicnetwork/key-did-provider-ed25519/blob/master/test/index.test.ts

import * as u8a from 'uint8arrays'
import { verifyJWS } from 'did-jwt'
import { randomBytes } from '@stablelib/random'
import type { GeneralJWS } from 'dids'

import { P256Provider } from '../src/index'

import { compressedKeyInHexfromRaw, encodeDIDfromHexString, rawKeyInHexfromUncompressed} from 'did-key-creator'

import elliptic from 'elliptic'

const secp256r1 = new elliptic.ec('p256')


const b64urlToObj = (s: string): Record<string, any> =>
  // eslint-disable-next-line @typescript-eslint/no-unsafe-return
  JSON.parse(u8a.toString(u8a.fromString(s, 'base64url')))


describe('key-did-provider-p256', () => {
    let provider: P256Provider
    let did: string
    let key: elliptic.ec.KeyPair
  //  let compressedPublicKey: string


 beforeAll(() => {
    const seed = randomBytes(32)
    key = secp256r1.keyFromPrivate(seed)
    const publicKey = String(key.getPublic('hex'))
    console.log(publicKey)
    console.log(rawKeyInHexfromUncompressed(publicKey))
    const compressedPublicKey = compressedKeyInHexfromRaw(rawKeyInHexfromUncompressed(publicKey))
    console.log(compressedPublicKey)
    provider = new P256Provider(seed) 
    did = encodeDIDfromHexString('p256-pub',compressedPublicKey)
 })

 it('has isDidProvider property', () => {
    expect(provider.isDidProvider).toEqual(true)
 })

 it('authenticates correctly', async () => {
        const nonce = 'adfberg'
        const aud = 'https://my.app'
        const paths = ['a', 'b']
        const resp = await provider.send({
          jsonrpc: '2.0',
          id: 0,
          method: 'did_authenticate',
          params: { nonce, aud, paths },
        })
        const jws = resp?.result as GeneralJWS
        const payload = b64urlToObj(jws.payload)
        const header = b64urlToObj(jws.signatures[0].protected)
        expect(payload.aud).toEqual(aud)
        expect(payload.nonce).toEqual(nonce)
        expect(payload.paths).toEqual(paths)
        expect(payload.did).toEqual(did)
        expect(payload.exp).toBeGreaterThan(Date.now() / 1000)
        expect(header.kid).toEqual(expect.stringContaining(did))
        expect(header.alg).toEqual('ES256')
 })

 it('signs JWS properly', async () => {
        const payload = { foo: 'bar' }
        const prot = { bar: 'baz' }
        const res = await provider.send({
          jsonrpc: '2.0',
          id: 0,
          method: 'did_createJWS',
          params: { payload, protected: prot, did },
        })
        const pubkey = {
            id: '',
            type: '',
            controller: '',  // compressedPublicKey
           // publicKeyBase64: u8a.toString(u8a.fromString(compressedPublicKey,'hex'), 'base64pad'),
            publicKeyBase64: u8a.toString(u8a.fromString(key.getPublic('hex'),'hex'), 'base64pad'),
        }
       // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access,@typescript-eslint/no-unsafe-assignment
       const gjws = res?.result?.jws as GeneralJWS
       // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
       const jws = [gjws.signatures[0].protected, gjws.payload, gjws.signatures[0].signature].join('.')
       expect(verifyJWS(jws, pubkey)).toEqual(pubkey)
 })

    // this will be able to change when did-jwt supports ES256 for JWE 
     // https://github.com/decentralized-identity/did-jwt/issues/225
    /*
    it('decrypts JWE properly', async () => {

    })

    it('thows if fails to decrypt JWE', async () => {
   
    })
    */

})