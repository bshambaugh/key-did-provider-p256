/** this will either look for a public key on the cryptographic co-processor or in the ceramic network. In the case of the latter, did:key will need to be mapped to 
 *  public key and public key will need to be mapped to did:key. It is possible to verify a signature with the original message and the public key. The private key
 *  will always remain on the cryptographic co-processor. It should be possible to take an arbitary did:key and see if its public key corresponds to the private
 *  key of a cryptographic co-processor attached to an edge device.
 */
 import * as WebSocket from 'websocket-stream'
 import * as http from 'http'
 import { didKeyURLtoPubKeyHex } from 'did-key-creator'
 //import { publicKeyIntToUint8ArrayPointPair } from 'key-did-resolver/lib/nist_weierstrass_common' 
 import * as keydidresolver from '/home/ubuntu/Downloads/nov22nd/js-ceramic/packages/key-did-resolver/lib/index' 
 // now that you have an octet point from publicKeyIntToUint8ArrayPointPair, convert x and y to hex then concatenate
 import { fromString } from 'uint8arrays/from-string'
 import { toString } from 'uint8arrays/to-string'
 
 /**
  * x,y point as a BigInt (requires at least ES2020)
  * For BigInt see: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt
  */
 interface BigIntPoint {
    x: BigInt,
    y : BigInt
 }


/**
  * Elliptic curve point with coordinates expressed as byte arrays (Uint8Array)
  */
 interface octetPoint {
    xOctet: Uint8Array,
    yOctet: Uint8Array
  }
 
 //import WebSocket, { createWebSocketStream, WebSocketServer } from 'ws';
 
 /**************************websocket_example.js*************************************************/
 const server = http.createServer();
 const websocketServer = new WebSocket.Server({ server });
 
 
 //***************this snippet gets the local ip of the node.js server. copy this ip to the client side code and add ':3000' *****
 
 //****************exmpl. 192.168.56.1---> var sock =new WebSocket("ws://192.168.56.1:3000");*************************************
 require('dns').lookup(require('os').hostname(), function (err, add, fam) {
   console.log('addr: '+add);

// I wish I could write this function without requiring the spinning up of a websocket server...it would be better if it could take it as an argument
 async function getPublicKey() : string {
    /// look at the RPC call to get the public key
    let rpcPayload = '2'+'1200';
    websocketServer.on('stream',function(stream,request) {
        stream.setEncoding('utf8');
        stream.write(rpcPayload); 
        return new Promise((resolve,reject) => {
            stream.once('data',(resolve) => {
                 return resolve;  /// this is the public key that is returned from the function as a hex string
            });
            stream.once('error',reject); 
        });
    });
 }

 // add function that converts a did:key to a public key
 async function matchDIDKeyWithRemote(didkeyURL: string) : string {
     const compressedPublicKey = didKeyURLtoPubKeyHex(didkeyURL);
     const publicKey = keydidresolver.nist_weierstrass_common.publicKeyIntToUint8ArrayPointPair(keydidresolver.secp256r1.ECPointDecompress(fromString(compressedPublicKey,'base16'))); // actually I need to create a function called compressed to raw
     // const publicKey = octetToRaw(publicKeyIntToUint8ArrayPointPair(ECPointDecompress(fromString(compressedPublicKey,'base16'))));
     //const publicKey = // compressedToRaw(compressedPublicKey) function that converts a compressed key to a raw key
     return await matchPublicKeyWithRemote(publicKey)
 }

 // function that matches a local public key in hex with a remote public key in hex
 // I wish I could write this function without requiring the spinning up of a websocket server...it would be better if it could take it as an argument 
async function matchPublicKeyWithRemote(publicKey: string) : boolean {
  // public key should be the raw public key
  let rpcPayload = '0'+'1200'+publicKey;
  websocketServer.on('stream',function(stream,request) {
    stream.setEncoding('utf8');
    stream.write(rpcPayload); 
    return new Promise((resolve,reject) => {
        stream.once('data',(resolve) => {
             if (resolve) === 1) {
                 return true;
             } else {
                 return false;
             }
             /// this is the public key that is returned from the function as a hex string
        });
        stream.once('error',reject); 
    });
});
}

