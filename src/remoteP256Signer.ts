import { Signer } from 'did-jwt'
import * as WebSocket from 'websocket-stream'
import * as http from 'http'

//import WebSocket, { createWebSocketStream, WebSocketServer } from 'ws';

/**************************websocket_example.js*************************************************/
const server = http.createServer();
const websocketServer = new WebSocket.Server({ server });

//***************this snippet gets the local ip of the node.js server. copy this ip to the client side code and add ':3000' *****

//****************exmpl. 192.168.56.1---> var sock =new WebSocket("ws://192.168.56.1:3000");*************************************
require('dns').lookup(require('os').hostname(), function (err, add, fam) {
  console.log('addr: '+add);
})

// this signer should only be used if the public key is appropriate for the device... use matchPublicKeyWithRemote from remotePublicKey.ts
export function remoteP256Signer(): Signer {
  
    return async (data: string | Uint8Array): Promise<string> => {
        return await getSignature(payload);
    }
}

// I wish I could write this function without requiring the spinning up of a websocket server...it would be better if it could take it as an argument 
async function getSignature(payload) : Base64URL {
    let data = '2'+'1200'+payload;  // this is parsed to type+signature+payload when it gets to the ESP32
    websocketServer.on('stream',function(stream,request) {
       stream.setEncoding('utf8');
       stream.write(data); // make sure they payload is sha256 hashed to make sure it isn't to much for the signer & network
return new Promise((resolve,reject) => {
      stream.once('data',(resolve) => {
          // do code to take the resolve to make it a Base64URL
           return resolve;
      });
      stream.once('error',reject); // I threw this in for errors, it may not be correct. I saw it here: https://www.derpturkey.com/event-emitter-to-promise/
    });
   });
}


/**
 * see issue: https://github.com/decentralized-identity/did-jwt/issues/229#issuecomment-1152937104
 * function P256Signer(): Signer {    // signer like ed25519, secp256k1 signer in did-jwt
      return async(payload: string | Uint8Array): Promise<string> => {
            return await getSignature(payload);
      }
}
 */