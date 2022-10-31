import { RPCRequest, RPCResponse, SendRequestFunc } from 'rpc-utils';
import type { DIDMethodName, DIDProviderMethods, DIDProvider } from 'dids';
export declare class P256Provider implements DIDProvider {
    _handle: SendRequestFunc<DIDProviderMethods>;
    constructor(secretKey: Uint8Array);
    get isDidProvider(): boolean;
    send<Name extends DIDMethodName>(msg: RPCRequest<DIDProviderMethods, Name>): Promise<RPCResponse<DIDProviderMethods, Name> | null>;
}
//# sourceMappingURL=index.d.ts.map