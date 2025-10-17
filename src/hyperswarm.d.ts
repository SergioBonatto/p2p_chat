declare module 'hyperswarm' {
  import { EventEmitter } from 'events'
  import { Socket } from 'net'

  interface PeerInfo {
    host?: string
    port?: number
  }

  interface ConnectionDetails {
    peer?: PeerInfo
    client?: boolean
  }

  interface JoinOptions {
    lookup?: boolean
    announce?: boolean
  }

  interface HyperswarmOptions {
    keyPair?: {
      publicKey: Buffer
      secretKey: Buffer
    }
    seed?: Buffer
    maxPeers?: number
    firewall?: (remotePublicKey: Buffer, payload: any) => boolean
  }

  class Hyperswarm extends EventEmitter {
    constructor(options?: HyperswarmOptions)
    join(topic: Buffer, options?: JoinOptions): void
    leave(topic: Buffer): void
    flush(): Promise<void>
    destroy(): Promise<void>
    on(event: 'connection', listener: (socket: Socket, details: ConnectionDetails) => void): this
    on(event: 'error', listener: (error: Error) => void): this
    on(event: string, listener: (...args: any[]) => void): this
  }

  export = Hyperswarm
}
