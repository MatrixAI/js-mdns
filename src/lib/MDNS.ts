import { CreateDestroyStartStop } from "@matrixai/async-init/dist/CreateDestroyStartStop"

interface MDNS extends CreateDestroyStartStop {}
@CreateDestroyStartStop()
class MDNS extends EventTarget {
  public async create(): Promise<void> {

  }

  // Starts the MDNS responder. This will work differently on different platforms. For platforms that already have a system-wide MDNS responder, this will do nothing. Else, sockets will be bound to interfaces for interacting with the multicast group address.
  public async start(): Promise<void> {

  }

  // Unregister all services, hosts, and sockets. For platforms with a built-in mDNS responder, this will not actually stop the responder.
  public async stop(): Promise<void> {

  }

  public async destroy(): Promise<void> {

  }

  // The most important method, this is used to register a service. All platforms support service registration of some kind. Note that some platforms may resolve service name conflicts automatically. This will have to be dealt with later. The service handle has a method that is able to then later unregister the service.
  registerService: (options: { name: string, type: string, protocol: 'udp' | 'tcp', port: number, txt?: Record<string, string> }) => Promise<void>

  unregisterService: (name: string, type: string, protocol: 'udp' | 'tcp') => Promise<void>

  // Query for all services of a type and protocol, the results will be emitted to eventtarget of the instance of this class.
  queryServices: (type: string, protocol: 'udp' | 'tcp') => Promise<void>
}
