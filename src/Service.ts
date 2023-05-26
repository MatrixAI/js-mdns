import { CreateDestroy } from '@matrixai/async-init/dist/CreateDestroy';

interface Service extends CreateDestroy {}
@CreateDestroy()
class Service extends EventTarget {
  name: string;

  type: string;
  protocol: 'tcp' | 'udp';

  host: string;
  port: number;

  fdqn: string; // Fully qualified domain name

  txt: Record<string, any>;

  constructor() {
    super();
  }

  public async create(): Promise<void> {}

  // On service destroy, make sure to send a 'goodbye' packet signaling that the service is no longer available.
  public async destroy(): Promise<void> {}
}
