import type { MDNSServiceEvent } from '@/events';
import type { Host, Hostname, Port } from '@/types';
import { Timer } from '@matrixai/timer';
import MDNS from '@/MDNS';
import { testUtility } from './utils';

describe('Responder', () => {
  test('some arbitrary test', async () => {
    const mdnsPort = 12345 as Port;

    const mdns1 = MDNS.createMDNS({});
    const mdns2 = MDNS.createMDNS({});

    const mdns1Hostname = "polykey1.local" as Hostname;
    await mdns1.start({ hostname: mdns1Hostname, port: mdnsPort });

    const mdns2Hostname = "polykey2.local" as Hostname;
    await mdns2.start({ hostname: mdns2Hostname, port: mdnsPort });

    const name = 'test';
    const port = 1234;
    const protocol = 'udp';
    const type = 'polykey';

    mdns1.registerService({
      name,
      port,
      protocol,
      type,
    });

    mdns2.query({
      type,
      protocol
    }).next();
    mdns2.addEventListener('service', (e: MDNSServiceEvent) => {
      console.log(e.detail)
      expect(e.detail.name).toBe(name);
      expect(e.detail.port).toBe(port);
      expect(e.detail.protocol).toBe(protocol);
      expect(e.detail.type).toBe(type);
      expect(e.detail.hostname).toBe(mdns1Hostname);
      mdns1.stop();
      mdns2.stop();
    });
    // Await new Timer(() => mdns?.unregisterService(name, type, protocol), 1000)
  });
});
