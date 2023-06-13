import { MDNSServiceEvent } from '@/events';
import MDNS from '@/MDNS';
import { Host } from '@/types';
import { Timer } from '@matrixai/timer';
import { testUtility } from './utils';

describe('Responder', () => {
  let mdns: MDNS | null;

  beforeAll(() => {
    mdns = MDNS.createMDNS({});
    // A noop test utility
    // demonstrates using utils inside tests
    testUtility();
  });

  afterAll(() => {
    mdns = null;
  });

  test('some arbitrary test', async () => {
    await mdns?.start({host: "::" as Host});
    const name = "test";
    const port = 1234;
    const protocol = 'udp';
    const type = "polykey";
    mdns?.registerService({
      name,
      port,
      protocol,
      type
    })
    mdns?.addEventListener("service", (e: MDNSServiceEvent) => {
      console.log(e.detail);
    });
    mdns?.query('uscan', 'tcp');
    // await new Timer(() => mdns?.unregisterService(name, type, protocol), 1000)
  });
});
