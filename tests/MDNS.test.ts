import MDNS from '@/MDNS';
import Responder from '@/Responder';
import { Host } from '@/types';
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
    await mdns?.start({});
  });
});
