import * as dgram from 'dgram';
import * as utils from '@/utils';
import * as native from '@/native';

describe('native', () => {
  test('', async () => {
    const socket = dgram.createSocket({
      type: 'udp4',
    });
    const fd = native.socketUtils.bindDgramFd(socket, {
      address: '224.0.0.251',
      port: "5353",
    });
    expect(fd).toBeGreaterThan(0);
    await new Promise<void>((resolve) => {
      socket.bind(
        {
          fd,
        },
        () => resolve(),
      );
    });
    socket.addListener('message', (msg) => {
      msgP.resolveP(msg.toString());
    });
  });
});
