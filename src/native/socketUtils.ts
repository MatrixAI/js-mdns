import path from 'path';
import nodeGypBuild from 'node-gyp-build';

interface SocketUtils {
  disableSocketMulticastAll(socketfd: number): boolean;
}

const socketUtils: SocketUtils = nodeGypBuild(path.join(__dirname, '../../'));

export default socketUtils;

export type { SocketUtils };
