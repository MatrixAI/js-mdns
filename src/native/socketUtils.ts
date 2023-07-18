import path from 'path';
import nodeGypBuild from 'node-gyp-build';
import * as utils from '../utils';

interface SocketUtils {
  disableSocketMulticastAll(socketfd: number): boolean;
}

const socketUtils: SocketUtils =
  utils.getPlatform() === 'linux'
    ? nodeGypBuild(path.join(__dirname, '../../'))
    : {};

export default socketUtils;

export type { SocketUtils };
