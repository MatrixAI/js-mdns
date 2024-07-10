# js-mdns

Multicast DNS Stack for TypeScript/JavaScript Applications.

## Installation

```sh
npm install --save @matrixai/mdns
```

## Development

Run `nix develop`, and once you're inside, you can use:

```sh
# install (or reinstall packages from package.json)
npm install
# build the dist
npm run build
# run the repl (this allows you to import from ./src)
npm run ts-node
# run the tests
npm run test
# lint the source code
npm run lint
# automatically fix the source
npm run lintfix
```

### Docs Generation

```sh
npm run docs
```

See the docs at: https://matrixai.github.io/js-mdns/

### Publishing

```sh
# npm login
npm version patch # major/minor/patch
npm run build
npm publish --access public
git push
git push --tags
```

## License

js-mdns is licensed under Apache-2.0, you may read the terms of the license [here](LICENSE).
