{
  'targets': [{
    'target_name': 'native',
    'include_dirs': [
      "<!(node -e \"require('napi-macros')\")"
    ],
    'sources': [],
    'conditions': [
      ['OS=="linux"', {
        'sources': [
          './src/native/napi/socketUtils.cpp',
          './src/native/napi/index.cpp',
        ],
        'cflags': [ '-std=c99', '-Wpedantic' ],
        'cflags!': [ '-fno-tree-vrp', '-fno-exceptions' ],
        'cflags_cc': [ '-std=c++17', '-Wpedantic' ],
        'cflags_cc!': [ '-fno-exceptions' ],
      }],
    ]
  }]
}
