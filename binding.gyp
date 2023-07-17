{
  'targets': [{
    'target_name': 'native',
    'include_dirs': [
      "<!(node -e \"require('napi-macros')\")"
    ],
    'sources': [
      './src/native/napi/socketUtils.cpp',
      './src/native/napi/index.cpp',
    ],
    'conditions': [
      ['OS=="linux"', {
        'cflags': [ '-std=c99', '-Wpedantic' ],
        'cflags!': [ '-fno-tree-vrp', '-fno-exceptions' ],
        'cflags_cc': [ '-std=c++17', '-Wpedantic' ],
        'cflags_cc!': [ '-fno-exceptions' ],
      }],
      ['OS=="win"', {
        'defines': [
          # See: https://github.com/nodejs/node-addon-api/issues/85#issuecomment-911450807
          '_HAS_EXCEPTIONS=0',
          'OS_WIN=1',
        ],
        'msvs_settings': {
          'VCCLCompilerTool': {
            'RuntimeTypeInfo': 'false',
            'EnableFunctionLevelLinking': 'true',
            'ExceptionHandling': '2',
            'DisableSpecificWarnings': [
              '4355',
              '4530',
              '4267',
              '4244',
              '4506',
            ],
            'AdditionalOptions': [ '/std:c++17' ]
          }
        },
      }],
      ['OS=="mac"', {
        # OSX symbols are exported by default
        # if 2 different copies of the same symbol appear in a process
        # it can cause a conflict
        # this prevents exporting the symbols
        # the `+` prepends these flags
        'cflags+': [ '-fvisibility=hidden' ],
        'cflags_cc+': [ '-fvisibility=hidden' ],
        'xcode_settings': {
          # Minimum mac osx target version (matches node v18.15.0 common.gypi)
          'MACOSX_DEPLOYMENT_TARGET': '10.15',
          # This is also needed to prevent exporting of symbols
          'GCC_SYMBOLS_PRIVATE_EXTERN': 'YES',
          'OTHER_CFLAGS': [
            '-std=c99',
            '-arch x86_64',
            '-arch arm64'
          ],
          'OTHER_CPLUSPLUSFLAGS': [
            '-std=c++17',
            '-arch x86_64',
            '-arch arm64'
          ],
          'OTHER_LDFLAGS': [
            '-arch x86_64',
            '-arch arm64'
          ]
        }
      }],
      ['target_arch == "arm"', {
        'cflags': [ '-mfloat-abi=hard' ],
        'cflags_cc': [ '-mfloat-abi=hard '],
      }],
    ]
  }]
}
