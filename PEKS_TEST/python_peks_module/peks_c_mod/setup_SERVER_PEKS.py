from distutils.core import setup, Extension

MOD = 'TEST_PEKS'
setup(name=MOD,
      ext_modules=[Extension(MOD,
                             sources=['mod_TEST_PEKS.c',],
                             extra_link_args=['-lpbc',
                                              '-lgmp',
                                              '-lcrypto'],
                             extra_compile_args=['--std=c99',])])
