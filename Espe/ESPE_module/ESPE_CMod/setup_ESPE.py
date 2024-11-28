
from distutils.core import setup, Extension

MOD = 'ESPE_mod'
setup(  name = MOD,
        version = '0.1',
        description= 'ESPE',
        author = 'ldlkancolle',
        author_email = 'ldlkancolle@outlook.com',
        ext_modules = [Extension( MOD,
                                sources = ['ESPE_RSA.c'],
                                extra_link_args = ['-lpbc','-lgmp','-lcrypto'],
                                extra_compile_args = ['--std=c99','-w']
                                )
                                ]
    )
