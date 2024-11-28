
from distutils.core import setup, Extension

MOD = 'test_SPCHS_mod'
setup(  name = MOD,
        version = '0.1',
        description= 'SPCHS',
        author = 'ldlkancolle',
        author_email = 'ldlkancolle@outlook.com',
        ext_modules = [Extension( MOD,
                                sources = ['test_SPCHS_mod.c','avltree.c'],
                                extra_link_args = ['-lpbc','-lgmp','-lcrypto'],
                                extra_compile_args = ['--std=c99','-w']
                                )
                                ]
    )
