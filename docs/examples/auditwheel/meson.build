project('greet', 'c', version: '1.0')

py = import('python').find_installation(pure: false)
py.extension_module('_greet', 'src/greet/_greet.c', install: true, subdir: 'greet', link_args: ['-l:libuuid.so.1'])
py.install_sources('src/greet/__init__.py', 'src/greet/cli.py', subdir: 'greet')
