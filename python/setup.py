#! /usr/bin/env python
from setuptools import setup, Extension, Command


class PyTest(Command):
    description = "run py.test unit tests"
    user_options = []
    def initialize_options(self):
        pass
    def finalize_options(self):
        pass
    def run(self):
        import sys,subprocess
        errno = subprocess.call([sys.executable, 'runtests.py'])
        raise SystemExit(errno)

mlbincat = Extension(
    "pybincat/mlbincat",
    sources=["pybincat/mlbincat.c"],
    libraries=["bincat"],
    library_dirs=["../ocaml/src"],
)

package_data_files = ['idabincat/conf/*ini']

setup(
    cmdclass = {'test': PyTest},
    name             = 'BinCAT',
    version          = '0.1',
    author           = 'Sarah Zennou',
    author_email     = 'sarah.zennou@airbus.com',
    description      = 'BINnary Code Analysis Toolkit',
    scripts          = ['bin/bincat'],
    packages         = ['pybincat', 'pybincat/tools', 'idabincat', 'idabincat/hexview', 'webbincat'],
    ext_modules      = [mlbincat],
    package_data = {
        'idabincat': package_data_files
    },
    license          = 'GPLv2'
)
