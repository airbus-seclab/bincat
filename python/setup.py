#! /usr/bin/env python
"""
    This file is part of BinCAT.
    Copyright 2014-2017 - Airbus Group

    BinCAT is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or (at your
    option) any later version.

    BinCAT is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with BinCAT.  If not, see <http://www.gnu.org/licenses/>.
"""
import os
import sys
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

if os.name == "nt" or sys.platform == 'cygwin':
    mlbincat = None
else:
    mlbincat = Extension(
        "pybincat/mlbincat",
        sources=["pybincat/mlbincat.c"],
        libraries=["bincat"],
        library_dirs=["../ocaml/src"],
        extra_compile_args=['-Wno-discarded-qualifiers'],
    )

package_data_files = ['idabincat/conf/*ini']

setup(
    cmdclass = {'test': PyTest},
    name             = 'BinCAT',
    version          = '0.1',
    author           = 'Sarah Zennou',
    author_email     = 'sarah.zennou@airbus.com',
    description      = 'Binary Code Analysis Toolkit',
    scripts          = ['bin/bincat.py'],
    packages         = ['pybincat', 'pybincat/tools', 'idabincat', 'idabincat/hexview', 'webbincat'],
    ext_modules      = [mlbincat] if mlbincat is not None else [],
    package_data = {
        'idabincat': package_data_files
    },
    license          = 'AGPLv3'
)
