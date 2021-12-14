# -*- coding: utf-8 -*-
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
import logging
import ida_diskio
try:
    import configparser as ConfigParser
except ImportError:
    import ConfigParser

# Logging
bc_log = logging.getLogger('bincat.gui.pluginoptions')
bc_log.setLevel(logging.DEBUG)


class PluginOptions(object):
    _options = None

    @classmethod
    def init(cls):
        # Configuration files path
        idausr = ida_diskio.get_user_idadir()
        cls.config_path = os.path.join(idausr, "plugins", "idabincat")

        # Plugin options
        def_options = {
            "save_to_idb": "False",  # config only - results are always saved
            "load_from_idb": "True",
            "server_url": "http://localhost:5000",
            "web_analyzer": "False",
            "autostart": "False"}
        cls._options = ConfigParser.ConfigParser(defaults=def_options)
        cls._options.optionxform = str
        cls.configfile = os.path.join(cls.config_path, "conf", "options.ini")
        if len(cls._options.read(cls.configfile)) != 1:
            cls._options.add_section("options")

    @classmethod
    def get(cls, name):
        return cls._options.get("options", name)

    @classmethod
    def set(cls, name, value):
        cls._options.set("options", name, value)

    @classmethod
    def save(cls):
        with open(cls.configfile, 'w') as optfile:
            cls._options.write(optfile)
