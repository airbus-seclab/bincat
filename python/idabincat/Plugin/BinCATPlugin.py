# -*- coding: utf-8 -*-


'''
Plugin IDA qui une fois copié dans le repertoire
plugins d'IDA est accessible depuis le menu 
Edit --> plugins 
'''

import idaapi 



class bincat_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "BinCAT is cool ! "

    help = "This is help"
    wanted_name = "BinCAT IDA Plugin"
    wanted_hotkey = "Alt-F8"

    def init(self):
        idaapi.msg("init() called!\n")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        idaapi.msg("run() called with %d!\n" % arg)

    def term(self):
        idaapi.msg("term() called!\n")

def PLUGIN_ENTRY():
    return bincat_plugin_t()

