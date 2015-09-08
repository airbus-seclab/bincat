# -*- coding: utf-8 -*-


'''
Plugin IDA qui une fois copié dans le repertoire
plugins d'IDA est accessible depuis le menu 
Edit --> plugins 
'''

import idaapi 

class HTooltip(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        idaapi.warning("Tooltip-providing action triggered")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class Hooks(idaapi.UI_Hooks):
    def populating_tform_popup(self, form, popup):
        idaapi.attach_action_to_popup(form, popup, "my:tooltip0", "BinCAT/Config/", idaapi.SETMENU_APP)
        idaapi.attach_action_to_popup(form, popup, "my:tooltip1", "BinCAT/Analyse/Taint register", idaapi.SETMENU_APP)


class bincat_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "BinCAT is cool ! "

    help = "This is help"
    wanted_name = "BinCAT IDA Plugin"
    wanted_hotkey = "Alt-F8"

    def init(self):
        idaapi.msg("init() called!\n")
        tooltip_act0 = idaapi.action_desc_t('my:tooltip0', 'BinCAT configuration ', HTooltip(), '', 'This is a tooltip-providing action tooltip', -1)
        tooltip_act1 = idaapi.action_desc_t('my:tooltip1', 'BinCAT analyser ', HTooltip(), '', 'This is yet another a tooltip-providing action tooltip', -1)
        idaapi.register_action(tooltip_act0)
        idaapi.register_action(tooltip_act1)
        idaapi.attach_action_to_menu("View/", 'my:tooltip0', idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu("View/", 'my:tooltip1', idaapi.SETMENU_APP)
        idaapi.open_disasm_window("BinCAT Plugin-view")

        hooks = Hooks()
        hooks.hook()


        return idaapi.PLUGIN_OK

    def run(self, arg):
        idaapi.msg("run() called with %d!\n" % arg)

    def term(self):
        idaapi.msg("term() called!\n")
        #TO DO unhook actions 

def PLUGIN_ENTRY():
    return bincat_plugin_t()

