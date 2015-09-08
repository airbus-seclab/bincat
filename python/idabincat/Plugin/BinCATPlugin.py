# -*- coding: utf-8 -*-


'''
Plugin IDA qui une fois copié dans le repertoire
plugins d'IDA est accessible depuis le menu 
Edit --> plugins 
'''

import idaapi 


#Configuration Handler
class HTooltipC(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        idaapi.warning("Configuration : Tooltip-providing action triggered")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


#Analyse Handler 
class HTooltipA(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        idaapi.warning("Analyse : Tooltip-providing action triggered")
        idaapi.msg(" Analyzer handler %s "%type(ctx))
        idaapi.msg(" Analyzer handler current ea %s "%hex(ctx.cur_ea))
        for fdix in ctx.chooser_selection: 
            idaapi.msg(" fdix %s "%type(fdix))
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS



class Hooks(idaapi.UI_Hooks):
    def populating_tform_popup(self, form, popup):
        idaapi.msg("Hooks called\n")
        idaapi.attach_action_to_popup(form, popup, "my:tooltip0", "BinCAT/Config/", idaapi.SETMENU_APP)
        idaapi.attach_action_to_popup(form, popup, "my:tooltip1", "BinCAT/Analyse/", idaapi.SETMENU_APP)


class bincat_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    comment = "BinCAT is cool ! "

    help = "This is help"
    wanted_name = "BinCAT IDA Plugin"
    wanted_hotkey = "Alt-F8"
    hooks = None 

    def init(self):
        idaapi.msg("init() called!\n")
        self.hooks = Hooks()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        idaapi.msg("run() called with %d!\n" % arg)
        tooltip_act0 = idaapi.action_desc_t('my:tooltip0', 'BinCAT : Configuration ', HTooltipC(), '', 'This is a tooltip-providing action tooltip', -1)
        tooltip_act1 = idaapi.action_desc_t('my:tooltip1', 'BinCAT : Taint register ', HTooltipA(), '', 'This is yet another a tooltip-providing action tooltip', -1)
        idaapi.register_action(tooltip_act0)
        idaapi.register_action(tooltip_act1)
        idaapi.attach_action_to_menu("View/", 'my:tooltip0', idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu("View/", 'my:tooltip1', idaapi.SETMENU_APP)

        idaapi.open_disasm_window("BinCAT Plugin-view")

        #hooks = Hooks()
        idaapi.msg("Calling Hooks\n")
        self.hooks.hook()

    def term(self):
        idaapi.msg("term() called!\n")
        if self.hooks is not None :
            self.hooks.unhook()
            self.hooks =  None 
    
        #TO DO unhook actions 

def PLUGIN_ENTRY():
    return bincat_plugin_t()

