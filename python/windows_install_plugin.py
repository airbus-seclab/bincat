import shutil
import os.path
import os
import idaapi
import idc

ida = idc.AskFile(0, "*.*", "Select IDA binary")
ida_dir = os.path.dirname(ida)
plugin_dir = os.path.join(ida_dir, "plugins")

bincat_path = os.path.dirname(os.path.realpath(__file__))

if not os.path.isdir(plugin_dir) or not os.path.isdir(bincat_path):
    print "Something's wrong: %s or %s is not a dir" % (plugin_dir, bincat_path)

idabincat = os.path.join(bincat_path, "idabincat")
pybincat = os.path.join(bincat_path, "pybincat")
if os.path.isdir(idabincat) and os.path.isdir(pybincat):
    print "Copying 'idabincat' to "+plugin_dir
    shutil.copytree(idabincat, os.path.join(plugin_dir, "idabincat"))
    print "Copying 'pybincat' to "+plugin_dir
    shutil.copytree(pybincat, os.path.join(plugin_dir, "pybincat"))
    print "Copying 'bcplugin.py' to "+plugin_dir
    shutil.copy(os.path.join(idabincat, "bcplugin.py"), os.path.join(plugin_dir, "bcplugin.py"))
    print "Plugin installed"

confpath = os.getenv("IDAUSR")
if not confpath:
    confpath = os.path.join(os.getenv("APPDATA"), "Hex-Rays", "IDA Pro")
confpath = os.path.join(confpath, 'idabincat', 'conf')
print "Installing default config"
shutil.copytree(os.path.join(idabincat, "conf"), confpath)
