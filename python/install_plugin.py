import shutil
import distutils.dir_util as dir_util
import StringIO
import os
import os.path
import sys
import idaapi

try:
    import requests
    print "'requests' is installed, good."
except ImportError:
    if idaapi.ask_yn(idaapi.ASKBTN_NO,
                     "'requests' is not installed, do you want to install it ?\n"
                     "Choose 'no' if you do not intend to use a distant BinCAT server") == idaapi.ASKBTN_YES:
        print "requests is not installed, trying to install"
        import pip
        # Fugly hack (cause IDA console is not a real one)
        saved_stdout = sys.stdout
        saved_stderr = sys.stderr
        sys.stdout = StringIO.StringIO()
        sys.stderr = StringIO.StringIO()
        pip.main(['install', "requests"])
        sys.stdout.seek(0)
        sys.stderr.seek(0)
        saved_stdout.write(sys.stdout.read())
        saved_stderr.write(sys.stderr.read())
        sys.stdout = saved_stdout
        sys.stderr = saved_stderr

userdir = idaapi.get_user_idadir()
plugin_dir = os.path.join(userdir, "plugins")

bincat_path = os.path.dirname(os.path.realpath(__file__))

if not os.path.isdir(plugin_dir) or not os.path.isdir(bincat_path):
    print "Something's wrong: %s or %s is not a dir" % (plugin_dir, bincat_path)

p_idabincat = os.path.join(bincat_path, "python", "idabincat")
p_pybincat = os.path.join(bincat_path, "python", "pybincat")
if os.path.isdir(p_idabincat) and os.path.isdir(p_pybincat):
    try:
        print "Copying 'idabincat' to "+plugin_dir
        dir_util.copy_tree(p_idabincat, os.path.join(plugin_dir, "idabincat"))
        bin_path = os.path.join(plugin_dir, "idabincat", "bin")
        print "Copying 'bin' to "+bin_path
        dir_util.copy_tree(os.path.join(bincat_path, 'bin'), bin_path)
        print "Copying 'pybincat' to "+plugin_dir
        dir_util.copy_tree(p_pybincat, os.path.join(plugin_dir, "pybincat"))
        print "Copying 'bcplugin.py' to "+plugin_dir
        shutil.copy(os.path.join(p_idabincat, "bcplugin.py"),
                    os.path.join(plugin_dir, "bcplugin.py"))
        print "Plugin installed"
    except OSError as e:
        print "Could not install! Error: "+str(e)+"\n"


confpath = os.path.join(userdir, 'idabincat', 'conf')
print "Installing default config in "+confpath
try:
    dir_util.copy_tree(os.path.join(p_idabincat, "conf"), confpath)
except OSError as e:
    print "Could not install! Error: "+str(e)+"\n"

libpath = os.path.join(userdir, 'idabincat', 'lib')
print "Installing default headers in "+libpath
try:
    dir_util.copy_tree(os.path.join(p_idabincat, "lib"), libpath)
except OSError as e:
    print "Could not install! Error: "+str(e)+"\n"
