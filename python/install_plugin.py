import shutil
from io import StringIO
import os
import os.path
import sys
import idaapi

try:
    import requests
    print("'requests' is installed, good.")
except ImportError:
    if idaapi.ask_yn(idaapi.ASKBTN_NO,
             "'requests' is not installed, do you want to install it ?\n"
             "Choose 'no' if you do not intend to use "
             "a distant BinCAT server") == idaapi.ASKBTN_YES:
        print("requests is not installed, trying to install")
        import pip
        # Fugly hack (cause IDA console is not a real one)
        saved_stdout = sys.stdout
        saved_stderr = sys.stderr
        sys.stdout = StringIO()
        sys.stderr = StringIO()
        pip.main(['install', "requests"])
        sys.stdout.seek(0)
        sys.stderr.seek(0)
        saved_stdout.write(sys.stdout.read())
        saved_stderr.write(sys.stderr.read())
        sys.stdout = saved_stdout
        sys.stderr = saved_stderr

plugin_dir = os.path.join(idaapi.get_user_idadir(), "plugins")
if not os.path.isdir(plugin_dir):
    print("Creating plugin dir")
    os.makedirs(plugin_dir)

bincat_path = os.path.dirname(os.path.realpath(__file__))

src_idabincat = os.path.join(bincat_path, "python", "idabincat")
src_pybincat = os.path.join(bincat_path, "python", "pybincat")

if os.path.isdir(src_idabincat) and os.path.isdir(src_pybincat):
    try:
        print("Copying 'idabincat' to "+plugin_dir)
        shutil.copytree(src_idabincat, os.path.join(plugin_dir, "idabincat"))
        bin_path = os.path.join(plugin_dir, "idabincat", "bin")
        print("Copying 'bin' to "+bin_path)
        shutil.copytree(os.path.join(bincat_path, 'bin'), bin_path)
        print("Copying 'pybincat' to "+plugin_dir)
        shutil.copytree(src_pybincat, os.path.join(plugin_dir, "pybincat"))
        print("Copying 'bcplugin.py' to "+plugin_dir)
        shutil.copy(os.path.join(src_idabincat, "bcplugin.py"),
                    os.path.join(plugin_dir, "bcplugin.py"))
    except OSError as e:
        print("Could not install! Error: "+str(e)+"\n")
else:
    print("ERROR: %s or %s are not existing directories" % (src_idabincat, src_pybincat))


print("Plugin installed, please restart IDA to use BinCAT")
