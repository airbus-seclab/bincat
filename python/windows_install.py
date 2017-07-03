import shutil
import os.path
import StringIO
import os
import idaapi
import idc

try:
	import requests
	print "'requests' is installed, good."
except ImportError:
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

idabincat = os.path.join(bincat_path, "python", "idabincat")
pybincat = os.path.join(bincat_path, "python", "pybincat")
# XXX handle updates
if os.path.isdir(idabincat) and os.path.isdir(pybincat):
	try:
		print "Copying 'idabincat' to "+plugin_dir
		shutil.copytree(idabincat, os.path.join(plugin_dir, "idabincat"))
                bin_path = os.path.join(plugin_dir, "idabincat", "bin")
		print "Copying 'bin' to "+bin_path
		shutil.copytree(os.path.join(bincat_path,'bin'), bin_path)
		print "Copying 'pybincat' to "+plugin_dir
		shutil.copytree(pybincat, os.path.join(plugin_dir, "pybincat"))
		print "Copying 'bcplugin.py' to "+plugin_dir
		shutil.copy(os.path.join(idabincat, "bcplugin.py"), os.path.join(plugin_dir, "bcplugin.py"))
		print "Plugin installed"
	except OSError as e:
		print "Could not install ! Error: "+str(e)+"\n"


confpath = os.path.join(userdir, 'idabincat', 'conf')
print "Installing default config in "+confpath
try:
	shutil.copytree(os.path.join(idabincat, "conf"), confpath)
except OSError as e:
	print "Could not install ! Error: "+str(e)+"\n"
