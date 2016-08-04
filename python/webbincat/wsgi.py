import ConfigParser
import distutils.spawn
import hashlib
import os
import shutil
import re
import subprocess
import sys
import tempfile
import flask

# Make sure bincat is properly installed, and that none of the required files
# reside in your home dir
# To smoke test, run "firejail --private bincat"
# tested with firejail 0.9.40

SHA256_RE = re.compile('[a-fA-F0-9]{64}')
app = flask.Flask(__name__)

# check existence of binary storage folder
if 'BINARY_STORAGE_FOLDER' not in app.config:
    app.config['BINARY_STORAGE_FOLDER'] = '/tmp/bincat_web'

if not os.path.isdir(app.config['BINARY_STORAGE_FOLDER']):
    app.logger.error("Binary storage folder %s does not exist",
                     app.config['BINARY_STORAGE_FOLDER'])
    sys.exit(1)

# check whether firejail is installed
firejail = distutils.spawn.find_executable("firejail")
if firejail is None:
    app.logger.error("firejail has not been installed")
    sys.exit(1)


@app.route("/download/<sha256>", methods=['HEAD', 'GET'])
def download(sha256):
    if not SHA256_RE.match(sha256):
        return flask.make_response(
            "SHA256 expected as endpoint parameter.", 400)
    sha256 = sha256.lower()
    filename = os.path.join(app.config['BINARY_STORAGE_FOLDER'], sha256)
    if os.path.isfile(filename):
        return open(filename, 'r').read()
    else:
        return flask.make_response(
            "No file having sha256=%s has been uploaded." % sha256, 404)


@app.route("/add", methods=['PUT'])
def upload():
    if 'file' not in flask.request.files:
        return flask.make_response(
            "No file named 'file' has been uploaded.", 400)
    f = flask.request.files['file']
    h = hashlib.new('sha256')
    h.update(f.read())
    sha256 = h.hexdigest().lower()
    f.seek(0)
    f.save(os.path.join(app.config['BINARY_STORAGE_FOLDER'], sha256))
    result = {'sha256': sha256}
    return flask.make_response(flask.jsonify(**result), 200)


@app.route("/analyze", methods=['POST'])
def analyze():
    if 'init.ini' not in flask.request.files:
        return flask.make_response(
            "No file named 'init.ini' has been uploaded.", 400)
    result = {}
    init_file = flask.request.files['init.ini']
    init_file.seek(0)

    # validation: valid ini file + referenced binary file has already been
    # uploaded
    config = ConfigParser.RawConfigParser()
    try:
        config.readfp(init_file)
    except ConfigParser.MissingSectionHeaderError:
        return flask.make_response(
            "Supplied init.ini file format is incorrect (missing section "
            "header).", 400)
    if not config.has_section("binary"):
        return flask.make_response(
            "No [binary] section in supplied init.ini file.", 400)
    try:
        binary_name = config.get('binary', 'filepath').lower()
    except ConfigParser.NoOptionError:
        return flask.make_response(
            "No filepath in [binary] section in supplied init.ini file.", 400)
    if not SHA256_RE.match(binary_name):
        return flask.make_response(
            "Binary filepath (%s) is not a valid sha256 hex string."
            % binary_name, 400)
    binpath = os.path.join(app.config['BINARY_STORAGE_FOLDER'], binary_name)
    if not os.path.exists(binpath):
        return flask.make_response(
            "Binary file %s has not yet been uploaded." % binary_name, 400)
    # ini file references a known file, proceeding
    # I miss python3's tempfile.TemporaryDirectory...
    dirname = tempfile.mkdtemp('bincat-web-analysis')
    app.logger.debug("created %s %s", dirname, str(os.path.exists(dirname)))

    cwd = os.getcwd()
    os.chdir(dirname)  # bincat outputs .dot in cwd
    # prepare input files
    init_file.seek(0)
    init_file.save(os.path.join(dirname, 'init.ini'))
    os.link(binpath, os.path.join(dirname, binary_name))
    # run bincat
    err, stdout = run_bincat(dirname)

    # gather outputs
    result['stdout'] = stdout
    result['errorcode'] = err
    logfname = os.path.join(dirname, 'analyzer.log')
    if os.path.isfile(logfname):
        result['analyzer.log'] = open(logfname).read()
    else:
        result['analyzer.log'] = ""
    outfname = os.path.join(dirname, 'out.ini')
    if os.path.isfile(outfname):
        result['out.ini'] = open(outfname).read()
    else:
        result['out.ini'] = ""

    os.chdir(cwd)
    shutil.rmtree(dirname)

    return flask.make_response(flask.jsonify(**result), 200)


def run_bincat(dirname):
    # do not use chroot: not compatible with grsec
    cmdline = ("%s --nosound --caps.drop=all"
               " --quiet"
               " --private"  # new /root, /home
               " --private-dev"  # new /dev, few devices
               " --private-etc=ld.so.cache,ld.so.conf,ld.so.conf.d"  # new /etc
               " --nogroups"  # no supplementary groups
               " --noroot"  # new user namespace
               " --nonewprivs"  # NO_NEW_PRIVS
               " --seccomp"  # default seccomp blacklist
               " --net=none"  # no network
               " --whitelist=%s"  # only allow current analysis dir from /tmp
               " -- ") % (firejail, dirname)
    cmdline += "bincat init.ini out.ini analyzer.log"
    err = 0
    try:
        out = subprocess.check_output(
            cmdline.split(' '),
            stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as exc:
        err = exc.returncode
        out = exc.output

    return err, out


if __name__ == "__main__":
    app.run()
