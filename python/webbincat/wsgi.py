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
            "This request was expected to include a file named 'file'.", 400)
    f = flask.request.files['file']
    sha256 = store_to_file(f.read())
    result = {'sha256': sha256}
    return flask.make_response(flask.jsonify(**result), 200)


def store_to_file(s):
    h = hashlib.new('sha256')
    h.update(s)
    sha256 = h.hexdigest().lower()
    fname = os.path.join(app.config['BINARY_STORAGE_FOLDER'], sha256)
    with open(fname, 'w') as f:
        f.write(s)
    return sha256


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
    config.optionxform = str
    try:
        config.readfp(init_file)
    except ConfigParser.MissingSectionHeaderError:
        return flask.make_response(
            "Supplied init.ini file format is incorrect (missing section "
            "header).", 400)
    # check required sections are present
    for section in ["binary", "analyzer"]:
        if not config.has_section(section):
            return flask.make_response(
                "No [%s] section in supplied init.ini file." % section, 400)
    # check required values are present
    for section, key in [("binary", "filepath"),
                         ("analyzer", "in_marshalled_cfa_file"),
                         ("analyzer", "store_marshalled_cfa"),
                         ("analyzer", "analysis")]:
        try:
            config.get(section, key)
        except ConfigParser.NoOptionError:
            return flask.make_response(
                "No %s key in [%s] section in supplied init.ini file."
                % (section, key), 400)
    binary_name = config.get('binary', 'filepath').lower()
    analysis_method = config.get('analyzer', 'analysis').lower()
    input_files = [binary_name]
    if analysis_method in ("forward_cfa", "backward"):
        in_marshalled_cfa_file = \
            config.get('analyzer', 'in_marshalled_cfa_file').lower()
        input_files.append(in_marshalled_cfa_file)
    if config.has_section("imports"):
        try:
            headers_fname = config.get("imports", "headers")
            input_files.append(headers_fname)
        except ConfigParser.NoOptionError:
            # this is not mandatory
            pass
    for fname in input_files:
        if not SHA256_RE.match(fname):
            return flask.make_response(
                "Filepath (%s) is not a valid sha256 hex string."
                % fname, 400)
        fpath = os.path.join(app.config['BINARY_STORAGE_FOLDER'], fname)
        if not os.path.exists(fpath):
            return flask.make_response(
                "Input file %s has not yet been uploaded." % fname, 400)
    # ini file references a known file, proceeding
    # I miss python3's tempfile.TemporaryDirectory...
    dirname = tempfile.mkdtemp('bincat-web-analysis')
    app.logger.debug("created %s", dirname)

    cwd = os.getcwd()
    os.chdir(dirname)  # bincat outputs .dot in cwd
    config.set('analyzer', 'out_marshalled_cfa_file', 'cfaout.marshal')
    # prepare input files
    config.write(open(os.path.join(dirname, 'init.ini'), 'w'))
    for fname in input_files:
        os.link(os.path.join(app.config['BINARY_STORAGE_FOLDER'], fname),
                os.path.join(dirname, fname))
    # run bincat
    err, stdout = run_bincat(dirname)

    # gather outputs
    result['stdout'] = stdout
    result['errorcode'] = err
    logfname = os.path.join(dirname, 'analyzer.log')
    if config.get('analyzer', 'store_marshalled_cfa') == 'true':
        if os.path.isfile('cfaout.marshal'):
            with open('cfaout.marshal') as f:
                # store result?
                s = f.read()
                fname = store_to_file(s)
                result['cfaout.marshal'] = fname
    if os.path.isfile(logfname):
        with open(logfname) as f:
            s = f.read()
            store_to_file(s)
            result['analyzer.log'] = s
    else:
        result['analyzer.log'] = ""
    outfname = os.path.join(dirname, 'out.ini')
    if os.path.isfile(outfname):
        with open(outfname) as f:
            result['out.ini'] = f.read()
    else:
        result['out.ini'] = ""
    with open(os.path.join(dirname, 'stdout.txt'), 'w') as f:
        # for server-side debugging purposes
        f.write(result['stdout'])

    os.chdir(cwd)
    # shutil.rmtree(dirname)

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
