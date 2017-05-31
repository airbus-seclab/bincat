## Quick Install/Configuration on Linux (using docker)

These commands will build BinCAT from scratch and have it run as a
webapp microservice in a docker container (no need to worry about
dependencies, except for docker itself).

If you have access to a BinCAT remote server, where the docker container is
running, you may skip any docker-related steps.

The IDA plugin will then be installed and configured to use bincat as a webapp.


### Install

#### IDA plugin

* install IDA (v6.9 or later version) with bundled Python
* copy or symlink BinCAT plugin and libs into IDA plugins folder
```
mkdir -p ~/.idapro/plugins
ln -s $(pwd)/python//{idabincat,pybincat,idabincat/bcplugin.py} ~/.idapro/plugins/
```
* install Python <i>requests</i> library for IDA's bundled Python
```
virtualenv -p $(which python2) /tmp/installrequests
. /tmp/installrequests/bin/activate
pip install requests
deactivate
cp -a /tmp/installrequests/lib/python*/site-packages/requests ~/.idapro/plugins/
rm -rf /tmp/installrequests
```
* install BinCAT configuration files
```
mkdir -p ~/.idapro/idabincat
cp -a python/idabincat/conf ~/.idapro/idabincat/
```

#### Build the docker container
You may skip this step if you already have access to a remote BinCAT server.

* run ```docker build -t bincat .```


### Using BinCAT

#### Run the docker container
You may skip this step if you already have access to a remote BinCAT server.

* run the `bincat` Docker microservice: `docker run -p 5000:5000 bincat`

#### Configure the IDA plugin
* run IDA
* launch bincat plugin (Ctrl-Shift-B)
* If there's a problem with `hashlib` on Debian, do the following:

```bash
wget http://archive.debian.org/debian-security/pool/updates/main/o/openssl/libssl0.9.8_0.9.8o-4squeeze14_i386.deb
sha256sum libssl0.9.8_0.9.8o-4squeeze14_i386.deb | grep -q 3c2391187c88e732545a11f545ccd2abf224c17a717e73588f1ebedb15d932ad
if [ $? -eq 0 ]; then dpkg -i libssl0.9.8_0.9.8o-4squeeze14_i386.deb ; fi
```

* Configure IDA bincat plugin:
  *  go to *Edit > BinCAT > Options...* menu
  *  check *use remote bincat*
  *  Remote URL: http://localhost:5000 (or the URL of a remote BinCAT server)

* Now you can run analyses (Ctrl-Shift-A)


## Install (Linux / macOS)
### Dependencies

* ocaml 4.02.3 / check that type value = long in the include header caml/mlvalues.h (compiled with -fPIC for amd-64)
* ocamlfind
* zarith library >=1.4
* newspeak (https://github.com/airbus-seclab/c2newspeak)
* python 2.7
* pytest for tests
* ocamldoc for the ocaml documentation generation
* python2-sphinx for the python documentation generation
* menhir for the configuration parsing in ocaml
* the ocamlgraph library
* IDA >= 6.9 (for the plugin)

#### Installing linux packages
All these dependencies except ida and newspeak are usually packaged by linux
distributions.

on Debian Sid:
```
apt install ocaml menhir ocaml-findlib libzarith-ocaml-dev libocamlgraph-ocaml-dev python-setuptools python-dev
```

on Ubuntu 16.04:
```
apt install make python python-pip python-setuptools python-dev python-pytest \
        nasm libc6-dev-i386 gcc-multilib ocaml menhir ocaml-findlib \
        libzarith-ocaml-dev libocamlgraph-ocaml-dev
```

#### Installing c2newspeak
```
git clone https://github.com/airbus-seclab/c2newspeak
cd c2newspeak
make
make install
sudo ln -s bin/c2newspeak /usr/bin/c2newspeak
```

### Installing BinCAT

1. Clone this depository and enter it
```
git clone https://github.com/airbus-seclab/bincat
cd bincat
```

2. compilation

```
make
```

3. installation (as a super user)

```
make install
```

4. for the documentation (generated in directory doc)

```
make doc
```

### ocaml compilation
If messages indicating that the `-fPIC` must be used, update your OCaml installation to 4.02.3.

## Install (macOS)
**Warning**: the authors do not use macOS anymore, and thus do not test this
procedure anymore. If you run into problems on macOS, we recommend running
bincat in a linux virtual machine, or in a docker container (build procedure
provided in Dockerfile).

By default non initialized external symobols are not exported by `ranlib`.
Hence some symbols in `_caml_table` are not exported which results in a link
failure.
To avoid this, run the following command:

```
ranlib -c /path/to/the/lib/libsasmrun.a
```

## IDA plugin installation (Linux/macOS)

* Copy or create a symlink to `python/idabincat/bcplugin.py` in your IDA
  installation folder's `plugins/` directory, or in your `~/.idapro/plugins`
  directory

* Make the `pybincat` & `idabincat` packages available in your IDAPython
  distribution. To do so, you may copy or create a symlink to the
  `python/pybincat/` and `python/idabindat` folders in your IDA
  installation folder's `plugins/` directory, or in your `~/.idapro/plugins`
  directory.

* Make sure the `bincat` and `bincat_native` commands are in your path (`make
  install` should have taken care of that).

* On macOS, add the following line to `/etc/launchd.conf`:
  ```
  setenv PATH /usr/bin:/bin:/usr/sbin/sbin:/usr/local/bin:/path/to/bincat
  ```
  where `/path/to/bincat` is the output of `which bincat`

* If there's a problem with `hashlib` on Debian, do the following:


```bash
wget http://archive.debian.org/debian-security/pool/updates/main/o/openssl/libssl0.9.8_0.9.8o-4squeeze14_i386.deb
sha256sum libssl0.9.8_0.9.8o-4squeeze14_i386.deb | grep 3c2391187c88e732545a11f545ccd2abf224c17a717e73588f1ebedb15d932ad
if [ $? -eq 0 ]; then dpkg -i libssl0.9.8_0.9.8o-4squeeze14_i386.deb ; fi
```

## Install (Windows)

**Only IDA plugin is supported on Windows.**

### Easy install

* Launch IDA
* Click on "File -> Script File..." menu (or type ALT-F7)
* Select `python\windows_install_plugin.py`
* the BinCAT plugin is now installed in your IDA user dir

### Manual Install

#### Dependencies
The plugin requires the `requests` module to work:

* Get it from <https://pypi.python.org/pypi/requests/>
* Extract it
* Run `python setup.py build`
* Copy the `build\lib\requests` folder to IDA's `python` directory


#### Plugin install
* Copy the `python\idabincat` and `python\pybincat` folders to your IDA's `plugins` directory
* Copy `python\idabincat\bcplugin.py` to your IDA's `plugins` directory
* Copy the `python\idabincat\conf` folder to `%APPDATA%\Hex-Rays\IDA Pro\idabincat` (or `%IDAUSR%\idabincat` dir)
* Configure your server address

## IDA plugin usage

### Quick start
* Load the plugin by using the `Ctrl-Shift-B` shortcut, or using the
  `Edit -> Plugins -> BinCAT` menu

* Select an instruction in any IDA view, then use the `Ctrl-Shift-A` shortcut,
  or the `BinCAT -> Analyze from here` context menu

### Configuration
Default config and options are stored in `$IDAUSR/idabincat/conf`.

#### Options
Global options can be configured through the `Edit/BinCAT/Options` menu:

* Autostart: autoload BinCAT at IDA startup
* Load from IDB: load analyzer config by default if one is stored in IDB at
  cursor address
* Save to IDB: default state for the `save to idb` checkbox


#### Analyzer configuration files
Default config for analyzer.

## Usage

### Log levels

1. basic info
2. more info
3. debug
4. advanced debug

## Licenses

BinCAT is released under the [GNU Affero General Public
Licence](https://www.gnu.org/licenses/agpl.html).

The BinCAT OCaml code includes code from the original Ocaml runtime, released
under the [LGPLv2](https://www.gnu.org/licenses/lgpl-2.0.txt).

The BinCAT IDA plugin includes code from
[python-pyqt5-hexview](https://github.com/williballenthin/python-pyqt5-hexview)
by Willi Ballenthin, released under the Apache License 2.0.

