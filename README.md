## Introduction

### What is BinCAT ?

BinCAT is a *static* Binary Code Analysis Toolkit, designed to help reverse
engineers, directly from IDA.

It features:

* value analysis (registers and memory)
* taint analysis
* type reconstruction and propagation
* backward and forward analysis

### In action

TODO : add gif of taint analysis

### Quick FAQ

Supported Platforms:

* IDA plugin: all, version 6.9 or later
* analyzer (local or server): Linux, macOS (maybe)

Supported CPUs (for now):
* x86-32

## Installation

### Analyzer
The analyzer is only supported on Linux, but can expose a Web service for use
from a Windows IDA.

* Using Docker : [doc/install_docker.md](Docker installation instructions)
* Manual : [doc/install_manual.md](Manual installation instructions)

### IDA Plugin

**Only IDA v6.9 or later are supported**

#### Install for Windows

* Launch IDA
* Click on "File -> Script File..." menu (or type ALT-F7)
* Select `python\windows_install_plugin.py`
* the BinCAT plugin is now installed in your IDA user dir

Or [doc/plugin_manual_win.md](install manually).


#### Linux install

[doc/install_plugin.md](Installation instructions)

## Using BinCAT

* Now you can run analyses (Ctrl-Shift-A)

### Quick start
* Load the plugin by using the `Ctrl-Shift-B` shortcut, or using the
  `Edit -> Plugins -> BinCAT` menu

* Select an instruction in any IDA view, then use the `Ctrl-Shift-A` shortcut,
  or the `BinCAT -> Analyze from here` context menu

### Configuration
Global options can be configured through the `Edit/BinCAT/Options` menu.

Default config and options are stored in `$IDAUSR/idabincat/conf`.

#### Options

* Remote URL: http://localhost:5000 (or the URL of a remote BinCAT server)
* Autostart: autoload BinCAT at IDA startup
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

