## Introduction

### What is BinCAT?

BinCAT is a *static* Binary Code Analysis Toolkit, designed to help reverse
engineers, directly from IDA.

It features:

* value analysis (registers and memory)
* taint analysis
* type reconstruction and propagation
* backward and forward analysis

### In action

You can check BinCAT in action here:

* [Basic analysis](https://syscall.eu/bincat/main.mp4)
* [Using data tainting](https://syscall.eu/bincat/taint.mp4)

Check the [tutorial](doc/tutorial.md) out to see the corresponding tasks.

### Quick FAQ

Supported Platforms:

* IDA plugin: all, version 6.9 or later (BinCAT uses PyQt, not PySide)
* analyzer (local or server): Linux, macOS (maybe)

Supported CPUs (for now):
* x86-32

## Installation

### Analyzer
The analyzer is only supported on Linux, but can expose a Web service for use
from a Windows IDA.

* Using Docker: [Docker installation instructions](doc/install_docker.md)
* Manual: [Manual installation instructions](doc/install_manual.md)

### IDA Plugin

**Only IDA v6.9 or later are supported**

#### Install for Windows

* In IDA, click on "File -> Script File..." menu (or type ALT-F7)
* Select `python\windows_install_plugin.py`
* the BinCAT plugin is now installed in your IDA user dir

Or [install manually](doc/plugin_manual_win.md).


#### Linux install

[Installation instructions](doc/install_plugin.md)

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

* Use remote bincat: select if you are running docker in a Docker container
* Remote URL: http://localhost:5000 (or the URL of a remote BinCAT server)
* Autostart: autoload BinCAT at IDA startup
* Save to IDB: default state for the `save to idb` checkbox


#### Analyzer configuration files
Default config for analyzer.

## Documentation
A [manual](doc/manual.md) is provided. 

A [tutorial](doc/tutorial.md) is provided to help you try BinCAT's features. 
It makes use of a [sample binary](doc/get_key/get_key) and screenshots.

### Log levels

1. basic info
2. more info
3. debug
4. advanced debug

## Article and presentations about BinCAT

* [SSTIC 2017](https://www.sstic.org/2017/presentation/bincat_purrfecting_binary_static_analysis/), Rennes, France: [article](https://www.sstic.org/media/SSTIC2017/SSTIC-actes/bincat_purrfecting_binary_static_analysis/SSTIC2017-Article-bincat_purrfecting_binary_static_analysis-biondi_rigo_zennou_mehrenberger.pdf) (english), [slides](https://www.sstic.org/media/SSTIC2017/SSTIC-actes/bincat_purrfecting_binary_static_analysis/SSTIC2017-Slides-bincat_purrfecting_binary_static_analysis-biondi_rigo_zennou_mehrenberger.pdf) (french), [video of the presentation](https://static.sstic.org/videos2017/SSTIC_2017-06-07_P07.mp4) (french)
* [REcon 2017](https://recon.cx/2017/montreal/talks/bincat.html), Montreal, Canada: [slides](https://syscall.eu/bincat/bincat-recon.pdf)

## Licenses

BinCAT is released under the [GNU Affero General Public
Licence](https://www.gnu.org/licenses/agpl.html).

The BinCAT OCaml code includes code from the original Ocaml runtime, released
under the [LGPLv2](https://www.gnu.org/licenses/lgpl-2.0.txt).

The BinCAT IDA plugin includes code from
[python-pyqt5-hexview](https://github.com/williballenthin/python-pyqt5-hexview)
by Willi Ballenthin, released under the Apache License 2.0.

