## Introduction

### What is BinCAT?

BinCAT is a *static* Binary Code Analysis Toolkit, designed to help reverse
engineers, directly from IDA or using Python for automation.

It features:

* value analysis (registers and memory)
* taint analysis
* type reconstruction and propagation
* backward and forward analysis
* use-after-free and double-free detection

### In action

You can check (an older version of) BinCAT in action here:

* [Basic analysis](https://syscall.eu/bincat/main.mp4)
* [Using data tainting](https://syscall.eu/bincat/taint.mp4)

Check the [tutorial](doc/tutorial.md) out to see the corresponding tasks.

### Quick FAQ

Supported host platforms:

* IDA plugin: all, version **7.4 or later** (Only Python 3 is supported)
* analyzer (local or remote): Linux, Windows, macOS (maybe)

Supported CPU for analysis (for now):
* x86-32
* x86-64
* ARMv7
* ARMv8
* PowerPC

## Installation

**Only IDA v7.4 or later is supported**

Older versions may work, but we won't support them.

### Binary distribution install (recommended)

The [binary distribution](https://github.com/airbus-seclab/bincat/releases)
includes everything needed:

* the analyzer
* the IDA plugin

Install steps:

* Extract the [binary distribution](https://github.com/airbus-seclab/bincat/releases) of BinCAT (not the git repo)
* In IDA, click on "File -> Script File..." menu (or type ALT-F7)
* Select `install_plugin.py`
* BinCAT is now installed in your IDA user dir
* Restart IDA

### Manual installation

#### Analyzer
The analyzer can be used locally or through a Web service.

On Linux:
* Using Docker: [Docker installation instructions](doc/install_docker.md)
* Manual: [build and installation instructions](doc/install_manual.md)

On Windows:
* [build instructions](doc/windows_build.md)

#### IDA Plugin

* [Windows manual install](doc/plugin_manual_win.md).
* [Linux manual install](doc/install_plugin.md)

BinCAT should work with IDA on Wine, once pip is installed:

* download <https://bootstrap.pypa.io/get-pip.py> (verify it's good ;)
* `~/.wine/drive_c/Python/python.exe get-pip.py`

## Using BinCAT

### Quick start
* Load the plugin by using the `Ctrl-Shift-B` shortcut, or using the
  `Edit -> Plugins -> BinCAT` menu

* Go to the instruction where you want to start the analysis
* Select the `BinCAT Configuration` pane, click `<-- Current` to define the start address
* Launch the analysis

### Configuration
Global options can be configured through the `Edit/BinCAT/Options` menu.

Default config and options are stored in `$IDAUSR/idabincat/conf`.

#### Options

* "Use remote bincat": select if you are running docker in a Docker container
* "Remote URL": http://localhost:5000 (or the URL of a remote BinCAT server)
* "Autostart": autoload BinCAT at IDA startup
* "Save to IDB": default state for the `save to idb` checkbox


## Documentation
A [manual](doc/manual.md) is provided and check [here](doc/ini_format.md) for a
description of the configuration file format.


A [tutorial](doc/tutorial.md) is provided to help you try BinCAT's features. 


## Article and presentations about BinCAT

* [SSTIC 2017](https://www.sstic.org/2017/presentation/bincat_purrfecting_binary_static_analysis/), Rennes, France: [article](https://www.sstic.org/media/SSTIC2017/SSTIC-actes/bincat_purrfecting_binary_static_analysis/SSTIC2017-Article-bincat_purrfecting_binary_static_analysis-biondi_rigo_zennou_mehrenberger.pdf) (english), [slides](https://www.sstic.org/media/SSTIC2017/SSTIC-actes/bincat_purrfecting_binary_static_analysis/SSTIC2017-Slides-bincat_purrfecting_binary_static_analysis-biondi_rigo_zennou_mehrenberger.pdf) (french), [video of the presentation](https://static.sstic.org/videos2017/SSTIC_2017-06-07_P07.mp4) (french)
* [REcon 2017](https://recon.cx/2017/montreal/talks/bincat.html), Montreal, Canada: [slides](https://syscall.eu/bincat/bincat-recon.pdf), [video](https://recon.cx/media-archive/2017/mtl/recon2017-mtl-05-philippe-biondi-xavier-mehrenberger-raphael-rigo-sarah-zennou-BinCAT-purrfecting-binary-static-analysis.mp4)

## Licenses

BinCAT is released under the [GNU Affero General Public
Licence](https://www.gnu.org/licenses/agpl.html).

The BinCAT OCaml code includes code from the original Ocaml runtime, released
under the [LGPLv2](https://www.gnu.org/licenses/lgpl-2.0.txt).

The BinCAT IDA plugin includes code from
[python-pyqt5-hexview](https://github.com/williballenthin/python-pyqt5-hexview)
by Willi Ballenthin, released under the Apache License 2.0.

BinCAT includes a modified copy of
[newspeak](https://github.com/airbus-seclab/c2newspeak).

## Automated builds

### Windows
Automated builds are performed automatically (see
[azure-pipelines.yml](azure-pipelines.yml)). The latest builds and test results
can be accessed [here](https://dev.azure.com/airbus-seclab/bincat/_build)

### Linux
Automated builds are performed automatically using GitHub Actions (see
[here](.github/workflows/linux-build-and-test.yaml)), results can be obtained
on GitHub's [Actions](https://github.com/airbus-seclab/bincat/actions) tab.
