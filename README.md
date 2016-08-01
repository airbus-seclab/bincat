## Dependencies

ocaml 4.02.3 / check that type value = long in the include header caml/mlvalues.h (compiled with -fPIC for amd-64)
ocamlfind
zarith library >=1.4
python 2.7
pdflatex for documentation
pytest for tests
ocamldoc for the ocaml documentation generation
python2-sphinx for the python documentation generation
menhir for the configuration parsing in ocaml
the library ocamlgraph
IDA for the vizualisation
Graphviz

on Debian Sid :
apt install ocaml menhir ocaml-findlib libzarith-ocaml-dev libocamlgraph-ocaml-dev

## Installation

1. unzip this archive and enter it
2. compilation
make
3. installation
make install
4. for the documentation (generated in directory doc)
make doc

### ocaml compilation
If messages indicating that the -fPIC must be used, update your OCaml installation to 4.02.3.

### important remark
be sure to have the directory src/bincat into your LD_LIBRARY_PATH variable

### ocaml headers
OCAML headers are not installed in /usr/include or /usr/local/include, where
gcc looks for them, when installing from source.

Two solutions may be applied when compiling the Python using python2 setup.py build:

* Create a symlink (/usr/include/caml -> /usr/lib/ocaml/caml/, or
  /usr/local/include/caml -> /usr/local/lib/ocaml/caml/). This seems to be done
  in the debian packages.
* `export C_INCLUDE_PATH=/usr/lib/ocaml`

### mac os installation
by default non initialized external symobols are not exported by ranlib.
Hence some symbols in ` _caml_table` are not exported which resul in a link failure.
To avoid this, type

```
ranlib -c /path/to/the/lib/libsasmrun.a
```

### IDA plugin installation

* Copy or create a symlink to python/idabincat/bcplugin.py in your IDA
  installation folder's plugin/ directory, or in your ~/.idapro/plugins
  directory

* Make the pybincat & idabincat packages available in your idapython
  distribution. To do so, you may copy or create a symlink to the
  python/pybincat/ and python/idabindat folders in your IDA
  installation folder's plugin/ directory, or in your ~/.idapro/plugins
  directory.

* Make sure the "bincat" command is in your path (make install should have
  taken care of that)
  For mac installation, add in /etc/launchd.conf the line
  setenv PATH /usr/bin:/bin:/usr/sbin/sbin:/usr/local/bin:/path/to/bincat
  where /path/to/bincat is the result of which bincat

## IDA plugin usage


### Quick start
* Load the plugin by using the Ctrl-Shift-B shortcut, or using the
  "Edit -> Plugins -> BinCAT" menu

* Select an instruction in any IDA view, then use the Ctrl-Shift-A shortcut, or
  the "BinCAT -> Analyze from here" context menu

### Configuration
Default config and options are stored in `$IDAUSR/idabincat/conf`.

#### Options
Global options can be configured through the "Edit/BinCAT/Options" menu:
* Autostart : autoload BinCAT at startup
* Load from IDB : load analyzer config by default if one is stored in IDB at cursor address
* Save to IDB : default state for "save to idb" checkbox 


#### Analyzer configuration files
Default config for analyzer.
