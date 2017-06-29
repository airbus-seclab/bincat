### Manual Windows install
The plugin requires the `requests` module to work:

* Get it from <https://pypi.python.org/pypi/requests/>
* Extract it
* Run `python setup.py build`
* Copy the `build\lib\requests` folder to IDA's `python` directory


#### Plugin install
* Copy the `python\idabincat` and `python\pybincat` folders to your IDA's `plugins` directory
* Copy `bin` to `IDA\plugins\idabincat`
* Copy `python\idabincat\bcplugin.py` to your IDA's `plugins` directory
* Copy the `python\idabincat\conf` folder to `%APPDATA%\Hex-Rays\IDA Pro\idabincat` (or `%IDAUSR%\idabincat` dir)
