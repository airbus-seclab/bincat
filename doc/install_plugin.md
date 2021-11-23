### IDA plugin Linux

#### Plugin install

* clone this repository `git clone https://github.com/airbus-seclab/bincat`
* `cd bincat`
* run `make IDAuser`

#### Dependencies

##### Python requests module

If you want to use a distant server, ensure that the python `requests` module is installed. Use `pip` or a distribution-provided package.

#### Local analyzer

* Make sure the `bincat` and `bincat_native` commands are in your path (`make
  install` should have taken care of that).

* On macOS, add the following line to `/etc/launchd.conf`:
  ```
  setenv PATH /usr/bin:/bin:/usr/sbin/sbin:/usr/local/bin:/path/to/bincat
  ```
  where `/path/to/bincat` is the output of `which bincat`
