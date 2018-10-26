### IDA plugin Linux

#### Plugin install

* clone this repository `git clone https://github.com/airbus-seclab/bincat`
* `cd bincat`
* run `make IDAuser`

#### Dependencies

##### python requests module

If you are running ida 7: ensure that the python `requests` module is installed. Use `pip2` or a distribution-provided package.

If you are running ida 6.9 with bundled python: manually install requests.
```
virtualenv -p $(which python2) /tmp/installrequests
. /tmp/installrequests/bin/activate
pip install requests
deactivate
cp -a /tmp/installrequests/lib/python*/site-packages/{requests,urllib3,chardet,certifi,idna} ~/.idapro/plugins/
rm -rf /tmp/installrequests
```

If there's a problem with `hashlib` on Debian, do the following:
```bash
wget http://archive.debian.org/debian-security/pool/updates/main/o/openssl/libssl0.9.8_0.9.8o-4squeeze14_i386.deb
sha256sum libssl0.9.8_0.9.8o-4squeeze14_i386.deb | grep -q 3c2391187c88e732545a11f545ccd2abf224c17a717e73588f1ebedb15d932ad
if [ $? -eq 0 ]; then dpkg -i libssl0.9.8_0.9.8o-4squeeze14_i386.deb ; fi
```

#### Local analyzer

* Make sure the `bincat` and `bincat_native` commands are in your path (`make
  install` should have taken care of that).

* On macOS, add the following line to `/etc/launchd.conf`:
  ```
  setenv PATH /usr/bin:/bin:/usr/sbin/sbin:/usr/local/bin:/path/to/bincat
  ```
  where `/path/to/bincat` is the output of `which bincat`
