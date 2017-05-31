## Quick Install/Configuration on Linux (using docker)

These commands will build BinCAT from scratch and have it run as a
webapp microservice in a Docker container (no need to worry about
dependencies, except for Docker itself).

If you have access to a BinCAT remote server, where the docker container is
running, you may skip any docker-related steps.

The IDA plugin will then be installed and configured to use bincat as a webapp.


#### Build the Docker container
You may skip this step if you already have access to a remote BinCAT server.

* run ```docker build -t bincat .```
* run the `bincat` Docker microservice: `docker run -p 5000:5000 bincat`
