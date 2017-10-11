# Running BinCAT analyzer on Linux using Docker

These commands will build BinCAT from scratch and have it run as a
webapp microservice in a Docker container (no need to worry about
dependencies, except for Docker itself).

* run the `bincat` Docker microservice: `docker run -p 5000:5000 airbusseclab/bincat`

This will automatically fetch a public Docker image and run it on your machine.

## Building the Docker container
If you choose not to run the provided docker container, you may use this
command to build it, from the root of the repository :

* run ```docker build -t bincat .``` from the docker/ directory.
