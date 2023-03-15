## POC for ParseExcel and ParseXLSX vulnerabilities
### Memory corruption
Build and run docker image in `/bomb` folder, using this command

`docker build -t perl-xlsx-bomb . && docker run perl-xlsx-bomb -t perl-xlsx-bomb -m 4g -d`

`4g` to limit memory size for docker container.
It will keep filling memory, swap memory and finally terminates for out of resource

### RCE
Build and run docker image in `/rce`, using this command

`docker build -t parseexcel-rce . && docker run parseexcel-rce`

Notice that RCE will result in `root` being written in `/tmp/inject.txt` after each perl run
