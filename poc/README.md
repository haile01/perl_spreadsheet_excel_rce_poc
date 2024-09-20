## POC for ParseExcel and ParseXLSX vulnerabilities
### Memory corruption
Build and run docker image in `/bomb` folder, using this command

`docker build -t perl-xlsx-bomb . && docker run --name perl-xlsx-bomb -m 4g -d perl-xlsx-bomb`

`4g` to limit memory size for docker container.
It will keep filling memory, swap memory and finally terminates for out of resource

### RCE
Build and run docker image in `/rce`, using this command

`docker build -t parseexcel-rce . && docker run parseexcel-rce`

Notice that RCE will result in `root` being written in `/tmp/inject.txt` after each perl run

#### .xls exploit
Because the data is binary, it's quite hard to modify them manually. So I wrote a small script `xls-payload.py` to do that.
Also, there are a lot of flag checks and integrity ensurance stuffs on xls branch, I chose not to dig into all of that. And now I have zero idea what it does. So the overall idea of the script is to manually add a custom format on Excel app as a placeholder, which matches the length of the desired payload. Then the script overwrites that placeholder, do some format mapping stuffs. And vòila.

Here are the steps:
1. Run `xls-payload.py`, copy the placeholder (plz also copy the quotation marks on both ends)
2. Create `test.xls` file in the same folder (make sure to use Excel app on Windows, not sure why but Excel on MacOS or OpenOffice or Libre Office chips away some flags that we need). Input a number on a cell. Go to `Format Cell` > `Custom` and paste the placeholder. Now that cell should show a bunch of `a`s
3. Enter on the script once more. The xls file is now corrupted (make sure you won't open the file again on Excel app, or the payload will be gone). Then `mv test.xls rce/` and start a docker container to verify.
