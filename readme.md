# MalBuzz
### What is this ?
It's a handy tool to help you analyze malware. You can use this tool to query your malware samples using different hashes or find all other samples using YARA rules, CalmAV signatures, etc. This tool is based on [MalwareBazaar](https://bazaar.abuse.ch/). 

### Requirements
- curl _(available in most Linux distros)_
- jq
- sha256sum _(available in most Linux distros)_

### Installation
First you need to install ```curl``` and ```jq``` . sha256sum is already available in most Linux distros. 

Install curl and jq on an Arch based distro by running the following command.
```sh
sudo pacman -Sy curl jq --noconfirm
```
Install curl and jq on a Debian based distro by running the following command.
```sh
sudo apt update; sudo apt install curl jq -y
```
Clone the repository by running the following command
```sh
git clone https://github.com/NomanProdhan/malbuzz.git
```
Go to the ```malbuzz``` directory by running the following command
```sh
cd malbuzz
```
Add execute permission to ```malbuzz.sh```
```sh
chmod +x malbuzz.sh
```

Run the tool
```sh
./malbuzz
```

### Options
```sh
Available Options:
------------------
 -h     : Search using SHA256 hash of the malware sample.
 -t     : Search using Trend Micro Locality Sensitive Hash (TLSH) of the malware sample.
 -e     : Search using Trend Micro ELF Hash (TELF) of the malware sample.
 -g     : Search using gimphash.
 -i     : Search using imphash.
 -d     : In case the file is a PE executable, search using DHASH of the samples icon.
 -c     : Search using ClamAV signature.
 -y     : Search YARA rule. You can get a list of malware samples associated with a specific YARA rule.
 -S     : Search using malware family. Example : RedLineStealer, Ransomware etc.
 -T     : Search using Tag. Example : BotNet, DDoS BotNet, EXE etc.
 -D     : Download a malware sample using SHA256 hash.
 -f     : Select a file to search. It will do a SHA256SUM of the file and search for it.
```

### Example Usages
Search using SHA256 hash
```sh
./malbuzz.sh -h 32420d512aecb2598e0e2c7237e796562e54984a4b21d45210a1d7a3a6763831
```
Search for malware family
```sh
./malbuzz.sh -S WannaCry
```
Search using a malware sample
```sh
./malbuzz.sh -f /path/to/malware/sample.exe
```

### Screenshots
![Screenshot-1](https://raw.githubusercontent.com/NomanProdhan/malbuzz/master/screenshots/malbuzz_screenshot_1.png)
![Screenshot-2](https://raw.githubusercontent.com/NomanProdhan/malbuzz/master/screenshots/malbuzz_screenshot_2.png)
![Screenshot-3](https://raw.githubusercontent.com/NomanProdhan/malbuzz/master/screenshots/malbuzz_screenshot_3.png)


### Follow Me ;P [If you want]
- Twitter @[NomanProdhan](https://twitter.com/nomanProdhan)
- YouTube @[nomanprodhan](https://www.youtube.com/c/NOMANPRODHAN)
- Websites [www.nomantheking.com](https://nomantheking.com) [www.nomanprodhan.com](https://nomanprodhan.com)

---

### License
```
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
