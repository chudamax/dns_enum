## Install amass
Go to https://github.com/owasp-amass/amass/releases and download any suitable release (tested on v4.1.0)

## Install massdns
git clone https://github.com/blechschmidt/massdns.git

cd massdns

make && make install

## Install python modules
pip3 install -r requirements.txt

## Prepare resolvers
dns_enum.py --update-mass-resolvers

## Run the tool
dns_enum.py --amass --brute --enrich --altmutations -d domain.com
