while [ ! -z "`ps -e | grep 'apt\|dpkg'`" ]; do echo "Waiting for apt or dpkg to exit."; sleep 6; done && \
sudo apt-get update && sudo apt-get -y install software-properties-common python3-pip python3-distro ca-certificates wget && \
pip3 install pyOpenSSL --upgrade && \
cd /home && \
HOSTNAME=$(uname -n) && \
sudo debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'" && \
sudo debconf-set-selections <<< "postfix postfix/mailname string $HOSTNAME" && \
sudo wget -nv -O /usr/bin/fastcp-updater https://gist.githubusercontent.com/meetsohail/9f887ca06a509a2e685d17536a6da244/raw/9707b89b7b160a82458332aecbede9f82d9e97c7/fastcp-updater.py && \
sudo chmod +x /usr/bin/fastcp-updater && \
sudo wget -nv -O fastcp-installer https://raw.githubusercontent.com/shiptycoon/cpFast/main/installer.py && \
sudo chmod +x fastcp-installer && \
sudo ./fastcp-installer
