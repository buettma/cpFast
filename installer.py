#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
File name: fastcp-installer.py
Author: Rehmat Alam (contact@rehmat.works)
Date created: 8/17/2021
Date last modified: 10/17/2022
Python Version: 3.9
"""

import os
import stat
import sys
import shutil
from subprocess import (
    STDOUT, Popen, DEVNULL, PIPE, check_call, CalledProcessError
)
import zipfile
import secrets
import string
import requests
import time
import OpenSSL
import socket


class FastcpInstaller(object):
    """FastCP installer.

    This is FastCP installer. The installer will install the required libraries like NGINX, PHP, MySQL and so on as well as it
    will install and configure FastCP control panel.

    Attributes:
        errors: Contains errors if any encountered by the installer.
    """
    errors = []

    def rand_passwd(self, length: int = 20) -> str:
        """Generate a random password.

        Generate a random and strong password using secrets module.
        """
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    def print_text(self, text: str, color: str = '', bold: bool = False) -> None:
        """Print text.

        Prints a colorful text. The color codes used below are obtained from the StackOverflow answer https://stackoverflow.com/questions/287871/how-to-print-colored-text-to-the-terminal.

        Args:
            text (str): The text to print to the terminal using print() function
            color (str): The color to use for the text. based on message type. It can be success, warning, or error.
        """
        OKGREEN = '\033[92m'
        WARNING = '\033[93m'
        FAIL = '\033[91m'
        OKBLUE = '\033[94m'
        BOLD = '\033[1m'
        ENDC = '\033[0m'

        text = f'==> {text}'
        if bold:
            text = f'{BOLD}{text}{ENDC}'

        if color and color in ['success', 'warning', 'info', 'error']:
            if color == 'success':
                text = f'{OKGREEN}{text}{ENDC}'
            elif color == 'warning':
                text = f'{WARNING}{text}{ENDC}'
            elif color == 'error':
                text = f'{FAIL}{text}{ENDC}'
            elif color == 'info':
                text = f'{OKBLUE}{text}{ENDC}'
        print(text)

    def check_requirements(self) -> bool:
        """Check requirements.

        Checks and ensures that the requirements are met.

        Returns:
            bool: Returns True if all requirements are met, and returns False otherwise.
        """
        try:
            # We assume that distro module is available
            # in Python3 on all latest Ubuntu releases.
            import distro
            distro = distro.linux_distribution()
            # Ensure that only LTS distros after 20.x are supported
            if str(distro[-1]).lower() not in ['focal']:
                self.errors.append(
                    'FastCP only supports the LTS releases of Ubuntu 20.04.')
        except ImportError:
            self.errors.append(
                'FastCP only supports the LTS releases of Ubuntu 20.04.')

        # Check and ensure that user is root
        if int(os.geteuid()) != 0:
            self.errors.append('You must run FastCP installer as root user.')

        # Check and ensure that server is clean
        packages = ['mysql', 'php', 'nginx', 'apache2']
        for pkg in packages:
            if os.path.exists(os.path.join('/etc', pkg)):
                self.errors.append(
                    f'{pkg} is already installed. Only clean servers can be configured.')

    def generate_csr(self, domains: list) -> tuple:
        """Create certificate signing request.

        Generates a certificate signing request. If private key is not provided, it will be created too.

        Params:
            domains (list): The domain names to generate the CSR (and private key) for.

        Returns:
            tuple: Returns a tuple with private key at index 0 and with CSR at index 1
        """
        pkey = OpenSSL.crypto.PKey()
        pkey.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
        req = OpenSSL.crypto.X509Req()
        req.get_subject().CN = ','.join(domains)
        req.set_pubkey(pkey)
        req.sign(pkey, 'sha256')
        priv_key = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM,
                                                  pkey)
        csr_pem = OpenSSL.crypto.dump_certificate_request(
               OpenSSL.crypto.FILETYPE_PEM, req)
        return priv_key, csr_pem

    def generate_certificate(self, priv_key, **kwargs):
        cert = OpenSSL.crypto.X509()
        cert.get_subject().C = kwargs.get('country', 'Pakistan')
        cert.get_subject().ST = kwargs.get('province', 'Gilgit-Baltistan')
        cert.get_subject().L = kwargs.get('locality', 'GB')
        cert.get_subject().O = kwargs.get('org', 'FastCP')
        cert.get_subject().OU = kwargs.get('org_unit', 'FastCP')
        cert.get_subject().CN = kwargs.get('common_name', 'fastcp.org')
        cert.get_subject().emailAddress = kwargs.get('email', 'support@fastcp.org')
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter((60 * 60 * 24 * 30 * 365))
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(priv_key)
        cert.sign(priv_key, 'sha512')

    def run_cmd(self, cmd: str, shell=False) -> bool:
        """Runs a shell command.
        Runs a shell command using subprocess.

        Args:
            cmd (str): The shell command to run.
            shell (bool): Defines either shell should be set to True or False.

        Returns:
            bool: Returns True on success and False otherwise
        """
        try:
            if not shell:
                check_call(cmd.split(' '),
                           stdout=DEVNULL, stderr=STDOUT, timeout=300)
            else:
                Popen(cmd, stdin=PIPE, stdout=DEVNULL,
                      stderr=STDOUT, shell=True).wait()
            return True
        except CalledProcessError:
            return False

    def install_package(self, pkg: str) -> bool:
        """Install package.

        Using subprocess module, this method attempts to install an APT package.

        Returns:
            bool: True on success and False otherwise.
        """
        return self.run_cmd(f'apt-get install -y {pkg}')


FASTCP_ASCII_LOGO = """
8 8888888888       .8.            d888888o.   8888888 8888888888 ,o888888o.    8 888888888o
8 8888            .888.         .\`8888:' \88.       8 8888      8888     \`88.  8 8888    \`88.
8 8888           :88888.        8.\`8888.    Y8      8 8888   ,8 8888       \`8. 8 8888     \`88
8 8888          . \`88888.       \`8.\`8888.         8 8888   88 8888            8 8888     ,88
8 888888888888 .8. \`88888.       \`8.\`8888.        8 8888   88 8888            8 8888.   ,88'
8 8888        .8\`8. \`88888.       \`8.\`8888.      8 8888   88 8888            8 888888888P'
8 8888       .8' \`8. \`88888.       \`8.\`8888.     8 8888   88 8888            8 8888
8 8888      .8'   \`8. \`88888.  8b   \`8.\`8888.    8 8888   \`8 8888       .8' 8 8888
8 8888     .888888888. \`88888. \`8b.  ;8.\`8888     8 8888      8888     ,88'   8 8888
8 8888    .8'       \`8. \`88888. \`Y8888P ,88P'     8 8888       \`8888888P'    8 8888
"""

# Print FastCP logo
print(FASTCP_ASCII_LOGO)

fcpi = FastcpInstaller()
fcpi.print_text('Welcome to FastCP installer.', bold=True)
fcpi.check_requirements()

# Check if errors encountered
if len(fcpi.errors) > 0:
    fcpi.print_text('FastCP installer encountered errors:',
                    'error', bold=True)
    for i, err in enumerate(fcpi.errors):
        fcpi.print_text(f'{i} {err}', 'error')
    sys.exit(1)

# Proceed if no errors encountered
fcpi.print_text('Initial checks passed. Proceeding.',
                'success')

# APT packages list
APT_PACKAGES = ['python3-software-properties', 'build-essential', 'zip', 'acl', 'mysql-server', 'python3-mysqldb', 'curl',
                'expect', 'python3-pip', 'apache2', 'apache2-suexec-custom', 'libmysqlclient-dev', 'postfix', 'mailutils']
PHP_VERSIONS = ['php7.1', 'php7.2', 'php7.3', 'php7.4', 'php8.0']
PHP_EXTENSIONS = ['common', 'curl', 'imagick', 'json', 'mbstring',
                  'mysql', 'xml', 'zip', 'bcmath', 'gd', 'intl', 'ssh2']

EXCLUDED_EXTS = {
    'php8.0': ['json'],
    'php7.4': [],
    'php7.3': [],
    'php7.2': [],
    'php7.1': []
}

# Use final PHP version for phpMyAdmin
PHPMYADMIN_SOCKET_PATH = os.path.join('/var/run/php', 'pma{}.sock'.format(PHP_VERSIONS[-1].replace('php', '')))

# Apache modules
APACHE_MODULES = ['proxy_fcgi', 'cache', 'remoteip', 'rewrite', 'suexec']

# Add PHP packages to APT packages list
for php in PHP_VERSIONS:
    APT_PACKAGES.append(f'{php}-fpm')
    # Add extensions to each PHP version
    for ext in PHP_EXTENSIONS:
        if ext not in EXCLUDED_EXTS[php]:
            APT_PACKAGES.append(f'{php}-{ext}')


# PIP packages
PIP_PACKAGES = ['pexpect', 'virtualenv', 'acme']

# Define some needed global vars
FASTCP_API_BASE = 'https://api.fastcp.org'
FASTCP_ROOT = '/etc/fastcp'
FASTCP_APP_ROOT = os.path.join(FASTCP_ROOT, 'fastcp')
FASTCP_SSL_PATH = os.path.join(FASTCP_ROOT, 'ssl')
FASTCP_SSL_KEY_PATH = os.path.join(FASTCP_SSL_PATH, 'fastcp.key')
FASTCP_SSL_CSR_PATH = os.path.join(FASTCP_SSL_PATH, 'fastcp.csr')
FASTCP_SSL_CERT_PATH = os.path.join(FASTCP_SSL_PATH, 'fastcp.crt')
FASTCP_SSL_CERT_BUNDLE_PATH = os.path.join(
    FASTCP_SSL_PATH, 'fastcp_bundle.crt')
FASTCP_VENV_ROOT = os.path.join(FASTCP_ROOT, 'venv')
FASTCP_LIB_PATH = '/var/fastcp'
FASTCP_ACME_CHALLENGE_DIR = os.path.join(FASTCP_LIB_PATH, 'well-known')
FASTCP_USER_GROUP = 'fcp-users'
FASTCP_EXTRACTED_PATH = os.path.join(FASTCP_ROOT, 'fastcp-master')
FASTCP_PACKAGE_URL = 'https://github.com/meetsohail/fastcp/archive/refs/tags/latest.zip'
FASTCP_PORT = 2050
FASTCP_CRON_RUN_SCRIPT = os.path.join(FASTCP_APP_ROOT, 'run-crons.sh')
FASTCP_CRON_JOB = f"""# FastCP cron job
*/5 * * * * root /bin/bash {FASTCP_CRON_RUN_SCRIPT} > /dev/null 2>&1
"""
PHPMYADMIN_PACKAGE_URL = 'https://files.phpmyadmin.net/phpMyAdmin/5.2.1/phpMyAdmin-5.2.1-all-languages.zip'
PHPMYADMIN_ROOT = os.path.join(FASTCP_LIB_PATH, 'phpmyadmin')
PHP_FPM_TPL = """; Dynamically generated by FastCP. Don't modify this configuration file.
[pma{php}]
user = www-data
group = www-data
listen = /var/run/php/pma{php}.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 660
pm = ondemand
pm.max_children = 20
"""
NGINX_ROOT = '/etc/nginx'
NGINX_SNIPPETS_DIR = os.path.join(NGINX_ROOT, 'snippets')
FASTCP_NGINX_SNIPPET_PATH = os.path.join(NGINX_SNIPPETS_DIR, 'fastcp.conf')
PHPMYADMIN_NGINX_SNIPPET_PATH = os.path.join(NGINX_SNIPPETS_DIR, 'pma.conf')
APACHE_ROOT = '/etc/apache2'
FILE_MANAGER_ROOT = '/srv/users'
PHP_ROOT = '/etc/php'
NGINX_VHOSTS_DIR = os.path.join(NGINX_ROOT, 'vhosts.d')
MYSQL_ROOT_PASSWORD = fcpi.rand_passwd()
FASTCP_SQL_USER = 'fastcp'
FASTCP_SQL_PASSWORD = fcpi.rand_passwd()
FASTCP_APP_SECRET = fcpi.rand_passwd(length=64)

try:
    SERVER_IP = requests.get('https://ipinfo.io/ip').text
except:
    while SERVER_IP is None:
        SERVER_IP = input('Server IP: ')
        if SERVER_IP:
            SERVER_IP = SERVER_IP.strip()

# Test code start

# Test code end

# Beging Installation
# Start the installation of APT packages as well, PIP packages, and ultimately
# install and configure FastCP control panel.
HOSTNAME = socket.gethostname()

# Configure MySQL root password
fcpi.run_cmd(
    f'debconf-set-selections <<< "mysql-server mysql-server/root_password password {MYSQL_ROOT_PASSWORD}"', shell=True)
fcpi.run_cmd(
    f'debconf-set-selections <<< "mysql-server mysql-server/root_password_again password {MYSQL_ROOT_PASSWORD}"', shell=True)

fcpi.print_text('Sit back and relax while FastCP configures your server.')
fcpi.print_text('This is going to take several minutes.')
fcpi.print_text('FastCP is now configuring your server.')
fcpi.print_text(
    'Adding APT repo ppa:ondrej/php for multiple PHP versions support.')
fcpi.run_cmd('add-apt-repository ppa:ondrej/php -y')
fcpi.print_text('Updating APT packages cache.')
fcpi.run_cmd('apt update')

# Install APT packages
fcpi.print_text(f'Installing selected packages.')
failed = []
for pkg in APT_PACKAGES:
    fcpi.print_text(f'Installing {pkg}')
    result = fcpi.install_package(pkg)
    if not result:
        failed.append(pkg)

# Install PIP packages
for pip_pkg in PIP_PACKAGES:
    result = fcpi.run_cmd(f'pip3 install {pip_pkg}')
    if not result:
        failed.append(pip_pkg)

if len(failed) == 0:
    fcpi.print_text(f'Core packages installed successfully.', 'success')
else:
    fcpi.print_text(
        f'Some packages ({", ".join(failed)}) cannot be installed. Installation aborted!', 'warning')
    sys.exit(1)

# Configure Apache2
# Update ports & enable modules
APACHE_CONF_TPL = """# Configured by FastCP.
DefaultRuntimeDir ${APACHE_RUN_DIR}
PidFile ${APACHE_PID_FILE}
Timeout 300
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 5
User ${APACHE_RUN_USER}
Group ${APACHE_RUN_GROUP}
HostnameLookups Off
ErrorLog ${APACHE_LOG_DIR}/error.log
LogLevel crit
IncludeOptional mods-enabled/*.load
IncludeOptional mods-enabled/*.conf
Listen 127.0.0.1:8080
AccessFileName .htaccess
<FilesMatch "^\.ht">
	Require all denied
</FilesMatch>
<Directory />
	Options FollowSymLinks
	AllowOverride None
	Require all denied
</Directory>
IncludeOptional conf-enabled/*.conf
IncludeOptional vhosts.d/*.conf"""

# Adjust vhosts directory
# Remove NGINX vhosts default dirs
try:
    shutil.rmtree(os.path.join(APACHE_ROOT, 'sites-available'))
    shutil.rmtree(os.path.join(APACHE_ROOT, 'sites-enabled'))
except FileNotFoundError:
    pass

# Delete ports.conf
APACHE_PORTS_CONF = os.path.join(APACHE_ROOT, 'ports.conf')
if os.path.exists(APACHE_PORTS_CONF):
    os.remove(APACHE_PORTS_CONF)

# Update Apache conf
APACHE_MAIN_CONF = os.path.join(APACHE_ROOT, 'apache2.conf')
with open(APACHE_MAIN_CONF, 'w') as f:
    f.write(APACHE_CONF_TPL)

# Activate modules
for apache_mod in APACHE_MODULES:
    fcpi.run_cmd(f'/usr/sbin/a2enmod {apache_mod}')

# Restart Apache
fcpi.run_cmd('/usr/bin/systemctl restart apache2')

# Improve NGINX
# Update NGINX conf as well as restructure the
# vhosts directory improve the organization. The directory
# structure is a result of inspiration from ServerPilot.io

NGINX_CONF = """user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;
worker_rlimit_nofile 100000;
error_log /var/log/nginx/error.log crit;

events {
    worker_connections 4000;
    use epoll;
    multi_accept on;
}

http {
    open_file_cache max=200000 inactive=20s;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors on;
    access_log off;
    sendfile on;
    tcp_nopush on;
    client_max_body_size 100M;
    tcp_nodelay on;
    gzip on;
    gzip_min_length 10240;
    gzip_comp_level 1;
    gzip_vary on;
    gzip_disable msie6;
    gzip_proxied expired no-cache no-store private auth;
    gzip_types
        text/css
        text/javascript
        text/xml
        text/plain
        text/x-component
        application/javascript
        application/x-javascript
        application/json
        application/xml
        application/rss+xml
        application/atom+xml
        font/truetype
        font/opentype
        application/vnd.ms-fontobject
        image/svg+xml;
    reset_timedout_connection on;
    client_body_timeout 30;
    send_timeout 30;
    keepalive_timeout 90;
    keepalive_requests 100;
    include /etc/nginx/mime.types;
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/vhosts.d/*.conf;
}
"""

PHPMYADMIN_NGINX_CONF = """# Donot modify. Added and required by FastCP
location /phpmyadmin {
    index index.php;
    alias %s;
}

location ~ ^/phpmyadmin/(.+\.php)$ {
    alias %s/$1;
    fastcgi_pass   unix:%s;
    fastcgi_index  %s/index.php;
    fastcgi_param  SCRIPT_FILENAME  $request_filename;
    include fastcgi_params;
}""" % (PHPMYADMIN_ROOT, PHPMYADMIN_ROOT, PHPMYADMIN_SOCKET_PATH, PHPMYADMIN_ROOT)

FASTCP_NGINX_CONF = """# Donot modify. Added & required by FastCP
location ^~ /.well-known/ {
    default_type "text/plain";
    rewrite /.well-known/(.*) /$1 break;
    root %s;
}""" % (FASTCP_ACME_CHALLENGE_DIR)

NGINX_DEFAULT_VHOST_CONTENT = """# Donot modify. Added & required by FastCP
server {
    listen    80 default_server;
    listen    [::]:80 default_server;

    include %s;

    location /phpmyadmin {
        return 302 https://$host$request_uri;
    }

    location / {
        return 444;
    }
}
""" % (FASTCP_NGINX_SNIPPET_PATH)


NGINX_DEFAULT_SSL_CONTENT = """# Donot modify. Added & required by FastCP.
server {
    listen       443 ssl default_server;
    listen       [::]:443 ssl default_server;

    include %s;
    include %s;

    ssl_certificate_key %s;
    ssl_certificate %s;

    location / {
        return 444;
    }
}""" % (FASTCP_NGINX_SNIPPET_PATH, PHPMYADMIN_NGINX_SNIPPET_PATH, FASTCP_SSL_KEY_PATH, FASTCP_SSL_CERT_PATH)

fcpi.print_text(f'Installing & configuring NGINX as reverse proxy.')

# Install NGINX now, after Apache is installed
# and ports are updated
fcpi.install_package('nginx')

# Update NGINX conf
with open(os.path.join(NGINX_ROOT, 'nginx.conf'), 'w') as f:
    f.write(NGINX_CONF)

# Remove NGINX vhosts default dirs
try:
    shutil.rmtree(os.path.join(NGINX_ROOT, 'sites-available'))
    shutil.rmtree(os.path.join(NGINX_ROOT, 'sites-enabled'))
except FileNotFoundError:
    pass

# Create new vhost dir if missing
if not os.path.exists(NGINX_VHOSTS_DIR):
    os.makedirs(NGINX_VHOSTS_DIR)

# Create ACME challenge dir
if not os.path.exists(FASTCP_ACME_CHALLENGE_DIR):
    os.makedirs(FASTCP_ACME_CHALLENGE_DIR)
    fcpi.run_cmd(f'chown -R www-data:www-data {FASTCP_ACME_CHALLENGE_DIR}')

# Create FastCP verification file
# FastCP will use thie file to ensure that a
# domain resolves to the server before attempting
# to request SSLs from Let's Encrypt
with open(os.path.join(FASTCP_ACME_CHALLENGE_DIR, 'fastcp-verify.txt'), 'w') as f:
    f.write('fastcp')

# Write ACME challenge server block
if not os.path.exists(NGINX_SNIPPETS_DIR):
    os.makedirs(NGINX_SNIPPETS_DIR)
with open(FASTCP_NGINX_SNIPPET_PATH, 'w') as f:
    f.write(FASTCP_NGINX_CONF)

# Write phpMyAdmin snippet
with open(PHPMYADMIN_NGINX_SNIPPET_PATH, 'w') as f:
    f.write(PHPMYADMIN_NGINX_CONF)

# Write default server block
with open(os.path.join(NGINX_VHOSTS_DIR, 'default.conf'), 'w') as f:
    f.write(NGINX_DEFAULT_VHOST_CONTENT)

# Reload NGINX
fcpi.run_cmd('service nginx reload')

# MySQL related operations start here.
# We will store root credentials that we generated
# as well as we will secure the MySQL installation.

fcpi.print_text('Securing MySQL installation.')
try:
    # Create FastCP user
    import MySQLdb as mdb
    con = mdb.connect(host='localhost', user='root', passwd=MYSQL_ROOT_PASSWORD)
    cur = con.cursor()
    cur.execute('SET sql_log_bin = 0')
    cur.execute(f'CREATE USER "{FASTCP_SQL_USER}"@"localhost" IDENTIFIED BY "{FASTCP_SQL_PASSWORD}"')
    cur.execute(f'CREATE USER "{FASTCP_SQL_USER}"@"%" IDENTIFIED BY "{FASTCP_SQL_PASSWORD}"')
    cur.execute(f'GRANT ALL PRIVILEGES on *.* TO "{FASTCP_SQL_USER}"@"localhost" WITH GRANT OPTION')
    cur.execute(f'GRANT ALL PRIVILEGES on *.* TO "{FASTCP_SQL_USER}"@"%" WITH GRANT OPTION')
    cur.execute('FLUSH PRIVILEGES')

    # Write MySQL credentials
    MYSQL_CNF_PATH = '/root/.my.cnf'
    MYSQL_CNF_CONTENT = f"""[client]
    user=root
    password={MYSQL_ROOT_PASSWORD}"""
    if not os.path.exists(MYSQL_CNF_PATH):
        with open(MYSQL_CNF_PATH, 'w') as f:
            f.write(MYSQL_CNF_CONTENT)


    # Use native passwords as default auth method
    with open('/etc/mysql/conf.d/fastcp.cnf', 'w') as f:
        f.write("""[mysqld]
    default-authentication-plugin=mysql_native_password""")

    fcpi.run_cmd('systemctl restart mysql')

    # Import pexpect
    import pexpect

    # Secure MySQL
    try:
        child = pexpect.spawn('mysql_secure_installation')
        child.expect('like to setup VALIDATE PASSWORD component')
        child.sendline('2')
        child.expect('the password for root')
        child.sendline('n')
        child.expect('anonymous users')
        child.sendline('y')
        child.expect('root login remotely')
        child.sendline('y')
        child.expect('test database and access to it')
        child.sendline('y')
        child.expect('privilege tables now')
        child.sendline('y')
        child.close(force=True)
    except:
        fcpi.print_text('Error occured when confuring MySQL. Setup cannot proceed.', color='error')
        sys.exit(1)
except:
    fcpi.print_text('Error occured when installing MySQL. Setup cannot proceed.', color='error')
    sys.exit(1)

# Update PHP resources
# We will allocate more resources to PHP
# i.e. will increase memory limit, upload file size etc.

fcpi.print_text('Optimizing PHP resource allocation.')

PHP_RESOURCES_CONTENT = """upload_max_filesize=1G;
post_max_size=1G;
memory_limit=512M;
display_errors=on;
max_input_vars=10000;"""


for php in PHP_VERSIONS:
    php = php.replace('php', '')

    # Update resources
    php_conf_dir = os.path.join(PHP_ROOT, php, 'fpm', 'conf.d')
    php_pool_conf = os.path.join(PHP_ROOT, php, 'fpm', 'pool.d', 'www.conf')
    if os.path.exists(php_conf_dir):
        with open(os.path.join(php_conf_dir, '10-fastcp.ini'), 'w') as f:
            f.write(PHP_RESOURCES_CONTENT)

    # Crate phpMyAdmin FPM pool
    PHPMYADMIN_FPM_POOL = PHP_FPM_TPL.format(php=php)
    with open(os.path.join(PHP_ROOT, php, 'fpm', 'pool.d', 'pma.conf'), 'w') as f:
        f.write(PHPMYADMIN_FPM_POOL)

    # Reload PHP
    fcpi.run_cmd(f'service php{php}-fpm reload')

# Create user data root
# Create the root directory of user data if missing
# The same dir will be served as the root directory of file manager
if not os.path.exists(FILE_MANAGER_ROOT):
    os.makedirs(FILE_MANAGER_ROOT)

# Fix permissions

# Create FastCP users group
fcpi.run_cmd(f'/usr/sbin/groupadd {FASTCP_USER_GROUP}')
fcpi.run_cmd(f'/usr/bin/chown -R root:root {FILE_MANAGER_ROOT}')
fcpi.run_cmd(f'/usr/bin/setfacl -m g:{FASTCP_USER_GROUP}:x /srv')
fcpi.run_cmd(
    f'/usr/bin/setfacl -m g:{FASTCP_USER_GROUP}:x {FILE_MANAGER_ROOT}')


# Install & configure phpMyAdmin
fcpi.print_text('Downloading phpMyAdmin.')
PHPMYADMIN_ZIP_ROOT = os.path.join(FASTCP_LIB_PATH, 'pma.zip')
if not os.path.exists(PHPMYADMIN_ZIP_ROOT):
    res = requests.get(PHPMYADMIN_PACKAGE_URL)
    with open(PHPMYADMIN_ZIP_ROOT, 'wb') as f:
        f.write(res.content)

    # Unzip package
    fcpi.print_text('Extracting phpMyAdmin package.')
    with zipfile.ZipFile(PHPMYADMIN_ZIP_ROOT, 'r') as zip_ref:
        zip_ref.extractall(FASTCP_LIB_PATH)

    # Complete install
    fcpi.print_text('Completing phpMyAdmin installation.')

    # Rename config file and set blowfish secret
    PHPMYADMIN_CONF_SAMPLE = os.path.join(PHPMYADMIN_ROOT, 'config.sample.inc.php')
    PHPMYADMIN_BLOWFISH_SEC = fcpi.rand_passwd(32)
    if os.path.exists(PHPMYADMIN_CONF_SAMPLE):
        with open(PHPMYADMIN_CONF_SAMPLE) as f:
            content = f.read()
            content = content.replace("$cfg['blowfish_secret'] = '';", f"$cfg['blowfish_secret'] = '{PHPMYADMIN_BLOWFISH_SEC}';")

        # Delete sample config file
        os.remove(PHPMYADMIN_CONF_SAMPLE)

        # Create config file
        with open(os.path.join(PHPMYADMIN_ROOT, 'config.inc.php'), 'w') as f:
            f.write(content)

    # Create temp dir & fix permissions
    PHPMYADMIN_TMP_PATH = os.path.join(PHPMYADMIN_ROOT, 'tmp')
    if not os.path.exists(PHPMYADMIN_TMP_PATH):
        os.makedirs(PHPMYADMIN_TMP_PATH)
    fcpi.run_cmd(f'/usr/bin/chown -R www-data:www-data {PHPMYADMIN_TMP_PATH}')


# Delete phpMyAdmin zip package
if os.path.exists(PHPMYADMIN_ZIP_ROOT):
    os.remove(PHPMYADMIN_ZIP_ROOT)

# Install FastCP
# Install FastCP control panel and create as systemd service
# Also attempt to get an SSL for FastCP or create
# a self-signed SSL cert if an SSL can't be obtained.

fcpi.print_text('Installing & configuring FastCP libraries.', 'info')

if not os.path.exists(FASTCP_ROOT):
    os.makedirs(FASTCP_ROOT)

# Allow only root access
fcpi.run_cmd(f'/usr/bin/chown -R root:root {FASTCP_ROOT}')
fcpi.run_cmd(f'/usr/bin/chmod 750 {FASTCP_ROOT}')

fcpi.print_text(f'Downloading FastCP source code from {FASTCP_PACKAGE_URL}')
# Download FastCP source code
FASTCP_ZIP_ROOT = os.path.join(FASTCP_ROOT, 'fastcp.zip')
if not os.path.exists(FASTCP_APP_ROOT):
    res = requests.get(FASTCP_PACKAGE_URL)
    with open(FASTCP_ZIP_ROOT, 'wb') as f:
        f.write(res.content)

    # Unzip the package
    fcpi.print_text(f'Extracting FastCP source code zip package.')
    with zipfile.ZipFile(FASTCP_ZIP_ROOT, 'r') as zip_ref:
        zip_ref.extractall(FASTCP_ROOT)

    # Rename FastCP extracted directory
    fcpi.print_text('Installing FasatCP.')
    if os.path.exists(FASTCP_EXTRACTED_PATH):
        os.rename(FASTCP_EXTRACTED_PATH, FASTCP_APP_ROOT)

# Delete archive
if os.path.exists(FASTCP_ZIP_ROOT):
    os.remove(FASTCP_ZIP_ROOT)

# Create a virtualenv
fcpi.run_cmd(f'virtualenv -p python3 {FASTCP_VENV_ROOT}')

# Install requirements
fcpi.run_cmd(
    f'{FASTCP_VENV_ROOT}/bin/python -m pip install -r {FASTCP_APP_ROOT}/requirements.txt')

# Populate vars.ini
FASTCP_INI_CONTENT = f"""FASTCP_SQL_PASSWORD={FASTCP_SQL_PASSWORD}
FASTCP_SQL_USER={FASTCP_SQL_USER}
FILE_MANAGER_ROOT={FILE_MANAGER_ROOT}
SERVER_IP_ADDR={SERVER_IP}
FASTCP_APP_SECRET={FASTCP_APP_SECRET}
"""

# Populate vars.sh
FASTCP_VARS_CONTENT = f"""export FASTCP_SQL_PASSWORD={FASTCP_SQL_PASSWORD}
export FASTCP_SQL_USER={FASTCP_SQL_USER}
export FILE_MANAGER_ROOT={FILE_MANAGER_ROOT}
export SERVER_IP_ADDR={SERVER_IP}
export FASTCP_APP_SECRET={FASTCP_APP_SECRET}
"""

with open(os.path.join(FASTCP_APP_ROOT, 'vars.ini'), 'w') as f:
    f.write(FASTCP_INI_CONTENT)

with open(os.path.join(FASTCP_APP_ROOT, 'vars.sh'), 'w') as f:
    f.write(FASTCP_VARS_CONTENT)

# Run python migrations
fcpi.run_cmd(
    f'{FASTCP_VENV_ROOT}/bin/python {FASTCP_APP_ROOT}/manage.py migrate')

# Create root user in the control panel db
# You can safely ignore the password here, because FastCP validates
# the Unix passwords and relies partially on Django authentication
fcpi.run_cmd(
    f'{FASTCP_VENV_ROOT}/bin/python {FASTCP_APP_ROOT}/manage.py createsuperuser --username root --noinput')

# Obtain a valid SSL or create a self-signed cert
# if a valid SSL can't be obtained.
cert_obtained = False
try:
    fcpi.print_text('Trying to obtain a valid SSL for FastCP.')

    # Create an SSL certificate
    if not os.path.exists(FASTCP_SSL_PATH):
        os.makedirs(FASTCP_SSL_PATH)

    # Create CSR & priv key
    priv_key, csr = fcpi.generate_csr([SERVER_IP])
    priv_key = priv_key.decode('utf-8')
    csr = csr.decode('utf-8')

    with open(FASTCP_SSL_KEY_PATH, 'w') as f:
        f.write(priv_key)

    with open(FASTCP_SSL_CSR_PATH, 'w') as f:
        f.write(csr)

    # Request a cert
    data = {
        'domain': SERVER_IP,
        'csr': csr
    }
    res = requests.post(
        f'{FASTCP_API_BASE}/request-certificate', json=data).json()
    FASTCP_CERT_ID = res.get('id')
    VALIDATION_FILE_CONTENT = res.get('validation').get(
        'other_methods').get(SERVER_IP)
    if FASTCP_CERT_ID and VALIDATION_FILE_CONTENT:
        VALIDATION_FILE_NAME = os.path.basename(
            VALIDATION_FILE_CONTENT.get('file_validation_url_http'))
        PKI_VALIDATION_DIR = os.path.join(
            FASTCP_ACME_CHALLENGE_DIR, 'pki-validation')
        if not os.path.exists(PKI_VALIDATION_DIR):
            os.makedirs(PKI_VALIDATION_DIR)
        with open(os.path.join(PKI_VALIDATION_DIR, VALIDATION_FILE_NAME), 'w') as f:
            for line in VALIDATION_FILE_CONTENT.get('file_validation_content'):
                f.write(f'{line}\n')

        # Request cert verification
        res = requests.get(
            f'{FASTCP_API_BASE}/verify-domain?cert_id={FASTCP_CERT_ID}')
        if res.status_code == 200:
            # Keep trying 5 times to get a cert
            tries = 0
            while tries < 5 and not cert_obtained:
                tries += 1
                fcpi.print_text(
                    f'Checking SSL status for {SERVER_IP} [Tries: {tries}/5]', 'info')
                res = requests.get(
                    f'{FASTCP_API_BASE}/certificate-status?cert_id={FASTCP_CERT_ID}')
                if res.status_code == 200 and res.json().get('validation_completed') == 1:
                    # Download cert
                    res = requests.get(
                        f'{FASTCP_API_BASE}/download-certificate?cert_id={FASTCP_CERT_ID}')
                    if res.status_code == 200:
                        res = res.json()
                        cert_content = res.get('certificate.crt')
                        cert_bundle_content = res.get('ca_bundle.crt')
                        with open(FASTCP_SSL_CERT_PATH, 'w') as f:
                            f.write(str(cert_content))
                        with open(FASTCP_SSL_CERT_BUNDLE_PATH, 'w') as f:
                            f.write(str(cert_bundle_content))
                        cert_obtained = True
                if not cert_obtained:
                    time.sleep(5)
except Exception as e:
    pass

if cert_obtained:
    fcpi.print_text(
        f'Successfully obtained a valid SSL for the IP {SERVER_IP}', 'success')
else:
    fcpi.print_text(
        'A valid SSL cannot be obtained at this time. Using a self-signed SSL instead.', 'error')

    # Generate a self-signed cert
    keypair = OpenSSL.crypto.PKey()
    keypair.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
    cert = OpenSSL.crypto.X509()
    cert.set_version(2)
    hostname = socket.gethostname()
    cert.get_subject().CN = 'fastcp.org'
    cert.get_issuer().CN = 'fastcp.org'
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_pubkey(keypair)
    cert.sign(keypair, 'sha256')
    certificate = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    privatekey = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, keypair)

    # Write key and cert files
    with open(FASTCP_SSL_KEY_PATH, 'w') as f:
        f.write(privatekey.decode('utf-8'))

    with open(FASTCP_SSL_CERT_PATH, 'w') as f:
        f.write(certificate.decode('utf-8'))

# Write default SSL vhost block
with open(os.path.join(NGINX_VHOSTS_DIR, 'default_ssl.conf'), 'w') as f:
    f.write(NGINX_DEFAULT_SSL_CONTENT)

# Restart NGINX
fcpi.run_cmd('/usr/bin/systemctl restart nginx')



# Create FastCP systemd service
FASTCP_SERVICE_CONTENT = f"""[Service]
User=root
Group=root
EnvironmentFile={FASTCP_APP_ROOT}/vars.ini
WorkingDirectory={FASTCP_APP_ROOT}
Environment=\"PATH={FASTCP_ROOT}/venv/bin\"
Restart=always
RestartSec=3
ExecStart={FASTCP_ROOT}/venv/bin/gunicorn -k uvicorn.workers.UvicornWorker --certfile={FASTCP_SSL_CERT_PATH} --keyfile={FASTCP_SSL_KEY_PATH} --workers=4 --bind 0.0.0.0:{FASTCP_PORT} fastcp.asgi:application

[Install]
WantedBy=multi-user.target"""

with open('/etc/systemd/system/fastcp.service', 'w') as f:
    f.write(FASTCP_SERVICE_CONTENT)

# Enable & start fastcp service
fcpi.run_cmd('systemctl enable fastcp')
fcpi.run_cmd('service fastcp start')

# Configure CRON job
fcpi.print_text('Configuring FastCP CRON jobs.')

# Create an executable script that will run
# Django crons via crontab
CRON_SCRIPT_CONTENT = f"""#!/bin/bash
# FastCP process crons
source {FASTCP_VENV_ROOT}/bin/activate && \
cd {FASTCP_APP_ROOT} && \
source vars.sh && \
{FASTCP_VENV_ROOT}/bin/python manage.py runcrons
"""

# Write CRON processing script
with open(FASTCP_CRON_RUN_SCRIPT, 'w') as f:
    f.write(CRON_SCRIPT_CONTENT)

st = os.stat(FASTCP_CRON_RUN_SCRIPT)
os.chmod(FASTCP_CRON_RUN_SCRIPT, st.st_mode | stat.S_IEXEC)

# Write CRON job file
with open('/etc/cron.d/fastcp', 'w') as f:
    f.write(FASTCP_CRON_JOB)


fcpi.print_text(
    'Congrats! Installation has completed successfully.', 'success')
fcpi.print_text(
    f'You can access FastCP at https://{SERVER_IP}:{FASTCP_PORT}', 'info', bold=True)
fcpi.print_text(
    'Consider donating to FastCP at https://fastcp.org/donate', 'info')
fcpi.print_text(
    'Each penny helps the further development of this project.', 'info')
fcpi.print_text(
    'Thank you for choosing FastCP! We hope you will enjoy using it.')
