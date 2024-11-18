# Installing MITRE Caldera

### Requirements

Caldera aims to support a wide range of target systems, the core requirements are listed below:

* Linux or MacOS operating system
* Python 3.8 or later (with pip3)
* NodeJS v16 or later (for Caldera v5)
* A modern browser (Google Chrome is recommended)
* The packages listed in the [requirements file](https://github.com/mitre/caldera/blob/master/requirements.txt)

### Recommended

To set up a development environment for Caldera, and to dynamically compile agents, the following is recommended:

* GoLang 1.17+ (for optimal agent functionality)
* Hardware: 8GB+ RAM and 2+ CPUs
* The packages listed in the [dev requirements file](https://github.com/mitre/caldera/blob/master/requirements-dev.txt)

### Installation Steps

The system that we are using to install Caldera is **Debian GNU/Linux 12 (bookworm).** The system specification can be found [here](lab-architecture.md).

#### Install NodeJS

<pre class="language-bash"><code class="lang-bash"><strong>sudo apt install nodejs
</strong>sudo apt install npm
</code></pre>

#### Install GoLang

1. Go to [https://go.dev/dl/](https://go.dev/dl/)
2. Choose the specific package as per CPU Architecture and OS version. For me, it is **go1.23.3.linux-amd64.tar.gz** as of today's date.

```bash
wget https://go.dev/dl/go1.23.2.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.23.2.linux-amd64.tar.gz
# To add system-wide path for go
echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee -a /etc/profile 
go version
```

#### Install Caldera

```bash
git clone https://github.com/mitre/caldera.git --recursive
cd caldera
pip3 install -r requirements.txt

python3 server.py --build 
# This will autogenerate a local.yml
# Once finished, then exit with Ctrl+C

npm audit fix --force
```

Now we need to change the `conf/local.yml` with our required values.

```bash
vim  ./caldera/conf/local.yml

# app.contact.http: http://SERVER-IP:8888
# app.frontend.api_base_url: http://SERVER-IP:8888

vim ./caldera/plugins/magma/.env
# VITE_CALDERA_URL=http://SERVER-IP:8888

python3 server.py --build --fresh

# find passwords to login
cat ./caldera/conf/local.yml
```

Now we can type the server IP or hostname to access the caldera from a different machine.

### Create Caldera service

We will create a caldera service so that we can run the service in the background.

```bash
cd /etc/systemd/system/
nano caldera.service
# Add the below lines in the file and save
[Unit]
Description=MITRE Caldera Server

[Service]
User=root
WorkingDirectory=/root/caldera
ExecStart=/usr/bin/python3 server.py

[Install]
WantedBy=multi-user.target
```

### References

1. [https://go.dev/doc/install](https://go.dev/doc/install)
2. [https://caldera.readthedocs.io/en/latest/Installing-Caldera.html](https://caldera.readthedocs.io/en/latest/Installing-Caldera.html)
3. [https://www.digitalocean.com/community/tutorials/how-to-install-node-js-on-ubuntu-20-04](https://www.digitalocean.com/community/tutorials/how-to-install-node-js-on-ubuntu-20-04)
