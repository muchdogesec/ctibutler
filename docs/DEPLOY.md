# Basic Cloud deployment steps

For those wanting to deploy to a Cloud server, here's a simple guide (that is not production ready).

Create an Ubuntu server on a Cloud provider. We like https://www.hetzner.com/cloud/

## 0. Create a ctibutler user

### 0.1 Create the user

```shell
sudo adduser ctibutler
```

```shell
sudo usermod -aG sudo ctibutler && \
sudo service ssh restart
```

### 0.2 Copy SSH keys

```shell
cd /home/ctibutler
mkdir .ssh/
vi .ssh/authorized_keys
```

Add SSH keys

Now logout and check created user can authenticate as user before next step, else you will be locked out

### 0.3 Disable root login

```shell
sudo vi /etc/ssh/sshd_config
```

## 1. Install Docker on Your VPS

### 1.1: Update the package list

```shell
sudo apt update && \
sudo apt install apt-transport-https ca-certificates curl software-properties-common && \
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg && \
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null  && \
sudo apt update && \
sudo apt install docker-ce && \
sudo usermod -aG docker ctibutler && \
sudo newgrp docker && \
sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose && \
sudo chmod +x /usr/local/bin/docker-compose
```

## 3. Install ArangoDB using Docker

### 3.1 Pull the ArangoDB Docker image

```shell
docker pull arangodb/arangodb:latest && \
sudo mkdir -p /var/lib/arangodb_data && \
sudo chown -R $USER:$USER /var/lib/arangodb_data
```

### 3.3  Run ArangoDB in a Docker container

```shell
docker run -e ARANGO_ROOT_PASSWORD=yourpassword -d --name arangodb -p 8529:8529 -v /var/lib/arangodb_data:/var/lib/arangodb3 arangodb/arangodb:latest
```

Replace `yourpassword`

### 3.4 Verify that ArangoDB is running

```shell
docker ps
```

### 4. Clone the Repository

```shell
sudo apt install git && \
cd /etc && \
sudo git clone https://github.com/muchdogesec/ctibutler.git && \
cd ctibutler && \
sudo cp .env.example .env
```

Setup your env file with variables

```shell
sudo vi .env
```

Changing

```
ARANGODB_HOST_URL='http://host.docker.internal:8529'
ARANGODB_USERNAME=root
ARANGODB_PASSWORD=yourpassword
DJANGO_ALLOWED_HOSTS=yourserverip
```

Replace `yourpassword` with what you set earlier and `yourserverip` with the ip address / domain of your server

```shell
docker compose build && \
docker compose up -d && \
docker ps
```

You should now be able go to the ArangoDB interface on your server

`http://<SERVER_IP>:8529/`

and the swagger UI for ctibutler

`http://<SERVER_IP>:8006/api/schema/swagger-ui/#/`


### 6. Set up Firewall rules

All non-essential ports should be blocked using ufw.

First switch off ufw (to ensure we don't kick ourselves off server when blocking all ports): 

```shell
sudo ufw disable
```

Then block all ports: 

```shell
sudo ufw default deny
sudo ufw allow 22 #ssh
sudo ufw allow 8006 #ctibutler
sudo ufw allow 8529 #arangodb
sudo ufw allow 443 #ssl
sudo ufw allow 80 #http
```

```shell
sudo ufw enable
```

