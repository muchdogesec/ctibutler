##

For those wanting to deploy to a Cloud server, here's a simple guide (that is not production ready).



Create an Ubuntu server on a Cloud provider. We like https://www.hetzner.com/cloud/

## 0. Create a ctibutler user

### 0.1 Create the user

```shell
sudo adduser ctibutler
```

### 0.2 Make user sudoer

```shell
sudo usermod -aG sudo ctibutler
```

### 0.3 Restart SSH server

```shell
sudo service ssh restart
```

### 0.4 Use ctibutler user

```shell
su ctibutler
```

## 1. Install Docker on Your VPS

### 1.1: Update the package list

```shell
sudo apt update
```
### 1.2 Install required packages

```shell
sudo apt install apt-transport-https ca-certificates curl software-properties-common
```

### 1.3: Add Docker’s official GPG key and repository

```shell
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
```

### 1.4: Install Docker

```shell
sudo apt update
sudo apt install docker-ce
```
```shell
sudo usermod -aG docker ctibutler
sudo newgrp docker
```

## 2 Install Docker Compose

```shell
sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

## 3. Install ArangoDB using Docker

### 3.1 Pull the ArangoDB Docker image

```shell
docker pull arangodb/arangodb:latest
```

### 3.2 Make a directory to ensure persistent storage

```
sudo mkdir -p /var/lib/arangodb_data
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
sudo apt install git
cd /etc
git clone https://github.com/muchdogesec/ctibutler.git
cd ctibutler
```

### 5. Run the app

Setup your env file with variables

```shell
cp .env.example .env
vi .env
```

Changing

```
ARANGODB_HOST_URL='http://host.docker.internal:8529'
ARANGODB_USERNAME=root
ARANGODB_PASSWORD=yourpassword
```

Replace `yourpassword` with what you set earlier

```shell
docker compose build
docker compose up -d
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
```

To ensure config is saved when changed install iptables-persistent: 

```shell
sudo apt-get install iptables-persistent
sudo sh -c "iptables-save > /etc/iptables/rules.v4"
sudo sh -c "ip6tables-save > /etc/iptables/rules.v6"
```