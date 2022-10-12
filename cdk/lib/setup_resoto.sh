# switching the user
whoami
su - ec2-user
whoami
cd /home/ec2-user 
whoami

# docker setup 
echo "installing docker"
sudo yum update -y
sudo yum install docker -y
sudo usermod -a -G docker ec2-user
newgrp docker

# docker compose setup
echo "installing docker-compose"
wget https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)
sudo mv docker-compose-$(uname -s)-$(uname -m) /usr/local/bin/docker-compose
sudo chmod -v +x /usr/local/bin/docker-compose
sudo systemctl enable docker.service
sudo systemctl start docker.service

# resoto setup
echo "installing resoto"q
mkdir -p resoto/dockerV2
cd resoto
curl -o docker-compose.yaml https://raw.githubusercontent.com/someengineering/resoto/2.4.3/docker-compose.yaml
curl -o dockerV2/prometheus.yml https://raw.githubusercontent.com/someengineering/resoto/2.4.3/dockerV2/prometheus.yml
docker-compose up -d