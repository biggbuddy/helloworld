# !/bin/bash  
cd ~
# echo -n "what is the IP? :"  
# read  IP 
echo -n "what is the domain? :"  
read  V2RAY_DOMAIN   

# echo "writing the hosts....."
# echo "$IP $V2RAY_DOMAIN" >> /etc/hosts

timedatectl set-timezone Asia/Shanghai
timedatectl set-ntp true
timedatectl 
echo "timezone change done...."
apt-get update 
apt install curl socat nginx -y 
systemctl stop nginx 
bash <(curl -L -s https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)

wget https://raw.githubusercontent.com/biggbuddy/helloworld/master/v2ray.json 
wget https://raw.githubusercontent.com/biggbuddy/helloworld/master/nginx.conf

sed -i "s/V2RAY_DOMAIN/$V2RAY_DOMAIN/g" v2ray.json
sed -i "s/V2RAY_DOMAIN/$V2RAY_DOMAIN/g" nginx.conf

cp v2ray.json /usr/local/etc/v2ray/config.json
cp nginx.conf /etc/nginx/sites-available/default

mkdir -p /app/config/ 
wget https://raw.githubusercontent.com/biggbuddy/helloworld/master/acme.sh
chmod u+x acme.sh
./acme.sh --register-account  -m fushcpc@gmail.com --server zerossl
./acme.sh --issue -d $V2RAY_DOMAIN --standalone -k ec-256 
./acme.sh --installcert -d $V2RAY_DOMAIN --fullchainpath /app/config/v2ray.crt --keypath /app/config/v2ray.key --ecc

systemctl restart nginx && systemctl restart v2ray

echo "installing bbr....."

sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
sysctl -p >/dev/null 2>&1

echo "install successfully....."
echo "rebooting....."
reboot