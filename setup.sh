echo Set up env

sudo apt update
sudo apt upgrade -y
sudo apt install -y clang bpfcc-tools llvm
sudo apt install -y libc6-dev-i386 libjansson-dev libelf-dev linux-tools-common
sudo apt install -y linux-headers-$(uname -r) linux-tools-$(uname -r) liblog4c-dev iperf3

echo Install libbpf v1.3.0

cd ~
git clone https://github.com/libbpf/libbpf.git
cd libbpf/src
git checkout v1.3.0
sudo make install
