apt install aptitude
aptitude install  miniupnpc libminiupnpc-dev

apt-get install qt5-default qt5-qmake qtbase5-dev-tools qttools5-dev-tools build-essential libboost-dev libboost-system-dev libboost-filesystem-dev libboost-program-options-dev libboost-thread-dev libssl-dev libdb++-dev
cd /home/user/eclipse-workspace/fenixcoin
cd src
make -f makefile.unix
chmod -R 777 /home/user/eclipse-workspace/fenixcoin/src


touch .fenixcoin/fenixcoin.conf
vim .fenixcoin/fenixcoin.conf
added rpcuser & rpcpassword
start wallet
 ./fenixcoind --daemon -txindex
// check processing
 pidof fenixcoind
//





