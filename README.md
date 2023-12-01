# sniffer_CSCI
Final project for CSCI 2025
To use this sniffer, type into bash:
$ifconfig
^from this find out the name of your connection, it should be something like "eth0", following a 3 letter number pattern, then type:
$sudo ifconfig e__# up
$sudo ifconfig e__# promisc
this comes with a makefile so just use $make all
then to use it, you must specify how many packets you want to sniff first, then the protocol you wish to investigate and get packets over, I would sugest 6 for TCP:
$./sniffer 3 6
you should now have 3 text files of captured packets if there was any TCP trafic through your network card

