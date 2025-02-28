# ****DDoS Defender Tool

#### This tutorial for Linux Debian, Kali Linux or Ubuntu only.

### How to install?

1. Clone this source code to your server

   `git clone https://github.com/craftgirlsss/DDoS-Defender`
2. Install Package to your server

   `sudo apt update && apt upgrade -y`

   `sudo apt install libpcap-dev`

   `cd DDoS-Defender`
3. Compile C program with GCC

   `gcc dos defender_libpcap.c -lpcap -o defender_pcap`
4. Run compiled file

   `sudo nohup ./defender_pcap > defender.log 2>&1 &`
5. Check this program is running or not

   `ps aux | grep defender_pcap`

   if this program is running, will show this message

   `[username] [PID] 0.0 0.1 1233 ? Ss 10:00 0:00 ./dos_defender_pcap `
