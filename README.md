# fdown
A simple HTTP-based file downloader for Linux written in Python. Achieves 80-90% of WGET's efficiency.

**Overview:**

 fdown is a non-interactive HTTP-based file downloader for Linux constructed using 
 raw sockets (POSIX/Berkley Sockets API) in Python 2.7.
 Originally built for an academic project in a Networks course.

**Execution:**
- This program requires root privileges to execute and hence must be executed using su or sudo.
- NOTE: This program uses TCP over raw sockets. In order to accomodate this, an iptables rule
  is added temporarily during program execution to drop all RST packets to unsolicited incoming 
  TCP packets. Do not run this program if this can cause your computer to become vulnerable during 
  execution.

_./fdown _[_URL_]_

# Development Details
**High level approach:**
- To construct a GET request from the given URL.
- To construct TCP and IP headers based on their RFCs and to use raw sockets
  to send and recieve IP datagrams.
- To implement TCP and its features to communicate with the webservers.
- To order the payload data obtained from the server and to deliver it to the 
  higher layer (HTTP).
- To parse the given url and find a name for the downloaded file and write the
  data to that file.

**TCP/IP features implemented:**
- 60 second timeout before an ACK is resent.
- 180 second timeout before the program prints an error and terminates due to
  no incoming packets from the server.
- Ordering of out-of-order incoming packets before they are delivered to the
  function using the sockets.
- Verification of checksum of incoming packets.

**Challenges faced:**
- Implementing the checksum calculation function correctly took time and the case
  of an odd number of octets was tricky but easily fixable.
- Initially, I did not attach any payload to our SYN packets and they were not 
  getting a server response and wireshark flagged it for wrong checksum. The issue 
  got fixed when I added an empty string as payload.
- Ordering out-of-order incoming packets was non-trivial and had to be done efficiently.
  I implemented a min-heap based technique to order the packets based on the sequence numbers.
