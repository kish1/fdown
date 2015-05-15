# imports
import socket
import urlparse
import struct
import random
import heapq
import time
import sys

# global constants
CRLF = '\r\n'

# min-heap
class min_heap():
	# min-heap : Void -> min-heap
	# Returns: An empty min-heap object.
	def __init__(self):
		self.heap = []

	# insert : PosInt -> Void
	# Effect: Adds the given value into the min-heap.
	def insert(self, value):
		heapq.heappush(self.heap, value)

	# pop : Void -> PosInt
	# Returns: The root of the min-heap, ie the minimum value.
	def pop(self):
		if self.heap == []:
			return None
		return heapq.heappop(self.heap)

	# view_top : Void -> PosInt
	# Returns: The root of the min-heap without removing it from the min-heap.
	def view_top(self):
		if self.heap == []:
			return None
		return self.heap[0]

# ip-packet-header
class ip():
	# ip : String, String -> ip
	# Returns: An object initialized with the values for the header.
	def __init__(self, src, dest):
		self.version = 4                                  # IP Version
		self.ih_length = 5                             	  # Internet Header Length
		self.tos = 0                                      # Type of Service
		self.tl = 0                                       # Total Length
		self.id = 42872                                   # Packet ID
		self.flags = 0                                    # Flags
		self.offset = 0                                   # Fragment Offset
		self.ttl = 255                                    # Time to live
		self.protocol = socket.IPPROTO_TCP                # Transport Layer Protocol
		self.checksum = 0                                 # Checksum
		self.source = socket.inet_aton(src)               # Source IP Address
		self.destination = socket.inet_aton(dest)         # Destination IP Address

	# pack : Void -> String
	# Returns: An IP header encoded as a string.
	def pack(self):
		version_ih_len = (self.version << 4) + self.ih_length
		flags_offset = (self.flags << 13) + self.offset
		header = struct.pack("!BBHHHBBH4s4s",
					version_ih_len,
					self.tos,
					self.tl,
					self.id,
					flags_offset,
					self.ttl,
					self.protocol,
					self.checksum,
					self.source,
					self.destination)
		return header


# tcp-segment
class tcp():
	# tcp : PosInt, PosInt, PosInt, PosInt, String -> tcp
	# Returns : a TCP segment with values intialized.
	def __init__(self, src_port, dst_port, seq_num, ack_num, payload = ''):
		self.src_port = src_port           # Source Port
		self.dst_port = dst_port           # Destination Port
		self.seq_num = seq_num             # Sequence Number
		self.ack_num = ack_num             # Acknowledgement Number
		self.offset = 5            	   # Data offset 
		self.reserved = 0                  # Reserved
		self.urg = 0                       # Urgent Pointer
		self.ack = 1                       # ACK flag
		self.psh = 0                       # PSH flag
		self.rst = 0                       # RST flag
		self.syn = 0                       # SYN flag
		self.fin = 0                       # FIN flag
		self.window = socket.htons(5840)   # Window size
		self.checksum = 0                  # Checksum
		self.urgp = 0                      # Urgent Pointer
		self.payload = payload             # Payload

	# set_syn : Void -> Void
	# Effect: Sets the SYN flag.
	def set_syn(self):
		self.syn = 1

	# clear_ack : Void -> Void
	# Effect: Clears the ACK flag.
	def clear_ack(self):
		self.ack = 0

	# set_fin : Void -> Void
	# Effect: Sets the FIN flag.
	def set_fin(self):
		self.fin = 1

	# pack : String, String -> String
	# Returns: A TCP segment encoded as a string.
	def pack(self, src_ip, dest_ip):
		data_offset = (self.offset << 4) + 0
		flags = self.fin + (self.syn << 1) + (self.rst << 2) + (self.psh << 3) + (self.ack << 4) + (self.urg << 5)
		tcp_header = struct.pack('!HHLLBBHHH',
					 self.src_port,
					 self.dst_port,
					 self.seq_num,
					 self.ack_num,
					 data_offset,
					 flags,
					 self.window,
					 self.checksum,
					 self.urgp)

		# Fields for Pseudo-header
		source_ip = socket.inet_aton(src_ip)
		destination_ip = socket.inet_aton(dest_ip)
		reserved = 0
		protocol = socket.IPPROTO_TCP
		total_length = len(tcp_header) + len(self.payload)
		
		# Construction of Pseudo-header 
		psh = struct.pack("!4s4sBBH",
			  source_ip,
			  destination_ip,
			  reserved,
			  protocol,
			  total_length)

		psh = psh + tcp_header + self.payload
		tcp_checksum = checksum(psh)

		tcp_header = struct.pack("!HHLLBBH",
				  self.src_port,
				  self.dst_port,
				  self.seq_num,
				  self.ack_num,
				  data_offset,
				  flags,
				  self.window)
		tcp_header += struct.pack('H', tcp_checksum) + struct.pack('!H', self.urgp)		
		return tcp_header + self.payload

# my_socket (Custom client socket built using raw sockets)
class my_socket():
	# my_socket : String, PosInt -> my_socket
	# Returns: A socket object connected to the given IP address and port.
	def __init__(self, ip, port):
		# Socket for sending
		self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

		# Socket for recieving
		self.recieve_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
		self.recieve_sock.setblocking(0)

		# Maximum buffer size for recieving socket
		self.buffer_size = 4096

		# Local IP address of the device currently in use
		self.source_ip = find_local_ip()
		# Destination IP address
		self.dest_ip = ip

		# Source port
		self.source_port = arbitrary_unused_port()
		# Destination port
		self.dest_port = port

		# Current sequence number
		self.seq_num = 1008
		# Current acknowledgement number
		self.ack_num = 0

		# Congestion window size
		self.cwnd = 1

		# Timeout duration before data is resent
		self.ack_timeout_duration = 60
		# Timeout duration before connection is closed due to non-arrival of packets
		self.terminate_timeout = 180

		# True when an ACK needs to be sent, false otherwise.
		self.send_ack = False

		# The expected ACK number for the FIN packet that has been sent out. -1 if FIN is yet to be sent.
		self.teardown_ack = -1
		# True when self.teardown_ack has been recieved and afterward, false otherwise.
		self.teardown_acked = False

		# True when a SYN has been recieved and afterward, false otherwise.
		self.connected = False
		# True when a FIN has been recieved and afterward, false otherwise.
		self.torndown = False

		# Dictionary of unACKed sent packets by expected acknowledgement numbers
		self.unacked = {}

		# Dictionary of data recieved and not yet delivered to recv, by sequence numbers
		self.payload_data = {}
		# Dictionary of the sizes of all the data recieved, by sequence numbers
		self.payload_data_sizes = {}
		# Min-heap for ordering data by sequence numbers
		self.payload_heap = min_heap()

		self.__handshake__()

	# __send__ : String, PosInt, Boolean -> Posint/None
	# Effect: Sends the given packet.
	# Returns: The expected acknowledgement number for a data packet, None for other packets.
	def __send__(self, packet, size, data=True):
		self.send_sock.sendto(packet, (self.dest_ip, self.dest_port))
		if size > 0:

			self.seq_num += size

		if data and (self.seq_num not in self.unacked):

			self.unacked[self.seq_num] = packet

			return self.seq_num
		return None

	# __recieve__ : Void -> None
	# Effect: Recieves packets from the source IP/port and stores them in self.payload_data.
	def __receive__(self):

		response = None
		address = None
		start = time.time()
		now = None
		while not self.teardown_acked:
			try:
				response, address = self.recieve_sock.recvfrom(self.buffer_size)
			except socket.error:
				pass
			if address != None and address[0] == self.dest_ip:
				start = time.time()
				if self.__correct_protocol_and_ports_ackset__(response):
					break

			now = time.time()
			if now - start >= self.terminate_timeout:
				print('No data from the server for the past ' + str(self.terminate_timeout) + ' seconds. Terminating connection.')
				sys.exit(1)

		seqnum, acknum, payload = self.__seqn_ackn_data__(response)

		size = len(payload)

		if acknum in self.unacked:
			self.unacked.pop(acknum)
		elif acknum == self.teardown_ack:
			self.teardown_acked = True

		
		if self.torndown:
			self.send_ack = True
			self.__teardown__()
		
		if seqnum < self.ack_num:
			pass

		elif seqnum > self.ack_num:
			self.send_ack = True
			if size > 0:
				
				if seqnum not in self.payload_data_sizes:
					self.payload_data[seqnum] = payload
					self.payload_data_sizes[seqnum] = size
					self.payload_heap.insert(seqnum)

		elif seqnum == self.ack_num:
			if size > 0:
				self.send_ack = True
				self.ack_num = seqnum + size

				if seqnum not in self.payload_data_sizes:
					self.payload_data[seqnum] = payload
					self.payload_data_sizes[seqnum] = size
					self.payload_heap.insert(seqnum)

				new_ack = seqnum + size
				while new_ack in self.payload_data_sizes:
					new_ack += self.payload_data_sizes[new_ack]
				else:
					self.ack_num = new_ack

		if self.send_ack:
			ack = self.ack_packet()
			self.__send__(ack, 0, False)
			self.send_ack = False
	
		return None

	# increase_cwnd : Void -> Void
	# Effect: Increases cwnd.
	def increase_cwnd(self):
		self.cwnd = min(self.cwnd + 1, 1000)

	# decrease_cwnd : Void -> Void
	# Effect: Decreases cwnd.
	def decrease_cwnd(self):
		self.cwnd = 1

	# send : String -> Void
	# Effect: Sends packets with payload and recieves ACKs for them.
	def send(self, payload):
		data_pkt = self.data_packet(payload)
		expected_ack = self.__send__(data_pkt, len(payload))
		
		start = time.time()
		now = None
		resend = False
		while (not self.torndown) and (expected_ack in self.unacked):
			if resend:
				self.__send__(data_pkt, len(payload))
				resend = False
				start = time.time()
			try:
				self.__receive__()
				pass
			except socket.error:
				pass
			now = time.time()
			if now - start >= self.ack_timeout_duration:
				self.decrease_cwnd()
				resend = True
		self.increase_cwnd() 

	# recv : PosInt -> String
	# Returns: A portion of the payload sent by the server not exceeding the given beffer_length.
	def recv(self, buffer_length):
		size = 0
		buffer = ''
		
		seqn = None
		data = None
		
		fetch_data = False
		while True:
			if not fetch_data:
				seqn = self.payload_heap.pop()
				if seqn == None: 
					fetch_data = True
				else:
					data = self.payload_data[seqn]
					length = len(data)

					if size + length > buffer_length:
						if size != 0:
							self.payload_data[seqn] = data
							self.payload_heap.insert(seqn)
						else:
							diff = buffer_length - size
							residue = data[diff:]
							extract = data[:diff]

							self.payload_data[seqn] = residue
							self.payload_data_sizes[seqnum] = len(residue)
							self.payload_heap.insert(seqn)

							buffer += data
							size += length		
						break

					buffer += data
					size += length

					seqn += length

					if  self.payload_heap.view_top() != seqn:
						fetch_data = True

			if fetch_data:
				if self.torndown:
					self.__teardown__()
					break
				else:
					self.__receive__()
				if seqn == None:
					if self.payload_heap.view_top() != None:
						fetch_data = False
				else:
					if self.payload_heap.view_top() == seqn:
						fetch_data = False
		return buffer

	# retrieve_data : Void -> Void
	# Returns: The data structures for handling the payload from the server.
	# USED ONLY FOR TESTING.
	def retreive_data(self):
		return [self.payload_data, self.payload_heap.heap, self.payload_data_sizes]

	# __handshake__ : Void -> Void
	# Effect: Connects to the server by performing a three-way handshake.
	def __handshake__(self):
		transmit = True
		start = None
		now = None
		while not self.connected:
			if transmit:
				syn = self.syn_packet()
				self.__send__(syn, 1, False)
				transmit = False
				start = time.time()
			try:
				self.__receive__()
			except socket.error:
				pass
			now = time.time()
			if now - start >= self.ack_timeout_duration:
				transmit = True
				self.decrease_cwnd()
		self.increase_cwnd()

	# __teardown__ : Void -> Void
	# Effect: Tears down the existing connection with the server.
	def __teardown__(self):
		transmit = True
		start = None
		now = None
		while not self.teardown_acked:
			if transmit:
				fin = self.fin_packet()
				self.__send__(fin, 0, False)
				transmit = False
				start = time.time()
			try:
				self.__receive__()
			except socket.error:
				pass
			now = time.time()
			if now - start >= self.ack_timeout_duration:
				transmit = True
				self.decrease_cwnd()
		self.increase_cwnd()

	# __seqn_ackn_data__ : String -> (PosInt, PosInt, String)
	# Returns: A 3-tuple containing the sequence number, acknowledgement number
	# and the payload from the given packet.
	def __seqn_ackn_data__(self, packet):
		# ip header is atleast 20 bytes long
		ip_header = packet[0:20]
		 
		iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
		 
		version_ih = iph[0]
		version = version_ih >> 4
		ihl = version_ih & 0xF
		 
		iph_length = ihl * 4
				 
		tcp_header = packet[iph_length:iph_length+20]
		 
		tcph = struct.unpack('!HHLLBBHHH' , tcp_header)
		 
		sequence = tcph[2]
		acknowledgement = tcph[3]

		data_off_reserved = tcph[4]
		tcph_length = data_off_reserved >> 4

		h_size = iph_length + tcph_length * 4
		data_size = len(packet) - h_size
		 
		data = packet[h_size:]
		 
		return (sequence, acknowledgement, data)


	# __correct_protocol_and_ports_ackset__ : String -> Boolean
	# Returns: True if the packet is from the right source and its checksum is correct
	def __correct_protocol_and_ports_ackset__(self, packet):
		ip_header = packet[0:20]
		 
		iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
		 
		version_ih = iph[0]
		version = version_ih >> 4
		ihl = version_ih & 0xF
		 
		iph_length = ihl * 4
		
		protocol = iph[6]
		s_addr = socket.inet_ntoa(iph[8]);
		d_addr = socket.inet_ntoa(iph[9]); 
		 
		tcp_header = packet[iph_length:iph_length+20]

		tcp = packet[iph_length:]
		source_ip = s_addr
		destination_ip = d_addr
		reserved = 0
		proto = protocol
		total_length = len(tcp)
		
		psh = struct.pack("!4s4sBBH",
			  source_ip,
			  destination_ip,
			  reserved,
			  proto,
			  total_length)

		tcph = struct.unpack('!HHLLBBHHH' , tcp_header)
		 
		source_port = tcph[0]
		dest_port = tcph[1]

		sequence = tcph[2]

		data_off_reserved = tcph[4]
		tcph_length = data_off_reserved >> 4

		flags = tcph[5]

		h_size = iph_length + tcph_length * 4
		data_size = len(packet) - h_size

		# side effects
		if bool(flags & (1 << 1)):
			self.connected = True
			self.ack_num = sequence + 1
			self.send_ack = True

		if bool(flags & (1 << 0)):
			self.torndown = True
			self.send_ack = True

		return (protocol == socket.IPPROTO_TCP) and (source_port == self.dest_port) and (dest_port == self.source_port) and bool(flags & (1 << 4)) and (checksum(ip_header) == 0x0)

	# ip_header : Void -> String
	# Returns: An IP header.
	def ip_header(self):
		return ip(self.source_ip, self.dest_ip).pack()

	# syn_packet : Void -> String
	# Returns: A zero payload packet with the SYN flag set.
	def syn_packet(self):
		tcp_obj = tcp(self.source_port, self.dest_port, self.seq_num, self.ack_num)
		tcp_obj.set_syn()
		tcp_obj.clear_ack()
		return self.ip_header() + tcp_obj.pack(self.source_ip, self.dest_ip)

	# ack_packet : Void -> String
	# Returns: A zero payload packet with the ACK flag set
	def ack_packet(self):
		tcp_obj = tcp(self.source_port, self.dest_port, self.seq_num, self.ack_num)
		return self.ip_header() + tcp_obj.pack(self.source_ip, self.dest_ip)

	# fin_packet : Void -> String
	# Returns: A zero payload packet with the FIN and ACK flags set.
	def fin_packet(self):
		tcp_obj = tcp(self.source_port, self.dest_port, self.seq_num, self.ack_num)
		tcp_obj.set_fin()
		self.teardown_ack = self.seq_num + 1
		return self.ip_header() + tcp_obj.pack(self.source_ip, self.dest_ip)

	# data_packet : String -> String
	# Returns: A packet containing the given data as payload and with the ACK flag set.
	def data_packet(self, data):
		tcp_obj = tcp(self.source_port, self.dest_port, self.seq_num, self.ack_num, data)
		return self.ip_header() + tcp_obj.pack(self.source_ip, self.dest_ip)

# checksum : String -> PosInt
# Returns : The internet checksum of the given String.
def checksum(data):
	s = 0
	if len(data) % 2 == 1:
		data = data + '\0'

	for i in range(0, len(data), 2):
		s+= ord(data[i]) + (ord(data[i+1]) << 8)

	while (s >> 16):
		s = (s & 0xFFFF) + (s >> 16)

	s = ~s & 0xFFFF
	return s

# get : String -> String
# Returns: The response to a HTTP GET request sent to the given url.
def get(url):
	host = urlparse.urlparse(url).netloc
	port = 80

	host_header = 'Host: ' + host + CRLF

	request_line = 'GET ' + url + ' HTTP/1.0' + CRLF
	headers = host_header
	request = request_line + headers + CRLF

	s = my_socket(socket.gethostbyname(host), port)

	s.send(request)

	message = ''
	buffer = None
	buffer_length = 5000

	while buffer != '':
		buffer = s.recv(buffer_length)
		message += buffer

	status = None
	try:
		status = message.split(CRLF)[0].split()[1]
	except IndexError:
		pass

	if status != '200':
		print('Status Code was not 200. Exiting program: ' + str(status))
		sys.exit(1)

	return message

# find_loacal_ip : Void -> String
# Returns: The IP address of the device currently active in the local machine.
def find_local_ip():
	s = socket.socket()
	host = socket.gethostbyname('www.ccs.neu.edu')
	s.connect((host, 80))
	ip = s.getsockname()[0]
	s.close()
	return ip

# arbitrary_unused_port : Void -> PosInt
# Returns: An arbitrary unused port in the local system.
def arbitrary_unused_port():
    s = socket.socket()
    s.bind(('', 0))
    s.listen(1)
    port = s.getsockname()[1]
    s.close()
    return port

# payload_from_response : String -> String/None
# Returns: The payload from an HTTP response.
def payload_from_response(http_response):
	if http_response == '':
		return http_response
	return reduce(lambda x,y: x + y, http_response.split(CRLF*2)[1:])

# main : Void -> Void
# Effect: Downloads the file specified by the url given as a command line input.
def main():
	url = sys.argv[1]
	file_name = urlparse.urlparse(url).path.split('/')[-1]
	if file_name == '':
		file_name = 'index.html'
#	print(file_name)
	response = get(url)
	contents = payload_from_response(response)
	fp = open(file_name, 'w+')
	fp.write(contents)
	fp.close()

# Beginning of execution
if __name__ == '__main__':
	main()
