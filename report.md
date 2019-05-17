Tom van der Waa
Douwe Huijsmans

# Programming style
We chose a procedural style for the client and server rather than an Object Oriented style. This choice was based on personal preference.

# Utilities
We use a file called bTCP.py, where we store general functions for things like calculating the CRC or making a packet.

## calculate\_checksum
This function uses a lookup table of precomputed values for each possible value of a byte.
This speeds up calculating the checksum, It was implemented according to the pseudo-code for this algorithm from Wikipedia.

## make\_packet
This function takes the fields of the header and the data as input and returns a packet.
It makes the packet using the pack function, using the ! modifier to pack it in network byteorder (big-endian).

# Client-side
The client-side consists of three phases:
1. Connect to the server
2. Send the file
3. Disconnect from the server

## Connecting to the server
Here we implement the three-way handshake.
after sending the syn and receiving the syn-ack
we check if the packet is corrupted.
We decided to drop the packet and wait for a new packet to arrive, relying on the other party's timeout.

