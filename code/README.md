# Covert Storage Channel that exploits Protocol Field Manipulation using AA Flag field in DNS [Code: CSC-PSV-DNS-AAF] 

Our covert channel manipulates AA flag field in DNS. We send and receive data through this flag. 

CAPACITY: 38 - 40 bits per second average


Our algorithm encodes the message in a certain format when sending and decodes on the receiver side. 


Our implementation takes 2 parameters:
first_input = initial value of encoder integer
number_bit = number of bits to process each turn


PARAMETER CONSTRAINTS:
number_bit > 0
first_input and number_bit are integers.
Same parameters should be passed to both send and receive functions.  


We send the message char with the following formula:

message = char to send
a = encoder integer (given as a parameter for the first turn)
final = encoded message char to send
number_bit = number of bits to process each turn
modulo = 2^number_bit 

final = (message - a + modulo) % modulo
a = (a + message) / 2

If the last number isn't completely filled with encoded data, we pad the remaining part with randomly generated bits since we send the data as numbers containing number_bit bits. 


We receive the message with the following formula:

message = received encoded data (contains number_bit bits)
a = encoder integer (given as a parameter for the first turn)
final = received message char
number_bit = number of bits to process each turn
modulo = 2^number_bit

final = (message + a) % modulo
a = (a + message) / 2

After obtaining final message, we append it to a holder bit list. Then, we read it as bytes. The program is finished when '.' char is received.




