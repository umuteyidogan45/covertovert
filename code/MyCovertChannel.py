from CovertChannelBase import CovertChannelBase
from socket import socket
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS

from scapy.all import sniff
import time
import random
class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        """
        - You can edit __init__.
        """
        pass
    def send(self, dst,  first_input, number_bit, log_file_name):
        """
        - Parameters: 
        number_bit: integer

        first_input: integer
        
        log_file_name: string

        - Implementation logic:
        We convert the message to binary format and iterate over it. We fill the bits to temp_int until it reaches number_bit bits. 

        Also we calculate a modulo number as modulo = 2^number_bit

        When temp_int is obtained, we encode it according to this format:

        messagetosend = (temp_int - first_input + modulo) % modulo

        And we update first_input variable:

        first_input = (first_input + temp_int) // 2

        Then, we reset temp_int and start filling it again with the following number_bit bits.

        After iterating all binary message, we fill the last number with randomly generated bits if it isn't completely filled with encoded data. 

        As a result, we obtain a list of encoded numbers each containing number_bit bits.

        Then, we iterate over this list and convert the numbers to binary format and add padding. 

        Finally, we send the number as bits over AA flag field in DNS.
        """
        start = time.time()
        binary_message = self.generate_random_binary_message_with_logging(log_file_name, 16, 16)
        message_to_send_integers = []
        temp_int = 0
        modulo = 2**number_bit
        for i in range(len(binary_message)):
            if i % number_bit == 0 and i != 0:
                message_to_send_integers.append((temp_int - first_input + modulo)%modulo)
                first_input = (first_input + temp_int) // 2
                temp_int = 0
            temp_int *= 2
            if binary_message[i] == '1':
                temp_int += 1
        added = (number_bit - len(binary_message)%number_bit)%number_bit
        for i in range(added):
            temp_int *= 2
            temp_int += random.randint(0, 1)
        message_to_send_integers.append((temp_int - first_input + modulo)%modulo)

        
        for integer in message_to_send_integers:
            str_integer = bin(integer)[2:].zfill(number_bit)
            for bit in str_integer:
                pkt = IP(dst = dst) / UDP() / DNS(aa = int(bit))
                super().send(pkt)
        end = time.time()
        print(128/(end - start))

    def receive(self, first_input, number_bit, log_file_name):
        """
        - Parameters: 
        number_bit: integer

        first_input: integer
        
        log_file_name: string

        - Implementation logic:

        We hold the received bits in taken-bits first. 

        When it's bit count reaches number_bit, we start processing it. 

        We obtain the decoded message with this formula:

        added = (temp_int + first_input)%modulo

        Also, we uptade first_input variable:

        first_input = (added + first_input) // 2

        Then, we convert the received number to binary, add padding and add to taken_bits. 

        Finally, we read bytes from taken_bits and append the received char to message until taken_bits' size is smaller than 8.

        When we receive '.' char, we end the program. 

        
        """
        taken_bits = ""
        current_number_bit = 0
        temp_int = 0
        modulo = 2**number_bit
        message = []
        is_dot_detected = False
        def packet_call_back(packet):
            nonlocal taken_bits, current_number_bit, temp_int, message, first_input, number_bit, is_dot_detected
            if DNS in packet:
                aa_flag = packet[DNS].aa
                temp_int *= 2
                temp_int += aa_flag
                current_number_bit += 1
                if current_number_bit == number_bit:
                    added = (temp_int + first_input)%modulo
                    first_input = (added + first_input) // 2
                    current_number_bit = 0
                    temp_int = 0
                    str_added = bin(added)[2:].zfill(number_bit)
                    taken_bits += str_added
                    while len(taken_bits) >= 8:
                        chara = self.convert_eight_bits_to_character(taken_bits[:8])
                        taken_bits = taken_bits[8:]
                        message.append(chara)
                        if chara == '.':
                            is_dot_detected = True
                            break
        def stop_filter(packet):
            return is_dot_detected
        sniff(prn = packet_call_back, stop_filter = stop_filter,filter="udp port 53")
        self.log_message("".join(message), log_file_name)
