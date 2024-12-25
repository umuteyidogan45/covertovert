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
    def send(self, log_file_name, first_input, number_bit):
        """
        - In this function, you expected to create a random message (using function/s in CovertChannelBase), and send it to the receiver container. Entire sending operations should be handled in this function.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name, 16, 16)
        print(binary_message)
        message_to_send_integers = []
        temp_int = 0
        modulo = 2**number_bit
        for i in range(len(binary_message)):
            if i % number_bit == 0 and i != 0:
                print("umut ", temp_int)
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
            print(str_integer)
            for bit in str_integer:
                pkt = IP(dst = "receiver") / UDP() / DNS(aa = int(bit))
                super().send(pkt)
    def receive(self, number_bit, first_input, log_file_name):
        """
        - In this function, you are expected to receive and decode the transferred message. Because there are many types of covert channels, the receiver implementation depends on the chosen covert channel type, and you may not need to use the functions in CovertChannelBase.
        - After the implementation, please rewrite this comment part to explain your code basically.
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
                    print(temp_int)
                    added = (temp_int + first_input)%modulo
                    first_input = (added + first_input) // 2
                    current_number_bit = 0
                    temp_int = 0
                    str_added = bin(added)[2:].zfill(number_bit)
                    print(str_added)
                    taken_bits += str_added
                    while len(taken_bits) >= 8:
                        chara = self.convert_eight_bits_to_character(taken_bits[:8])
                        taken_bits = taken_bits[8:]
                        message.append(chara)
                        print(chara)
                        if chara == '.':
                            is_dot_detected = True
                            break
        def stop_filter(packet):
            return is_dot_detected
        sniff(prn = packet_call_back, stop_filter = stop_filter,filter="udp port 53")
        self.log_message("".join(message), log_file_name)
