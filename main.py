"""Project 1: Password Cracking"""
import hashlib
from itertools import product
import os
import time
from multiprocessing import Process, Value


salt = "4fTgjp6q"[:8]
char = "abcdefghijklmnopqrstuvwxyz"
magic = "$1$"
target_hash = "AY4XvVTQoJWFbv7nJcx/a/"


def md5_crypt(password, salt, magic):
    # Compute the Alternate sum
    alt_sum = hashlib.md5((password + salt + password).encode()).digest()  # md5 string = 16 bytes long

    # Compute the Intermediate sum_0
    intermediate = password.encode() + magic.encode() + salt.encode()

    # compare length of alt_sum & pw, if pw > alt_sum, alt_num need to multiply.
    # Then add length of pw bytes of alt_sum to intermediate
    while len(alt_sum) < len(password):
        alt_sum += alt_sum
    intermediate += alt_sum[:len(password)]
    # step 5: Add 1 byte of password or null byte to intermediate based on password bits
    password_bin = bin(len(password))[2:]
    for bit in password_bin[::-1]:
        if bit == "0":
            intermediate += password[:1].encode()
        else:
            intermediate += b'\x00'
    # compute intermediate sum_0
    intermediate = hashlib.md5(intermediate).digest()

    for j in range(1000):
        new_intermediate = password.encode() if j % 2 == 1 else intermediate
        new_intermediate += salt.encode() if j % 3 != 0 else b''
        new_intermediate += password.encode() if j % 7 != 0 else b''
        new_intermediate += intermediate if j % 2 == 1 else password.encode()
        intermediate = hashlib.md5(new_intermediate).digest()

    final_str = convert_special(intermediate)  # pass intermediate sum_1000 and convert to special base64
    return final_str


def convert_special(inter_sum):
    final = ''
    # select bytes in the specified order
    byte_order = [11, 4, 10, 5, 3, 9, 15, 2, 8, 14, 1, 7, 13, 0, 6, 12]
    byte_list = [inter_sum[i] for i in byte_order]  # hold integer
    crypt_chars = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    # convert byte_list to integer
    num = int.from_bytes(byte_list, byteorder='big') #'big' means using big-endian
    for i in range(22):
        # extract the next 6 bits from the integer
        bits = num & 0x3f
        if i == 22:
            bits = num & 0x3  # no padding for the last 2 bits
        # look up the corresponding crypt character
        crypt = crypt_chars[bits]
        # add the crypt character to the final string
        final += crypt
        num >>= 6  #shift right to remove the least 6 bits for the next round
    return final

def check_combination(first_c, char, length, target, flag):
    for p in product(char, repeat=length):      #generate diff. strings in this length
        combined_text = first_c + "".join(p)    #add the passed character to make it equal to the pw's length
        if flag.value == 1:
            break
        print(combined_text)
        if md5_crypt(combined_text, salt, magic) == target:
            print(f"The password is {combined_text}")
            flag.value = 1
            break
        else:
            print("Not match")

def main():
    start_time = time.time()
    processes = []
    flag = Value('i', 0)
    length = 5
    #parallel checking pw for inside each process, starts with the same character, total of 26 processes
    for c in char:
        processes.append(Process(target=check_combination, args=(c, char, length, target_hash, flag)))
    process_num = len(processes)

    for process in processes:
        process.start()
    for process in processes:
        process.join()

    print('Number of CPUs in the system: {}'.format(os.cpu_count()))
    print(f"Number of processes:          {process_num}")
    end_time = time.time()
    print(f"Time taken:                   {round(end_time - start_time, 3)} sec")
    pw_per_sec = process_num * (len(char) ** length) / (end_time - start_time)    #**gives the total number of
                                    #possible passwords with this length using the characters in the char list.
    print(f"Throughput:                   {round(pw_per_sec, 3)} passwords per second")

if __name__ == "__main__":
    main()