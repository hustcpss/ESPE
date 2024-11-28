#coding=utf-8

import socket
import TEST_PEKS
import string
import random
import struct
import time
import hashlib
import pickle

A_PARAM = '''type a\nq 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\nh 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\nr 730750818665451621361119245571504901405976559617\nexp2 159\nexp1 107\nsign1 1\nsign0 1'''
PEKS_G = b""
PEKS_H = b""
PRINTABLE_CHR = string.ascii_letters + string.digits + string.printable

def send_data(sock, data):
    data = struct.pack("!i%ds" % (len(data),),
                       len(data),
                       data)
    data_len = len(data)
    while True:
        sent_len = sock.send(data)
        data_len -= sent_len
        if data_len <= 0:
            break
        data = data[sent_len:]

def recv_data(sock):
    data = sock.recv(512)
    data_len, data = struct.unpack("!i%ds" % (len(data)-4,),
                                   data)
    while True:
        if data_len <= len(data):
            break
        data += sock.recv(512)
    return data

def random_string():
    str_len = random.randint(5, 20)
    return "".join(random.choices(PRINTABLE_CHR, k=str_len))


def init_PEKS(param):
    global PEKS_G, PEKS_H
    TEST_PEKS.InitLib(param)
    _, PEKS_G, _, PEKS_H = TEST_PEKS.Get_g_an_h()

def do_test_benchmark(times=200):
    time_net = 0.0
    time_cal = 0.0
    counter = 0
    stack = []
    keyword_list = [random_string() for i in range(times)]
    sock = socket.socket()
    sock.connect(("47.52.98.65", 25565))
    data = struct.pack("!i", times)
    send_data(sock, data)
    _ = recv_data(sock)

    for keyword in keyword_list:
        t11 = int(round(time.time() * 1000))
        c1_len, c1, c2_len, c2 = TEST_PEKS.Calculate_gr_hr(PEKS_G, PEKS_H)
        keyword_hash = hashlib.sha256(keyword.encode()).digest()
        cipher = [keyword_hash, c1, c2]

        data = pickle.dumps(cipher)

        t12 = int(round(time.time()*1000))
        time_cal += t12 - t11
        t21 = int(round(time.time() * 1000))
        send_data(sock, data)
        _ = recv_data(sock)
        t22 = int(round(time.time()*1000))
        time_net += t22 - t21

    print("time for calculating: %f\ntime for transfering: %f\n" % (time_cal/times, time_net/times))
    sock.close()

if __name__ == "__main__":
    init_PEKS(A_PARAM)
    do_test_benchmark()
