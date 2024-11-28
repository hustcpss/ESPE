#coding=utf-8

import socket
import test_SPCHS_mod
import string
import random
import struct
import time
import hashlib
import pickle

PRINTABLE_CHR = string.ascii_letters
g = b""
P = b""
s = b""
Pub = b""
u = b""

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


def init_SPCHS():
    global g , P , s , Pub , u
    test_SPCHS_mod.Init()
    _,g,_,P,_,s = test_SPCHS_mod.SysSetup()
    _,Pub,_,u = test_SPCHS_mod.StruInit(g)

def do_test_benchmark(times=60):
    time_net = 0.0
    time_cal = 0.0
    time_cal_after_pairing = 0.0
    time_cal_local = 0.0
    counter = 0
    keyword_list = [random_string() for i in range(times)]
    keyword_list = keyword_list + keyword_list + keyword_list
    sock = socket.socket()
    #On my Alibaba Cloud Elastic Compute Service
    sock.connect(("192.168.234.129", 25565))
    #server only calc times
    data = struct.pack("!i", times)
    send_data(sock, data)
    _ = recv_data(sock)

    for keyword in keyword_list:
        keyword_b = keyword.encode('ascii')
        t11 = int(round(time.time() * 1000))
        ret1 = test_SPCHS_mod.Case1EncModCalc(P,g,keyword_b)
        if ret1[0] == 0 :
            find_ret,_,per,_,hwer,_,ptuw,_,r3,_,c2 = ret1
            transfer = pickle.dumps((per , hwer))
            t12 = int(round(time.time()*1000))
            time_cal += t12 - t11
            t21 = int(round(time.time() * 1000))
            #pairing achieve on Cloud or Edge
            send_data(sock, transfer)
            transfer = recv_data(sock)
            _ , transfer = pickle.loads(transfer)
            t22 = int(round(time.time()*1000))
            time_net += t22 - t21
            t31 = int(round(time.time() * 1000))
            _ , c1 , _ ,c3 =test_SPCHS_mod.Case1EncPairingafter(r3 , ptuw , transfer ,u)
            Cipher = (c1 , c2 , c3)
            t32 = int(round(time.time() * 1000))
            time_cal_after_pairing += t32 - t31
        else:
            #if exist time add to cal
            Cipher = (ret1[2] , ret1[4] , ret1[6])
            t12 = int(round(time.time()*1000))
            time_cal_local += t12 - t11
    #local calc time*2
    print("time for mod: %f\ntime for transfering: %f\n time for after_pairing: %f\n time for local: %f\n" % (time_cal/times, time_net/times ,time_cal_after_pairing/times ,time_cal_local/times/2))
    sock.close()

if __name__ == "__main__":
    init_SPCHS()
    do_test_benchmark()
