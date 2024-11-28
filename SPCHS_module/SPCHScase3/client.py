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
g_r1 = b""
r1 = b""
r2 = b""
host = "192.168.1.113"
port = 34222

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
    global g , P , s , Pub , u , g_r1 , r1 ,r2
    test_SPCHS_mod.Init()
    _,g,_,P,_,s = test_SPCHS_mod.SysSetup()
    _,Pub,_,u,_,r1,_,g_r1 = test_SPCHS_mod.Case3StruInit(g)

def do_test_benchmark(time1 = 20 , time2 = 40):
    time_net = 0.0
    time_cal = 0.0
    time_cal_after_pairing = 0.0
    time_cal_local = 0.0
    counter = 0
    sock = socket.socket()
    #On my Alibaba Cloud Elastic Compute Service
    sock.connect((host, port))
    #server only calc times
    keyword_list = [random_string() for i in range(time1)]
    times = time1 * time2
    data = struct.pack("!i", times)
    send_data(sock, data)
    _ = recv_data(sock)
    for j in range(time2):
        for keyword in keyword_list:
            keyword_b = keyword.encode('ascii')
            t11 = int(round(time.time() * 1000))
            ret1 = test_SPCHS_mod.Case3EncModCalc(keyword_b)
            t12 = int(round(time.time()*1000))
            time_cal += t12 - t11
            find_ret, _ , H_W , _ , r2 = ret1
            transfer = pickle.dumps((P , H_W))
            #pairing achieve on Cloud or Edge
            t21 = int(round(time.time() * 1000))
            send_data(sock, transfer)
            transfer = recv_data(sock)
            t22 = int(round(time.time()*1000))
            time_net += t22 - t21
            _ , transfer = pickle.loads(transfer)
            t31 = int(round(time.time() * 1000))
            _ , c1 , _ , c2 = test_SPCHS_mod.Case3EncPairingafter(find_ret , r1, r2, g_r1, transfer ,u)
            t32 = int(round(time.time() * 1000))
            time_cal_after_pairing += t32 - t31
            #Cipher = (c1 , c2 )
    print("time for mod: %f\ntime for transfering: %f\n  " % ((time_cal+time_cal_after_pairing)/times, time_net/times  ))
    sock.close()
def test_SPCHS():
    for i in range(1,10):
        import test_SPCHS_mod
        init_SPCHS()
        do_test_benchmark()
if __name__ == "__main__":
    random.seed(123)
    test_SPCHS()
