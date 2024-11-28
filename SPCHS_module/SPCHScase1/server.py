#coding=utf-8


import socket
import test_SPCHS_mod
import string
import random
import struct
import time
import pickle


def init_SPCHS():
    #on server only Init ECC
    test_SPCHS_mod.Init()


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

sock = socket.socket(socket.AF_INET)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#   On my Alibaba Cloud Elastic Compute Service
print("bind port...")
sock.bind(("192.168.1.113", 34222))
print("bind success ,start listening ...")
sock.listen(10)

init_SPCHS()
conn, addr = sock.accept()
data = recv_data(conn)
times = struct.unpack("!i", data)[0]
data_out = b"aaaaaaffff"
send_data(conn, data_out)
time1 = 0
for i in range(times):
    data = recv_data(conn)
    #send_data(conn, data_out)
    t11 = int(round(time.time() * 1000))
    data = pickle.loads(data)
    data_out = test_SPCHS_mod.Case1EncPairing(data[0], data[1])
    t12 = int(round(time.time() * 1000))
    time1 += t12 - t11
    data_out = pickle.dumps(data_out)
    send_data(conn, data_out)
print("process time:%f" % (time1/times))

conn.close()
sock.close()
