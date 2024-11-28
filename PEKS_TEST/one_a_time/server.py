#coding=utf-8


import socket
import TEST_PEKS
import string
import random
import struct
import time
import pickle


A_PARAM = '''type a\nq 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\nh 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\nr 730750818665451621361119245571504901405976559617\nexp2 159\nexp1 107\nsign1 1\nsign0 1'''
PEKS_G = b""
PEKS_H = b""

def init_PEKS(param):
    global PEKS_G, PEKS_H
    TEST_PEKS.InitLib(param)
    _, PEKS_G, _, PEKS_H = TEST_PEKS.Get_g_an_h()


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

sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("10.42.0.1", 18233))
sock.listen(10)

init_PEKS(A_PARAM)
conn, addr = sock.accept()
data = recv_data(conn)
times = struct.unpack("!i", data)[0]
data_out = b"aaaaaaffff"
send_data(conn, data_out)
time1 = 0
for i in range(times):
    data = recv_data(conn)
    send_data(conn, data_out)
    t11 = int(round(time.time() * 1000))
    data = pickle.loads(data)
    TEST_PEKS.Pairing_H2(data[0], data[1])
    t12 = int(round(time.time() * 1000))
    time1 += t12 - t11
print("process time:%f" % (time1/times))

conn.close()
sock.close()

