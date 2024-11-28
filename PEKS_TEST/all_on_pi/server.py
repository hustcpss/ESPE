#coding=utf-8

import socket
import TEST_PEKS
import string
import random
import struct
import time


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

conn, addr = sock.accept()
data = recv_data(conn)
times = struct.unpack("!i", data)[0]
data_out = b"aaaaaaffff"
send_data(conn, data_out)
for i in range(times):
    data = recv_data(conn)
    send_data(conn, data_out)

conn.close()
sock.close()

