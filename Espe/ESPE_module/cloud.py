#coding=utf-8
#accroding to server this module needs this part
import socket
import string
import struct
import hashlib
import pickle
import pdb
import random , pprint
import threading

myhost = "127.0.0.1"
myport = 59999
hostlist = [("127.0.0.1" , 60000)]
# in this method when
def send_data(sock, data):
    data = struct.pack("!i%ds" % (len(data),),
                       len(data),
                       data)
    data_lenr = data_len = len(data)
    while True:
        sent_len = sock.send(data)
        data_len -= sent_len
        if data_len <= 0:
            break
        data = data[sent_len:]
    return data_lenr

def recv_data(sock):
    data = sock.recv(512)
    data_len, data = struct.unpack("!i%ds" % (len(data)-4,),
                                   data)
    while True:
        if data_len <= len(data):
            break
        data += sock.recv(512)
    return data

def RSAPlan():

  sock = socket.socket(socket.AF_INET)
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  sock.bind((myhost, myport))

  sock.listen(10)

  conn, addr = sock.accept()
  data = recv_data(conn)

  ManaPub = pickle.loads(data)

  datalist = []

  for (host,port) in hostlist:

    socktemp = socket.socket()
    socktemp.connect((host, port))

    transfer = pickle.dumps(ManaPub)
    send_data(socktemp , transfer)   
    data = recv_data(socktemp)
    data = pickle.loads(data)
    datalist+= data
  transfer = pickle.dumps(datalist)
  datalen = send_data(conn, transfer)
  print("send_data:" , datalen/1024 , "KB")
if __name__ == "__main__":
	RSAPlan()