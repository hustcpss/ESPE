#coding=utf-8
#accroding to server this module needs this part
import ESPE_mod
import string
import struct
import hashlib
import pickle
import pdb
import random , pprint
import socket
import time
ManaPubPath = "./Mana_Pub.pem"
skeypath = "./Mana_rsa.pem"
host = "127.0.0.1"
port = 59999
# in this method when
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
def RSAPlan():

  sock = socket.socket()
  sock.connect((host, port))

  ManaPub = ESPE_mod.ManaSelect(ManaPubPath)
  transfer = pickle.dumps(ManaPub)
  send_data(sock , transfer)

  datalist = recv_data(sock)
  datalist = pickle.loads(datalist)
  #pdb.set_trace()
  t11 = int(round(time.time() * 1000))
  for data in datalist:
    AESlen, AES ,plaintextlen, plaintext = ESPE_mod.ManaDecrypt(data[0] , data[1] , data[2] , skeypath)
  t12 = int(round(time.time() * 1000))
  time_cal = t12 - t11
  print("decrypt time: %f ms \n" %(time_cal))

if __name__ == "__main__":
	RSAPlan()