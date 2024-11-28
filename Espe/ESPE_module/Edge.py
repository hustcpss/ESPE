#coding=utf-8
#accroding to server this module needs this part
import socket
import ESPE_mod
import string
import struct
import hashlib
import pickle
import pdb
import random , pprint
import sys
import time
ManaPubPath = "./Mana_Pub.pem"
OTHPubPath = "./Other_Pub.pem"
PRINTABLE_CHR = string.ascii_letters
host = "127.0.0.1"
port = 60000
str_len = 163840
sample = 600
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
def random_string():
    
    return "".join(random.choices(PRINTABLE_CHR, k=str_len))
def RSAPlan():
  #data prep
  print("initiall...")
  database =[]
  for i in range(sample):
    plaintext = random_string()
    flag = random.randint(1,1)
    if flag == 1 :
      ManaPublen , ManaPub , RSADataLen , RSAData ,AESDataLen ,  AESData = ESPE_mod.IoTEncrypt(plaintext , ManaPubPath)
    else:
      ManaPublen , ManaPub , RSADataLen , RSAData ,AESDataLen ,  AESData = ESPE_mod.IoTEncrypt(plaintext , OTHPubPath)
    database += [(ManaPub,RSAData,AESData),]
  #prep to seek
  sock = socket.socket(socket.AF_INET)
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  sock.bind((host, port))
  sock.listen(10)

  print("ready to connnect...")
  #seek
  conn, addr = sock.accept()
  data = recv_data(conn)
  seekPub = pickle.loads(data)

  #pdb.set_trace()
  #transfer to cloud
  transfer = []
  t11 = int(round(time.time() * 1000))
  for (i,j,k) in database:
    if i == seekPub[1]:
      transfer += [(i,j,k),]
  t12 = int(round(time.time() * 1000))
  time_cal = t12 - t11
  print("seek time: %f ms \n" %(time_cal))

  transfer = pickle.dumps(transfer)

  datalen = send_data(conn , transfer)

  print("send_data:" , datalen/1024 , "KB")

if __name__ == "__main__":
	RSAPlan()