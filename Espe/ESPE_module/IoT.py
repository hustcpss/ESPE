#coding=utf-8
#accroding to server this module needs this part
import ESPE_module
import string
import struct
import hashlib
import pickle
import pdb
import random , pprint

publickeypath = ""
host = ""
port = ""
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
def random_string():
    str_len = 256
    return "".join(random.choices(PRINTABLE_CHR, k=str_len))

def RSAPlan()
	sock = socket.socket()
    #On my Alibaba Cloud Elastic Compute Service
    sock.connect((host, port))
   	for i in range(sample)
   		plaintext = random_string()
   		ManaPublen , ManaPub , RSADataLen , RSAData ,AESDataLen ,  AESData = ESPE_module.IoTencrypt(plaintext , publickeypath)
   		transfer = pickle.dumps((ManaPub , RSAData , AESData))
   		send_data(sock , transfer)

if __name__ == "__main__":
	RSAPlan()