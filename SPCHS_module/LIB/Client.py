#coding=utf-8
#accroding to server this module needs this part
import socket ,ssl
import string
import struct
import hashlib
import pickle
import pdb
import test_SPCHS_mod
import random , pprint
from Crypto.Cipher import AES  
from binascii import b2a_hex, a2b_hex 

g = b""
P = b""
s = b""
Pub = b""
u = b""
g_r1 = b""
r1 = b""
host = "127.0.0.1"
port = 34227
accept	= b"0"
decline	= b"201"
attach 	= b"202"
pairing = b"203"
upload  = b"204"
search 	= b"205"
drop	= b"401"  
class prpcrypt():  
	def __init__(self, key):  
		self.key = key  
		self.mode = AES.MODE_CBC  
	   

	def encrypt(self, text):  
		cryptor = AES.new(self.key, self.mode, self.key)  
		length = 16  
		count = len(text)  
		if(count % length != 0) :  
			add = length-(count % length)
			text = text + ('\0' * add)
		else:  
			add = 0  
		ciphertext = cryptor.encrypt(text)
		return ciphertext  
	   	

	def decrypt(self, text):  
		cryptor = AES.new(self.key, self.mode, self.key)  
		plain_text = cryptor.decrypt(text)  
		return plain_text.decode("utf-8").rstrip('\0')                      

def init_SPCHS():
	#because of its client
    global g , P , s , Pub , u , g_r1 , r1  , pc
    test_SPCHS_mod.Init()
    _,g,_,P,_,s = test_SPCHS_mod.SysSetupAt()
    _,Pub,_,u,_,r1,_,g_r1 = test_SPCHS_mod.Case3StruInitAt(g)
    pc = prpcrypt("1122334455667788")
def send_data(connstream, data):
    data = struct.pack("!i%ds" % (len(data),),
                       len(data),
                       data)
    data_len = len(data)
    while True:
        sent_len = connstream.send(data)
        data_len -= sent_len
        if data_len <= 0:
            break
        data = data[sent_len:]

def recv_data(connstream):
    data = connstream.recv(512)
    data_len, data = struct.unpack("!i%ds" % (len(data)-4,),
                                   data)
    while True:
        if data_len <= len(data):
            break
        data += connstream.recv(512)
    return data

def attach_to_edge(connstream):
	global attach , pairing , upload , searchs , Pub
	connstream.connect((host, port))
	pprint.pprint(connstream.getpeercert())   
	data = (Pub , attach , Pub)
	data = pickle.dumps(data)
	send_data(connstream, data)
	data = recv_data(connstream)
	data = pickle.loads(data)
	print("recive option code")
	if data[0] == accept:
		pairing , upload , searchs  ,drop = data[1 : 5]
		return accept
	else :
		return decline
def upload_to_edge(connstream , keyword , value):
	global pc , r1 ,g_r1 , u , Pub , P 
	#connstream.connect((host, port))
	#pprint.pprint(connstream.getpeercert())    
	#print( "socket connect success , start test" )
	# encrypt value prepupload
	value = pc.encrypt(value)
	print("encrypt success . value:" , value)
	find_ret, _ , H_W , _ , r2 = test_SPCHS_mod.Case3EncModCalcAt(keyword)
	data = pickle.dumps((Pub , upload , P , H_W))
	print("upload data is : ",data)
	send_data(connstream , data)
	data = recv_data(connstream)
	_ ,data = pickle.loads(data)
	print("upload success")
	_ , c1 , _ , c2 = test_SPCHS_mod.Case3EncPairingafterAt(find_ret , r1, r2, g_r1, data ,u)
	data = pickle.dumps((Pub , upload , c1 , c2 , value))
	print("start store . keywordcipher:",(c1,c2))
	print("start store . value :" ,value)
	send_data(connstream , data)
	data = recv_data(connstream)
	#connstream.close()
	if data[0] == accept:
		return accept
	else :
		return decline
def search_on_edge(connstream , keyword):
	global s , pc , Ans
	Ans = ()
	_ , Tw = test_SPCHS_mod.TrapDoorAt(s , keyword)
	#connstream.connect((host, port))  
	#pprint.pprint(connstream.getpeercert())  
	#print( "socket connect success , start test" )

	data = pickle.dumps((Pub, search , Tw))
	send_data(connstream ,data)
	data = recv_data(connstream)
	#connstream.close()
	data = pickle.loads(data)
	data = data[1:len(data)]
	for val in data:
			Ans +=(pc.decrypt(val[0]) , )		
	return Ans
def drop_connection(connstream , keyword):
	data = pickle.dumps((Pub, drop))
	send_data(connstream ,data)
	connstream.close()
# in this method init server and 
def client_init():
	#init_SPCHS enviroment
	init_SPCHS()
	s = socket.socket()
	print( "socket create success" )  
	# require a certificate from the server  
	connstream = ssl.wrap_socket(s,  
                           ca_certs="edgecert.pem",  
                           cert_reqs=ssl.CERT_REQUIRED)
	#pdb.set_trace()
	print("start attach to edge ...")  
	attach_to_edge(connstream)
	print("attach success")  
	keyword = b"flower"
	value = "black_rouse"
	print("start upload to edge ... , keyword : ",keyword , "value : ", value)  
	upload_to_edge(connstream ,keyword , value)
	print("store  success")
	print("start search on edge ... , keyword is : ", keyword)  
	ans  = search_on_edge(connstream ,keyword )
	print("find result . \n" , ans)
	drop_connection(connstream , drop)
# in this method when
if __name__ == "__main__":
	client_init()