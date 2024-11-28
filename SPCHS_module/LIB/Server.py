#coding=utf-8
"""

Task:
	1.recive link request and handler request , if accept give a Hidden Storage space.
	  note: in this part you need to give a sk for private communication .

	2.if upload v||c , store . 

	3.if upload Tw , search in his own space and download
"""
import struct ,pdb
import socket , ssl ,pickle
import test_SPCHS_mod


host = "127.0.0.1"
port = 34227

IotPub 	= {}
Ciphers = {}
accept	= b"0"
decline	= b"201"
attach 	= b"202"
pairing = b"203"
upload  = b"204"
search 	= b"205"
drop	= b"401"
def init_SPCHS():
    #on server only Init ECC
    test_SPCHS_mod.Init()
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

    data = connstream.recv(1024)
    data_len, data = struct.unpack("!i%ds" % (len(data)-4,),
                                   data)
    while True:
        if data_len <= len(data):
            break
        data += connstream.recv(1024)
    return data
# in this method init server and 
def server_init():
	#init_SPCHS enviroment
	init_SPCHS()
	context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
	context.load_cert_chain(certfile = "edgecert.pem" , keyfile = "edgekey.pem" )
	print( "chain load success")
	bindsocket = socket.socket()
	print( "socket create success" )
	bindsocket.bind((host , port))
	print( "socket bind success" )
	bindsocket.listen(10)
	print( "start listening ")
	while True:
		newsocket , fromaddr = bindsocket.accept()
		print( "socket accept one client" )

		connstream = context.wrap_socket(newsocket , server_side = True)
		peer_with_iot(connstream)
		connstream.shutdown(socket.SHUT_RDWR)
# in this method when
def attach_to_iot(data):
	global IotPub
	#attach iot ID and iot Pub
	ret = (decline ,)
	print("recive IotPub :" , data[2])
	IotPub[data[0]] = data[2]
	#give a new space about iot hidden structure , index use cipher hash
	ret = (accept , pairing , upload , search , drop)
	return ret
def save_iot_data(connstream , data):
	global Ciphers
	data = test_SPCHS_mod.Case3EncPairingAt(data[2], data[3])
	print("upload reply , pairing is : ", data)
	data = pickle.dumps(data)
	send_data(connstream , data)
	data = recv_data(connstream)
	data = pickle.loads(data)
	print("recive store request")
	Ciphers[hash(data[2])]=(data[2] , data[3] , data[4])
	ret = (accept , )
	return ret	
def search_iot_data(data):
	global IotPub ,Ciphers
	global Ans
	print("start search . Trapdoor is :",data[2])
	Ans = ()
	_ , Pt = test_SPCHS_mod.Case3StruSearchAt(IotPub[data[0]] , data[2])
		#print("Pt: " ,Pt)
	while hash(Pt) in Ciphers:
		print("find keywordCipher is :" , Ciphers[hash(Pt)])
		Ans += (Ciphers[hash(Pt)][2] ,)
		_ ,Pt = test_SPCHS_mod.Case3StruSearchAt(Ciphers[hash(Pt)][0] , data[2])
	ret = (accept , Ans)
	print("find value ,retun IoT is :" , ret)	
	return ret
def peer_with_iot(connstream):
	while  True:
		print("prepare to recive request ...")
		data = recv_data(connstream)
		data = pickle.loads(data)
		if data[1] == attach:
			print("recive attach request")
			ret = attach_to_iot(data)
			print("attach reply")
		if data[1] == upload:
			print("recive upload request")
			ret = save_iot_data(connstream , data)
			print("store reply")
		if data[1] == search:
			print("recive search request")
			ret = search_iot_data(data)
			print("search reply")
		if data[1] == drop:
			break
		ret = pickle.dumps(ret)
		send_data(connstream, ret)
if __name__ == "__main__":
		server_init()