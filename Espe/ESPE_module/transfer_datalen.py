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
import numpy as np
import scipy.io as sio
ManaPubPath = "./Mana_Pub.pem"
skeypath = "./Mana_rsa.pem"

Sample_list = [136 , 544 , 2083 , 31245]
AES_length_list = [512 ,]


def KB(num):
	return 1024*num

def main():
	output = {}
	for AES_length in AES_length_list:
		for Sample in Sample_list:
			transfer = ESPE_mod.TestInit(Sample,KB(AES_length),ManaPubPath)
			print("env Sample: %d  , AES_length : %d KB , calc : %d KB "%(Sample , AES_length , transfer))
			if Sample_list.index(Sample) == 0:
				a = np.array([[Sample,transfer],])
			else:
				a = np.r_[a,[[Sample,transfer],]]
		print(a)
		output["KB"+str(AES_length)] = a
	textname = "mattransfer.mat"
	sio.savemat(textname , output)

	return

if __name__ == '__main__':
	main()