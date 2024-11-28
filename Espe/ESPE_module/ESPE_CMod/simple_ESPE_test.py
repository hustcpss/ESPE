#coding=utf-8
#accroding to server this module needs this part
import ESPE_mod
import random , pprint
import string
PRINTABLE_CHR = string.ascii_letters
def random_string():
    str_len = 163840
    return "".join(random.choices(PRINTABLE_CHR, k=str_len))
if __name__ == "__main__":
	sample = 100
	for i in range(sample):
		p = random_string();
		print("plaintext:" , p,'\n');
		ret = ESPE_mod.IoTEncrypt(p,"./pub.pem")
		print("RSAcipher:",ret[2], ret[3],'\n')
		print("AEScipher:",ret[4], ret[5],'\n')
		ret = ESPE_mod.ManaDecrypt(ret[1],ret[3],ret[5],"./rsa.pem")
		print("plaintext:",ret[2],ret[3],'\n')
