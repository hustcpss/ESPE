#coding=utf-8
"""
This part just simply test method
"""
import string
import test_SPCHS_mod
import pdb
if __name__ == "__main__":
		"""
		test_SPCHS_mod.Init()
		_,g,_,P,_,s = test_SPCHS_mod.SysSetup()
		print("g : " , g)
		_,Pub,_,u = test_SPCHS_mod.StruInit(g)
		print("pub : " ,Pub)
		print("u : " ,u)
		w = b"DongliLiu"
		#pdb.set_trace()
		for i in range(1,3):
			ret1 = test_SPCHS_mod.Case1EncModCalc(P,g,w)
			print(ret1)
			if ret1[0] == 0 :
					find_ret,_,per,_,hwer,_,ptuw,_,r3,_,c2 = ret1
					_,ret2 = test_SPCHS_mod.Case1EncPairing(per , hwer)
					print(ret2)
					Cipher = test_SPCHS_mod.Case1EncPairingafter(r3,ptuw,ret2,u)
					print(Cipher)
		for i in range(1,3):
			ret1 = test_SPCHS_mod.Case2EncModCalc(P,g,w)
			print("ret1 \n" , ret1)
			if ret1[0] == 0:
				find_ret,_,per,_,hwer,_,ptuw,_,r3,_,c2 = ret1
				_,ret2 = test_SPCHS_mod.Case2EncPairing(per , hwer)
				print("ret2 \n" , ret2)
				Cipher = test_SPCHS_mod.Case2EncPairingafter(find_ret ,r3,ptuw,ret2,u)
				print("Cipher \n" ,Cipher)
			else:
				find_ret,_,per,_,hwer,_,ptuw,_,r3,_,c2,_,c1 = ret1
				_,ret2 = test_SPCHS_mod.Case2EncPairing(per , hwer)
				print("ret2 \n" , ret2)
				Cipher = test_SPCHS_mod.Case2EncPairingafter(find_ret ,r3,ptuw,ret2)
				print("Cipher \n" ,Cipher)
		ret = test_SPCHS_mod.CaseEncLocal(P,g, u, w)
		print(ret)
		"""
		test_SPCHS_mod.Init()
		_,g,_,P,_,s = test_SPCHS_mod.SysSetupAt()
		ret = test_SPCHS_mod.Case3StruInitAt(g)
		#print(ret)
		_,Pub,_,u,_,r1,_,g_r1 = ret
		w = b"DongliLiu"
		Ciphers = {}
		Ans = {}
		for i in range(3):
			ret1 = test_SPCHS_mod.Case3EncModCalcAt(w)
			#print("ret1 :",ret1)
			find_ret, _ , H_W , _ , r2 = ret1
			#print("find_ret : " , find_ret)
			#print(" ")
			_,ret2 = test_SPCHS_mod.Case3EncPairingAt(P , H_W)
			#print("ret2 : " , ret2)
			Cipher = test_SPCHS_mod.Case3EncPairingafterAt(find_ret , r1, r2, g_r1,ret2,u)
			print("gen Cipher :" ,Cipher)
			print(" ")
			Ciphers[Cipher[1]]=Cipher
		#print("Ciphers :" ,Ciphers)
		print("Searching Cipher ...")
		print(" ")
		_ , Tw = test_SPCHS_mod.TrapDoorAt(s , w)
		#pdb.set_trace()
		_ , Pt = test_SPCHS_mod.Case3StruSearchAt(Pub , Tw)
		#print("Pt: " ,Pt)
		for ci in Ciphers:
			print("Pt: " ,Pt)
			print(" ")
			print("C[1]: " ,ci)
			print(" ")
			if Pt ==  ci:
				print("find Cipher")
				Ans[ci]= Ciphers[ci]
				_ ,Pt = test_SPCHS_mod.Case3StruSearchAt(Ciphers[ci][3] , Tw)
		print("find :" , len(Ans))
		print(" ")
		for i in Ans:
			print("Cipher : " , Ans[i])
			print(" ")

					