#coding=utf-8

import test_SPCHS_mod
import string
import random
import struct
import time
import hashlib
import pickle

PRINTABLE_CHR = string.ascii_letters
g = b""
P = b""
s = b""
Pub = b""
u = b""

def random_string():
    str_len = random.randint(5, 20)
    return "".join(random.choices(PRINTABLE_CHR, k=str_len))

def init_SPCHS():
    global g , P , s , Pub , u
    test_SPCHS_mod.Init()
    _,g,_,P,_,s = test_SPCHS_mod.SysSetup()
    _,Pub,_,u = test_SPCHS_mod.StruInit(g)

def do_test_benchmark(times=200):
    time_cal = 0.0
    t11 = int(round(time.time() * 1000))
    ret1 = test_SPCHS_mod.Iospeed(g)
    ret1 = test_SPCHS_mod.Iospeed(P)
    t12 = int(round(time.time() * 1000))
    time_cal += t12 - t11
    print("time for %f \n" % (time_cal/times/2))

if __name__ == "__main__":
    init_SPCHS()
    do_test_benchmark()

