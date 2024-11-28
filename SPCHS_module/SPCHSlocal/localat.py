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
    _,g,_,P,_,s = test_SPCHS_mod.SysSetupAt()
    _,Pub,_,u = test_SPCHS_mod.StruInitAt(g)

def do_test_benchmark(time1 = 20 , time2 = 40):
    time_net = 0.0
    time_cal = 0.0
    time_cal_after_pairing = 0.0
    time_cal_local = 0.0
    counter = 0
    keyword_list = [random_string() for i in range(time1)]
    times = time1 * time2
    for j in range(time2):
        for keyword in keyword_list:
            keyword_b = keyword.encode('ascii')
            t11 = int(round(time.time() * 1000))
            ret1 = test_SPCHS_mod.CaseEncLocalAt(P,g,u ,keyword_b)
            t12 = int(round(time.time() * 1000))
            time_cal += t12 - t11
    print("time for %f \n" % (time_cal/times))
def test_SPCHS():
    for i in range(1,10):
        import test_SPCHS_mod
        init_SPCHS()
        do_test_benchmark()
if __name__ == "__main__":
    random.seed(123)
    test_SPCHS()