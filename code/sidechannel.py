from pwn import *

import matplotlib.pyplot as plt

import time

context.log_level = "warning"

def get_t(p):
    start = time.time()
    p.recvuntil(b"Game ")
    p.readline()
    p.readline()
    end = time.time()
    return (end - start) * 1000

def calc_threshold(connector, samples=100):
    hits = []
    while len(hits) < samples:
        try:
            p = connector()
            get_t(p)
            p.sendline("0".encode())

            tt = get_t(p)
            p.sendline("1".encode())
            
            p.recvuntil(b"Game 2")

            p.close()
            hits.append(tt)

            if len(hits) % 1 == 0:
                print("got", len(hits), "/", samples, "hits")
        except KeyboardInterrupt:
            return
        except:
            try:
                p.close()
            except:
                pass
    
    misses = []
    while len(misses) < samples:
        try:
            p = connector()
            get_t(p)
            p.sendline("0".encode())

            tt = get_t(p)
            p.sendline("0".encode())
            
            p.recvuntil(b"Game 2")

            p.close()
            misses.append(tt)

            if len(misses) % 1 == 0:
                print("got", len(misses), "/", samples, "misses")
        except KeyboardInterrupt:
            return
        except:
            try:
                p.close()
            except:
                pass
        
    
    plt.scatter(list(range(len(hits))), hits, label="hits")
    plt.scatter(list(range(len(misses))), misses, label="misses")
    
    hits.sort()
    misses.sort()
    
    threshold = (hits[samples // 2] + misses[samples // 2]) / 2
    
    plt.plot([0, len(hits) - 1], [threshold, threshold], label="threshold")
    plt.legend()
    plt.show()

    return threshold



def try_solve(p):
    for i in range(100):
        try:
            tt = get_t(p)
            # print(tt)
            r = str((tt > threshold).real)
            p.sendline(r.encode())
        except:
            print(f"-> fail @ {i}")
            return False
    return True

cons = lambda: remote("challs.nusgreyhats.org", 35101) # process(["python3", "server.py"]) # 

threshold = calc_threshold(cons, samples=100)

print("--- THRESHOLD ---")
print(" ->", threshold)
print("")

try_no = 0
while True:
    try_no += 1
    print("try", try_no)
    p = cons()
    
    if try_solve(p):
        p.interactive()
        quit()
