#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import args, connect, process, log
log.info(f'Precomputing Matrix...')
from sage.all import *
from pwn import log
import server
import param

exe = './server.py'

host = args.HOST or 'challs.nusgreyhats.org'
port = int(args.PORT or 35101)


def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    return process(["python3", exe] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)


# Calculate Solution Matrix

A = Matrix(GF(2), param.A)
I = matrix.identity(GF(2), 64)
ZERO = Matrix(GF(2), 64)
# A,x,r,k = P.gens()


BITS = 16 * 8
# Show poly x
# x_matrix = Matrix(GF(2), [sum(A**i) for i in range(BITS)])

x_matrix = []
current = I
for i in range(BITS):
    x_matrix.append(sum(current))
    current = A * current
x_matrix = Matrix(GF(2), x_matrix)

# r_matrix
current = (I - I) # Null matrix
r_matrix = []
for i in range(BITS):
    r_matrix.append(sum(current))
    current = A * current
    if i % 3 == 0 or i % 3 == 2:
        current += I

r_matrix = Matrix(GF(2), r_matrix)
# k_matrix
current = (I - I)
k_matrix = []
for i in range(BITS):
    k_matrix.append(sum(current))
    current = A * current
    if i % 3 == 1 or i % 3 == 2:
        current += I

k_matrix = Matrix(GF(2), k_matrix)

SOL = x_matrix.augment(k_matrix).augment(r_matrix)


log.success("Precomputing DONE!")


io = start()
with log.progress("Guesses: ") as prog:
    for i in range(100):
        prog.status(f"{i}/100")
        io.recvuntil(b'Output: ')
        rng = server.bytes_to_bits(bytes.fromhex(io.recvline().decode()))
        rng = vector(rng)
        try:
            # If a solution is found:
            SOL.solve_right(rng)
            io.sendline(b'1')
        except ValueError:
            # No solution found
            io.sendline(b'0')


io.interactive()
