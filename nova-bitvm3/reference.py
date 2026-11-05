#!/usr/bin/env python3
"""Dependency-free Boolean mirror. This tests kernels, not Nova proof verification."""
import json
import random
import time
import unittest

P = int('40000000000000000000000000000000224698fc094cf91b992d30ed00000001', 16)
Q = int('40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001', 16)

def bits(x, n):
    return [(x >> i) & 1 for i in range(n)]

def sub(a, b):
    out, borrow = [], 0
    for x, y in zip(a, b):
        t = x ^ y
        out.append(t ^ borrow)
        borrow = ((1 ^ x) & y) ^ ((1 ^ t) & borrow)
    return out, borrow

def add(a, b, p):
    carry, out = 0, []
    for x, y in zip(a, b):
        t = x ^ y
        out.append(t ^ carry)
        carry = (x & y) ^ (t & carry)
    reduced, borrow = sub(out, p)
    return [r ^ (borrow & (r ^ s)) for r, s in zip(reduced, out)]

def predicate(a, b, z, modulus, multiply=False, width=256):
    if any(type(x) is not int or x < 0 or x >= 1 << width for x in (a, b, z)):
        raise ValueError('input is not a fixed-width unsigned word')
    aa, bb, zz, pp = (bits(x, width) for x in (a, b, z, modulus))
    valid = sub(aa, pp)[1] & sub(bb, pp)[1] & sub(zz, pp)[1]
    if multiply:
        result = [0] * width
        for i in reversed(range(width - 1)):
            result = add(add(result, result, pp), [x & bb[i] for x in aa], pp)
    else:
        result = add(aa, bb, pp)
    eq = 1
    for x, y in zip(result, zz):
        eq &= 1 ^ (x ^ y)
    return bool(valid & eq)

class KernelTests(unittest.TestCase):
    def test_exhaustive_small_add(self):
        for a in range(32):
            for b in range(32):
                for z in range(32):
                    self.assertEqual(predicate(a,b,z,13,width=5), a<13 and b<13 and z<13 and z==(a+b)%13)
    def test_exhaustive_small_mul(self):
        for a in range(32):
            for b in range(32):
                for z in (0, 1, 12, 13, 31, (a*b)%13):
                    self.assertEqual(predicate(a,b,z,13,True,5), a<13 and b<13 and z<13 and z==(a*b)%13)
    def test_full_width_edges(self):
        for p in (P,Q):
            for a,b in ((0,0),(p-1,1),(p-1,p-1),(1,1)):
                self.assertTrue(predicate(a,b,(a+b)%p,p))
                self.assertFalse(predicate(a,b,(a+b+1)%p,p))
    def test_all_wrong_output_bits(self):
        for p in (P,Q):
            a,b=12345,67890
            for bit in range(256):
                self.assertFalse(predicate(a,b,(a+b)^(1<<bit),p))
    def test_noncanonical_all_ports(self):
        for p in (P,Q):
            for bad in (p,p+1,1<<255,(1<<256)-1):
                for pos in range(3):
                    v=[0,0,0]; v[pos]=bad
                    self.assertFalse(predicate(*v,p))
    def test_random_additions(self):
        r=random.Random(20261106)
        for p in (P,Q):
            for _ in range(64):
                a,b=r.randrange(p),r.randrange(p)
                self.assertTrue(predicate(a,b,(a+b)%p,p))
    def test_full_width_multiplication(self):
        r=random.Random(317)
        for p in (P,Q):
            for a,b in ((0,p-1),(p-1,p-1),(r.randrange(p),r.randrange(p))):
                z=a*b%p
                self.assertTrue(predicate(a,b,z,p,True))
                self.assertFalse(predicate(a,b,(z+1)%p,p,True))
            for v in ((p,0,0),(0,p,0),(0,0,p),(0,1<<255,0)):
                self.assertFalse(predicate(*v,p,True))
    def test_input_bounds(self):
        for bad in (-1,1<<256,True,1.5):
            with self.assertRaises(ValueError): predicate(bad,0,0,P)

if __name__ == '__main__':
    start=time.monotonic()
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(KernelTests))
    print(json.dumps({'scope':'python_boolean_kernel_mirror','tests':result.testsRun,
                      'passed':result.wasSuccessful(),'elapsed_seconds':time.monotonic()-start,
                      'rust_compiled_locally':False,'full_nova_gc_verified':False}))
    raise SystemExit(0 if result.wasSuccessful() else 1)
