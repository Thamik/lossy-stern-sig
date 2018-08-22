'''
Created on Mar 1, 2018

@author: Dominik Leichtle, Technische Universiteit Eindhoven, dominik.leichtle@web.de
'''

# imports
from math import log, floor, ceil
import numpy as np

##################################################

# binomial coefficient (source: wikipedia)
def binom(n, k):
        if k < 0 or k > n:
                return 0
        if k == 0 or k == n:
                return 1
        k = min(k, n - k) # take advantage of symmetry
        c = 1
        for i in range(k):
                c = c * (n - i) / (i + 1)
        return c

# trinomial coefficient
def trinom_aux(n, k1, k2, k3):
        if k1 < 0 or k2 < 0 or k3 < 0 or k1 > n or k2 > n or k3 > n or k1+k2+k3 != n:
                return 0
	# sort to take advantage of the symmetry
	k1, k2, k3 = sorted([k1, k2, k3])
	# special cases
        if k3 == n:
                return 1
	if k1 == 0:
		return binom(n, k2)
        res = 1
        for i in range(k2):
                res = res * (n - i) / (i + 1)
	for i in range(k1):
		res = res * (n - k2 - i) / (i + 1)
        return res

trinom_precomputed = {}

def trinom(n, k1, k2, k3):
	key = (n,k1,k2,k3)
	if key in trinom_precomputed:
		return trinom_precomputed[key]
	elif ((n-1,k1-1,k2,k3) in trinom_precomputed) and ((n-1,k1,k2-1,k3) in trinom_precomputed) and ((n-1,k1,k2,k3-1) in trinom_precomputed):
		# use generalized Pascal's rule
		trinom_precomputed[key] = trinom_precomputed[(n-1,k1-1,k2,k3)] + trinom_precomputed[(n-1,k1,k2-1,k3)] + trinom_precomputed[(n-1,k1,k2,k3-1)]
	else:
		trinom_precomputed[key] = trinom_aux(n,k1,k2,k3)
		return trinom_precomputed[key]

def precompute_trinomials(n_bound):
	for n in range(n_bound+1):
		for k1 in range(n+1):
			for k2 in range(n-k1+1):
				k3 = n - k1 - k2
				trinom(n, k1, k2, k3)

##################################################

# computes the size of the truncated challenge space
# t is the number of parallel repetitions/rounds
# s0, s1, s2 are the sizes of the responses for challenge 0, 1 or 2, respectively
# sr is the size of additional parts of the signature, per round (except for the response, e.g. commitments)
# st is the size of additional parts of the signature (independent of the rounds, e.g. the challenges)
def size_truncated_ch_space(c, t, s0, s1, s2, sr, st):
	m = 0
	for x0 in range(t+1):
		for x1 in range(t-x0+1):
			x2 = t - x0 - x1
			if (st + t*sr + x0*s0 + x1*s1 + x2*s2) <= c:
				m += trinom(t, x0, x1, x2)
	return m

# computes the probability that the signature size is > c
def prob_sig_larger_than(c, t, s0, s1, s2, sr, st):
	return float((3**t) - size_truncated_ch_space(c,t,s0,s1,s2,sr,st))/float(3**t)

# computes the expected signature size
def sig_size_expected(t, s0, s1, s2, sr, st):
	return st + t*sr + t*(s0+s1+s2)/3

# computes the largest possible signature size
def sig_size_upper_bound(t, s0, s1, s2, sr, st):
	return st + t*sr + t*max(s0,s1,s2)

# computes the smallest possible signature size
def sig_size_lower_bound(t, s0, s1, s2, sr, st):
	return st + t*sr + t*min(s0,s1,s2)

# computes the probability for challenge 2 (the least likely) in a single round for truncated signatures
def prob_ch2_single_round(c, t, s0, s1, s2, sr, st):
	s = 0
	e = 0
	for x0 in range(t+1):
		for x1 in range(t-x0+1):
			x2 = t - x0 - x1
			if (st + t*sr + x0*s0 + x1*s1 + x2*s2) <= c:
				temp = trinom(t, x0, x1, x2)
				s += temp
				e += x2 * temp
	return float(e) / float(s) / float(t)

# computes the soundness error of the fixed-size signature scheme with threshold c
def soundness_error(c, t, s0, s1, s2, sr, st):
	return ( 1. - prob_ch2_single_round(c,t,s0,s1,s2,sr,st) ) ** t

# binary search to find the smallest threshold c such that the probability to be above is smaller than given p
# in bits
def optimize_threshold_given_max_exceeding_prob(t, s0, s1, s2, sr, st, p):
	c0 = sig_size_lower_bound(t, s0, s1, s2, sr, st) # smallest possible signature size
	c1 = sig_size_upper_bound(t, s0, s1, s2, sr, st) # greatest possible signature size
	while (c1-c0) > 0.1:
		c_new = (c0+c1)/2.
		if prob_sig_larger_than(c_new, t, s0, s1, s2, sr, st) < p:
			c1 = c_new
		else:
			c0 = c_new
	c_final = int(ceil(c1))
	return c_final

# binary search to find the smallest threshold c such that the soundness error is smaller than given err
# in bits
def optimize_threshold_given_max_soundness_err(t, s0, s1, s2, sr, st, err):
	c0 = sig_size_lower_bound(t, s0, s1, s2, sr, st) # smallest possible signature size
	c1 = sig_size_upper_bound(t, s0, s1, s2, sr, st) # greatest possible signature size
	while (c1-c0) > 0.1:
		c_new = (c0+c1)/2.
		if soundness_error(c_new, t, s0, s1, s2, sr, st) < err:
			c1 = c_new
		else:
			c0 = c_new
	c_final = int(ceil(c1))
	return c_final

##################################################

if __name__ == '__main__':
	# parameters (for the 128-bit pq level)
	t = 438

	# do some precomputation
	precompute_trinomials(438)

	# all values in bits
	s0 = 256 + 256 # seed for random y + seed for random permutation
	s1 = 2966 + 256 # one codeword + seed for random permutation
	s2 = 2966 * 2 # two codewords
	sr = 256 + 256*2 # one (initial) commitment + two times random coins from the commitments
	st = 256 # challenges
	
	# the expected signature size
	c_exp = sig_size_expected(t, s0, s1, s2, sr, st)
	print "Expected signature size: E[|sig|] = %d bits -> %d bytes" % (c_exp, (c_exp+7)/8)
	print "P(|sig| > E[|sig|]) = %f" % prob_sig_larger_than(c_exp, t, s0, s1, s2, sr, st)
	print "-" * 50

	# find the smallest threshold c such that the probability to be above is smaller than given p
	p = 1./float(2**256)
	c_final_p = optimize_threshold_given_max_exceeding_prob(t, s0, s1, s2, sr, st, p)
	print "Acceptable failure probability: p = %e" % p
	print "Found (safe) threshold: c = %d bits -> %d bytes" % (c_final_p, (c_final_p+7)/8)
	print "P(|sig| > c) = %e" % prob_sig_larger_than(c_final_p, t, s0, s1, s2, sr, st)
	print "-" * 50

	# find the smallest threshold c such that the soundness error is smaller than given p
	err = 1./float(2**256)
	c_final_err = optimize_threshold_given_max_soundness_err(t, s0, s1, s2, sr, st, err)
	print "Acceptable soundness error: eps_acc = %e" % err
	print "Found (safe) threshold: c = %d bits -> %d bytes" % (c_final_err, (c_final_err+7)/8)
	print "eps = %e" % soundness_error(c_final_err, t, s0, s1, s2, sr, st)
	print "-" * 50

