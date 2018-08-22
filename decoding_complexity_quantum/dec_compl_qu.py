'''
Created on Oct 18, 2017

@author: Dominik Leichtle, Technische Universiteit Eindhoven, dominik.leichtle@web.de
'''

# imports
from math import log, floor, ceil
from scipy.optimize import minimize
import numpy as np

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

# Gilbert-Varshamov bound
# see Bernstein et al: Post-Quantum Cryptography, chapter on code-based
def gvdist(n, r):

    #print "gvdist:", n, r

    if (r >= n) or (r <= 0) or (n <= 0):
        print "gvdist: warning"
        return

    sum = 0
    i=0
    two_to_r = 2**r
    while sum <= two_to_r:
        sum += binom(n,i)
        i += 1
    return i-1

# size of the spaces for the lossy function based on random codes (in bits)
# S = H*s
# where S in F_2^r, H in F_2^{r x n}, s in F_{2,w}^n (wt(s) = w)
def lspace(r):
    return float(r)

def rspace(n, w):
    return 1/log(2) * (n*log(n) - w*log(w) - (n-w)*log(n-w))

# binary entropy
"""def H2(x):
    return -x*log(x,2)-(1-x)*log(1-x,2)"""
def H2(x):
    if x<=0 or x>=1:
        return 0.0
    else:
        return -x*log(x,2)-(1-x)*log(1-x,2)


# MMTQW decoding complexity
# see Kachigar et al: Quantum Information Set Decoding Algorithms (2017), Theorem 4
def beta(R, l, p, dp):
    return 6./5*(R+l)*H2((p/2.+dp)/(R+l)) - p - (1-R-l)*H2(float(dp)/(1-R-l))

def gamma(R, l, p, w):
    return H2(w) - (1.-R-l)*H2(float(w-p)/(1.-R-l)) - (R+l)*H2(float(p)/(R+l))

def aux(R, w, p, dp, l):
    return ( beta(R,l,p,dp) + gamma(R,l,p,w) )/2.

########## test 1 ##########
def test1():
    R = 0.5
    w = 0.11
    p = 0.05
    dp = 0.1
    l = 0.1

    def f_opt(x):
        return aux(R,w,x[0],x[1],x[2])

    x0 = np.array([p,dp,l])

    cons = ({'type': 'ineq',
             'fun' : lambda x: np.array([x[1]]),
             'jac' : lambda x: np.array([0.0,1.0,0.0])},
            {'type': 'ineq',
             'fun' : lambda x: np.array([x[0]]),
             'jac' : lambda x: np.array([1.0,0.0,0.0])},
            {'type': 'ineq',
             'fun' : lambda x: np.array([x[2]]),
             'jac' : lambda x: np.array([0.0,0.0,1.0])},
            {'type': 'ineq',
             'fun' : lambda x: np.array([ R+x[2]-x[0]-x[1] ]),
             'jac' : lambda x: np.array([-1.0,-1.0,1.0])},
            {'type': 'ineq',
             'fun' : lambda x: np.array([ min(w,R+x[2])-x[0] ])},
            {'type': 'ineq',
             'fun' : lambda x: np.array([ 1.-R-w+x[0]-x[2] ]),
             'jac' : lambda x: np.array([1.0,0.0,-1.0])},
            {'type': 'eq',
             'fun' : lambda x: np.array([ H2( (x[0]/2.+x[1])/(R+x[2]) ) - 5.0*x[2]/4./(R+x[2]) ])} )

    res = minimize(f_opt, x0, constraints=cons, options={'disp':True})
##############################

def alpha_MMTQW(R, w, opt_disp=False):
    f_opt = lambda x: np.array( aux(R,w,x[0],x[1],x[2]) )

    p = w/2.0 # here should actually be min(w,R+lambda)/2
    l = (1.0-R-w+p)/2.0
    dp = (R+l-p)/10.0
    # there is actually one more equality...

    x0 = np.array([p,dp,l])

    cons = ({'type': 'ineq',
             'fun' : lambda x: np.array([x[1]]),
             'jac' : lambda x: np.array([0.0,1.0,0.0])},
            {'type': 'ineq',
             'fun' : lambda x: np.array([x[0]]),
             'jac' : lambda x: np.array([1.0,0.0,0.0])},
            {'type': 'ineq',
             'fun' : lambda x: np.array([x[2]]),
             'jac' : lambda x: np.array([0.0,0.0,1.0])},
            {'type': 'ineq',
             'fun' : lambda x: np.array([ R+x[2]-x[0]-x[1] ]),
             'jac' : lambda x: np.array([-1.0,-1.0,1.0])},
            {'type': 'ineq',
             'fun' : lambda x: np.array([ min(w,R+x[2])-x[0] ])},
            {'type': 'ineq',
             'fun' : lambda x: np.array([ 1.-R-w+x[0]-x[2] ]),
             'jac' : lambda x: np.array([1.0,0.0,-1.0])},
            {'type': 'eq',
             'fun' : lambda x: np.array([ H2( (x[0]/2.+x[1])/(R+x[2]) ) - 5.0*x[2]/4./(R+x[2]) ])} )

    res = minimize(f_opt, x0, constraints=cons, tol=1e-12, options={'disp':opt_disp})

    # check final status of minimization
    if res.status != 0:
        # probably something went wrong
        print "alpha_MMTQ: warning"
        return

    return res.fun

# the security level in bits (considering the MMTQW quantum algorithm)
def security_level_full_decoding(n, r, w):
    return n*alpha_MMTQW(float(n-r)/float(n),float(w)/float(n),opt_disp=False)

########## test 2 ##########
def test2():
    R = 0.5
    w = 0.11
    print alpha_MMTQW(R, w)
##############################

########## test 3 ##########
# check some parameters
def test3():
    n = 4451
    r = n/2
    w = gvdist(n,r)-1
    print "For the parameters"
    print "n =", n
    print "r =", r
    print "w =", w
    print "the estimated number of operations necessary to solve the syndrome decoding problem equals 2^" + str(n*alpha_MMTQW(float(n-r)/float(n), float(w)/float(n))) + "."

    factor = 1.17 #1.2
    n = int(round(factor*n))
    r = n/2
    print "For the parameters"
    print "n =", n
    print "r =", r
    print "w =", w
    print "the estimated number of operations necessary to solve the syndrome decoding problem equals 2^" + str(n*alpha_MMTQW(float(n-r)/float(n), float(w)/float(n))) + "."
    print "Moreover:"
    print "Size of the left-hand space (in bits):\t", lspace(r)
    print "Size of the right-hand space (in bits):\t", rspace(n,w)
    print "Difference:\t\t\t\t", lspace(r) - rspace(n,w)
##############################

# find parameters matching a certain security level
def find_params_full_decoding(sec_level):
    def aux_check(n):
        r = n/2
        w = gvdist(n,r)-1
        return n*alpha_MMTQW(float(n-r)/float(n),float(w)/float(n),opt_disp=False) >= sec_level

    upper = 1000
    lower = 2
    while True:
        if aux_check(upper):
            break
        else:
            lower = upper
            upper *= 2

    while upper > lower+1:
        mid = (upper+lower)/2
        if aux_check(mid):
            upper = mid
        else:
            lower = mid

    n = upper
    r = n/2
    w = gvdist(n,r)-1
    return (n, r, w)

# find parameters matching a certain security level and with a certain gap between lspace and rspace
# this algorithm will minimize the length of codewords
def find_params_gap(sec_level, gap):
    def aux_check(n):
        r = n/2
        # compute the GV bound
        w_gv = gvdist(n,r)-1
        # compute the bound for w regarding the gap
        def aux_aux_check(w):
            return r >= n*H2(float(w)/float(n))+gap
        if not aux_aux_check(1):
            w_gap = 0
        else:
            w_lower = 1
            w_upper = r
            while w_lower < w_upper-1:
                w_mid = (w_upper + w_lower)/2
                if aux_aux_check(w_mid):
                    w_lower = w_mid
                else:
                    w_upper = w_mid
            w_gap = w_lower
        w_max = min(w_gv, w_gap)
        # check the security requirements
        if n*alpha_MMTQW(float(n-r)/float(n),float(w_max)/float(n),opt_disp=False) >= sec_level:
            b = True
            w = w_max
        else:
            b = False
            w = 0
        return (b,w)

    upper = 1000
    lower = 2
    while True:
        if aux_check(upper)[0]:
            break
        else:
            lower = upper
            upper *= 2

    while upper > lower+1:
        mid = (upper+lower)/2
        b, w_temp = aux_check(mid)
        if b:
            upper = mid
            w = w_temp
        else:
            lower = mid

    n = upper
    r = n/2
    return (n, r, w)

########## test 4 ##########
def test4():
    print find_params_full_decoding(128)
    print find_params_gap(128, 256)

##############################

if __name__ == '__main__':
    #test2()
    #test3()
    test4()

