'''
Created on Jan 24, 2018

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


# BJMM decoding complexity
# see Becker et al: Decoding Random Binary Linear Codes in 2^(n/20) (2012), Equations (5) and up
# see computations in my thesis
def aux(K, W, P, L, E1, E2):
    r1 = P * H2(0.5) + (K+L-P) * H2(E1/(K+L-P))
    r2 = (P/2. + E1) * H2(0.5) + (K+L-P/2.-E1) * H2(E2/(K+L-P/2.-E1))
    S1 = (K+L) * H2((P/2.+E1)/(K+L)) - r1
    S2 = (K+L) * H2((P/4.+E1/2.+E2)/(K+L)) - r2
    S3 = (K+L)/2. * H2((P/4.+E1/2.+E2)/(K+L))
    EC1 = 2.*S1 + r1 - L
    EC2 = 2.*S2 + r2 - r1
    EC3 = 2.*S3 - r2

    P = (K+L) * H2(P/(K+L)) + (1-K-L) * H2((W-P)/(1-K-L)) - H2(W)

    return max(S1, S2, S3, EC1, EC2, EC3) - P

##############################

def alpha_BJMM(K, W, opt_disp=False):
    f_opt = lambda x: np.array( aux(K,W,x[0],x[1],x[2],x[3]) )

    # choose initial guess somehow
    x0 = np.array([0.05,0.25,0.02,0.01])

    cons = ({'type': 'ineq',
             'fun' : lambda x: np.array([x[0]]),
             'jac' : lambda x: np.array([1.0,0.0,0.0,0.0])
            },
            {'type': 'ineq',
             'fun' : lambda x: np.array([x[1]]),
             'jac' : lambda x: np.array([0.0,1.0,0.0,0.0])
            },
            {'type': 'ineq',
             'fun' : lambda x: np.array([x[2]]),
             'jac' : lambda x: np.array([0.0,0.0,1.0,0.0])
            },
            {'type': 'ineq',
             'fun' : lambda x: np.array([x[3]]),
             'jac' : lambda x: np.array([0.0,0.0,0.0,1.0])
            },
            {'type': 'ineq',
             'fun' : lambda x: np.array([ 1.-K -x[1] ]),
             'jac' : lambda x: np.array([0.0,-1.0,0.0,0.0])
            },
            {'type': 'ineq',
             'fun' : lambda x: np.array([ 1.-K-W-x[0] -x[1] ]),
             'jac' : lambda x: np.array([-1.0,-1.0,0.0,0.0])
            },
            {'type': 'ineq',
             'fun' : lambda x: np.array([ W -x[0] ]),
             'jac' : lambda x: np.array([-1.0,0.0,0.0,0.0])
            },
            {'type': 'ineq',
             'fun' : lambda x: np.array([ K+x[1] -x[0] ]),
             'jac' : lambda x: np.array([-1.0,1.0,0.0,0.0])
            },
            {'type': 'ineq',
             'fun' : lambda x: np.array([ K+x[1]-x[0] -x[2] ]),
             'jac' : lambda x: np.array([-1.0,1.0,-1.0,0.0])
            },
            {'type': 'ineq',
             'fun' : lambda x: np.array([ K+x[1]-(x[0]/2.+x[2]) -x[3] ]),
             'jac' : lambda x: np.array([-0.5,1.0,-1.0,-1.0])
            },
            {'type': 'ineq',
             'fun' : lambda x: np.array([ (x[0]/2. + x[2]) * H2(0.5) + (K+x[1]-x[0]/2.-x[2]) * H2(x[3]/(K+x[1]-x[0]/2.-x[2])) ])},
            {'type': 'ineq',
             'fun' : lambda x: np.array([ x[0] * H2(0.5) + (K+x[1]-x[0]) * H2(x[2]/(K+x[1]-x[0])) - ((x[0]/2. + x[2]) * H2(0.5) + (K+x[1]-x[0]/2.-x[2]) * H2(x[3]/(K+x[1]-x[0]/2.-x[2]))) ])},
            {'type': 'ineq',
             'fun' : lambda x: np.array([ x[1] - (x[0] * H2(0.5) + (K+x[1]-x[0]) * H2(x[2]/(K+x[1]-x[0]))) ])}
            )

    if not all([ c['fun'](x0) > 0 for c in cons ]):
        print 'alpha_BJMM: warning: x0 does not satisfy all constraints. (Constraints ' + str([ i for i,c in enumerate(cons) if c['fun'](x0) <= 0]) + ')'

    res = minimize(f_opt, x0, constraints=cons, method='SLSQP', tol=1e-12, options={'disp':opt_disp, 'maxiter':1000})

    # check final status of minimization
    if res.status != 0:
        # something went wrong
        print "alpha_BJMM: warning: optimization did not converge."
        print "x = ", res.x
        print "f = ", res.fun

    return res.fun

# the security level in bits (considering the BJMM classical decoding algorithm)
def security_level_full_decoding(n, r, w):
    return n*alpha_BJMM(float(n-r)/float(n),float(w)/float(n),opt_disp=True)

########## test 1 ##########

def test1():
    print "="*50
    print "Test 1"
    n = 2000
    r = n/2
    w = gvdist(n,r)

    print "n =", n
    print "r =", r
    print "w =", w

    alpha = alpha_BJMM(float(n-r)/float(n),float(w)/float(n),opt_disp=True)

    print "alpha_BJMM = ", alpha

########## test 2 ##########

def test2():
    print "="*50
    print "Test 2"
    print "Use typical McEliece Parameters (see BJMM examples/table)"
    print "K = k/n = 0.7577"
    print "W = w/n = 0.04"

    alpha = alpha_BJMM(0.7577,0.04,opt_disp=True)

    print "alpha_BJMM = ", alpha

########## test 3 ##########

# check some parameters
def test3():
    print "="*50
    print "Test 3"
    n = 4451
    r = n/2
    w = gvdist(n,r)-1
    print "For the parameters"
    print "n =", n
    print "r =", r
    print "w =", w
    print "the estimated number of operations necessary to solve the syndrome decoding problem equals 2^" + str(security_level_full_decoding(n,r,w)) + "."

    factor = 1.17 #1.2
    n = int(round(factor*n))
    r = n/2
    print "For the parameters"
    print "n =", n
    print "r =", r
    print "w =", w
    print "the estimated number of operations necessary to solve the syndrome decoding problem equals 2^" + str(security_level_full_decoding(n,r,w)) + "."
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
        return security_level_full_decoding(n,r,w) >= sec_level

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
        if security_level_full_decoding(n,r,w_max) >= sec_level:
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
    print "="*50
    print "Test 4"
    print "Find parameters that achieve a 128-bit (classical) security level"
    res = find_params_full_decoding(128)
    print "(n,r,w) = ", res
    print "Find lossy parameters that achieve a 128-bit (classical) security level with a gap of 128 bits"
    res = find_params_gap(128, 128)
    print "(n,r,w) = ", res

########## test 5 ##########

def test5():
    print "="*50
    print "Test 5"
    n = 1664
    r = 832
    w = 143

    print "n =", n
    print "r =", r
    print "w =", w

    alpha = alpha_BJMM(float(n-r)/float(n),float(w)/float(n),opt_disp=True)

    print "alpha_BJMM = ", alpha
    print "security: 2^" + str(n*alpha)


##############################

if __name__ == '__main__':
    test1()
    test2()
    test3()
    test4()
    test5()

