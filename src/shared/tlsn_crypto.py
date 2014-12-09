from __future__ import print_function
import math, os, binascii, hmac, time, rsa, re
from hashlib import md5, sha1
from shared.tlsn_common import bigint_to_list as bigint_to_list
from shared.tlsn_common import ba2int as ba2int, bi2ba as bi2ba
from shared.tlsn_common import xor as xor, randint as randint, inverse as inverse
from shared.tlsn_common import random_non_zero as random_non_zero
from shared.tlsn_common import generate_prime as generate_prime
from base64 import b64encode,b64decode
from pyasn1.type import univ
from pyasn1.codec.der import decoder
from slowaes import AESModeOfOperation
from slowaes import AES
from shared.tlsn_ssl import TLSNClientSession as TLSNClientSession
from shared.tlsn_ssl import tls_10_prf as tls_10_prf
#*********CODE FOR ENCRYPTION OF PEER TO PEER MESSAGING*******
#encrypt and base64 encode
def ee(msg,pubkey):
    return b64encode(rsa.encrypt(str(msg),pubkey))

#decrypt and base64decode
def dd(cipher,privkey):
    msg = rsa.decrypt(b64decode(cipher),privkey)
    return msg

#********END CODE FOR ENCRYPTION OF PEER TO PEER MESSAGING***

#Not currently in use; useful in any future 'dark mode' implementation
def aes_decrypt_section(ciphertext,server_encryption_key,key_size=16):
    '''Given ciphertext, an array of integers forming a whole number multiple
of blocks (so len(ciphertext) is a multiple of 16),and key server_encryption_key,
return conjoined plaintext as a string/char array, which represents the decryption
of all but the first block. The key size is either 16 (AES128) or 32 (AES256).
'''
    #sanity checks
    if len(ciphertext)%16 != 0:
        raise Exception("Invalid cipher input to AES decryption - incomplete block")
    if len(ciphertext)<32:
        raise Exception("Invalid cipher input to AES decryption - insufficient data, should be at least 32 bytes, but was: ",len(ciphertext)," bytes.")

    #object from slowaes which contains internal decryption algo
    aes = AES()

    #split ciphertext into blocks
    ciphertext_blocks=zip(*[iter(ciphertext)]*16)

    #implementation of decryption in AES-CBC
    #Note:
    decrypted = ''

    #first ciphertext block is used as input; cannot be decrypted
    iput = ciphertext_blocks[0]

    for block in ciphertext_blocks[1:]:
        output = aes.decrypt(block, server_encryption_key, key_size)
        for i in range(16):
            decrypted += chr(iput[i] ^ output[i])
        iput = block

    return decrypted


class Paillier(object):
    '''instantiate with (privkey_bits=...) to generate a new Paillier priv/pubkey pair or
    with (pubkey=...) to import a Paillier pubkey'''
    #making the list of smallprimes larger can even DEcrease performance. Benchmarking required
    def __init__(self, privkey_bits=None, pubkey=None):
        if (privkey_bits and pubkey) or (not privkey_bits and not pubkey):
            raise Exception('Provide either privkey_bits=<bits> or pubkey=<modulus>')
        elif pubkey:
            self.n = pubkey
            self.n_sq = self.n * self.n            
            self.g = self.n+1
            #we pre-compute r^n mod n^2 and use it for every encryption            
            r = randint(self.n-1)
            self.r_pow_n_mod_n_sq = pow(r, self.n, self.n_sq)
            return
        elif (privkey_bits < 1024):
            raise Exception ('Please don\'t be ridiculous. The private key must have be at least 1024 bits these days')          
        if (privkey_bits % 2 != 0): #p and q must be of the same size, need even bitlength
            raise Exception('Can only work with even bitlength keys')
        p = generate_prime(privkey_bits / 2)
        q = generate_prime(privkey_bits / 2)
        print ('Finished with primes')
        self.n = p * q
        self.n_sq = self.n * self.n
        self.g = self.n + 1
        self.l = (p-1) * (q-1)
        self.m = inverse(self.l, self.n)
        r = randint(self.n-1)
        #we pre-compute r^n mod n^2 and use it for every encryption
        self.r_pow_n_mod_n_sq = pow(r, self.n, self.n_sq)

    def encrypt(self, plain):
        return (pow(self.g, plain, self.n_sq) * self.r_pow_n_mod_n_sq) % self.n_sq

    def e_add(self, a, b):
        """Add one encrypted integer to another"""
        return a * b % self.n_sq

    def e_add_const(self, a, n):
        """Add constant n to an encrypted integer"""
        return (a * pow(self.g, n, self.n_sq)) % self.n_sq

    def e_mul_const(self, a, n):
        """Multiplies an ancrypted integer by a constant"""
        return pow(a, n, self.n_sq)

    def decrypt(self, cipher):
        if not self.l:
            raise Exception('You dont have a private key to decrypt')
        x = pow(cipher, self.l, self.n_sq) - 1
        return ((x // self.n) * self.m) % self.n

 



class TLSNClientSession_Paillier(TLSNClientSession):
    def __init__(self, server=None,port=443,ccs=None):
        super(TLSNClientSession_Paillier, self).__init__(server, port, ccs)
        #prepare the secrets right away. Depending on who will be using this class - 
        #auditee or auditor, accordingly secrets will be used
        self.auditee_secret = os.urandom(22)
        self.auditee_padding_secret = random_non_zero(103)
        self.auditee_padded_rsa_half = '\x02' + self.auditee_padding_secret + '\x00'*102 + '\x00\x03\x01' + self.auditee_secret + '\x00'*24        
        
        self.auditor_secret = os.urandom(24)
        self.auditor_padding_secret = random_non_zero(102)
        self.auditor_padded_rsa_half = self.auditor_padding_secret + '\x00'*25 + self.auditor_secret
    
    #overriden
    def set_auditee_secret(self):
        '''Sets up the auditee's half of the preparatory
        secret material to create the master secret.'''
        assert self.client_random and self.server_random,"one of client or server random not set"
        label = 'master secret'
        seed = self.client_random + self.server_random
        pms1 = '\x03\x01'+ self.auditee_secret
        self.p_auditee = tls_10_prf(label+seed,first_half = pms1)[0]
        #encrypted PMS has already been calculated before the audit began
        return (self.p_auditee)
    
    #overriden
    def set_auditor_secret(self):
        '''Sets up the auditor's half of the preparatory
        secret material to create the master secret, and
        the encrypted premaster secret.
        'secret' should be a bytearray of length n_auditor_entropy'''
        assert (self.client_random and self.server_random), "one of client or server random not set"
        label = 'master secret'
        seed = self.client_random + self.server_random
        pms2 = self.auditor_secret
        self.p_auditor = tls_10_prf(label+seed,second_half = pms2)[1]
        return (self.p_auditor)    

      
class Paillier_scheme_auditor():
    def __init__(self, padded_RSA_half, linkdata): #the data which auditee passes in the link
        assert len(linkdata) == (256+513+1026*(3*8+2))
        self.paillier_rounds = []
        N_ba = linkdata[:256]
        self.N = ba2int(N_ba)
        pubkey = linkdata[256:256+513]
        self.P = Paillier(pubkey=ba2int(pubkey))        
        offset = 256+513
        self.n_len = 4096+8        
        for i in range(8):
            d = {}
            d['P2'] = ba2int(linkdata[offset:offset+1026])
            d['P3'] = ba2int(linkdata[offset+1026:offset+2*1026])
            d['P4'] = ba2int(linkdata[offset+2*1026:offset+3*1026])
            offset += 3*1026
            self.paillier_rounds.append(d)
        #for round 9
        PX = ba2int(linkdata[offset:offset+1026])
        offset += 1026
        PA = ba2int(linkdata[offset:offset+1026])
        assert len(linkdata)-offset == 1026
        self.padded_RSA_half = padded_RSA_half #initial value for each round. B for first round
        self.paillier_rounds.append( {'PX':PX, 'PA':PA} )
        self.D = 0 #mask from the previous round        
        
    def do_round(self, round_no, F):
        assert round_no < 8
        N = self.N
        P = self.P
        n_len = self.n_len
        p_rounds = self.paillier_rounds
        if round_no == 0:
            iv = ba2int(self.padded_RSA_half)
        else:
            iv = (F-self.D) % N               
        T2 = P.e_mul_const(p_rounds[round_no]['P2'], iv )
        T3 = P.e_mul_const(p_rounds[round_no]['P3'], pow(iv, 2, N) )
        T4 = P.e_mul_const(p_rounds[round_no]['P4'], pow(iv, 3, N) )
        T5 = P.encrypt( pow(iv, 4, N) )        
        TSum = P.e_add(P.e_add(P.e_add(T2, T3), T4), T5)       
        #apply mask D
        self.D = randint(2**(n_len-2))
        E = P.e_add(TSum, P.encrypt(self.D))
        return E
        
    def do_ninth_round(self, F):
        N = self.N
        P = self.P
        Y = (F-self.D) % N
        B = ba2int(self.padded_RSA_half)
        p_rounds = self.paillier_rounds            
        BY = P.encrypt(B*Y % N)
        BX = P.e_mul_const(p_rounds[8]['PX'], B)
        AY = P.e_mul_const(p_rounds[8]['PA'], Y)
        PSum = P.e_add(P.e_add(BY, BX), AY)
        return PSum
            
                
class Paillier_scheme_auditee():
    def __init__(self, Paillier_obj):
        self.N = None
        self.n_len = 4096+8 #513 bytes
        self.P = Paillier_obj
        self.data_for_auditor = None
        self.K_values = [] #we will need this later for interactive calculations with auditor
        self.X = None #X for 9th round
        self.padded_RSA_half = None
                
    def get_data_for_auditor(self, padded_RSA_half, N_ba):
        self.padded_RSA_half = padded_RSA_half        
        self.N = ba2int(N_ba)
        self.data_for_auditor = bi2ba(self.N, fixed=256) + bi2ba(self.P.n, fixed=513) # contains server pubkey N, Paillier pubkey n and P(A), P(A^2), P(A^3) for each round        
        iv = ba2int(self.padded_RSA_half) #initial value (A for the first round)
        N = self.N
        P = self.P
        n_len = self.n_len
        for i in range(8):
            T1 = pow(iv, 4, N)
            #P2 stand for "part of T2"
            P2 = P.encrypt(4*pow(iv, 3, N) % N)
            P3 = P.encrypt(6*pow(iv, 2, N) % N)
            P4 = P.encrypt(4*iv % N)
            #len(K) < len(n_len) because we add K to another n_len-2 value. The sum must not overflow n
            K = randint(2**(n_len-2))
            #prepare iv for next round (L in the paper)
            iv = (T1 - K) % N
            self.data_for_auditor += bi2ba(P2, fixed=1026) + bi2ba(P3, fixed=1026) + bi2ba(P4, fixed=1026)
            self.K_values.append( {'K':K})
        #round 9
        X = iv
        A = ba2int(self.padded_RSA_half)
        PX = P.encrypt(X)
        PA = P.encrypt(A)
        self.data_for_auditor += bi2ba(PX, fixed=1026) + bi2ba(PA, fixed=1026)
        self.X = X
        #we now have 1KB*(3*8+2) ~26 KB worth of data
        return self.data_for_auditor
        
    def do_round(self, round_no, E):
        assert round_no < 8
        F = self.P.decrypt(E) + self.K_values[round_no]['K']
        return F
    
    def do_ninth_round(self, PSum):
        A = ba2int(self.padded_RSA_half)
        enc_pms = (self.P.decrypt(PSum) + (A * self.X)) % self.N
        return enc_pms 
        
        
            
                       