import math, os, binascii, hmac
from hashlib import md5, sha1
from tlsn_common import xor

md5_hash_len = 16
sha1_hash_len = 20

def TLS10PRF(seed, req_bytes = 48, first_half=None,second_half=None,full_secret=None):
    '''
    Calculates all or part of the pseudo random function PRF
    as defined in the TLS 1.0 RFC 2246 Section 5. If only first_half or
    second_half are provided, then the appropriate HMAC is returned
    as the first or second element of the returned tuple respectively.
    If both are provided, the full result of PRF is provided also in
    the third element of the returned tuple.
    For maximum clarity, variable names correspond to those used in the RFC.
    Notes:
    The caller should provide one or other but not both of first_half and
    second_half - the alternative is to provide full_secret. This is because
    the algorithm for splitting into two halves as described in the RFC,
    which varies depending on whether the secret length is odd or even,
    cannot be correctly deduced from two halves.
    '''
    #sanity checks, (see choices of how to provide secrets under 'Notes' above)
    if not first_half and not second_half and not full_secret:
        raise Exception("Error in TLSPRF: at least one half of the secret is required.")
    if (full_secret and first_half) or (full_secret and second_half):
        raise Exception("Error in TLSPRF: both full and half secrets should not be provided.")
    if first_half and second_half:
        raise Exception("Error in TLSPRF: please provide the secret in the parameter full_secret.")

    P_MD5 = P_SHA_1 = PRF = None

    #split the secret into two halves if necessary
    if full_secret:
        L_S = len(full_secret)
        L_S1 = L_S2 = int(math.ceil(L_S/2))
        first_half = full_secret[:L_S1]
        second_half = full_secret[L_S2:]

    #To calculate P_MD5, we need at most floor(req_bytes/md5_hash_len) iterations
    #of 'A'. If req_bytes is a multiple of md5_hash_len(16), we will use
    #0 bytes of the final iteration, otherwise we will use 1-15 bytes of it.
    #Note that A[0] is actually A(1) in the RFC, since A(0) in the RFC is the seed.
    if first_half:
        A=[hmac.new(first_half,seed,md5).digest()]
        for i in range(1,int(req_bytes/md5_hash_len)+1):
            A.append(hmac.new(first_half,A[len(A)-1],md5).digest())

        md5_P_hash = ''
        for x in A:
            md5_P_hash += hmac.new(first_half,x+seed,md5).digest()

        P_MD5 = md5_P_hash[:req_bytes]

    #To calculate P_SHA_1, we need at most floor(req_bytes/sha1_hash_len) iterations
    #of 'A'. If req_bytes is a multiple of sha1_hash_len(20), we will use
    #0 bytes of the final iteration, otherwise we will use 1-19 bytes of it.
    #Note that A[0] is actually A(1) in the RFC, since A(0) in the RFC is the seed.
    if second_half:
        A=[hmac.new(second_half,seed,sha1).digest()]
        for i in range(1,int(req_bytes/sha1_hash_len)+1):
            A.append(hmac.new(second_half,A[len(A)-1],sha1).digest())

        sha1_P_hash = ''
        for x in A:
            sha1_P_hash += hmac.new(second_half,x+seed,sha1).digest()

        P_SHA_1 = sha1_P_hash[:req_bytes]

    if full_secret:
        PRF = xor(P_MD5,P_SHA_1)

    return (P_MD5, P_SHA_1, PRF)


''' ** TESTING CODE **
def new_way(seed,pms1,pms2):
    ms = TLS10PRF('master secret'+seed,full_secret=pms1+pms2)[2]
    return TLS10PRF('key expansion'+seed,req_bytes=20,full_secret=ms)[2]

def old_way(seed,pms1,pms2):

    label = "master secret"
    sha1A1 = hmac.new(pms2, label+seed, sha1).digest()
    sha1A2 = hmac.new(pms2, sha1A1, sha1).digest()
    sha1A3 = hmac.new(pms2, sha1A2, sha1).digest()
    sha1hmac1 = hmac.new(pms2, sha1A1 + label + seed, sha1).digest()
    sha1hmac2 = hmac.new(pms2, sha1A2 + label + seed, sha1).digest()
    sha1hmac3 = hmac.new(pms2, sha1A3 + label + seed, sha1).digest()
    shahmac = (sha1hmac1+sha1hmac2+sha1hmac3)[:48]

    #derive MS
    label = 'master secret'
    md5A1 = hmac.new(pms1, label+seed, md5).digest()
    md5A2 = hmac.new(pms1, md5A1, md5).digest()
    md5A3 = hmac.new(pms1, md5A2, md5).digest()
    md5hmac1 = hmac.new(pms1, md5A1 + label + seed, md5).digest()
    md5hmac2 = hmac.new(pms1, md5A2 + label + seed, md5).digest()
    md5hmac3 = hmac.new(pms1, md5A3 + label + seed, md5).digest()
    md5hmac = md5hmac1+md5hmac2+md5hmac3
    ms = xor(md5hmac, shahmac)[:48]
    #derive expanded keys for AES256
    #this is not optimized in a loop on purpose. I want people to see exactly what is going on
    ms_first_half = ms[:24]
    ms_second_half = ms[24:]
    label = 'key expansion'
    md5A1 = hmac.new(ms_first_half, label+seed, md5).digest()
    md5A2 = hmac.new(ms_first_half, md5A1, md5).digest()
    md5A3 = hmac.new(ms_first_half, md5A2, md5).digest()
    md5A4 = hmac.new(ms_first_half, md5A3, md5).digest()
    md5A5 = hmac.new(ms_first_half, md5A4, md5).digest()
    md5A6 = hmac.new(ms_first_half, md5A5, md5).digest()
    md5A7 = hmac.new(ms_first_half, md5A6, md5).digest()
    md5A8 = hmac.new(ms_first_half, md5A7, md5).digest()
    md5A9 = hmac.new(ms_first_half, md5A8, md5).digest()
    #---------#
    md5hmac1 = hmac.new(ms_first_half, md5A1 + label + seed, md5).digest()
    md5hmac2 = hmac.new(ms_first_half, md5A2 + label + seed, md5).digest()
    md5hmac3 = hmac.new(ms_first_half, md5A3 + label + seed, md5).digest()
    md5hmac4 = hmac.new(ms_first_half, md5A4 + label + seed, md5).digest()
    md5hmac5 = hmac.new(ms_first_half, md5A5 + label + seed, md5).digest()
    md5hmac6 = hmac.new(ms_first_half, md5A6 + label + seed, md5).digest()
    md5hmac7 = hmac.new(ms_first_half, md5A7 + label + seed, md5).digest()
    md5hmac8 = hmac.new(ms_first_half, md5A8 + label + seed, md5).digest()
    md5hmac9 = hmac.new(ms_first_half, md5A9 + label + seed, md5).digest()
    md5hmac = md5hmac1+md5hmac2+md5hmac3+md5hmac4+md5hmac5+md5hmac6+md5hmac7+md5hmac8+md5hmac9
    #---------#
    sha1A1 = hmac.new(ms_second_half, label+seed, sha1).digest()
    sha1A2 = hmac.new(ms_second_half, sha1A1, sha1).digest()
    sha1A3 = hmac.new(ms_second_half, sha1A2, sha1).digest()
    sha1A4 = hmac.new(ms_second_half, sha1A3, sha1).digest()
    sha1A5 = hmac.new(ms_second_half, sha1A4, sha1).digest()
    sha1A6 = hmac.new(ms_second_half, sha1A5, sha1).digest()
    sha1A7 = hmac.new(ms_second_half, sha1A6, sha1).digest()
    #---------#
    sha1hmac1 = hmac.new(ms_second_half, sha1A1 + label + seed, sha1).digest()
    sha1hmac2 = hmac.new(ms_second_half, sha1A2 + label + seed, sha1).digest()
    sha1hmac3 = hmac.new(ms_second_half, sha1A3 + label + seed, sha1).digest()
    sha1hmac4 = hmac.new(ms_second_half, sha1A4 + label + seed, sha1).digest()
    sha1hmac5 = hmac.new(ms_second_half, sha1A5 + label + seed, sha1).digest()
    sha1hmac6 = hmac.new(ms_second_half, sha1A6 + label + seed, sha1).digest()
    sha1hmac7 = hmac.new(ms_second_half, sha1A7 + label + seed, sha1).digest()
    sha1hmac = sha1hmac1+sha1hmac2+sha1hmac3+sha1hmac4+sha1hmac5+sha1hmac6+sha1hmac7
    return xor(md5hmac, sha1hmac)[:20]

if __name__ == "__main__":
    seed = os.urandom(64)
    pms1 = '\x03\x01'+os.urandom(13) + ('\x00' * (24-2-13))
    pms2 =  os.urandom(8) + ('\x00' * (24-8-1)) + '\x01'
    print "using seed: "+binascii.hexlify(seed)
    print "using pms1: "+binascii.hexlify(pms1)
    print "using pms2: "+binascii.hexlify(pms2)

    print "expanded keys old way is: "+binascii.hexlify(old_way(seed,pms1,pms2))
    print "expanded keys new way is: "+binascii.hexlify(new_way(seed,pms1,pms2))
'''
