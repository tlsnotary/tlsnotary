from __future__ import print_function
import math, os, binascii, hmac, time, rsa, re
from hashlib import md5, sha1
from tlsn_common import *
from base64 import b64encode,b64decode
from pyasn1.type import univ
from pyasn1.codec.der import encoder, decoder
from slowaes import AESModeOfOperation

#encrypt and base64 encode
def ee(msg,pubkey):
    return b64encode(rsa.encrypt(str(msg),pubkey))

#decrypt and base64decode
def dd(cipher,privkey):
    msg = rsa.decrypt(b64decode(cipher),privkey)
    return msg

md5_hash_len = 16
sha1_hash_len = 20


#*********** TLS CODE ********************
class TLSNSSLClientSession(object):
    def __init__(self,server,port=443,ccs=53):
        self.serverName = server
        self.sslPort = port
        self.tlsVersionNum = '1.0'
        self.nAuditeeEntropy = 11
        self.nAuditorEntropy = 8
        self.auditorSecret = None
        self.auditeeSecret = None
        self.encFirstHalfPMS = None
        self.encSecondHalfPMS = None
        self.encPMS = None
        #client hello, server hello, certificate, server hello done, client key exchange, change cipher spec, finished
        self.handshakeMessages = [None] * 7
        #client random can be created immediately on instantiation
        cr_time = bigint_to_bytearray(int(time.time()))
        self.clientRandom = cr_time + os.urandom(28)
        self.serverRandom = None

        '''The amount of key material for each ciphersuite:
        AES256-CBC-SHA: mac key 20*2, encryption key 32*2, IV 16*2 == 136bytes
        AES128-CBC-SHA: mac key 20*2, encryption key 16*2, IV 16*2 == 104bytes
        RC4128_SHA: mac key 20*2, encryption key 16*2 == 72bytes
        RC4128_MD5: mac key 16*2, encryption key 16*2 == 64 bytes'''
        self.cipherSuites = {47:['AES128',20,20,16,16,16,16],53:['AES256',20,20,32,32,16,16],\
                        4:['RC4MD5',20,20,16,16,0,0],5:['RC4SHA',16,16,16,16,0,0]}

        #preprocessing: add the total number of bytes in the expanded keys format
        #for each cipher suite, for ease of reference
        for k,v in self.cipherSuites.iteritems():
            v.append(sum(v[1:]))

        self.chosenCipherSuite = ccs

        self.pAuditor = None
        self.pAuditee = None

        self.masterSecretHalfAuditor = None
        self.masterSecretHalfAuditee = None

        self.pMasterSecretAuditor = None
        self.pMasterSecretAuditee = None

        self.serverMacKey = None
        self.clientMacKey = None
        self.serverEncKey = None
        self.clientEncKey = None
        self.serverIV = None
        self.clientIV = None

        self.serverCertificate = None
        self.serverModulus = None
        self.serverExponent = 65537
        self.serverModLength = None

        #create clientHello on instantiation
        #note that this will not be actually used in the main session
        self.setClientHello()

    def dump(self):
        returnStr='Session state dump: \n'
        for k,v in self.__dict__.iteritems():
            returnStr += k + '\n'
            if type(v) == type(str()):
                returnStr += 'string: len:'+str(len(v)) + '\n'
                returnStr += v + '\n'
            elif type(v) == type(bytearray()):
                returnStr += 'bytearray: len:'+str(len(v)) + '\n'
                returnStr += binascii.hexlify(v) + '\n'
            else:
                returnStr += str(v) + '\n'
        return returnStr

    def setClientHello(self):
        if not self.clientRandom: return None
        if not self.chosenCipherSuite: return None
        self.handshakeMessages[0] = '\x16\x03\x01\x00\x2d\x01\x00\x00\x29\x03\x01' + \
                                    self.clientRandom + '\x00\x00\x02\x00'+chr(self.chosenCipherSuite)+'\x01\x00'
        return self.handshakeMessages[0]

    def setMasterSecretHalf(self,half=1,providedPValue=None):
        #non provision of p value means we use the existing p
        #values to calculate the whole MS
        if not providedPValue:
            self.masterSecretHalfAuditor = xor(self.pAuditee[:24],self.pAuditor[:24])
            self.masterSecretHalfAuditee = xor(self.pAuditee[24:],self.pAuditor[24:])
            return self.masterSecretHalfAuditor+self.masterSecretHalfAuditee

        #otherwise the p value must be enough to provide one half of MS
        if not len(providedPValue)==24: return None
        if half == 1:
            self.masterSecretHalfAuditor = xor(self.pAuditor[:24],providedPValue)
            return self.masterSecretHalfAuditor
        elif half == 2:
            self.masterSecretHalfAuditee = xor(self.pAuditee[24:],providedPValue)
            return self.masterSecretHalfAuditee
        else:
            return None


    def setCipherSuite(self, csByte):
        csInt = ba2int(csByte)
        if csInt not in self.cipherSuites.keys(): return None
        self.chosenCipherSuite = csInt
        return csInt

    def processServerHello(self,sh_cert_shd):
        #server hello always starts with 16 03 01 * * 02
        #certificate always starts with 16 03 01 * * 0b
        shd = '\x16\x03\x01\x00\x04\x0e\x00\x00\x00'
        sh_magic = re.compile(b'\x16\x03\x01..\x02')
        if not re.match(sh_magic, sh_cert_shd): raise Exception ('Invalid server hello')
        if not sh_cert_shd.endswith(shd): raise Exception ('invalid server hello done')
        #find the beginning of certificate message
        cert_magic = re.compile(b'\x16\x03\x01..\x0b')
        cert_match = re.search(cert_magic, sh_cert_shd)
        if not cert_match: raise Exception ('Invalid certificate message')
        cert_start_position = cert_match.start()
        sh = sh_cert_shd[:cert_start_position]
        self.handshakeMessages[2] = sh_cert_shd[cert_start_position : -len(shd)]
        self.handshakeMessages[1] = sh
        self.handshakeMessages[3] = shd
        self.serverRandom = sh[11:43]
        return (self.handshakeMessages[1:4], self.serverRandom)

    def setEncryptedPMS(self):
        if not (self.encFirstHalfPMS and self.encSecondHalfPMS and self.serverModulus):
            print ('failed to set encpms, first half was: ',self.encFirstHalfPMS, \
                    ' second half was: ',self.encSecondHalfPMS, ' modulus was: ', \
                                                        self.serverModulus)
            return None
        self.encPMS =  self.encFirstHalfPMS * self.encSecondHalfPMS % self.serverModulus
        return self.encPMS

    def setAuditeeSecret(self):
        '''Sets up the auditee's half of the preparatory
        secret material to create the master secret, and
        the encrypted premaster secret.'''
        if not (self.clientRandom and self.serverRandom): return None
        if not self.auditeeSecret:
            self.auditeeSecret = os.urandom(self.nAuditeeEntropy)
        label = 'master secret'
        seed = self.clientRandom + self.serverRandom
        pms1 = '\x03\x01'+self.auditeeSecret + ('\x00' * (24-2-self.nAuditeeEntropy))
        self.pAuditee = TLS10PRF(label+seed,first_half = pms1)[0]

        #we can construct the encrypted form if pubkey is known
        if (self.serverModulus):
            padding = '\x01'*15 #TODO this is intended to be random, but needs testing
            self.encFirstHalfPMS = pow(ba2int('\x02'+('\x01'*63)+padding+'\x00'+\
            pms1+('\x00'*24)) + 1, self.serverExponent, self.serverModulus)

        #can construct the full encrypted pre master secret if
        #the auditor's half is already calculated
        if (self.encSecondHalfPMS):
            self.setEncryptedPMS()

        return (self.pAuditee,self.encPMS)

    def setAuditorSecret(self):
        '''Sets up the auditor's half of the preparatory
        secret material to create the master secret, and
        the encrypted premaster secret.
        'secret' should be a bytearray of length nAuditorEntropy'''
        if not (self.clientRandom and self.serverRandom): return None
        if not self.auditorSecret:
            self.auditorSecret = os.urandom(self.nAuditorEntropy)

        label = 'master secret'
        seed = self.clientRandom + self.serverRandom
        pms2 =  self.auditorSecret + ('\x00' * (24-self.nAuditorEntropy-1)) + '\x01'
        self.pAuditor = TLS10PRF(label+seed,second_half = pms2)[1]

        #we can construct the encrypted form if pubkey is known
        if (self.serverModulus):
            padding = '\x01'*15 #TODO this is intended to be random but needs testing
            self.encSecondHalfPMS = pow( int(('\x01'+('\x01'*63)+padding+ \
            ('\x00'*25)+pms2).encode('hex'),16), self.serverExponent, self.serverModulus )

        return (self.pAuditor,self.encSecondHalfPMS)

    #this is only called for sessions that are hand-crafting the handshake
    #for the other type of session, the certificate is passed in in DER format
    #from NSS
    def extractCertificate(self):
        if not self.handshakeMessages[2]: return None
        cert_len = ba2int(self.handshakeMessages[2][12:15])
        self.serverCertificate = self.handshakeMessages[2][15:15+cert_len]
        return self.serverCertificate

    def extractModAndExp(self,certDER=None):
        if not (self.serverCertificate or certDER):
            print ("No server certificate, cannot extract pubkey")
            return None
        if certDER:
            rv  = decoder.decode(certDER, asn1Spec=univ.Sequence())
            bitstring = rv[0].getComponentByPosition(1)
        else:
            rv  = decoder.decode(self.serverCertificate, asn1Spec=univ.Sequence())
            bitstring = rv[0].getComponentByPosition(0).getComponentByPosition(6).getComponentByPosition(1)
        #bitstring is a list of ints, like [01110001010101000...]
        #convert it into into a string   '01110001010101000...'
        stringOfBits = ''
        for bit in bitstring:
            bit_as_str = str(bit)
            stringOfBits += bit_as_str
        #treat every 8 chars as an int and pack the ints into a bytearray
        ba = bytearray()
        for i in range(0, len(stringOfBits)/8):
            onebyte = stringOfBits[i*8 : (i+1)*8]
            oneint = int(onebyte, base=2)
            ba.append(oneint)
        #decoding the nested sequence
        rv  = decoder.decode(str(ba), asn1Spec=univ.Sequence())
        exponent = rv[0].getComponentByPosition(1)
        modulus = rv[0].getComponentByPosition(0)
        self.serverModulus = int(modulus)
        self.serverExponent = int(exponent)
        n = bigint_to_bytearray(self.serverModulus)
        e = bigint_to_bytearray(self.serverExponent)
        modulus_len_int = len(n)
        self.serverModLength = bigint_to_bytearray(modulus_len_int)
        if len(self.serverModLength) == 1: self.serverModLength.insert(0,0)  #zero-pad to 2 bytes

        return (self.serverModulus,self.serverExponent)

    #provide a list of keys that you want to 'garbageize' so as to hide
    #that key from the counterparty, in the array 'garbage', each number is
    #an index to that key in the cipherSuites dict
    def getPValueMS(self,ctrprty,garbage=[]):
        if not (self.serverRandom and self.clientRandom and self.chosenCipherSuite): return None
        label = 'key expansion'
        seed = self.serverRandom + self.clientRandom
        if ctrprty == 'auditor':
            self.pMasterSecretAuditor = TLS10PRF(label+seed,req_bytes=140,first_half=self.masterSecretHalfAuditor)[0]
        else:
            self.pMasterSecretAuditee = TLS10PRF(label+seed,req_bytes=140,second_half=self.masterSecretHalfAuditee)[1]

        tmp = self.pMasterSecretAuditor if ctrprty=='auditor' else self.pMasterSecretAuditee
        for k in garbage:
            start = self.cipherSuites[self.chosenCipherSuite][k]
            end = self.cipherSuites[self.chosenCipherSuite][k+1]
            #ugh, python strings are immutable, what's the elegant way to do this?
            tmp2 = tmp[:start]+os.urandom(end-start)+tmp[end:]
            tmp = tmp2
        return tmp

    def doKeyExpansion(self):
        '''A note about partial expansions:
        Often we will have sufficient information to extract particular
        keys, e.g. the client keys, but not others, e.g. the server keys.
        This should be handled by passing in garbage to fill out the relevant
        portions of the two master secret halves. TODO find a way to make this
        explicit so that querying the object will only give real keys.
        '''

        if not (self.serverRandom and self.clientRandom):
            return None
        label = 'key expansion'
        seed = self.serverRandom + self.clientRandom
        #for maximum flexibility, we will compute the sha1 or hmac
        #or the full keys, based on what secrets currently exist in this object
        if self.masterSecretHalfAuditee:
            self.pMasterSecretAuditee = TLS10PRF(label+seed,req_bytes=140,second_half=self.masterSecretHalfAuditee)[1]
        if self.masterSecretHalfAuditor:
            self.pMasterSecretAuditor = TLS10PRF(label+seed,req_bytes=140,first_half=self.masterSecretHalfAuditor)[0]

        if self.masterSecretHalfAuditee and self.masterSecretHalfAuditor:
            keyExpansion = TLS10PRF(label+seed,req_bytes=140,full_secret=self.masterSecretHalfAuditor+\
                                                                                self.masterSecretHalfAuditee)[2]
        elif self.pMasterSecretAuditee and self.pMasterSecretAuditor:
            keyExpansion = xor(self.pMasterSecretAuditee,self.pMasterSecretAuditor)
        else:
            print ('Cannot expand keys, insufficient data')
            return None

        #we have the raw key expansion, but want the keys. Use the data
        #embedded in the cipherSuite dict to identify the boundaries.
        if not self.chosenCipherSuite:
            print ("Cannot expand ssl keys without a chosen cipher suite.")
            return None

        keyAccumulator = []
        ctr=0
        for i in range(6):
            keySize = self.cipherSuites[self.chosenCipherSuite][i+1]
            if keySize == 0:
                keyAccumulator.append(None)
            else:
                keyAccumulator.append(keyExpansion[ctr:ctr+keySize])
            ctr += keySize

        self.clientMacKey,self.serverMacKey,self.clientEncKey,self.serverEncKey,self.clientIV,self.serverIV = keyAccumulator
        return bytearray('').join(filter(None,keyAccumulator))

    def getVerifyHMAC(self,sha_verify=None,md5_verify=None,half=1):
        label = 'client finished'
        seed = md5_verify + sha_verify
        if half==1:
            return TLS10PRF(label+seed,req_bytes=12,first_half = self.masterSecretHalfAuditor)[0]
        else:
            return TLS10PRF(label+seed,req_bytes=12,second_half = self.masterSecretHalfAuditee)[1]

    def getVerifyDataForFinished(self,sha_verify=None,md5_verify=None,half=1,providedPValue=None):
        if not providedPValue:
            #we calculate the verify data from the raw handshake messages
            if self.handshakeMessages[:6] != filter(None,self.handshakeMessages[:6]):
                print ('Handshake data was not complete, could not calculate verify data')
                print ('Here are the handshake messages: ',[str(x) for x in self.handshakeMessages[:6]])
                return None
            handshakeData = bytearray('').join([x[5:] for x in self.handshakeMessages[:5]])
            sha_verify = sha1(handshakeData).digest()
            md5_verify = md5(handshakeData).digest()
            label = 'client finished'
            seed = md5_verify + sha_verify
            ms = self.masterSecretHalfAuditor+self.masterSecretHalfAuditee
            #we don't store the verify data locally, just return it
            return TLS10PRF(label+seed,req_bytes=12,full_secret=ms)[2]
        #we calculate based on provided hmac and master secret data
        if not (sha_verify and md5_verify):
            print ('sha or md5 verify were not set, could not calculate verify data')
            return None
        return xor(providedPValue[:12],self.getVerifyHMAC(sha_verify=sha_verify,md5_verify=md5_verify,half=half))

    #TODO currently only applies to a AES-CBC 256 handshake;
    #for now, this is OK, as we only build handshakes for 'reliable site'
    def getCKECCSF(self):
        '''sets the handshake messages change cipher spec and finished,
        and returns the three final handshake messages client key exchange,
        change cipher spec and finished. '''
        self.handshakeMessages[4] = '\x16\x03\x01\x01\x06\x10\x00\x01\x02\x01\00' \
                                                + bigint_to_bytearray(self.encPMS)
        self.handshakeMessages[5] = '\x14\x03\01\x00\x01\x01'
        verifyData = self.getVerifyDataForFinished()
        if not verifyData:
            print ('Verify data was null')
            return None
        #HMAC and AES-encrypt the verify_data
        hmacVerify = hmac.new(self.clientMacKey, '\x00\x00\x00\x00\x00\x00\x00\x00' \
        + '\x16' + '\x03\x01' + '\x00\x10' + '\x14\x00\x00\x0c' + verifyData, sha1).digest()
        moo = AESModeOfOperation()
        cleartext = '\x14\x00\x00\x0c' + verifyData + hmacVerify
        cleartextList = bigint_to_list(ba2int(cleartext))
        clientEncList =  bigint_to_list(ba2int(self.clientEncKey))
        clientIVList =  bigint_to_list(ba2int(self.clientIV))
        paddedCleartext = cleartext + ('\x0b' * 12) #this is TLS CBC padding, NOT PKCS7
        try:
            mode, origLen, hmacedVerifyData = \
            moo.encrypt( str(paddedCleartext), moo.modeOfOperation['CBC'], \
            clientEncList, moo.aes.keySize['SIZE_256'], clientIVList)
        except Exception, e:
            print ('Caught exception while doing slowaes encrypt: ', e)
            raise
        self.handshakeMessages[6] = '\x16\x03\x01\x00\x30' + bytearray(hmacedVerifyData)
        return bytearray('').join(self.handshakeMessages[4:])

    def completeHandshake(self, rsapms2):
        self.extractCertificate()
        self.extractModAndExp()
        self.setAuditeeSecret()
        self.setMasterSecretHalf() #default values means full MS created
        self.doKeyExpansion()
        self.encSecondHalfPMS = ba2int(rsapms2)
        self.setEncryptedPMS()
        return self.getCKECCSF()

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
