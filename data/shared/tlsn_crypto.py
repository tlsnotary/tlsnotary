from __future__ import print_function
import math, os, binascii, hmac, time, rsa, re, random
from hashlib import md5, sha1
from tlsn_common import *
from base64 import b64encode,b64decode
from pyasn1.type import univ
from pyasn1.codec.der import encoder, decoder
from slowaes import AESModeOfOperation
from slowaes import AES

#*********CODE FOR ENCRYPTION OF PEER TO PEER MESSAGING*******
#encrypt and base64 encode
def ee(msg,pubkey):
    return b64encode(rsa.encrypt(str(msg),pubkey))

#decrypt and base64decode
def dd(cipher,privkey):
    msg = rsa.decrypt(b64decode(cipher),privkey)
    return msg

md5_hash_len = 16
sha1_hash_len = 20

#********END CODE FOR ENCRYPTION OF PEER TO PEER MESSAGING***


#*********** TLS CODE ***************************************
#This is a *heavily* restricted, and modified
#implementation of client-side TLS 1.0.
#Restrictions:
#-only for RSA key exchange
#-only for AES-CBC and RC4 ciphers
#-only implements one client request and one server response
# after the handshake is complete.
#-certificate is extracted but not checked using any PKI; the
# certificate check must be implemented by the calling code.
#-does not support record level compression.
#Modifications:
#The master secret and key generation is based on the
#tlsnotary algorithm as explained in TLSNotary.pdf as found
#in the documentation folder of the repo.
#This is achieved by creating a separate TLSNSSLClientSession
#object for each of auditor and auditee, containing separate
#subsets of the required information(in particular, secrets.)
#************************************************************
#constants
tlsver='\x03\x01'
#record types
appd = '\x17' #Application Data
hs = '\x16' #Handshake
chcis = '\x14' #Change Cipher Spec
alrt = '\x15' #Alert
#handshake types
h_ch = '\x01' #Client Hello
h_sh = '\x02' #Server Hello
h_cert = '\x0b' #Certificate
h_shd = '\x0e' #Server Hello Done
h_cke = '\x10' #Client Key Exchange
h_fin = '\x14' #Finished

class TLSNSSLClientSession(object):
    def __init__(self,server=None,port=443,ccs=None):
        self.serverName = server
        self.sslPort = port
        self.nAuditeeEntropy = 12
        self.nAuditorEntropy = 9
        self.auditorSecret = None
        self.auditeeSecret = None
        self.auditorPaddingSecret = None
        self.auditeePaddingSecret = None
        self.encFirstHalfPMS = None
        self.encSecondHalfPMS = None
        self.encPMS = None
        #client hello, server hello, certificate, server hello done,
        #client key exchange, change cipher spec, finished
        self.handshakeMessages = [None] * 7
        self.handshakeHashSHA = None
        self.handshakeHashMD5 = None
        #client random can be created immediately on instantiation
        cr_time = bi2ba(int(time.time()))
        self.clientRandom = cr_time + os.urandom(28)
        self.serverRandom = None

        '''The amount of key material for each ciphersuite:
        AES256-CBC-SHA: mac key 20*2, encryption key 32*2, IV 16*2 == 136bytes
        AES128-CBC-SHA: mac key 20*2, encryption key 16*2, IV 16*2 == 104bytes
        RC4128_SHA: mac key 20*2, encryption key 16*2 == 72bytes
        RC4128_MD5: mac key 16*2, encryption key 16*2 == 64 bytes'''
        self.cipherSuites = {47:['AES128',20,20,16,16,16,16],\
                             53:['AES256',20,20,32,32,16,16],\
                             5:['RC4SHA',20,20,16,16,0,0],\
                             4:['RC4MD5',16,16,16,16,0,0]}
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

        #these are stored to be used as IV
        #for encryption/decryption of the next SSL record
        self.lastClientCiphertextBlock = None
        self.lastServerCiphertextBlock = None

        #needed for maintaining RC4 cipher state
        self.clientRC4State = None
        self.serverRC4State = None

        #needed for record HMAC construction
        self.clientSeqNo = 0
        self.serverSeqNo = 0

        #array of ciphertexts from each SSL record
        self.serverResponseCiphertexts=[]

        #the HMAC required to construct the verify data
        #for the server Finished record
        self.verifyHMACForServerFinished = None
        
        #store the decrypted server finished message
        #for later mac check in form (plaintext,mac)
        self.decryptedServerFinished = (None,None)
        
        #all handshake messages are stored as transferred
        #over the wire, but the Finished message, which
        #is encrypted over the wire, is also needed for
        #hashing in unencrypted form.
        self.unencryptedClientFinished = None
        
        #create clientHello on instantiation
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
        assert self.clientRandom, "Client random should have been set in constructor."
        remaining = tlsver + self.clientRandom + '\x00' #last byte is session id length
        if self.chosenCipherSuite:
            #prepare_pms and testing only: use specific cs
            remaining  += '\x00\x02\x00'+chr(self.chosenCipherSuite) 
        else:
            #use all 4 ciphersuites
            remaining += '\x00'+chr(2*len(self.cipherSuites))
            for a in self.cipherSuites:
                remaining += '\x00'+chr(a)                        
        remaining += '\x01\x00' #compression methods
        self.handshakeMessages[0] = hs + tlsver + bi2ba(len(remaining)+4,fixed=2) + \
        h_ch + bi2ba(len(remaining),fixed=3) + remaining
        return self.handshakeMessages[0]

    def setMasterSecretHalf(self,half=1,providedPValue=None):
        #non provision of p value means we use the existing p
        #values to calculate the whole MS
        if not providedPValue:
            self.masterSecretHalfAuditor = xor(self.pAuditee[:24],self.pAuditor[:24])
            self.masterSecretHalfAuditee = xor(self.pAuditee[24:],self.pAuditor[24:])
            return self.masterSecretHalfAuditor+self.masterSecretHalfAuditee
        assert half in [1,2], "Must provide half argument as 1 or 2"
        #otherwise the p value must be enough to provide one half of MS
        assert len(providedPValue)==24, "Wrong length of P-hash value for half MS setting."
        if half == 1:
            self.masterSecretHalfAuditor = xor(self.pAuditor[:24],providedPValue)
            return self.masterSecretHalfAuditor
        else:
            self.masterSecretHalfAuditee = xor(self.pAuditee[24:],providedPValue)
            return self.masterSecretHalfAuditee

    def setCipherSuite(self, cs):
        assert cs in self.cipherSuites.keys(), "Invalid cipher suite chosen" 
        self.chosenCipherSuite = cs
        return cs

    def processServerHello(self,sh_cert_shd):
        shd = hs + tlsver + bi2ba(4,fixed=2) + h_shd + bi2ba(0,fixed=3)
        sh_magic = re.compile(hs + tlsver + '..' + h_sh,re.DOTALL)
        if not re.match(sh_magic, sh_cert_shd): 
            raise Exception ('Invalid server hello')
        if not sh_cert_shd.endswith(shd[-4:]): 
            with open('handbg','wb') as f: f.write(binascii.hexlify(sh_cert_shd))
            raise Exception ('invalid server hello done')
        #find the beginning of certificate message
        cert_magic = re.compile(hs + tlsver + '..' + h_cert,re.DOTALL)
        cert_match = re.search(cert_magic, sh_cert_shd)
        if not cert_match: 
            #fallback: the certificate and shd may have been packed
            #into the same record.
            #We expect that all three messages are in a single record
            #TODO consider if some annoying website decides to send two in one.
            tls_header = hs + tlsver
            assert sh_cert_shd[5] == h_sh, "Failed to find server hello"
            record_len = ba2int(sh_cert_shd[3:5])
            
            assert len(sh_cert_shd)-5 == record_len, "Failed to parse sh_cert_shd"
            #we know not to expect record headers for Cert and SHD
            sh_length = ba2int(sh_cert_shd[6:9])
            #build server hello
            self.handshakeMessages[1]=tls_header+str(bi2ba(4+sh_length,fixed=2))+ \
            sh_cert_shd[5:9]+sh_cert_shd[9:9+sh_length]
            
            assert sh_cert_shd[9+sh_length] == h_cert, "Failed to find certificate, server hello length was: "+str(sh_length)
            cert_len = ba2int(sh_cert_shd[9+sh_length+1:9+sh_length+4])
            #certificate
            self.handshakeMessages[2] = tls_header+str(bi2ba(4+cert_len,fixed=2))+\
                sh_cert_shd[9+sh_length:9+sh_length+4+cert_len]
            #server hello done
            self.handshakeMessages[3] = shd

        else:
            cert_start_position = cert_match.start()
            sh = sh_cert_shd[:cert_start_position]
            self.handshakeMessages[2] = sh_cert_shd[cert_start_position : -len(shd)]
            self.handshakeMessages[1] = sh
            self.handshakeMessages[3] = shd
            
        self.serverRandom = self.handshakeMessages[1][11:43]
        #extract the cipher suite
        #if a session id was provided, it will be preceded by its length 32:
        #note: 44 = 1 tls record type + 2 tls ver + 2 record length + 1 handshake type
        # + 3 handshake length + 2 tls ver + 32 server random + 1 session id lenth (zero)
        cs_start_byte = 44 if self.handshakeMessages[1][43] != '\x20' else 43+1+32
        if self.handshakeMessages[1][cs_start_byte] != '\x00' or \
           ord(self.handshakeMessages[1][cs_start_byte+1]) not in self.cipherSuites.keys():
            raise Exception("Could not locate cipher suite choice in server hello.")
        server_ciphersuite = ba2int(self.handshakeMessages[1][cs_start_byte+1])
        if self.chosenCipherSuite: #testing only,  we prefered a specific cs
            if self.chosenCipherSuite != server_ciphersuite:
                raise Exception ('Server did not return the ciphersuite we requested')
        self.setCipherSuite(server_ciphersuite)
        #if encPMS is not yet set, this is a call from prepare_pms()
        #otherwise this is a normal audit session
        if self.encPMS:
            self.setHandshakeHashes()
            self.setAuditeeSecret()
        
        print ("Set cipher suite to ", str(server_ciphersuite))
            
        return (self.handshakeMessages[1:4], self.serverRandom)

    def setEncryptedPMS(self):
        assert (self.encFirstHalfPMS and self.encSecondHalfPMS and self.serverModulus), \
            'failed to set encpms, first half was: ' + str(self.encFirstHalfPMS) +\
            ' second half was: ' + str(self.encSecondHalfPMS) + ' modulus was: ' + str(self.serverModulus)
        self.encPMS =  self.encFirstHalfPMS * self.encSecondHalfPMS % self.serverModulus
        return self.encPMS

    def setEncFirstHalfPMS(self):
        assert (self.serverModulus and not self.encFirstHalfPMS)
        oneslength = 23            
        pms1 = tlsver+self.auditeeSecret + ('\x00' * (24-2-self.nAuditeeEntropy))
        self.encFirstHalfPMS = pow(ba2int('\x02'+('\x01'*(oneslength))+\
        self.auditeePaddingSecret+'\x00'+pms1 +'\x00'*23 + '\x01'), self.serverExponent, self.serverModulus)
     
    def setAuditeeSecret(self):
        '''Sets up the auditee's half of the preparatory
        secret material to create the master secret.'''
        assert self.clientRandom and self.serverRandom,"one of client or server random not set"
        if not self.auditeeSecret:
            self.auditeeSecret = os.urandom(self.nAuditeeEntropy)             
        if not self.auditeePaddingSecret:
            self.auditeePaddingSecret = os.urandom(15)
        label = 'master secret'
        seed = self.clientRandom + self.serverRandom
        pms1 = tlsver+self.auditeeSecret + ('\x00' * (24-2-self.nAuditeeEntropy))
        self.pAuditee = TLS10PRF(label+seed,first_half = pms1)[0]
        #encrypted PMS has already been calculated before the audit began
        return (self.pAuditee)

    def setEncSecondHalfPMS(self):
        assert (self.serverModulus and not self.encFirstHalfPMS)
        oneslength = 103+ba2int(self.serverModLength)-256
        pms2 =  self.auditorSecret + ('\x00' * (24-self.nAuditorEntropy-1)) + '\x01'
        self.encSecondHalfPMS = pow( ba2int('\x01'+('\x01'*(oneslength))+\
        self.auditorPaddingSecret+ ('\x00'*25)+pms2), self.serverExponent, self.serverModulus )

    def setAuditorSecret(self):
        '''Sets up the auditor's half of the preparatory
        secret material to create the master secret, and
        the encrypted premaster secret.
        'secret' should be a bytearray of length nAuditorEntropy'''
        assert (self.clientRandom and self.serverRandom), "one of client or server random not set"
        if not self.auditorSecret:
            self.auditorSecret = os.urandom(self.nAuditorEntropy)
        if not self.auditorPaddingSecret:
            self.auditorPaddingSecret =  os.urandom(15)
        label = 'master secret'
        seed = self.clientRandom + self.serverRandom
        pms2 =  self.auditorSecret + ('\x00' * (24-self.nAuditorEntropy-1)) + '\x01'
        self.pAuditor = TLS10PRF(label+seed,second_half = pms2)[1]
        return (self.pAuditor)

    def extractCertificate(self):
        assert self.handshakeMessages[2], "Cannot extract certificate, no handshake message present."
        cert_len = ba2int(self.handshakeMessages[2][12:15])
        self.serverCertificate = self.handshakeMessages[2][15:15+cert_len]
        return self.serverCertificate

    def extractModAndExp(self,certDER=None):
        if not certDER: 
            self.extractCertificate()
            DERdata = self.serverCertificate
        else: DERdata = certDER
        assert (self.serverCertificate or certDER), "No server certificate, cannot extract pubkey"
        rv  = decoder.decode(DERdata, asn1Spec=univ.Sequence())
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
        n = bi2ba(self.serverModulus)
        e = bi2ba(self.serverExponent)
        modulus_len_int = len(n)
        self.serverModLength = bi2ba(modulus_len_int)
        if len(self.serverModLength) == 1: self.serverModLength.insert(0,0)  #zero-pad to 2 bytes

        return (self.serverModulus,self.serverExponent)

    #provide a list of keys that you want to 'garbageize' so as to hide
    #that key from the counterparty, in the array 'garbage', each number is
    #an index to that key in the cipherSuites dict
    def getPValueMS(self,ctrprty,garbage=[]):
        assert (self.serverRandom and self.clientRandom and self.chosenCipherSuite), \
               "server random, client random or cipher suite not set."
        label = 'key expansion'
        seed = self.serverRandom + self.clientRandom
        expkeys_len = self.cipherSuites[self.chosenCipherSuite][-1]        
        if ctrprty == 'auditor':
            self.pMasterSecretAuditor = TLS10PRF(label+seed,req_bytes=expkeys_len,first_half=self.masterSecretHalfAuditor)[0]
        else:
            self.pMasterSecretAuditee = TLS10PRF(label+seed,req_bytes=expkeys_len,second_half=self.masterSecretHalfAuditee)[1]

        tmp = self.pMasterSecretAuditor if ctrprty=='auditor' else self.pMasterSecretAuditee
        for k in garbage:
            if k==1:
                start = 0
            else:
                start = sum(self.cipherSuites[self.chosenCipherSuite][1:k])
            end = sum(self.cipherSuites[self.chosenCipherSuite][1:k+1])
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
        assert (self.serverRandom and self.clientRandom)," need client and server random"
        label = 'key expansion'
        seed = self.serverRandom + self.clientRandom
        #for maximum flexibility, we will compute the sha1 or md5 hmac
        #or the full keys, based on what secrets currently exist in this object
        expkeys_len = self.cipherSuites[self.chosenCipherSuite][-1]                
        if self.masterSecretHalfAuditee:
            self.pMasterSecretAuditee = TLS10PRF(label+seed,req_bytes=expkeys_len,second_half=self.masterSecretHalfAuditee)[1]
        if self.masterSecretHalfAuditor:
            self.pMasterSecretAuditor = TLS10PRF(label+seed,req_bytes=expkeys_len,first_half=self.masterSecretHalfAuditor)[0]

        if self.masterSecretHalfAuditee and self.masterSecretHalfAuditor:
            keyExpansion = TLS10PRF(label+seed,req_bytes=expkeys_len,full_secret=self.masterSecretHalfAuditor+\
                                                                                self.masterSecretHalfAuditee)[2]
        elif self.pMasterSecretAuditee and self.pMasterSecretAuditor:
            keyExpansion = xor(self.pMasterSecretAuditee,self.pMasterSecretAuditor)
        else:
            raise Exception ('Cannot expand keys, insufficient data')

        #we have the raw key expansion, but want the keys. Use the data
        #embedded in the cipherSuite dict to identify the boundaries.
        assert self.chosenCipherSuite,"Cannot expand ssl keys without a chosen cipher suite."

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

    def getVerifyHMAC(self,sha_verify=None,md5_verify=None,half=1,isForClient=True):
        '''returns only 12 bytes of hmac'''
        label = 'client finished' if isForClient else 'server finished'
        seed = md5_verify + sha_verify
        if half==1:
            return TLS10PRF(label+seed,req_bytes=12,first_half = self.masterSecretHalfAuditor)[0]
        else:
            return TLS10PRF(label+seed,req_bytes=12,second_half = self.masterSecretHalfAuditee)[1]

    def setHandshakeHashes(self):
        assert self.encPMS
        #TODO: This is a repetition of getCKECCSF. Obviously it should be got rid of.
        #I can't remember why it's necessary.
        #construct correct length bytes for CKE
        epms_len = len(bi2ba(self.encPMS))
        b_epms_len = bi2ba(epms_len,fixed=2)
        hs_len = 2 + epms_len
        b_hs_len = bi2ba(hs_len,fixed=3)
        record_len = 6+epms_len
        b_record_len = bi2ba(record_len,fixed=2)
        #construct CKE
        self.handshakeMessages[4] = hs + tlsver + b_record_len + h_cke + \
            b_hs_len + b_epms_len + bi2ba(self.encPMS)
        #Change cipher spec NB, not a handshake message
        self.handshakeMessages[5] = chcis + tlsver + bi2ba(1,fixed=2)+'\x01'
        
        handshakeData = bytearray('').join([x[5:] for x in self.handshakeMessages[:5]])
        self.handshakeHashSHA = sha1(handshakeData).digest()
        self.handshakeHashMD5 = md5(handshakeData).digest()
    
    def getServerHandshakeHashes(self):
        handshakeData = bytearray('').join([x[5:] for x in self.handshakeMessages[:5]])
        handshakeData += self.unencryptedClientFinished
        return(sha1(handshakeData).digest(), md5(handshakeData).digest())

    def getVerifyDataForFinished(self,sha_verify=None,md5_verify=None,half=1,providedPValue=None):
        if not (sha_verify and md5_verify):
            sha_verify, md5_verify = self.handshakeHashSHA, self.handshakeHashMD5

        if not providedPValue:
            #we calculate the verify data from the raw handshake messages
            if self.handshakeMessages[:6] != filter(None,self.handshakeMessages[:6]):
                print ('Here are the handshake messages: ',[str(x) for x in self.handshakeMessages[:6]])
                raise Exception('Handshake data was not complete, could not calculate verify data')
            label = 'client finished'
            seed = md5_verify + sha_verify
            ms = self.masterSecretHalfAuditor+self.masterSecretHalfAuditee
            #we don't store the verify data locally, just return it
            return TLS10PRF(label+seed,req_bytes=12,full_secret=ms)[2]

        #we calculate based on provided hmac by the other party
        return xor(providedPValue[:12],self.getVerifyHMAC(sha_verify=sha_verify,md5_verify=md5_verify,half=half))

    def buildRequest(self, cleartext):
        '''Constructs the raw bytes to send over TCP
        for a given client request. Implicitly the request
        will be less than 16kB and therefore only 1 SSL record.
        This can in principle be used more than once.'''
        bytes_to_send = appd+tlsver #app data, tls version

        record_mac = self.buildRecordMac(False,cleartext,appd)
        cleartext += record_mac
        if self.chosenCipherSuite in [4,5]:
            ciphertext, self.clientRC4State = RC4crypt(bytearray(cleartext),self.clientEncKey,self.clientRC4State)
        elif self.chosenCipherSuite in [47,53]:
            cleartextList = map(ord,cleartext)
            #clientEncList = map(ord,self.clientEncKey)
            clientEncList = bi2ba(ba2int(self.clientEncKey))
            padding = getCBCPadding(len(cleartextList))
            paddedCleartext = bytearray(cleartextList) + padding
            key_size = self.cipherSuites[self.chosenCipherSuite][3]
            moo = AESModeOfOperation()
            mode, origLen, ciphertext = \
            moo.encrypt(str(paddedCleartext), moo.modeOfOperation['CBC'], \
            clientEncList, key_size , self.lastClientCiphertextBlock)
        else:
            raise Exception ("Error, unrecognized cipher suite in buildRequest")

        cpt_len = bi2ba(len(ciphertext),fixed=2)
        bytes_to_send += cpt_len + bytearray(ciphertext)
        #just in case we plan to send more data,
        #update the client ssl state
        self.clientSeqNo += 1
        self.lastClientCiphertextBlock = ciphertext[-16:]
        return bytes_to_send

    def buildRecordMac(self, isFromServer, cleartext, recordType):
        '''Note: the fragment should be the cleartext of the record
        before mac and pad; but for handshake messages there is a header
        to the fragment, of the form (handshake type), 24 bit length.'''
        mac_algo = md5 if self.chosenCipherSuite == 4 else sha1
        
        seqNo = self.serverSeqNo if isFromServer else self.clientSeqNo
        #build sequence number bytes; 64 bit integer #TODO make this tidier
        seqByteList = bigint_to_list(seqNo)
        seqByteList = [0]*(8-len(seqByteList)) + seqByteList
        seqNoBytes = ''.join(map(chr,seqByteList))
        macKey = self.serverMacKey if isFromServer else self.clientMacKey
        if not macKey:
            raise Exception("Failed to build mac; mac key is missing")
        fragment_len = bi2ba(len(cleartext),fixed=2)    
        record_mac = hmac.new(macKey,seqNoBytes + recordType + \
                    tlsver+fragment_len + cleartext, mac_algo).digest()
        return record_mac

    def getCKECCSF(self,providedPValue = None):
        '''sets the handshake messages change cipher spec and finished,
        and returns the three final handshake messages client key exchange,
        change cipher spec and finished.
        If providedPValue is non null, it means the caller does not have
        access to the full master secret, and is providing the pvalue to be
        passed into getVerifyDataForFinished.'''
        assert self.encPMS
        assert self.handshakeMessages[4] #cke
        assert self.handshakeMessages[5] #ccs
        #CKE and CCS were already prepared earlier
        #start processing for Finished
        if providedPValue:
            verifyData = self.getVerifyDataForFinished(providedPValue=providedPValue,half=2)
        else:
            verifyData = self.getVerifyDataForFinished()
        assert verifyData,'Verify data was null'

        #HMAC and encrypt the verify_data
        hs_header = h_fin + bi2ba(12,fixed=3)
        hmacVerify = self.buildRecordMac(False,hs_header + verifyData,hs)
        cleartext = hs_header + verifyData + hmacVerify
        self.unencryptedClientFinished = hs_header + verifyData
        assert self.chosenCipherSuite in self.cipherSuites.keys(), "invalid cipher suite"
        if self.chosenCipherSuite in [4,5]:
            hmacedVerifyData, self.clientRC4State = RC4crypt(cleartext,self.clientEncKey)
        elif self.chosenCipherSuite in [47,53]:
            cleartextList,clientEncList,clientIVList = \
                [map(ord,str(x)) for x in [cleartext,self.clientEncKey,self.clientIV]]
            paddedCleartext = cleartext + getCBCPadding(len(cleartext))
            moo = AESModeOfOperation()
            mode, origLen, hmacedVerifyData = \
            moo.encrypt( str(paddedCleartext), moo.modeOfOperation['CBC'], \
                         clientEncList, len(self.clientEncKey), clientIVList)
            self.lastClientCiphertextBlock = hmacedVerifyData[-16:]

        self.clientSeqNo += 1
        self.handshakeMessages[6] = hs + tlsver + bi2ba(len(hmacedVerifyData),fixed=2) \
            + bytearray(hmacedVerifyData)
        return bytearray('').join(self.handshakeMessages[4:])

    def processServerCCSFinished(self, data, providedPValue):
        if data[:6] != chcis + tlsver + bi2ba(1,fixed=2)+'\x01':
            print ("Got response:",binascii.hexlify(data))
            raise Exception("Server CCSFinished did not contain CCS")
        self.serverFinished = data[6:]
        assert self.serverFinished[:3] == hs+tlsver,"Server CCSFinished does not contain Finished"
        recordLen = ba2int(self.serverFinished[3:5])
        assert recordLen == len(self.serverFinished[5:]), "unexpected data at end of server finished."
        #For CBC only: because the verify data is 12 bytes and the handshake header
        #is a further 4, and the mac is another 20, we have 36 bytes, meaning
        #that the padding is 12 bytes long, making a total of 48 bytes record length
        if recordLen != 48 and self.chosenCipherSuite in [47,53]:
            raise Exception("Server Finished record record length should be 48, is: ",recordLen)
        
        #decrypt:
        if self.chosenCipherSuite in [4,5]:
            decrypted,self.serverRC4State = RC4crypt(bytearray(self.serverFinished[5:5+recordLen]),self.serverEncKey) #box is null for first record
        elif self.chosenCipherSuite in [47,53]:
            ciphertextList,serverEncList,serverIVList = \
                [map(ord,x) for x in [self.serverFinished[5:5+recordLen],str(self.serverEncKey),str(self.serverIV)]]
            moo = AESModeOfOperation()
            key_size = self.cipherSuites[self.chosenCipherSuite][4]
            decrypted = moo.decrypt(ciphertextList,recordLen,moo.modeOfOperation['CBC'],serverEncList,key_size,serverIVList)
            #for CBC, unpad
            decrypted = cbcUnpad(decrypted)
                
        #strip the mac (NB The mac cannot be checked, as in tlsnotary, the serverMacKey
        #is garbage until after the commitment. This mac check occurs in 
        #processServerAppDataRecords)
        hash_len = sha1_hash_len if self.chosenCipherSuite in [5,47,53] else md5_hash_len
        received_mac = decrypted[-hash_len:]
        plaintext = decrypted[:-hash_len]
        
        #check the finished message header
        assert plaintext[:4] == h_fin+bi2ba(12,fixed=3), "The server Finished verify data is invalid"
        #Verify the verify data
        verifyData = plaintext[4:]
        sha_verify,md5_verify = self.getServerHandshakeHashes()
        if len(plaintext[4:]) != 12:
            print ("Wrong length of plaintext")
        verifyDataCheck = xor(providedPValue,\
                            self.getVerifyHMAC(sha_verify=sha_verify,md5_verify=md5_verify,half=2,isForClient=False))
        assert verifyData == verifyDataCheck, "Server Finished record verify data is not valid."
        #now the server finished is verified (except mac), we store
        #the plaintext of the message for later mac check 
        #(after auditor has passed server mac key)
        self.decryptedServerFinished = (plaintext,received_mac)
        #necessary for CBC
        self.lastServerCiphertextBlock = self.serverFinished[-16:]
        return True

    def storeServerAppDataRecords(self, response):
        self.serverAppDataRecords = response
        #extract the ciphertext from the raw records as a list
        #for maximum flexibility in decryption
        while True:
            if response[:3] != appd+tlsver:
                if response[:3] == alrt + tlsver:
                    print ("Got encrypted alert, done")
                    break
                raise Exception('Invalid TLS Header for App Data record')
            recordLen = ba2int(response[3:5])
            if self.chosenCipherSuite in [47,53] and recordLen %16: 
                raise Exception('Invalid ciphertext length for App Data')
            one_record = response[5:5+recordLen]
            if len(one_record) != recordLen:
                #TODO - we may want to rerun the audit for this page
                raise Exception ('Invalid record length')
            self.serverResponseCiphertexts.append(one_record)
            #prepare for next record, if there is one:
            if len(response) == 5+len(self.serverResponseCiphertexts[-1]):
                break
            response = response[5+recordLen:]
        print ("We got this many record ciphertexts:",len(self.serverResponseCiphertexts))


#used only during testing. Get ciphertexts which will be shipped off to browser
#for AES decryption
    def getCiphertexts(self):
        assert len(self.serverResponseCiphertexts),"Could not process the server response, no ciphertext found."
        if not self.chosenCipherSuite in [47,53]: #AES-CBC
            raise Exception("non-AES cipher suite.")                    
        ciphertexts = [] #each item contains a tuple (ciphertext, encryption_key, iv)
        for ciphertext in self.serverResponseCiphertexts:
            ciphertexts.append( (ciphertext, self.serverEncKey, self.lastServerCiphertextBlock) )
            self.lastServerCiphertextBlock = ciphertext[-16:] #ready for next record
        return ciphertexts


#used only during testing. Check mac on each plaintext and return the combined plaintexts
#with macs stripped
    def macCheckPlaintexts(self, plaintexts):
        mac_stripped_plaintext = ''
        for idx,raw_plaintext in enumerate(plaintexts):
            #need correct sequence number for macs            
            self.serverSeqNo += 1
            hash_len = sha1_hash_len if self.chosenCipherSuite in [5,47,53] else md5_hash_len
            received_mac = raw_plaintext[-hash_len:]
            check_mac = self.buildRecordMac(True,raw_plaintext[:-hash_len],appd)
            if received_mac != check_mac:
                raise Exception ("Warning, record mac check failed. in index:" + str(idx))
            mac_stripped_plaintext += raw_plaintext[:-hash_len]
        return mac_stripped_plaintext
        
        
 
    def processServerAppDataRecords(self,checkFinished=False):
        '''Using the encrypted records in self.serverResponseCiphertexts, 
        containing the response from
        the server to a GET or POST request (the *first* request after
        the handshake), this function will process the response one record
        at a time. Each of these records is decrypted and reassembled
        into the plaintext form of the response. The plaintext is returned
        along with the number of record mac failures (more than zero means
        the response is unauthenticated/corrupted).
        Notes:
        self.serverSeqNo should be set to zero before executing this function.
        This will occur by default if the session object has not undergone
        any handshake, or if it has undergone a handshake, so no intervention
        should, in theory, be required.'''
        bad_record_mac = 0
        if checkFinished:
            #before beginning, we must authenticate the server finished
            check_mac = self.buildRecordMac(True,self.decryptedServerFinished[0],hs)
            if self.decryptedServerFinished[1] != check_mac:
                print ("Warning, record mac check failed from server Finished message.")
                bad_record_mac += 1
                return None        #TODO - exception here?        
        plaintext = ''
        
        assert len(self.serverResponseCiphertexts),"Could not process the server response, no ciphertext found."
        
        for ciphertext in self.serverResponseCiphertexts:
            #need correct sequence number for macs
            self.serverSeqNo += 1
            if self.chosenCipherSuite in [4,5]: #RC4
                raw_plaintext, self.serverRC4State = RC4crypt(bytearray(ciphertext),self.serverEncKey,\
                                                            self.serverRC4State)
            elif self.chosenCipherSuite in [47,53]: #AES-CBC
                ciphertextList,serverEncList,serverIVList = \
                    [map(ord,x) for x in [ciphertext,str(self.serverEncKey),self.lastServerCiphertextBlock]]
                moo = AESModeOfOperation()
                key_size = self.cipherSuites[self.chosenCipherSuite][4]
                raw_plaintext = moo.decrypt(ciphertextList,len(ciphertextList),\
                                moo.modeOfOperation['CBC'],serverEncList,key_size,serverIVList)
                #unpad (and verify padding)
                raw_plaintext = cbcUnpad(raw_plaintext)
                self.lastServerCiphertextBlock = ciphertext[-16:] #ready for next record
            else:
                raise Exception("Unrecognized cipher suite.")

            #mac check
            hash_len = sha1_hash_len if self.chosenCipherSuite in [5,47,53] else md5_hash_len
            received_mac = raw_plaintext[-hash_len:]
            check_mac = self.buildRecordMac(True,raw_plaintext[:-hash_len],appd)
            if received_mac != check_mac:
                raise Exception ("Warning, record mac check failed.")
                #bad_record_mac += 1
            plaintext += raw_plaintext[:-hash_len]

        return (plaintext, bad_record_mac)

    def completeHandshake(self, rsapms2):
        '''Called from prepare_pms(). For auditee only,
        who passes the second half of the encrypted
        PMS product (see TLSNotary.pdf under documentation).'''
        self.extractCertificate()
        self.extractModAndExp()
        self.setAuditeeSecret()
        self.setMasterSecretHalf() #default values means full MS created
        self.doKeyExpansion()
        self.encSecondHalfPMS = ba2int(rsapms2)
        self.setEncFirstHalfPMS()
        self.setEncryptedPMS()
        self.setHandshakeHashes()         
        return self.getCKECCSF()
        
def getCBCPadding(data_length):
    req_padding = 16 - data_length % 16
    return chr(req_padding-1) * req_padding

def cbcUnpad(pt):
    '''Given binary string pt, return
    unpadded string, raise fatal exception
    if padding format is not valid'''
    padLen = ba2int(pt[-1])
    #verify the padding
    if not all(padLen == x for x in map(ord,pt[-padLen-1:-1])):
        raise Exception ("Invalid CBC padding.")
    return pt[:-(padLen+1)]    
                    
def RC4crypt(data, key, state=None):
    """RC4 algorithm.
    Symmetric, so performs encryption and decryption
    'state', if passed, is a tuple of three values,
    box (a bytearray), x and y (integers), allowing
    restart of the algorithm from an intermediate point.
    This is necessary since stream ciphers
    in TLS use the final state of the cipher at the end
    of one record to initialise the next record (see RFC 2246)."""
    if not state:
        x = 0
        box = range(256)
        for i in range(256):
            x = (x + box[i] + key[i % len(key)]) % 256
            box[i], box[x] = box[x], box[i]
        x = y = 0
    else:
        box,x,y = state
        
    out = []
    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(chr(char ^ box[(box[x] + box[y]) % 256]))
    out_state = (box, x, y)
    return (''.join(out), out_state )

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

#*********************END TLS CODE***************************************************

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
    smallprimes = (2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101)            
    def __init__(self, privkey_bits=None, pubkey=None):
        if (privkey_bits and pubkey) or (not privkey_bits and not pubkey):
            raise Exception('Provide either privkey_bits=<bits> or pubkey=<modulus>')
        elif pubkey:
            self.n = pubkey
            self.n_sq = self.n * self.n            
            self.g = self.n+1
            #we pre-compute r^n mod n^2 and use it for every encryption            
            r = random.randint(1,self.n)
            self.r_pow_n_mod_n_sq = pow(r, self.n, self.n_sq)
            return
        elif (privkey_bits < 1024):
            raise Exception ('Please don\'t be ridiculous. The private key must have be at least 1024 bits these days')          
        if (privkey_bits % 2 != 0): #p and q must be of the same size, need even bitlength
            raise Exception('Can only work with even bitlength keys')
        p = self.generate_prime(privkey_bits / 2)
        q = self.generate_prime(privkey_bits / 2)
        print ('Finished with primes')
        self.n = p * q
        self.n_sq = self.n * self.n
        self.g = self.n + 1
        self.l = (p-1) * (q-1)
        self.m = Paillier.inverse(self.l, self.n)
        r = random.randint(1, self.n-1)
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

    @staticmethod
    def generate_prime(bits):
        s = 0
        hundreds = 0
        while True:
            #time.sleep(0.1) #go easy on the CPU if speed is not critical
            s += 1
            if s == 100:
                hundreds += 1
                s = 0
                print('Finding prime. Try no ' + str(hundreds*100))
            #get and odd int
            candidate = random.randint(2 ** (bits-1) + 1, 2 ** bits) | 1
            if Paillier.is_probably_prime(candidate, 40):
                return candidate

    @staticmethod    
    def is_probably_prime(candidate, k):
        for prime in Paillier.smallprimes:
            if candidate % prime == 0:     
                return False
        for i in xrange(k):
            test = random.randrange(2, candidate - 1) | 1
            if Paillier.rabin_miller_witness(test, candidate):
                return False
        return True

    #copied from https://github.com/mikeivanov/paillier/blob/master/primes.py
    @staticmethod    
    def rabin_miller_witness(test, candidate):
        """Using Rabin-Miller witness test, will return True if candidate is
           definitely not prime (composite), False if it may be prime."""    
        return 1 not in Paillier.ipow(test, candidate-1, candidate)    

    @staticmethod    
    def ipow(a, b, n):
        """calculates (a**b) % n via binary exponentiation, yielding itermediate
           results as Rabin-Miller requires"""
        A = a = long(a % n)
        yield A
        t = 1L
        while t <= b:
            t <<= 1   
        # t = 2**k, and t > b
        t >>= 2
        while t:
            A = (A * A) % n
            if t & b:
                A = (A * a) % n
            yield A
            t >>= 1
            
    
    #copied from pyrsa
    @staticmethod        
    def extended_gcd(a, b):
        '''Returns a tuple (r, i, j) such that r = gcd(a, b) = ia + jb
        '''
        # r = gcd(a,b) i = multiplicitive inverse of a mod b
        #      or      j = multiplicitive inverse of b mod a
        # Neg return values for i or j are made positive mod b or a respectively
        # Iterateive Version is faster and uses much less stack space
        x = 0
        y = 1
        lx = 1
        ly = 0
        oa = a                             #Remember original a/b to remove 
        ob = b                             #negative values from return results
        while b != 0:
            q = a // b
            (a, b)  = (b, a % b)
            (x, lx) = ((lx - (q * x)),x)
            (y, ly) = ((ly - (q * y)),y)
        if (lx < 0): lx += ob              #If neg wrap modulo orignal b
        if (ly < 0): ly += oa              #If neg wrap modulo orignal a
        return (a, lx, ly)                 #Return only positive values
    
    @staticmethod        
    def inverse(x, n):
        '''Returns x^-1 (mod n)'''
        (divider, inv, _) = Paillier.extended_gcd(x, n)
        if divider != 1:
            raise ValueError("x (%d) and n (%d) are not relatively prime" % (x, n))
        return inv



class TLSNSSLClientSession_Paillier(TLSNSSLClientSession):
    def __init__(self, server=None,port=443,ccs=None):
        super(TLSNSSLClientSession_Paillier, self).__init__(server, port, ccs)
        #prepare the secrets right away. Depending on who will be using this class - 
        #auditee or auditor, accordingly secrets will be used
        self.auditeeSecret = os.urandom(22)
        self.auditeePaddingSecret = self.random_non_zero(103)
        self.auditeePaddedRSAHalf = '\x02' + self.auditeePaddingSecret + '\x00'*102 + '\x00\x03\x01' + self.auditeeSecret + '\x00'*24        
        
        self.auditorSecret = os.urandom(24)
        self.auditorPaddingSecret = self.random_non_zero(102)
        self.auditorPaddedRSAHalf = self.auditorPaddingSecret + '\x00'*25 + self.auditorSecret
  
    def random_non_zero(self, byte_len):
        ba = os.urandom(byte_len)
        while True:
            pos = ba.find('\x00')
            if pos == -1:
                break
            ba = ba[:pos]+os.urandom(1)+ba[pos+1:]
        return ba
    
    #overriden
    def setAuditeeSecret(self):
        '''Sets up the auditee's half of the preparatory
        secret material to create the master secret.'''
        assert self.clientRandom and self.serverRandom,"one of client or server random not set"
        label = 'master secret'
        seed = self.clientRandom + self.serverRandom
        pms1 = '\x03\x01'+ self.auditeeSecret
        self.pAuditee = TLS10PRF(label+seed,first_half = pms1)[0]
        #encrypted PMS has already been calculated before the audit began
        return (self.pAuditee)
    
    #overriden
    def setAuditorSecret(self):
        '''Sets up the auditor's half of the preparatory
        secret material to create the master secret, and
        the encrypted premaster secret.
        'secret' should be a bytearray of length nAuditorEntropy'''
        assert (self.clientRandom and self.serverRandom), "one of client or server random not set"
        label = 'master secret'
        seed = self.clientRandom + self.serverRandom
        pms2 = self.auditorSecret
        self.pAuditor = TLS10PRF(label+seed,second_half = pms2)[1]
        return (self.pAuditor)    

      
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
        self.D = random.randint(2 ** (n_len-3) + 1, 2 ** (n_len-2))
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
            K = random.randint(2 ** (n_len-3) + 1, 2 ** (n_len-2))
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
        encPMS = (self.P.decrypt(PSum) + (A * self.X)) % self.N
        return encPMS 
        
        
            
                       