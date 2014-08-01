from __future__ import print_function
import math, os, binascii, hmac, time, rsa, re
from hashlib import md5, sha1
from tlsn_common import *
from base64 import b64encode,b64decode
from pyasn1.type import univ
from pyasn1.codec.der import encoder, decoder
from slowaes import AESModeOfOperation
from slowaes import AES

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
    def __init__(self,server,port=443,ccs=53,audit=False):
        self.serverName = server
        self.sslPort = port
        self.tlsMajorVersionNum = '\x03'
        self.tlsMinorVersionNum = '\x01'
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
        self.cipherSuites = {47:['AES128',20,20,16,16,16,16],53:['AES256',20,20,32,32,16,16]}
        #,\
         #               4:['RC4MD5',20,20,16,16,0,0],5:['RC4SHA',16,16,16,16,0,0]}

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

        #needed for record HMAC construction
        self.clientSeqNo = 0
        self.serverSeqNo = 0

        #create clientHello on instantiation
        self.setClientHello(audit)

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

    def setClientHello(self,audit):
        if not self.clientRandom: return None
        if not self.chosenCipherSuite: return None
        # 2d is the length; this byte is edited on completion
        self.handshakeMessages[0] = '\x16\x03\x01\x00\x2d\x01\x00\x00'
        remaining = '\x03\x01' + self.clientRandom + '\x00' #last byte is session id length
        if not audit:
            remaining  += '\x00\x02\x00'+chr(self.chosenCipherSuite)
        else:
            remaining += '\x00'+chr(2*len(self.cipherSuites))
            for a in self.cipherSuites:
                remaining += '\x00'+chr(a)
        remaining += '\x01\x00'
        self.handshakeMessages[0] += chr(len(remaining)) + remaining
        self.handshakeMessages[0][4] = chr(len(remaining)+4)
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
        if csInt not in self.cipherSuites.keys():
            print ("Invalid cipher suite chosen")
            return None
        self.chosenCipherSuite = csInt
        print ('we set the cipher suite to: ',self.cipherSuites[csInt][0])
        return csInt

    def processServerHello(self,sh_cert_shd):
        #server hello always starts with 16 03 01 * * 02
        #certificate always starts with 16 03 01 * * 0b
        shd = '\x16\x03\x01\x00\x04\x0e\x00\x00\x00'
        sh_magic = re.compile(b'\x16\x03\x01..\x02',re.DOTALL)
        if not re.match(sh_magic, sh_cert_shd): raise Exception ('Invalid server hello')
        if not sh_cert_shd.endswith(shd): raise Exception ('invalid server hello done')
        #find the beginning of certificate message
        cert_magic = re.compile(b'\x16\x03\x01..\x0b',re.DOTALL)
        cert_match = re.search(cert_magic, sh_cert_shd)
        if not cert_match: raise Exception ('Invalid certificate message')
        cert_start_position = cert_match.start()
        sh = sh_cert_shd[:cert_start_position]
        self.handshakeMessages[2] = sh_cert_shd[cert_start_position : -len(shd)]
        self.handshakeMessages[1] = sh
        self.handshakeMessages[3] = shd
        self.serverRandom = sh[11:43]
        #extract the cipher suite
        #if a session id was provided, it will be preceded by its length 32:
        cs_start_byte = 43 if sh[43] != '\x20' else 43+1+32
        if sh[cs_start_byte] != '\x00' or ord(sh[cs_start_byte+1]) not in self.cipherSuites.keys():
            raise Exception("Could not locate cipher suite choice in server hello.")
        self.setCipherSuite(sh[cs_start_byte+1])
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

        if not (self.serverRandom and self.clientRandom):
            print ("Cannot expand keys, need client and server random")
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

    def getHandshakeHashes(self):
        self.handshakeMessages[4] = '\x16\x03\x01\x01\x06\x10\x00\x01\x02\x01\00' \
                                            + bigint_to_bytearray(self.encPMS)
        self.handshakeMessages[5] = '\x14\x03\01\x00\x01\x01'
        handshakeData = bytearray('').join([x[5:] for x in self.handshakeMessages[:5]])
        sha_verify = sha1(handshakeData).digest()
        md5_verify = md5(handshakeData).digest()
        return (sha_verify,md5_verify)

    def getVerifyDataForFinished(self,sha_verify=None,md5_verify=None,half=1,providedPValue=None):
        sha_verify, md5_verify = self.getHandshakeHashes()
        if not (sha_verify and md5_verify):
            print ('sha or md5 verify were not set, could not calculate verify data')
            return None

        if not providedPValue:
            #we calculate the verify data from the raw handshake messages
            if self.handshakeMessages[:6] != filter(None,self.handshakeMessages[:6]):
                print ('Handshake data was not complete, could not calculate verify data')
                print ('Here are the handshake messages: ',[str(x) for x in self.handshakeMessages[:6]])
                return None
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
        bytes_to_send = '\x17'+self.tlsMajorVersionNum+self.tlsMinorVersionNum #app data, tls version
        key_size = self.cipherSuites[self.chosenCipherSuite][3]
        moo = AESModeOfOperation()
        record_mac = self.buildRecordMac(False,cleartext,'\x17')
        cleartext += record_mac
        #cleartextList,clientEncList = [map(ord,x) for x in [cleartext,self.clientEncKey]]
        cleartextList = map(ord,cleartext)
        #clientEncList = map(ord,self.clientEncKey)
        clientEncList = bigint_to_bytearray(ba2int(self.clientEncKey))
        padding = getCBCPadding(len(cleartextList))
        paddedCleartext = bytearray(cleartextList) + padding
        mode, origLen, ciphertext = \
        moo.encrypt(str(paddedCleartext), moo.modeOfOperation['CBC'], \
        clientEncList, key_size , self.lastClientCiphertextBlock)
        #get length bytes
        cpt_len = bigint_to_bytearray(len(ciphertext))
        #combine
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

        seqNo = self.serverSeqNo if isFromServer else self.clientSeqNo
        #build sequence number bytes; 64 bit integer
        seqByteList = bigint_to_list(seqNo)
        seqByteList = [0]*(8-len(seqByteList)) + seqByteList
        seqNoBytes = ''.join(map(chr,seqByteList))
        encKey = self.serverMacKey if isFromServer else self.clientMacKey
        if not encKey:
            print ("Failed to build mac; mac key is missing")
            return None
        fragment_len = bigint_to_bytearray(len(cleartext))
        if len(fragment_len) ==1:
            fragment_len = '\x00'+fragment_len
        record_mac = hmac.new(encKey,seqNoBytes + recordType + \
                    self.tlsMajorVersionNum + self.tlsMinorVersionNum \
                    +fragment_len + cleartext,sha1).digest()
        return record_mac

    #TODO currently only applies to a AES-CBC handshake;
    def getCKECCSF(self,providedPValue = None):
        '''sets the handshake messages change cipher spec and finished,
        and returns the three final handshake messages client key exchange,
        change cipher spec and finished.
        If providedPValue is non null, it means the caller does not have
        access to the full master secret, and is providing the pvalue to be
        passed into getVerifyDataForFinished.'''
        self.handshakeMessages[4] = '\x16\x03\x01\x01\x06\x10\x00\x01\x02\x01\00' \
                                                + bigint_to_bytearray(self.encPMS)
        self.handshakeMessages[5] = '\x14\x03\01\x00\x01\x01'
        if providedPValue:
            verifyData = self.getVerifyDataForFinished(providedPValue=providedPValue,half=2)
        else:
            verifyData = self.getVerifyDataForFinished()
        if not verifyData:
            print ('Verify data was null')
            return None

        #HMAC and AES-encrypt the verify_data
        hmacVerify = self.buildRecordMac(False,'\x14\x00\x00\x0c' + verifyData,'\x16')
        moo = AESModeOfOperation()
        cleartext = '\x14\x00\x00\x0c' + verifyData + hmacVerify
        cleartextList = bigint_to_list(ba2int(cleartext))
        clientEncList =  bigint_to_list(ba2int(self.clientEncKey))
        clientIVList =  bigint_to_list(ba2int(self.clientIV))
        paddedCleartext = cleartext + getCBCPadding(len(cleartext))
        mode, origLen, hmacedVerifyData = \
        moo.encrypt( str(paddedCleartext), moo.modeOfOperation['CBC'], clientEncList, len(self.clientEncKey), clientIVList)
        self.lastClientCiphertextBlock = hmacedVerifyData[-16:]
        self.clientSeqNo += 1
        self.handshakeMessages[6] = '\x16\x03\x01\x00\x30' + bytearray(hmacedVerifyData)
        return bytearray('').join(self.handshakeMessages[4:])

    def processServerCCSFinished(self, data):
        #check for existence of CCS:
        if data[:6] != '\x14\x03\x01\x00\x01\x01':
            print ("Server CCSFinished did not contain CCS")
            return None
        self.serverFinished = data[6:]
        if self.serverFinished[:3] != '\x16\x03\x01':
            print ("Server CCSFinished does not contain Finished")
            return None
        recordLen = ba2int(self.serverFinished[3:5])
        #because the verify data is 12 bytes and the handshake header
        #is a further 4, and the mac is another 20, we have 36 bytes, meaning
        #that the padding is 12 bytes long, making a total of 48 bytes record length
        if recordLen != 48:
            print ("Server Finished record record length should be 48, is: ",recordLen)
            return None
        #TODO we should verify the verify data
        #we will, for now, only extract the final ciphertext block
        self.lastServerCiphertextBlock = self.serverFinished[-16:]

    def storeServerAppDataRecords(self, response):
        self.serverAppDataRecords = response


    def processServerAppDataRecords(self):
        '''Given the binary array 'response', containing the response from
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

        plaintext = ''
        bad_record_mac = 0
        response = self.serverAppDataRecords

        while True:
            if response[:3] != '\x17\x03\x01':
                if response[:3] == '\x15\x03\x01':
                    print ("Got encrypted alert, done")
                    break
                print ('Invalid TLS Header for App Data record')
                return None
            recordLen = ba2int(response[3:5])
            if recordLen %16:
                print ('Invalid ciphertext length for App Data')
                return None

            self.serverSeqNo += 1

            #decrypt, unpad and verify mac
            #ciphertextList = bigint_to_list(ba2int(record[5:5+recordLen]))
            ciphertextList = map(ord,response[5:5+recordLen])
            serverEncList =  bigint_to_list(ba2int(self.serverEncKey))
            serverIVList =  bigint_to_list(ba2int(self.lastServerCiphertextBlock))
            moo = AESModeOfOperation()
            key_size = self.cipherSuites[self.chosenCipherSuite][4]
            decr_resp = moo.decrypt(ciphertextList,recordLen,moo.modeOfOperation['CBC'],serverEncList,key_size,serverIVList)
            padLen = ba2int(decr_resp[-1])
            decr_unpad_resp = decr_resp[:-(padLen+1)] #TODO double check the padding bytes are actually right, don't just drop them

            #mac check
            received_mac = decr_unpad_resp[-sha1_hash_len:]
            check_mac = self.buildRecordMac(True,decr_unpad_resp[:-sha1_hash_len],'\x17')
            if received_mac != check_mac:
                print ("Warning, record mac check failed.")
                bad_record_mac += 1
            plaintext += decr_unpad_resp[:-sha1_hash_len]

            #prepare for next record, if there is one:
            if len(response) == 5+len(ciphertextList):
                break
            self.lastServerCiphertextBlock = response[5+recordLen-16:5+recordLen]
            response = response[5+recordLen:]

        return (plaintext,bad_record_mac)

    def completeHandshake(self, rsapms2):
        self.extractCertificate()
        self.extractModAndExp()
        self.setAuditeeSecret()
        self.setMasterSecretHalf() #default values means full MS created
        self.doKeyExpansion()
        self.encSecondHalfPMS = ba2int(rsapms2)
        self.setEncryptedPMS()
        return self.getCKECCSF()

def getCBCPadding(data_length):
    req_padding = 16 - data_length % 16
    return chr(req_padding-1) * req_padding

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
