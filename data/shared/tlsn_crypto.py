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
        self.server_name = server
        self.ssl_port = port
        self.n_auditee_entropy = 12
        self.n_auditor_entropy = 9
        self.auditor_secret = None
        self.auditee_secret = None
        self.auditor_padding_secret = None
        self.auditee_padding_secret = None
        self.enc_first_half_pms = None
        self.enc_second_half_pms = None
        self.enc_pms = None
        #client hello, server hello, certificate, server hello done,
        #client key exchange, change cipher spec, finished
        self.handshake_messages = [None] * 7
        self.handshake_hash_sha = None
        self.handshake_hash_md5 = None
        #client random can be created immediately on instantiation
        cr_time = bi2ba(int(time.time()))
        self.client_random = cr_time + os.urandom(28)
        self.server_random = None

        '''The amount of key material for each ciphersuite:
        AES256-CBC-SHA: mac key 20*2, encryption key 32*2, IV 16*2 == 136bytes
        AES128-CBC-SHA: mac key 20*2, encryption key 16*2, IV 16*2 == 104bytes
        RC4128_SHA: mac key 20*2, encryption key 16*2 == 72bytes
        RC4128_MD5: mac key 16*2, encryption key 16*2 == 64 bytes'''
        self.cipher_suites = {47:['AES128',20,20,16,16,16,16],\
                             53:['AES256',20,20,32,32,16,16],\
                             5:['RC4SHA',20,20,16,16,0,0],\
                             4:['RC4MD5',16,16,16,16,0,0]}
        #preprocessing: add the total number of bytes in the expanded keys format
        #for each cipher suite, for ease of reference
        for k,v in self.cipher_suites.iteritems():
            v.append(sum(v[1:]))

        self.chosen_cipher_suite = ccs

        self.p_auditor = None
        self.p_auditee = None

        self.master_secret_half_auditor = None
        self.master_secret_half_auditee = None

        self.p_master_secret_auditor = None
        self.p_master_secret_auditee = None

        self.server_mac_key = None
        self.client_mac_key = None
        self.server_enc_key = None
        self.client_enc_key = None
        self.serverIV = None
        self.clientIV = None

        self.server_certificate = None
        self.server_modulus = None
        self.server_exponent = 65537
        self.server_mod_length = None

        #these are stored to be used as IV
        #for encryption/decryption of the next SSL record
        self.last_client_ciphertext_block = None
        self.last_server_ciphertext_block = None

        #needed for maintaining RC4 cipher state
        self.client_rc4_state = None
        self.server_rc4_state = None

        #needed for record HMAC construction
        self.client_seq_no = 0
        self.server_seq_no = 0

        #array of ciphertexts from each SSL record
        self.server_response_ciphertexts=[]

        #the HMAC required to construct the verify data
        #for the server Finished record
        self.verify_hmac_for_server_finished = None
        
        #store the decrypted server finished message
        #for later mac check in form (plaintext,mac)
        self.decrypted_server_finished = (None,None)
        
        #all handshake messages are stored as transferred
        #over the wire, but the Finished message, which
        #is encrypted over the wire, is also needed for
        #hashing in unencrypted form.
        self.unencrypted_client_finished = None
        
        #create clientHello on instantiation
        self.set_client_hello()

    def dump(self):
        return_str='Session state dump: \n'
        for k,v in self.__dict__.iteritems():
            return_str += k + '\n'
            if type(v) == type(str()):
                return_str += 'string: len:'+str(len(v)) + '\n'
                return_str += v + '\n'
            elif type(v) == type(bytearray()):
                return_str += 'bytearray: len:'+str(len(v)) + '\n'
                return_str += binascii.hexlify(v) + '\n'
            else:
                return_str += str(v) + '\n'
        return return_str

    def set_client_hello(self):
        assert self.client_random, "Client random should have been set in constructor."
        remaining = tlsver + self.client_random + '\x00' #last byte is session id length
        if self.chosen_cipher_suite:
            #prepare_pms and testing only: use specific cs
            remaining  += '\x00\x02\x00'+chr(self.chosen_cipher_suite) 
        else:
            #use all 4 cipher_suites
            remaining += '\x00'+chr(2*len(self.cipher_suites))
            for a in self.cipher_suites:
                remaining += '\x00'+chr(a)                        
        remaining += '\x01\x00' #compression methods
        self.handshake_messages[0] = hs + tlsver + bi2ba(len(remaining)+4,fixed=2) + \
        h_ch + bi2ba(len(remaining),fixed=3) + remaining
        return self.handshake_messages[0]

    def set_master_secret_half(self,half=1,provided_p_value=None):
        #non provision of p value means we use the existing p
        #values to calculate the whole MS
        if not provided_p_value:
            self.master_secret_half_auditor = xor(self.p_auditee[:24],self.p_auditor[:24])
            self.master_secret_half_auditee = xor(self.p_auditee[24:],self.p_auditor[24:])
            return self.master_secret_half_auditor+self.master_secret_half_auditee
        assert half in [1,2], "Must provide half argument as 1 or 2"
        #otherwise the p value must be enough to provide one half of MS
        assert len(provided_p_value)==24, "Wrong length of P-hash value for half MS setting."
        if half == 1:
            self.master_secret_half_auditor = xor(self.p_auditor[:24],provided_p_value)
            return self.master_secret_half_auditor
        else:
            self.master_secret_half_auditee = xor(self.p_auditee[24:],provided_p_value)
            return self.master_secret_half_auditee

    def set_cipher_suite(self, cs):
        assert cs in self.cipher_suites.keys(), "Invalid cipher suite chosen" 
        self.chosen_cipher_suite = cs
        return cs

    def process_server_hello(self,sh_cert_shd):
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
            self.handshake_messages[1]=tls_header+str(bi2ba(4+sh_length,fixed=2))+ \
            sh_cert_shd[5:9]+sh_cert_shd[9:9+sh_length]
            
            assert sh_cert_shd[9+sh_length] == h_cert, "Failed to find certificate, server hello length was: "+str(sh_length)
            cert_len = ba2int(sh_cert_shd[9+sh_length+1:9+sh_length+4])
            #certificate
            self.handshake_messages[2] = tls_header+str(bi2ba(4+cert_len,fixed=2))+\
                sh_cert_shd[9+sh_length:9+sh_length+4+cert_len]
            #server hello done
            self.handshake_messages[3] = shd

        else:
            cert_start_position = cert_match.start()
            sh = sh_cert_shd[:cert_start_position]
            self.handshake_messages[2] = sh_cert_shd[cert_start_position : -len(shd)]
            self.handshake_messages[1] = sh
            self.handshake_messages[3] = shd
            
        self.server_random = self.handshake_messages[1][11:43]
        #extract the cipher suite
        #if a session id was provided, it will be preceded by its length 32:
        #note: 44 = 1 tls record type + 2 tls ver + 2 record length + 1 handshake type
        # + 3 handshake length + 2 tls ver + 32 server random + 1 session id lenth (zero)
        cs_start_byte = 44 if self.handshake_messages[1][43] != '\x20' else 43+1+32
        if self.handshake_messages[1][cs_start_byte] != '\x00' or \
           ord(self.handshake_messages[1][cs_start_byte+1]) not in self.cipher_suites.keys():
            raise Exception("Could not locate cipher suite choice in server hello.")
        server_cipher_suite = ba2int(self.handshake_messages[1][cs_start_byte+1])
        if self.chosen_cipher_suite: #testing only,  we prefered a specific cs
            if self.chosen_cipher_suite != server_cipher_suite:
                raise Exception ('Server did not return the ciphersuite we requested')
        self.set_cipher_suite(server_cipher_suite)
        #if enc_pms is not yet set, this is a call from prepare_pms()
        #otherwise this is a normal audit session
        if self.enc_pms:
            self.set_handshake_hashes()
            self.set_auditee_secret()
        
        print ("Set cipher suite to ", str(server_cipher_suite))
            
        return (self.handshake_messages[1:4], self.server_random)

    def set_encrypted_pms(self):
        assert (self.enc_first_half_pms and self.enc_second_half_pms and self.server_modulus), \
            'failed to set enc_pms, first half was: ' + str(self.enc_first_half_pms) +\
            ' second half was: ' + str(self.enc_second_half_pms) + ' modulus was: ' + str(self.server_modulus)
        self.enc_pms =  self.enc_first_half_pms * self.enc_second_half_pms % self.server_modulus
        return self.enc_pms

    def set_enc_first_half_pms(self):
        assert (self.server_modulus and not self.enc_first_half_pms)
        ones_length = 23            
        pms1 = tlsver+self.auditee_secret + ('\x00' * (24-2-self.n_auditee_entropy))
        self.enc_first_half_pms = pow(ba2int('\x02'+('\x01'*(ones_length))+\
        self.auditee_padding_secret+'\x00'+pms1 +'\x00'*23 + '\x01'), self.server_exponent, self.server_modulus)
     
    def set_auditee_secret(self):
        '''Sets up the auditee's half of the preparatory
        secret material to create the master secret.'''
        assert self.client_random and self.server_random,"one of client or server random not set"
        if not self.auditee_secret:
            self.auditee_secret = os.urandom(self.n_auditee_entropy)             
        if not self.auditee_padding_secret:
            self.auditee_padding_secret = os.urandom(15)
        label = 'master secret'
        seed = self.client_random + self.server_random
        pms1 = tlsver+self.auditee_secret + ('\x00' * (24-2-self.n_auditee_entropy))
        self.p_auditee = tls_10_prf(label+seed,first_half = pms1)[0]
        #encrypted PMS has already been calculated before the audit began
        return (self.p_auditee)

    def set_enc_second_half_pms(self):
        assert (self.server_modulus and not self.enc_first_half_pms)
        ones_length = 103+ba2int(self.server_mod_length)-256
        pms2 =  self.auditor_secret + ('\x00' * (24-self.n_auditor_entropy-1)) + '\x01'
        self.enc_second_half_pms = pow( ba2int('\x01'+('\x01'*(ones_length))+\
        self.auditor_padding_secret+ ('\x00'*25)+pms2), self.server_exponent, self.server_modulus )

    def set_auditor_secret(self):
        '''Sets up the auditor's half of the preparatory
        secret material to create the master secret, and
        the encrypted premaster secret.
        'secret' should be a bytearray of length n_auditor_entropy'''
        assert (self.client_random and self.server_random), "one of client or server random not set"
        if not self.auditor_secret:
            self.auditor_secret = os.urandom(self.n_auditor_entropy)
        if not self.auditor_padding_secret:
            self.auditor_padding_secret =  os.urandom(15)
        label = 'master secret'
        seed = self.client_random + self.server_random
        pms2 =  self.auditor_secret + ('\x00' * (24-self.n_auditor_entropy-1)) + '\x01'
        self.p_auditor = tls_10_prf(label+seed,second_half = pms2)[1]
        return (self.p_auditor)

    def extract_certificate(self):
        assert self.handshake_messages[2], "Cannot extract certificate, no handshake message present."
        cert_len = ba2int(self.handshake_messages[2][12:15])
        self.server_certificate = self.handshake_messages[2][15:15+cert_len]
        return self.server_certificate

    def extract_mod_and_exp(self,certDER=None):
        if not certDER: 
            self.extract_certificate()
            DERdata = self.server_certificate
        else: DERdata = certDER
        assert (self.server_certificate or certDER), "No server certificate, cannot extract pubkey"
        rv  = decoder.decode(DERdata, asn1Spec=univ.Sequence())
        bit_string = rv[0].getComponentByPosition(0).getComponentByPosition(6).getComponentByPosition(1)
        #bit_string is a list of ints, like [01110001010101000...]
        #convert it into into a string   '01110001010101000...'
        string_of_bits = ''
        for bit in bit_string:
            bit_as_str = str(bit)
            string_of_bits += bit_as_str
        #treat every 8 chars as an int and pack the ints into a bytearray
        ba = bytearray()
        for i in range(0, len(string_of_bits)/8):
            onebyte = string_of_bits[i*8 : (i+1)*8]
            oneint = int(onebyte, base=2)
            ba.append(oneint)
        #decoding the nested sequence
        rv  = decoder.decode(str(ba), asn1Spec=univ.Sequence())
        exponent = rv[0].getComponentByPosition(1)
        modulus = rv[0].getComponentByPosition(0)
        self.server_modulus = int(modulus)
        self.server_exponent = int(exponent)
        n = bi2ba(self.server_modulus)
        e = bi2ba(self.server_exponent)
        modulus_len_int = len(n)
        self.server_mod_length = bi2ba(modulus_len_int)
        if len(self.server_mod_length) == 1: self.server_mod_length.insert(0,0)  #zero-pad to 2 bytes

        return (self.server_modulus,self.server_exponent)

    #provide a list of keys that you want to 'garbageize' so as to hide
    #that key from the counterparty, in the array 'garbage', each number is
    #an index to that key in the cipher_suites dict
    def get_p_value_ms(self,ctrprty,garbage=[]):
        assert (self.server_random and self.client_random and self.chosen_cipher_suite), \
               "server random, client random or cipher suite not set."
        label = 'key expansion'
        seed = self.server_random + self.client_random
        expkeys_len = self.cipher_suites[self.chosen_cipher_suite][-1]        
        if ctrprty == 'auditor':
            self.p_master_secret_auditor = tls_10_prf(label+seed,req_bytes=expkeys_len,first_half=self.master_secret_half_auditor)[0]
        else:
            self.p_master_secret_auditee = tls_10_prf(label+seed,req_bytes=expkeys_len,second_half=self.master_secret_half_auditee)[1]

        tmp = self.p_master_secret_auditor if ctrprty=='auditor' else self.p_master_secret_auditee
        for k in garbage:
            if k==1:
                start = 0
            else:
                start = sum(self.cipher_suites[self.chosen_cipher_suite][1:k])
            end = sum(self.cipher_suites[self.chosen_cipher_suite][1:k+1])
            #ugh, python strings are immutable, what's the elegant way to do this?
            tmp2 = tmp[:start]+os.urandom(end-start)+tmp[end:]
            tmp = tmp2
        return tmp

    def do_key_expansion(self):
        '''A note about partial expansions:
        Often we will have sufficient information to extract particular
        keys, e.g. the client keys, but not others, e.g. the server keys.
        This should be handled by passing in garbage to fill out the relevant
        portions of the two master secret halves. TODO find a way to make this
        explicit so that querying the object will only give real keys.
        '''
        assert (self.server_random and self.client_random)," need client and server random"
        label = 'key expansion'
        seed = self.server_random + self.client_random
        #for maximum flexibility, we will compute the sha1 or md5 hmac
        #or the full keys, based on what secrets currently exist in this object
        expkeys_len = self.cipher_suites[self.chosen_cipher_suite][-1]                
        if self.master_secret_half_auditee:
            self.p_master_secret_auditee = tls_10_prf(label+seed,req_bytes=expkeys_len,second_half=self.master_secret_half_auditee)[1]
        if self.master_secret_half_auditor:
            self.p_master_secret_auditor = tls_10_prf(label+seed,req_bytes=expkeys_len,first_half=self.master_secret_half_auditor)[0]

        if self.master_secret_half_auditee and self.master_secret_half_auditor:
            key_expansion = tls_10_prf(label+seed,req_bytes=expkeys_len,full_secret=self.master_secret_half_auditor+\
                                                                                self.master_secret_half_auditee)[2]
        elif self.p_master_secret_auditee and self.p_master_secret_auditor:
            key_expansion = xor(self.p_master_secret_auditee,self.p_master_secret_auditor)
        else:
            raise Exception ('Cannot expand keys, insufficient data')

        #we have the raw key expansion, but want the keys. Use the data
        #embedded in the cipherSuite dict to identify the boundaries.
        assert self.chosen_cipher_suite,"Cannot expand ssl keys without a chosen cipher suite."

        key_accumulator = []
        ctr=0
        for i in range(6):
            keySize = self.cipher_suites[self.chosen_cipher_suite][i+1]
            if keySize == 0:
                key_accumulator.append(None)
            else:
                key_accumulator.append(key_expansion[ctr:ctr+keySize])
            ctr += keySize

        self.client_mac_key,self.server_mac_key,self.client_enc_key,self.server_enc_key,self.clientIV,self.serverIV = key_accumulator
        return bytearray('').join(filter(None,key_accumulator))

    def get_verify_hmac(self,sha_verify=None,md5_verify=None,half=1,is_for_client=True):
        '''returns only 12 bytes of hmac'''
        label = 'client finished' if is_for_client else 'server finished'
        seed = md5_verify + sha_verify
        if half==1:
            return tls_10_prf(label+seed,req_bytes=12,first_half = self.master_secret_half_auditor)[0]
        else:
            return tls_10_prf(label+seed,req_bytes=12,second_half = self.master_secret_half_auditee)[1]

    def set_handshake_hashes(self):
        assert self.enc_pms
        #TODO: This is a repetition of get_cke_ccs_f. Obviously it should be got rid of.
        #I can't remember why it's necessary.
        #construct correct length bytes for CKE
        epms_len = len(bi2ba(self.enc_pms))
        b_epms_len = bi2ba(epms_len,fixed=2)
        hs_len = 2 + epms_len
        b_hs_len = bi2ba(hs_len,fixed=3)
        record_len = 6+epms_len
        b_record_len = bi2ba(record_len,fixed=2)
        #construct CKE
        self.handshake_messages[4] = hs + tlsver + b_record_len + h_cke + \
            b_hs_len + b_epms_len + bi2ba(self.enc_pms)
        #Change cipher spec NB, not a handshake message
        self.handshake_messages[5] = chcis + tlsver + bi2ba(1,fixed=2)+'\x01'
        
        handshake_data = bytearray('').join([x[5:] for x in self.handshake_messages[:5]])
        self.handshake_hash_sha = sha1(handshake_data).digest()
        self.handshake_hash_md5 = md5(handshake_data).digest()
    
    def get_server_handshake_hashes(self):
        handshake_data = bytearray('').join([x[5:] for x in self.handshake_messages[:5]])
        handshake_data += self.unencrypted_client_finished
        return(sha1(handshake_data).digest(), md5(handshake_data).digest())

    def get_verify_data_for_finished(self,sha_verify=None,md5_verify=None,half=1,provided_p_value=None):
        if not (sha_verify and md5_verify):
            sha_verify, md5_verify = self.handshake_hash_sha, self.handshake_hash_md5

        if not provided_p_value:
            #we calculate the verify data from the raw handshake messages
            if self.handshake_messages[:6] != filter(None,self.handshake_messages[:6]):
                print ('Here are the handshake messages: ',[str(x) for x in self.handshake_messages[:6]])
                raise Exception('Handshake data was not complete, could not calculate verify data')
            label = 'client finished'
            seed = md5_verify + sha_verify
            ms = self.master_secret_half_auditor+self.master_secret_half_auditee
            #we don't store the verify data locally, just return it
            return tls_10_prf(label+seed,req_bytes=12,full_secret=ms)[2]

        #we calculate based on provided hmac by the other party
        return xor(provided_p_value[:12],self.get_verify_hmac(sha_verify=sha_verify,md5_verify=md5_verify,half=half))

    def build_request(self, cleartext):
        '''Constructs the raw bytes to send over TCP
        for a given client request. Implicitly the request
        will be less than 16kB and therefore only 1 SSL record.
        This can in principle be used more than once.'''
        bytes_to_send = appd+tlsver #app data, tls version

        record_mac = self.build_record_mac(False,cleartext,appd)
        cleartext += record_mac
        if self.chosen_cipher_suite in [4,5]:
            ciphertext, self.client_rc4_state = rc4_crypt(bytearray(cleartext),self.client_enc_key,self.client_rc4_state)
        elif self.chosen_cipher_suite in [47,53]:
            cleartext_list = map(ord,cleartext)
            #client_enc_list = map(ord,self.client_enc_key)
            client_enc_list = bi2ba(ba2int(self.client_enc_key))
            padding = get_cbc_padding(len(cleartext_list))
            padded_cleartext = bytearray(cleartext_list) + padding
            key_size = self.cipher_suites[self.chosen_cipher_suite][3]
            moo = AESModeOfOperation()
            mode, orig_len, ciphertext = \
            moo.encrypt(str(padded_cleartext), moo.modeOfOperation['CBC'], \
            client_enc_list, key_size , self.last_client_ciphertext_block)
        else:
            raise Exception ("Error, unrecognized cipher suite in build_request")

        cpt_len = bi2ba(len(ciphertext),fixed=2)
        bytes_to_send += cpt_len + bytearray(ciphertext)
        #just in case we plan to send more data,
        #update the client ssl state
        self.client_seq_no += 1
        self.last_client_ciphertext_block = ciphertext[-16:]
        return bytes_to_send

    def build_record_mac(self, is_from_server, cleartext, record_type):
        '''Note: the fragment should be the cleartext of the record
        before mac and pad; but for handshake messages there is a header
        to the fragment, of the form (handshake type), 24 bit length.'''
        mac_algo = md5 if self.chosen_cipher_suite == 4 else sha1
        
        seq_no = self.server_seq_no if is_from_server else self.client_seq_no
        #build sequence number bytes; 64 bit integer #TODO make this tidier
        seq_byte_list = bigint_to_list(seq_no)
        seq_byte_list = [0]*(8-len(seq_byte_list)) + seq_byte_list
        seq_no_bytes = ''.join(map(chr,seq_byte_list))
        mac_key = self.server_mac_key if is_from_server else self.client_mac_key
        if not mac_key:
            raise Exception("Failed to build mac; mac key is missing")
        fragment_len = bi2ba(len(cleartext),fixed=2)    
        record_mac = hmac.new(mac_key,seq_no_bytes + record_type + \
                    tlsver+fragment_len + cleartext, mac_algo).digest()
        return record_mac

    def get_cke_ccs_f(self,provided_p_value = None):
        '''sets the handshake messages change cipher spec and finished,
        and returns the three final handshake messages client key exchange,
        change cipher spec and finished.
        If provided_p_value is non null, it means the caller does not have
        access to the full master secret, and is providing the pvalue to be
        passed into get_verify_data_for_finished.'''
        assert self.enc_pms
        assert self.handshake_messages[4] #cke
        assert self.handshake_messages[5] #ccs
        #CKE and CCS were already prepared earlier
        #start processing for Finished
        if provided_p_value:
            verify_data = self.get_verify_data_for_finished(provided_p_value=provided_p_value,half=2)
        else:
            verify_data = self.get_verify_data_for_finished()
        assert verify_data,'Verify data was null'

        #HMAC and encrypt the verify_data
        hs_header = h_fin + bi2ba(12,fixed=3)
        hmac_verify = self.build_record_mac(False,hs_header + verify_data,hs)
        cleartext = hs_header + verify_data + hmac_verify
        self.unencrypted_client_finished = hs_header + verify_data
        assert self.chosen_cipher_suite in self.cipher_suites.keys(), "invalid cipher suite"
        if self.chosen_cipher_suite in [4,5]:
            hmaced_verify_data, self.client_rc4_state = rc4_crypt(cleartext,self.client_enc_key)
        elif self.chosen_cipher_suite in [47,53]:
            cleartext_list,client_enc_list,client_iv_list = \
                [map(ord,str(x)) for x in [cleartext,self.client_enc_key,self.clientIV]]
            padded_cleartext = cleartext + get_cbc_padding(len(cleartext))
            moo = AESModeOfOperation()
            mode, orig_len, hmaced_verify_data = \
            moo.encrypt( str(padded_cleartext), moo.modeOfOperation['CBC'], \
                         client_enc_list, len(self.client_enc_key), client_iv_list)
            self.last_client_ciphertext_block = hmaced_verify_data[-16:]

        self.client_seq_no += 1
        self.handshake_messages[6] = hs + tlsver + bi2ba(len(hmaced_verify_data),fixed=2) \
            + bytearray(hmaced_verify_data)
        return bytearray('').join(self.handshake_messages[4:])

    def process_server_ccs_finished(self, data, provided_p_value):
        if data[:6] != chcis + tlsver + bi2ba(1,fixed=2)+'\x01':
            print ("Got response:",binascii.hexlify(data))
            raise Exception("Server CCSFinished did not contain CCS")
        self.server_finished = data[6:]
        assert self.server_finished[:3] == hs+tlsver,"Server CCSFinished does not contain Finished"
        record_len = ba2int(self.server_finished[3:5])
        assert record_len == len(self.server_finished[5:]), "unexpected data at end of server finished."
        #For CBC only: because the verify data is 12 bytes and the handshake header
        #is a further 4, and the mac is another 20, we have 36 bytes, meaning
        #that the padding is 12 bytes long, making a total of 48 bytes record length
        if record_len != 48 and self.chosen_cipher_suite in [47,53]:
            raise Exception("Server Finished record record length should be 48, is: ",record_len)
        
        #decrypt:
        if self.chosen_cipher_suite in [4,5]:
            decrypted,self.server_rc4_state = rc4_crypt(bytearray(self.server_finished[5:5+record_len]),self.server_enc_key) #box is null for first record
        elif self.chosen_cipher_suite in [47,53]:
            ciphertext_list,server_enc_list,server_iv_list = \
                [map(ord,x) for x in [self.server_finished[5:5+record_len],str(self.server_enc_key),str(self.serverIV)]]
            moo = AESModeOfOperation()
            key_size = self.cipher_suites[self.chosen_cipher_suite][4]
            decrypted = moo.decrypt(ciphertext_list,record_len,moo.modeOfOperation['CBC'],server_enc_list,key_size,server_iv_list)
            #for CBC, unpad
            decrypted = cbc_unpad(decrypted)
                
        #strip the mac (NB The mac cannot be checked, as in tlsnotary, the server_mac_key
        #is garbage until after the commitment. This mac check occurs in 
        #process_server_app_data_records)
        hash_len = sha1_hash_len if self.chosen_cipher_suite in [5,47,53] else md5_hash_len
        received_mac = decrypted[-hash_len:]
        plaintext = decrypted[:-hash_len]
        
        #check the finished message header
        assert plaintext[:4] == h_fin+bi2ba(12,fixed=3), "The server Finished verify data is invalid"
        #Verify the verify data
        verify_data = plaintext[4:]
        sha_verify,md5_verify = self.get_server_handshake_hashes()
        if len(plaintext[4:]) != 12:
            print ("Wrong length of plaintext")
        verify_data_check = xor(provided_p_value,\
                            self.get_verify_hmac(sha_verify=sha_verify,md5_verify=md5_verify,half=2,is_for_client=False))
        assert verify_data == verify_data_check, "Server Finished record verify data is not valid."
        #now the server finished is verified (except mac), we store
        #the plaintext of the message for later mac check 
        #(after auditor has passed server mac key)
        self.decrypted_server_finished = (plaintext,received_mac)
        #necessary for CBC
        self.last_server_ciphertext_block = self.server_finished[-16:]
        return True

    def store_server_app_data_records(self, response):
        self.serverAppDataRecords = response
        #extract the ciphertext from the raw records as a list
        #for maximum flexibility in decryption
        while True:
            if response[:3] != appd+tlsver:
                if response[:3] == alrt + tlsver:
                    print ("Got encrypted alert, done")
                    break
                raise Exception('Invalid TLS Header for App Data record')
            record_len = ba2int(response[3:5])
            if self.chosen_cipher_suite in [47,53] and record_len %16: 
                raise Exception('Invalid ciphertext length for App Data')
            one_record = response[5:5+record_len]
            if len(one_record) != record_len:
                #TODO - we may want to rerun the audit for this page
                raise Exception ('Invalid record length')
            self.server_response_ciphertexts.append(one_record)
            #prepare for next record, if there is one:
            if len(response) == 5+len(self.server_response_ciphertexts[-1]):
                break
            response = response[5+record_len:]
        print ("We got this many record ciphertexts:",len(self.server_response_ciphertexts))


#used only during testing. Get ciphertexts which will be shipped off to browser
#for AES decryption
    def getCiphertexts(self):
        assert len(self.server_response_ciphertexts),"Could not process the server response, no ciphertext found."
        if not self.chosen_cipher_suite in [47,53]: #AES-CBC
            raise Exception("non-AES cipher suite.")                    
        ciphertexts = [] #each item contains a tuple (ciphertext, encryption_key, iv)
        for ciphertext in self.server_response_ciphertexts:
            ciphertexts.append( (ciphertext, self.server_enc_key, self.last_server_ciphertext_block) )
            self.last_server_ciphertext_block = ciphertext[-16:] #ready for next record
        return ciphertexts


#used only during testing. Check mac on each plaintext and return the combined plaintexts
#with macs stripped
    def macCheckPlaintexts(self, plaintexts):
        mac_stripped_plaintext = ''
        for idx,raw_plaintext in enumerate(plaintexts):
            #need correct sequence number for macs            
            self.server_seq_no += 1
            hash_len = sha1_hash_len if self.chosen_cipher_suite in [5,47,53] else md5_hash_len
            received_mac = raw_plaintext[-hash_len:]
            check_mac = self.build_record_mac(True,raw_plaintext[:-hash_len],appd)
            if received_mac != check_mac:
                raise Exception ("Warning, record mac check failed. in index:" + str(idx))
            mac_stripped_plaintext += raw_plaintext[:-hash_len]
        return mac_stripped_plaintext
        
        
 
    def process_server_app_data_records(self,checkFinished=False):
        '''Using the encrypted records in self.server_response_ciphertexts, 
        containing the response from
        the server to a GET or POST request (the *first* request after
        the handshake), this function will process the response one record
        at a time. Each of these records is decrypted and reassembled
        into the plaintext form of the response. The plaintext is returned
        along with the number of record mac failures (more than zero means
        the response is unauthenticated/corrupted).
        Notes:
        self.server_seq_no should be set to zero before executing this function.
        This will occur by default if the session object has not undergone
        any handshake, or if it has undergone a handshake, so no intervention
        should, in theory, be required.'''
        bad_record_mac = 0
        if checkFinished:
            #before beginning, we must authenticate the server finished
            check_mac = self.build_record_mac(True,self.decrypted_server_finished[0],hs)
            if self.decrypted_server_finished[1] != check_mac:
                print ("Warning, record mac check failed from server Finished message.")
                bad_record_mac += 1
                return None        #TODO - exception here?        
        plaintext = ''
        
        assert len(self.server_response_ciphertexts),"Could not process the server response, no ciphertext found."
        
        for ciphertext in self.server_response_ciphertexts:
            #need correct sequence number for macs
            self.server_seq_no += 1
            if self.chosen_cipher_suite in [4,5]: #RC4
                raw_plaintext, self.server_rc4_state = rc4_crypt(bytearray(ciphertext),self.server_enc_key,\
                                                            self.server_rc4_state)
            elif self.chosen_cipher_suite in [47,53]: #AES-CBC
                ciphertext_list,server_enc_list,server_iv_list = \
                    [map(ord,x) for x in [ciphertext,str(self.server_enc_key),self.last_server_ciphertext_block]]
                moo = AESModeOfOperation()
                key_size = self.cipher_suites[self.chosen_cipher_suite][4]
                raw_plaintext = moo.decrypt(ciphertext_list,len(ciphertext_list),\
                                moo.modeOfOperation['CBC'],server_enc_list,key_size,server_iv_list)
                #unpad (and verify padding)
                raw_plaintext = cbc_unpad(raw_plaintext)
                self.last_server_ciphertext_block = ciphertext[-16:] #ready for next record
            else:
                raise Exception("Unrecognized cipher suite.")

            #mac check
            hash_len = sha1_hash_len if self.chosen_cipher_suite in [5,47,53] else md5_hash_len
            received_mac = raw_plaintext[-hash_len:]
            check_mac = self.build_record_mac(True,raw_plaintext[:-hash_len],appd)
            if received_mac != check_mac:
                raise Exception ("Warning, record mac check failed.")
                #bad_record_mac += 1
            plaintext += raw_plaintext[:-hash_len]

        return (plaintext, bad_record_mac)

    def complete_handshake(self, rsapms2):
        '''Called from prepare_pms(). For auditee only,
        who passes the second half of the encrypted
        PMS product (see TLSNotary.pdf under documentation).'''
        self.extract_certificate()
        self.extract_mod_and_exp()
        self.set_auditee_secret()
        self.set_master_secret_half() #default values means full MS created
        self.do_key_expansion()
        self.enc_second_half_pms = ba2int(rsapms2)
        self.set_enc_first_half_pms()
        self.set_encrypted_pms()
        self.set_handshake_hashes()         
        return self.get_cke_ccs_f()
        
def get_cbc_padding(data_length):
    req_padding = 16 - data_length % 16
    return chr(req_padding-1) * req_padding

def cbc_unpad(pt):
    '''Given binary string pt, return
    unpadded string, raise fatal exception
    if padding format is not valid'''
    padLen = ba2int(pt[-1])
    #verify the padding
    if not all(padLen == x for x in map(ord,pt[-padLen-1:-1])):
        raise Exception ("Invalid CBC padding.")
    return pt[:-(padLen+1)]    
                    
def rc4_crypt(data, key, state=None):
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

def tls_10_prf(seed, req_bytes = 48, first_half=None,second_half=None,full_secret=None):
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

 



class TLSNSSLClientSession_Paillier(TLSNSSLClientSession):
    def __init__(self, server=None,port=443,ccs=None):
        super(TLSNSSLClientSession_Paillier, self).__init__(server, port, ccs)
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
        
        
            
                       