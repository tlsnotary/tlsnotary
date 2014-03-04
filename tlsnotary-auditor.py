#!/usr/bin/env python
from __future__ import print_function

import BaseHTTPServer
import base64
import binascii
import hashlib
import hmac
import os
import platform
import Queue
import shutil
import SimpleHTTPServer
import socket
from SocketServer import ThreadingMixIn
import struct
import subprocess
import sys
import threading
import time
import random

installdir = os.path.dirname(os.path.realpath(__file__))
datadir = os.path.join(installdir, 'auditor')
sessionsdir = os.path.join(datadir, 'sessions')

sys.path.append(os.path.join(datadir, 'python', 'rsa-3.1.4'))
sys.path.append(os.path.join(datadir, 'python', 'pyasn1-0.1.7'))
import rsa
import pyasn1
from pyasn1.type import univ
from pyasn1.codec.der import encoder, decoder

platform = platform.system()
if platform == 'Windows':
    OS = 'mswin'
elif platform == 'Linux':
    OS = 'linux'
elif platform == 'Darwin':
    OS = 'macos'

#exit codes
MINIHTTPD_FAILURE = 2
MINIHTTPD_WRONG_RESPONSE = 3
MINIHTTPD_START_TIMEOUT = 4
FIREFOX_MISSING= 1
FIREFOX_START_ERROR = 5
BROWSER_NOT_FOUND = 6

sslkeylogfile = ''
current_sessiondir = ''
browser_exepath = 'firefox'

IRCsocket = socket._socketobject
my_nick = ''
auditee_nick = ''
channel_name = '#tlsnotary'
myPrivateKey = rsa.key.PrivateKey
auditeePublicKey = rsa.key.PublicKey
#uid used to create a unique name when logging each set of messages
uid = ''

#There are 2 ways to convert the FF's internal DER pubkey structure: using openssl or pure-python rsa module
#Ideally, we don't want to ship openssl on Windows, so we use pyasn1 by default
#Still, we leave the openssl implementation switch here just in case
DER_to_pubkey_using_openssl = False
DER_to_pubkey_using_pyasn1 = True

recvQueue = Queue.Queue() #all IRC messages are placed on this queue
countQueue = Queue.Queue() #count_my_messages_thread places messages' ordinal numbers on this thread 
progressQueue = Queue.Queue() #messages intended to be displayed by the frontend are placed here


#processes each http request in a separate thread
#we need threading in order to send progress updates to the frontend in a non-blocking manner
class StoppableThreadedHttpServer (ThreadingMixIn, BaseHTTPServer.HTTPServer):
    """http server that reacts to self.stop flag"""
    retval = ''
    def serve_forever (self):
        """Handle one request at a time until stopped. Optionally return a value"""
        self.stop = False
        while not self.stop:
                self.handle_request()
        return self.retval;
    


def get_encrypted_pms(der):    
      #if DER_to_pubkey_using_openssl == True:
      #import subprocess
      ##check out the output of "openssl asn1parse -inform der -in /tmp/der -strparse 19" to understand the parsing below
      #rv = subprocess.check_output(['openssl', 'asn1parse', '-inform', 'der', '-in', os.path.join(NSS_PATCH_DIR, 'der'+uid), '-strparse', '19'])
      #items = rv.split()
      #key_material = dict()
      #is_modulus_found = False
      #for index,one_item in enumerate(items):
          #if one_item == 'INTEGER':
              #if not is_modulus_found:
                  #key_material["modulus"] = items[index+1][1:]
                  #is_modulus_found = True
                  #continue
              #else:
                  #key_material["exponent"] = items[index+1][1:]
                  #break
      
      #exponent_openssl = key_material['exponent'].decode('hex')
      #e_intlist = []
      #for c in bytearray(exponent_openssl): e_intlist.append(c)
      #e_int = reduce(lambda x, y: (x<<8) + y, e_intlist)
      
      #modulus_openssl = key_material['modulus'].decode('hex')
      #m_intlist = []
      #for c in bytearray(modulus_openssl): m_intlist.append(c)
      #m_int = reduce(lambda x, y: (x<<8) + y, m_intlist)
      
      #pubkey = rsa.PublicKey(m_int, e_int)
  
    #if DER_to_pubkey_using_pyasn1 == True:
    try:       
        rv  = decoder.decode(der, asn1Spec=univ.Sequence())
        bitstring = rv[0].getComponentByPosition(1)
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
        modulus_int = int(modulus)
        exponent_int = int(exponent)
        pubkey = rsa.PublicKey(modulus_int, exponent_int)
    except:
        return('failure', 0,0)
        
    #generate PMS and encrypt it
    #see RFC2246 7.4.7.1. RSA encrypted premaster secret message
    rand_string = bytearray(os.urandom(46))
    pms = bytearray()
    ints = bytearray()
    ints.append(3)
    ints.append(1)
    pms = ints + rand_string
    with open(os.path.join(current_sessiondir, 'pms'+uid), 'w') as f: f.write(pms)
    enc_pms = rsa.encrypt(str(pms), pubkey)
    with open(os.path.join(current_sessiondir, 'encpms'+uid), 'w') as f: f.write(enc_pms)
    return ('success', pms, enc_pms)
   
   
        
def get_expanded_keys(cr, sr, pms):
    with open(os.path.join(current_sessiondir, 'cr'+uid), 'w') as f: f.write(cr)
    
    #derive master secret
    #see RFC2246 8.1. Computing the master secret & 5. HMAC and the pseudorandom function    
    secret = pms
    secret_first_half = secret[:24]
    secret_second_half = secret[24:]
    label = "master secret"
    seed = cr + sr
    
    #start the PRF
    md5A1 = hmac.new(secret_first_half,  label+seed, hashlib.md5).digest()
    md5A2 = hmac.new(secret_first_half,  md5A1, hashlib.md5).digest()
    md5A3 = hmac.new(secret_first_half,  md5A2, hashlib.md5).digest()
    
    md5hmac1 = hmac.new(secret_first_half, md5A1 + label + seed, hashlib.md5).digest()
    md5hmac2 = hmac.new(secret_first_half, md5A2 + label + seed, hashlib.md5).digest()
    md5hmac3 = hmac.new(secret_first_half, md5A3 + label + seed, hashlib.md5).digest()
    md5hmac = md5hmac1+md5hmac2+md5hmac3
    
    sha1A1 = hmac.new(secret_second_half,  label+seed, hashlib.sha1).digest()
    sha1A2 = hmac.new(secret_second_half,  sha1A1, hashlib.sha1).digest()
    sha1A3 = hmac.new(secret_second_half,  sha1A2, hashlib.sha1).digest()
    
    sha1hmac1 = hmac.new(secret_second_half, sha1A1 + label + seed, hashlib.sha1).digest()
    sha1hmac2 = hmac.new(secret_second_half, sha1A2 + label + seed, hashlib.sha1).digest()
    sha1hmac3 = hmac.new(secret_second_half, sha1A3 + label + seed, hashlib.sha1).digest()
    sha1hmac = sha1hmac1+sha1hmac2+sha1hmac3
    
    #xor the two hmacs
    xored = [ord(a) ^ ord(b) for a,b in zip(md5hmac,sha1hmac)]
    ms = bytearray(xored)

    with open(os.path.join(current_sessiondir, 'ms'+uid), 'w') as f: f.write(ms)
    #from https://developer.mozilla.org/en-US/docs/NSS_Key_Log_Format
    #CLIENT_RANDOM <space> <64 bytes of hex encoded client_random> <space> <96 bytes of hex encoded master secret>
    sslkeylogfile.write('CLIENT_RANDOM ' + binascii.hexlify(cr) + ' ' + binascii.hexlify(ms) + '\n')
    sslkeylogfile.flush()
    
    #master secret key expansion
    #see RFC2246 6.3. Key calculation & 5. HMAC and the pseudorandom function   
    #for AES-CBC-SHA  (in bytes): mac secret 20, write key 32, IV 16
    #hence we need to generate 2*(20+32+16)= 136 bytes
    # 7 sha hmacs * 20 = 140 and 9 md5 hmacs * 16 = 144
    ms_first_half = ms[:24]
    ms_second_half = ms[24:]
    label = "key expansion"
    seed = sr + cr
    #this is not optimized in a loop on purpose. I want people to see exactly what is going on
    md5A1 = hmac.new(ms_first_half,  label+seed, hashlib.md5).digest()
    md5A2 = hmac.new(ms_first_half,  md5A1, hashlib.md5).digest()
    md5A3 = hmac.new(ms_first_half,  md5A2, hashlib.md5).digest()
    md5A4 = hmac.new(ms_first_half,  md5A3, hashlib.md5).digest()
    md5A5 = hmac.new(ms_first_half,  md5A4, hashlib.md5).digest()
    md5A6 = hmac.new(ms_first_half,  md5A5, hashlib.md5).digest()
    md5A7 = hmac.new(ms_first_half,  md5A6, hashlib.md5).digest()
    md5A8 = hmac.new(ms_first_half,  md5A7, hashlib.md5).digest()
    md5A9 = hmac.new(ms_first_half,  md5A8, hashlib.md5).digest()
    
    md5hmac1 = hmac.new(ms_first_half, md5A1 + label + seed, hashlib.md5).digest()
    md5hmac2 = hmac.new(ms_first_half, md5A2 + label + seed, hashlib.md5).digest()
    md5hmac3 = hmac.new(ms_first_half, md5A3 + label + seed, hashlib.md5).digest()
    md5hmac4 = hmac.new(ms_first_half, md5A4 + label + seed, hashlib.md5).digest()
    md5hmac5 = hmac.new(ms_first_half, md5A5 + label + seed, hashlib.md5).digest()
    md5hmac6 = hmac.new(ms_first_half, md5A6 + label + seed, hashlib.md5).digest()
    md5hmac7 = hmac.new(ms_first_half, md5A7 + label + seed, hashlib.md5).digest()
    md5hmac8 = hmac.new(ms_first_half, md5A8 + label + seed, hashlib.md5).digest()
    md5hmac9 = hmac.new(ms_first_half, md5A9 + label + seed, hashlib.md5).digest()
    
    md5hmac = md5hmac1+md5hmac2+md5hmac3+md5hmac4+md5hmac5+md5hmac6+md5hmac7+md5hmac8+md5hmac9
    
    
    sha1A1 = hmac.new(ms_second_half,  label+seed, hashlib.sha1).digest()
    sha1A2 = hmac.new(ms_second_half,  sha1A1, hashlib.sha1).digest()
    sha1A3 = hmac.new(ms_second_half,  sha1A2, hashlib.sha1).digest()
    sha1A4 = hmac.new(ms_second_half,  sha1A3, hashlib.sha1).digest()
    sha1A5 = hmac.new(ms_second_half,  sha1A4, hashlib.sha1).digest()
    sha1A6 = hmac.new(ms_second_half,  sha1A5, hashlib.sha1).digest()
    sha1A7 = hmac.new(ms_second_half,  sha1A6, hashlib.sha1).digest()
    
    sha1hmac1 = hmac.new(ms_second_half, sha1A1 + label + seed, hashlib.sha1).digest()
    sha1hmac2 = hmac.new(ms_second_half, sha1A2 + label + seed, hashlib.sha1).digest()
    sha1hmac3 = hmac.new(ms_second_half, sha1A3 + label + seed, hashlib.sha1).digest()
    sha1hmac4 = hmac.new(ms_second_half, sha1A4 + label + seed, hashlib.sha1).digest()
    sha1hmac5 = hmac.new(ms_second_half, sha1A5 + label + seed, hashlib.sha1).digest()
    sha1hmac6 = hmac.new(ms_second_half, sha1A6 + label + seed, hashlib.sha1).digest()
    sha1hmac7 = hmac.new(ms_second_half, sha1A7 + label + seed, hashlib.sha1).digest()
    
    sha1hmac = sha1hmac1+sha1hmac2+sha1hmac3+sha1hmac4+sha1hmac5+sha1hmac6+sha1hmac7
    
    xored = [ord(a) ^ ord(b) for a,b in zip(md5hmac,sha1hmac)]
    expanded_keys = bytearray(xored)
    
    #we hide the server_mac from the auditee and put random data instead
    ek = expanded_keys[:20]+ bytearray(os.urandom(20)) + expanded_keys[40:]  
    return (ms, ek)
  
  
def get_verify_data( md5, sha, ms):      
    #calculate verify_data for Finished message
    #see RFC2246 7.4.9. Finished & 5. HMAC and the pseudorandom function
    label = "client finished"
    seed = md5 + sha
    ms_first_half = ms[:24]
    ms_second_half = ms[24:]
   
    md5A1 = hmac.new(ms_first_half,  label+seed, hashlib.md5).digest()
    md5hmac1 = hmac.new(ms_first_half, md5A1 + label + seed, hashlib.md5).digest()
    
    sha1A1 = hmac.new(ms_second_half,  label+seed, hashlib.sha1).digest()
    sha1hmac1 = hmac.new(ms_second_half, sha1A1 + label + seed, hashlib.sha1).digest()
    
    xored = [ord(a) ^ ord(b) for a,b in zip(md5hmac1,sha1hmac1)]
    verify_data = bytearray(xored[:12])
    return verify_data


#respond to PING messages and put all the other messages onto the recvQueue
def receivingThread():
    while True:
        buffer = ''
        try: buffer = IRCsocket.recv(1024)
        except: continue #1 sec timeout
        if not buffer: continue
        #sometimes the IRC server may pack multiple PRIVMSGs into one message separated with \r\n
        print (buffer)
        messages = buffer.split('\r\n')
        for onemsg in messages:
            msg = onemsg.split()
            if len(msg)==0 : continue  #stray newline
            if msg[0] == "PING": #check if server have sent ping command
                IRCsocket.send("PONG %s" % msg[1]) #answer with pong as per RFC 1459
                continue
            else:
                #check if the message is correctly formatted
                if not len(msg) == 6: continue
                if not (msg[1]=='PRIVMSG' and msg[2]==channel_name and (msg[3]==':'+my_nick or msg[3]==':broadcast') and msg[4].startswith('seq:') and msg[5].startswith(('client_hello:', 'der:', 'crsr:', 'md5sha:', 'zipsig:'))): continue
                if not msg[5].startswith('client_hello'):
                    #we only process messages which were sent from the auditee
                    #we exclude the client_hello message because auditee's nick is not yet known at that point
                    exclamaitionMarkPosition = msg[0].find('!')
                    auditee_nick_from_message = msg[0][1:exclamaitionMarkPosition]
                    if not auditee_nick == auditee_nick_from_message: continue
                recvQueue.put(msg)


def send_message(msg, ack):
    #try 3 times to send a message and have my shadow user pick it up and put it on the countQueue
    for i in range (3):
        if i > 0: time.sleep(2)
        bytessent = IRCsocket.send(msg)
        print('SENT: ' + str(bytessent) + ' ' + msg)
        try:
            ack_check = countQueue.get(block=True, timeout=3)
            if ack == ack_check:
                return
        except: #nothing showed up on the queue in 2 secs
            continue
    

#Receive messages from auditee, perform calculations, and respond to them accordingly
def process_messages():
    global auditee_nick
    global uid
    
    #the very first message should be a client_hello
    print('waiting for hello from auditee')
    #get the hash of my public key - this serves as a signal from auditee that he is addressing me
    #This way the auditee does not have to know my (auditor's) IRC nickname in advance, neither I his
    with open(os.path.join(current_sessiondir, 'mypubkey'), 'r') as f: my_pubkey_pem =f.read()
    myPublicKey = rsa.PublicKey.load_pkcs1(my_pubkey_pem)
    myPublicKeyHash = hashlib.sha256(str(myPublicKey.n)).hexdigest()
    while True:
        msg = recvQueue.get(block=True) 
        if not (msg[5].startswith('client_hello:') and msg[3]==':broadcast'): continue
        b64_hello = msg[5][len('client_hello'):]
        try:
            hello = base64.b64decode(b64_hello)
            keyhash = hello[:64] #this is the hash of auditor's pubkey
            sig = hello[64:] #this is a sig for 'client_hello'. The auditor is expected to have received auditee's pubkey via other channels
            if keyhash != myPublicKeyHash : continue
            rsa.verify('client_hello', sig, auditeePublicKey)
            #we get here if there was no exception
            #msg[0] looks like (without quotes) ":supernick!some_other_info"
            exclamaitionMarkPosition = msg[0].find('!')
            auditee_nick = msg[0][1:exclamaitionMarkPosition]
            print ('Auditee successfully verified')
        except:
            print ('Verification of a hello message failed')
            continue
        #send back a hello message
        ack = msg[4][len('seq:'):]
        signed_hello = rsa.sign('server_hello', myPrivateKey, 'SHA-1')
        b64_signed_hello = base64.b64encode(signed_hello)
        send_message('PRIVMSG ' + channel_name + ' :' + auditee_nick + ' ack:' + ack + ' server_hello:'+ b64_signed_hello + '\r\n', ack)
        progressQueue.put(time.strftime('%H:%M:%S', time.localtime()) + ': Auditee has been authorized. Awaiting data...')
        break
        
    #after the auditee was authorized, entering a regular message processing loop
    while True:
        uid =  ''.join(random.choice('0123456789') for x in range(10)) #unique id is needed to create unique filenames
        msg = recvQueue.get(block=True) #block on the very first message. Subsequent messages must be received within the timeout window
        
        if msg[5].startswith('zipsig:'): #the user has finished  and send the signature of the trace zipfile
            ack = msg[4][len('seq:'):]
            b64_zipsig = msg[5][len('zipsig:'):]
            try:
                zipsig = base64.b64decode(b64_zipsig)
                shahash = zipsig[:64]
                sig = zipsig[64:]
                #sanity-check the signature
                rsa.verify(shahash, sig, auditeePublicKey)
            except:
                print ('Verification of the auditee\'s hash failed')
                return 'Verification of the auditee\'s hash failed'
            with open(os.path.join(current_sessiondir, 'auditor_signed_hash.txt'), 'w') as f: f.write(shahash + '\n' + b64_zipsig)
            
            #send out sslkeylogfile hash in response
            sslkeylogfile.close()
            sslkeylog_data = None
            with open(os.path.join(current_sessiondir, 'sslkeylogfile'), 'r') as f : sslkeylog_data = f.read()
            shahash = hashlib.sha256(sslkeylog_data).hexdigest()
            sig = rsa.sign(shahash, myPrivateKey, 'SHA-1')
            b64_sig = base64.b64encode(shahash+sig)
            send_message('PRIVMSG ' + channel_name + ' :' + auditee_nick + ' ack:' + ack + ' logsig:' + b64_sig  +'\r\n', ack)
            progressQueue.put(time.strftime('%H:%M:%S', time.localtime()) + ': The auditee has successfully finished the audit session')
            progressQueue.put(time.strftime('%H:%M:%S', time.localtime()) + ': All data pertaining to this session can be found at ' + current_sessiondir)
            progressQueue.put(time.strftime('%H:%M:%S', time.localtime()) + ': You may now close the browser.')
            break
        #Note: after the auditor receives the tracefile, he can (optionally "mergecap -w merged *" ) open it in wireshark  
        #and go to Edit-Preferences-Protocols-HTTP in SSL/TLS Ports enter 1024-65535, 
        #otherwise wireshark will fail do decrypt even when using the Decode As function
            
        elif msg[5].startswith('der:'): #the first msg must be 'der'
            ack = msg[4][len('seq:'):]
            b64_der = msg[5][len('der:'):]
            try:
                der = base64.b64decode(b64_der)
            except:
                print ('base64 decode error')
                continue
            status, pms, encpms = get_encrypted_pms(der)
            if status != 'success':
                print ('Error in get_encrypted_pms')
                continue
            b64_encpms = base64.b64encode(encpms)
            send_message('PRIVMSG ' + channel_name + ' :' + auditee_nick + ' ack:' + ack + ' encpms:'+ b64_encpms + '\r\n', ack)
            progressQueue.put(time.strftime('%H:%M:%S', time.localtime()) + ': Processing data from the auditee.')
        else:
            print ('expected der, received something else instead')
            continue
        
        msg = recvQueue.get(block=True, timeout=10)
        if not msg[5].startswith('crsr'): continue
        ack = msg[4][len('seq:'):]
        b64_crsr = msg[5][len('crsr:'):]
        try:
            crsr = base64.b64decode(b64_crsr)
        except:
            print ('base64 decode error')
            continue
        cr = crsr[:32]
        sr = crsr[32:]
        ms, ek = get_expanded_keys(cr,sr, pms)
        b64_ek = base64.b64encode(ek)
        send_message('PRIVMSG ' + channel_name + ' :' + auditee_nick + ' ack:' + ack + ' ek:'+ b64_ek  + '\r\n', ack)
        
        msg = recvQueue.get(block=True, timeout=10)
        if not msg[5].startswith('md5sha'): continue
        ack = msg[4][len('seq:'):]
        b64_md5sha = msg[5][len('md5sha:'):]
        try:
            md5sha = base64.b64decode(b64_md5sha)
        except:
            print ('base64 decode error')
            continue
        md5 = md5sha[:16] #md5 hash is 16bytes
        sha = md5sha[16:]   #sha hash is 20 bytes
        verify_data = get_verify_data(md5, sha, ms)
        b64_verify_data = base64.b64encode(verify_data)
        send_message('PRIVMSG ' + channel_name + ' :' + auditee_nick + ' ack:' + ack + ' verify_data:'+ b64_verify_data  + '\r\n', ack)
        
      
#Receive HTTP HEAD requests from FF extension. This is how the extension communicates with python backend.
class Handler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    #Using HTTP/1.0 instead of HTTP/1.1 is crucial, otherwise the minihttpd just keep hanging
    #https://mail.python.org/pipermail/python-list/2013-April/645128.html
    protocol_version = "HTTP/1.0"      
    
    def do_HEAD(self):
        global myPrivateKey
        global auditeePublicKey
        
        print ('minihttp received ' + self.path + ' request',end='\r\n')
        # example HEAD string "/page_marked?accno=12435678&sum=1234.56&time=1383389835"    
        # we need to adhere to CORS and add extra headers in server replies
        if self.path.startswith('/get_recent_keys'):
            #this is the very first command that we expect in a new session.
            #If this is the very first time tlsnotary is run, there will be no saved keys
            #otherwise we load up the saved keys which the user can override with new keys if need be
            my_privkey_pem = my_pubkey_pem = auditee_pubkey_pem = ''
            if os.path.exists(os.path.join(datadir, 'recentkeys')):
                if os.path.exists(os.path.join(datadir, 'recentkeys', 'myprivkey')) and os.path.exists(os.path.join(datadir, 'recentkeys', 'mypubkey')):
                    with open(os.path.join(datadir, 'recentkeys', 'myprivkey'), 'r') as f: my_privkey_pem = f.read()
                    with open(os.path.join(datadir, 'recentkeys', 'mypubkey'), 'r') as f: my_pubkey_pem = f.read()
                    with open(os.path.join(current_sessiondir, 'myprivkey'), 'w') as f: f.write(my_privkey_pem)
                    with open(os.path.join(current_sessiondir, 'mypubkey'), 'w') as f: f.write(my_pubkey_pem)
                    myPrivateKey = rsa.PrivateKey.load_pkcs1(my_privkey_pem)
                if os.path.exists(os.path.join(datadir, 'recentkeys', 'auditeepubkey')):
                    with open(os.path.join(datadir, 'recentkeys', 'auditeepubkey'), 'r') as f: auditee_pubkey_pem = f.read()
                    with open(os.path.join(current_sessiondir, 'auditorpubkey'), 'w') as f: f.write(auditee_pubkey_pem)
                    auditeePublicKey = rsa.PublicKey.load_pkcs1(auditee_pubkey_pem)
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "response, mypubkey, auditeepubkey")
            self.send_header("response", "get_recent_keys")
            #if pem keys were empty '' then slicing[:] will produce an empty string ''
            #Esthetical step: cut off the standard header and footer to make keys look smaller replacing newlines wth dashes
            my_pubkey_pem_stub = my_pubkey_pem[40:-38].replace('\n', '_')
            auditee_pubkey_pem_stub = auditee_pubkey_pem[40:-38].replace('\n', '_')
            self.send_header("mypubkey", my_pubkey_pem_stub)
            self.send_header("auditeepubkey", auditee_pubkey_pem_stub)
            self.end_headers()
            return
             
             
        if self.path.startswith('/new_keypair'):            
            pubkey, privkey = rsa.newkeys(1024)
            myPrivateKey = privkey
            my_pubkey_pem = pubkey.save_pkcs1()
            my_privkey_pem = privkey.save_pkcs1()
            #------------------------------------------
            with open(os.path.join(current_sessiondir, 'myprivkey'), 'w') as f: f.write(my_privkey_pem)
            with open(os.path.join(current_sessiondir, 'mypubkey'), 'w') as f: f.write(my_pubkey_pem)
            #also save the keys as recent, so that they could be reused in the next session
            if not os.path.exists(os.path.join(datadir, 'recentkeys')): os.makedirs(os.path.join(datadir, 'recentkeys'))
            with open(os.path.join(datadir, 'recentkeys' , 'myprivkey'), 'w') as f: f.write(my_privkey_pem)
            with open(os.path.join(datadir, 'recentkeys', 'mypubkey'), 'w') as f: f.write(my_pubkey_pem)
            #---------------------------------------------
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "response, pubkey")
            self.send_header("response", "new_keypair")
            my_pubkey_pem_stub = my_pubkey_pem[40:-38].replace('\n', '_')
            self.send_header("pubkey", my_pubkey_pem_stub)
            self.end_headers()
            return

        if self.path.startswith('/import_auditee_pubkey'):
            arg_str = self.path.split('?', 1)[1]
            if not arg_str.startswith('pubkey='):
                self.send_response(400)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Expose-Headers", "response, status")
                self.send_header("response", "import_auditee_pubkey")
                self.send_header("status", 'wrong HEAD parameter')
                self.end_headers()
                return
            #elif HEAD parameters were OK
            auditee_pubkey_pem_stub = arg_str[len('pubkey='):]
            auditee_pubkey_pem_stub = auditee_pubkey_pem_stub.replace('_', '\n')
            auditee_pubkey_pem = '-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBA' + auditee_pubkey_pem_stub + 'AgMBAAE=\n-----END RSA PUBLIC KEY-----\n'
            auditeePublicKey = rsa.PublicKey.load_pkcs1(auditee_pubkey_pem)
            with open(os.path.join(current_sessiondir, 'auditeepubkey'), 'w') as f: f.write(auditee_pubkey_pem)
            #also save the key as recent, so that they could be reused in the next session
            if not os.path.exists(os.path.join(datadir, 'recentkeys')): os.makedirs(os.path.join(datadir, 'recentkeys'))
            with open(os.path.join(datadir, 'recentkeys' , 'auditeepubkey'), 'w') as f: f.write(auditee_pubkey_pem)
            #-----------------------------------------
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "response, status")
            self.send_header("response", "import_auditee_pubkey")
            self.send_header("status", 'success')
            self.end_headers()
            return
        
        if self.path.startswith('/start_irc'):
            #connect to IRC send hello to the auditor and get a hello in return
            rv = start_irc()
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "response, status")
            self.send_header("response", "start_irc")
            self.send_header("status", rv)
            self.end_headers()
            return
        
        
        if self.path.startswith('/progress_update'):
            #receive this command in a loop, blocking for 30 seconds until there is something to respond with
            update = 'no update'
            try :
                update = progressQueue.get(block=True, timeout=30)
            except:
                pass
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "response, update")
            self.send_header("response", "progress_update")
            self.send_header("update", update)
            self.end_headers()
            return
        
        
        if self.path.startswith('/terminate'):
            rv = 'terminate()'
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "response, status")
            self.send_header("response", "terminate")
            self.send_header("status", rv)
            self.end_headers()
            return   
        else:
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "response")
            self.send_header("response", "unknown command")
            self.end_headers()
            return
      
#listen for auditor's messages and count them. Used to prevent the loss of messages.
def count_my_messages_thread(nick, IRCsocket):
    while True:
        buffer = ''
        try: buffer = IRCsocket.recv(1024)
        except: continue #1 sec timeout
        if not buffer: continue
        #sometimes the IRC server may pack multiple PRIVMSGs into one message separated with \r\n
        print (buffer)
        messages = buffer.split('\r\n')
        for onemsg in messages:
            msg = onemsg.split()
            if len(msg)==0 : continue  #stray newline
            if msg[0] == "PING": #check if server have sent ping command
                IRCsocket.send("PONG %s" % msg[1]) #answer with pong as per RFC 1459
                continue
            else:
                if not len(msg) == 6: continue
                #check if the message was sent by me (the auditor)
                exclamaitionMarkPosition = msg[0].find('!')
                auditor_nick_from_message = msg[0][1:exclamaitionMarkPosition]
                if not nick == auditor_nick_from_message: continue
                #extract the ack No and put it on the Queue
                if not msg[4].startswith('ack:'): continue
                ackno = msg[4][len('ack:'):]
                countQueue.put(ackno)

      
      
def start_irc():
    progressQueue.put(time.strftime('%H:%M:%S', time.localtime()) +': Connecting to irc.freenode.org and joining #tlsnotary')
    global my_nick
    global IRCsocket
    my_nick= 'user' + ''.join(random.choice('0123456789') for x in range(10))    
    IRCsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    IRCsocket.settimeout(1)
    IRCsocket.connect(('chat.freenode.net', 6667))
    thread = threading.Thread(target= receivingThread)
    thread.daemon = True
    thread.start()
    IRCsocket.send("USER %s %s %s %s" % ('one', 'two', 'three', 'four') + '\r\n')
    IRCsocket.send("NICK " + my_nick + '\r\n')  
    IRCsocket.send("JOIN %s" % channel_name + '\r\n')
        
    thread = threading.Thread(target= process_messages)
    thread.daemon = True
    thread.start()
    
    #connect a shadow user which does nothing but counts our messages on the channel
    #this is needed because I observed that even though I dispatch messages to Freenode,
    #sometimes (very rarely, though) they fail to appear on the channel
    shadow_nick= 'user' + ''.join(random.choice('0123456789') for x in range(10))    
    shadow_IRCsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    shadow_IRCsocket.settimeout(1)
    shadow_IRCsocket.connect(('chat.freenode.net', 6667))
    shadow_IRCsocket.send("USER %s %s %s %s" % ('five', 'six', 'seven', 'eight') + '\r\n')
    shadow_IRCsocket.send("NICK " + shadow_nick + '\r\n')  
    shadow_IRCsocket.send("JOIN %s" % channel_name + '\r\n')
    
    thread = threading.Thread(target= count_my_messages_thread, args=(my_nick, shadow_IRCsocket))
    thread.daemon = True
    thread.start()
    progressQueue.put(time.strftime('%H:%M:%S', time.localtime()) + ': Connected to IRC successfully. You may now invite the auditee to start the auditing process')
    progressQueue.put(time.strftime('%H:%M:%S', time.localtime()) + ': Waiting for the auditee to join the channel...')
    
    return 'success'
    

#use miniHTTP server to receive commands from Firefox addon and respond to them
def minihttp_thread(parentthread):    
    #allow three attempts to start mini httpd in case if the port is in use
    bWasStarted = False
    for i in range(3):
        FF_to_backend_port = random.randint(1025,65535)
        print ('Starting mini http server to communicate with Firefox plugin')
        #for the GET request, serve files only from within the datadir
        os.chdir(datadir)
        try:
            httpd = StoppableThreadedHttpServer(('127.0.0.1', FF_to_backend_port), Handler)
            bWasStarted = True
            break
        except Exception, e:
            print ('Error starting mini http server. Maybe the port is in use?', e,end='\r\n')
            continue
    if bWasStarted == False:
        #retval is a var that belongs to our parent class which is ThreadWithRetval
        parentthread.retval = ('failure',)
        return
    #elif minihttpd started successfully
    #Let the invoking thread know that we started successfully the calling process can check thread.retval
    parentthread.retval = ('success', FF_to_backend_port)
    sa = httpd.socket.getsockname()
    print ("Serving HTTP on", sa[0], "port", sa[1], "...",end='\r\n')
    httpd.serve_forever()
    return
  
#a thread which returns a value. This is achieved by passing self as the first argument to a called function
#the calling function can then set parentthread.retval
class ThreadWithRetval(threading.Thread):
    def __init__(self, target, args=()):
        super(ThreadWithRetval, self).__init__(target=target, args = (self,)+args )
    retval = ''



if __name__ == "__main__": 
    
    thread = ThreadWithRetval(target= minihttp_thread)
    thread.daemon = True
    thread.start()
    #wait for minihttpd thread to indicate its status
    
    bWasStarted = False
    for i in range(10):
        if thread.retval == '':
            time.sleep(1)
            continue
        elif thread.retval[0] == 'failure':
            print ('Failed to start minihttpd server. Please investigate')
            exit(MINIHTTPD_FAILURE)
        elif thread.retval[0] == 'success':
            bWasStarted = True
            break
        else:
            print ('Unexpected minihttpd server response. Please investigate')
            exit(MINIHTTPD_WRONG_RESPONSE)
    if bWasStarted == False:
        print ('minihttpd failed to start in 10 secs. Please investigate')
        exit(MINIHTTPD_START_TIMEOUT)
    FF_to_backend_port = thread.retval[1]
    
    if OS=='mswin':
        if os.path.isfile(os.path.join(os.getenv('programfiles'), "Mozilla Firefox",  "firefox.exe" )): 
            browser_exepath = os.path.join(os.getenv('programfiles'), "Mozilla Firefox",  "firefox.exe" )
        elif  os.path.isfile(os.path.join(os.getenv('programfiles(x86)'), "Mozilla Firefox",  "firefox.exe" )): 
            browser_exepath = os.path.join(os.getenv('programfiles(x86)'), "Mozilla Firefox",  "firefox.exe" )
        else:
            print ('Please make sure firefox is installed and in your PATH', end='\r\n')
            exit(BROWSER_NOT_FOUND)
            
    try:
        ff_proc = subprocess.Popen([browser_exepath, os.path.join('http://127.0.0.1:' + str(FF_to_backend_port) + '/auditor.html')])
    except Exception,e:
        print ("Error starting Firefox")
        exit(FIREFOX_START_ERROR)
    
    #minihttpd server was started successfully, create a unique session dir
    #create a session dir
    time_str = time.strftime("%d-%b-%Y-%H-%M-%S", time.gmtime())
    current_sessiondir = os.path.join(sessionsdir, time_str)
    os.makedirs(current_sessiondir)
    sslkeylogfile = open(os.path.join(current_sessiondir, 'sslkeylogfile'), 'w')
       
    try:
        while True:
            time.sleep(.1)
    except KeyboardInterrupt:
        print ('Interrupted by user')