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
import re
import shutil
import SimpleHTTPServer
import socket
from SocketServer import ThreadingMixIn
import struct
import subprocess
import sys
import tarfile
import threading
import time
import random
import urllib2
import zipfile
try: import wingdbstub
except: pass

datadir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.dirname(datadir))
import shared
installdir = os.path.dirname(os.path.dirname(datadir))
sessionsdir = os.path.join(datadir, 'sessions')
time_str = time.strftime("%d-%b-%Y-%H-%M-%S", time.gmtime())
current_sessiondir = os.path.join(sessionsdir, time_str)
os.makedirs(current_sessiondir)

platform = platform.system()
if platform == 'Windows': OS = 'mswin'
elif platform == 'Linux': OS = 'linux'
elif platform == 'Darwin': OS = 'macos'

my_nick = ''
auditee_nick = ''
myPrivateKey = auditeePublicKey = None
recvQueue = Queue.Queue() #all messages destined for me
ackQueue = Queue.Queue() #auditee ACKs
progressQueue = Queue.Queue() #messages intended to be displayed by the frontend
google_modulus = google_exponent = 0
secretbytes_amount=8
bTerminateAllThreads = False

#processes each http request in a separate thread
#we need threading in order to send progress updates to the frontend in a non-blocking manner
class StoppableThreadedHttpServer (ThreadingMixIn, BaseHTTPServer.HTTPServer):
    """http server that reacts to self.stop flag"""
    retval = ''
    def serve_forever (self):
        """Handle one request at a time until stopped. Optionally return a value"""
        self.stop = False
        self.socket.setblocking(1)
        while not self.stop:
                self.handle_request()
        return self.retval;

#respond to PING messages and put all the other messages onto the recvQueue
def receivingThread():
    shared.msg_receiver(my_nick,auditee_nick,ackQueue,recvQueue,shared.message_types_from_auditee,seq_init=None)                

def send_message(data):
    if ('success' == shared.send_msg(data,ackQueue,auditee_nick)):
        return ('success',)
    else:
        return ('failure',)
 
#Receive messages from auditee, perform calculations, and respond to them accordingly
def process_messages():
    while True:
        try: msg = recvQueue.get(block=True, timeout=1)
        except: continue
        if msg.startswith('gcr_gsr:'):
            b64_gcr_gsr = msg[len('gcr_gsr:'):]
            try: gcr_gsr = base64.b64decode(b64_gcr_gsr)
            except: raise Exception ('base64 decode error in cr_gcr_gsr')
            google_cr = gcr_gsr[:32]
            google_sr = gcr_gsr[32:64]
            #second half of pre-master secret
            PMS2 =  os.urandom(secretbytes_amount) + ('\x00' * (24-secretbytes_amount-1)) + '\x01'
            RSA_PMS_google_int = pow( int(('\x01'+('\x00'*25)+PMS2).encode('hex'),16), google_exponent, google_modulus )
            grsapms = shared.bigint_to_bytearray(RSA_PMS_google_int)
            #-------------------BEGIN get sha1hmac for google
            label = "master secret"
            seed = google_cr + google_sr
            ghmac = shared.TLS10PRF(label+seed,second_half=PMS2)[1]
            #-------------------END get sha1hmac for google            
            b64_grsapms_ghmac = base64.b64encode(grsapms+ghmac)
            send_message('grsapms_ghmac:'+ b64_grsapms_ghmac)
            continue
         #---------------------------------------------------------------------#
        elif msg.startswith('cr_sr_hmac_n_e:'): 
            progressQueue.put(time.strftime('%H:%M:%S', time.localtime()) + ': Processing data from the auditee.')
            b64_cr_sr_hmac_n_e = msg[len('cr_sr_hmac_n_e:'):]
            try: cr_sr_hmac_n_e = base64.b64decode(b64_cr_sr_hmac_n_e)
            except: raise Exception ('base64 decode error in cr_sr_hmac_n_e')
            cipher_suite_int = int(cr_sr_hmac_n_e[:1].encode('hex'), 16)
            if cipher_suite_int == 4: cipher_suite = 'RC4MD5'
            elif cipher_suite_int == 5: cipher_suite = 'RC4SHA'
            elif cipher_suite_int == 47: cipher_suite = 'AES128'
            elif cipher_suite_int == 53: cipher_suite = 'AES256'
            else: raise Exception ('invalid cipher sute')
            cr = cr_sr_hmac_n_e[1:33]
            sr = cr_sr_hmac_n_e[33:65]
            md5hmac1_for_MS=cr_sr_hmac_n_e[65:89] #half of MS's 48 bytes
            n_len = cr_sr_hmac_n_e[89:91]
            n_len_int = int(n_len.encode('hex'),16)
            n = cr_sr_hmac_n_e[91:91+n_len_int]
            e = cr_sr_hmac_n_e[91+n_len_int:91+n_len_int+3]
            n_int = int(n.encode('hex'),16)
            e_int = int(e.encode('hex'),16)                        
            #RSA encryption without padding: ciphertext = plaintext^e mod n
            RSA_PMS2_int = pow( int(('\x01'+('\x00'*25)+PMS2).encode('hex'),16), e_int, n_int )
            #get my sha1hmac to xor with auditee's md5hmac and get MS first half
            label = "master secret"
            seed = cr + sr        
            sha1hmac = shared.TLS10PRF(label+seed,second_half=PMS2)[1]
            sha1hmac1_for_MS = sha1hmac[:24]
            sha1hmac2_for_MS = sha1hmac[24:48]
            MS1 = shared.xor(md5hmac1_for_MS, sha1hmac1_for_MS)
            #master secret key expansion
            #see RFC2246 6.3. Key calculation & 5. HMAC and the pseudorandom function
            #The amount of key material for each ciphersuite:
            #AES256-CBC-SHA: mac key 20*2, encryption key 32*2, IV 16*2 == 136bytes
            #AES128-CBC-SHA: mac key 20*2, encryption key 16*2, IV 16*2 == 104bytes
            #RC4128_MD5: mac key 16*2, encryption key 16*2 == 64 bytes
            #RC4128_SHA: mac key 20*2, encryption key 16*2 == 72bytes
            #Regardless of theciphersuite, we generate the max key material we'd ever need which is 136 bytes
            label = "key expansion"
            seed = sr + cr
            md5hmac = shared.TLS10PRF(label+seed,req_bytes=140,first_half=MS1)[0]

            #fill the place of server MAC with zeroes
            if cipher_suite == 'AES256': 
                md5hmac_for_ek = md5hmac[:20] + bytearray(os.urandom(20)) + md5hmac[40:136]
            elif cipher_suite == 'AES128':
                md5hmac_for_ek = md5hmac[:20] + bytearray(os.urandom(20)) + md5hmac[40:104]
            elif cipher_suite == 'RC4SHA':
                md5hmac_for_ek = md5hmac[:20] + bytearray(os.urandom(20)) + md5hmac[40:72]
            elif cipher_suite == 'RC4MD5': 
                md5hmac_for_ek = md5hmac[:16] + bytearray(os.urandom(16)) + md5hmac[32:64]     
            rsapms_hmacms_hmacek = shared.bigint_to_bytearray(RSA_PMS2_int)+sha1hmac2_for_MS+md5hmac_for_ek
            b64_rsapms_hmacms_hmacek = base64.b64encode(rsapms_hmacms_hmacek)
            send_message('rsapms_hmacms_hmacek:'+ b64_rsapms_hmacms_hmacek)
            continue
        #---------------------------------------------------------------------#
        elif msg.startswith('verify_md5sha:'):
            b64_md5sha = msg[len('verify_md5sha:') : ]
            try: md5sha = base64.b64decode(b64_md5sha)
            except: raise Exception ('base64 decode error in verify_md5sha')
            md5 = md5sha[:16] #md5 hash is 16bytes
            sha = md5sha[16:]   #sha hash is 20 bytes          
            #calculate verify_data for Finished message
            #see RFC2246 7.4.9. Finished & 5. HMAC and the pseudorandom function
            label = "client finished"
            seed = md5 + sha
            md5hmac1 = shared.TLS10PRF(label+seed,req_bytes=12,first_half=MS1)[0]
            b64_verify_hmac = base64.b64encode(md5hmac1)
            send_message('verify_hmac:'+b64_verify_hmac)
            continue
        #------------------------------------------------------------------------------------------------------#    
        elif msg.startswith('commit_hash:'):
            b64_commit_hash = msg[len('commit_hash:'):]
            try: commit_hash = base64.b64decode(b64_commit_hash)
            except: raise Exception ('base64 decode error in commit_hash')
            trace_hash = commit_hash[:32]
            md5hmac_hash = commit_hash[32:64]
            commit_dir = os.path.join(current_sessiondir, 'commit')
            if not os.path.exists(commit_dir): os.makedirs(commit_dir)
            #file names are assigned sequentially hash1, hash2 etc.
            #The auditee must provide tracefiles trace1, trace2 corresponding to these sequence numbers
            commdir_list = os.listdir(commit_dir)
            #get last seqno
            seqnos = [int(one_trace[len('tracehash'):]) for one_trace 
                      in commdir_list if one_trace.startswith('tracehash')]
            last_seqno = max([0] + seqnos) #avoid throwing by feeding at least one value 0
            my_seqno = last_seqno+1
            trace_hash_path = os.path.join(commit_dir, 'tracehash'+str(my_seqno))
            n_hexlified = binascii.hexlify(n)
            n_write = " ".join(n_hexlified[i:i+2] for i in range(0, len(n_hexlified), 2)) #pubkey in the format 09 56 23 ....
            pubkey_path = os.path.join(commit_dir, 'pubkey'+str(my_seqno))
            trace_hash_path = os.path.join(commit_dir, 'tracehash'+str(my_seqno))
            md5hmac_hash_path =  os.path.join(commit_dir, 'md5hmac_hash'+str(my_seqno))
            with open(pubkey_path, 'wb') as f: f.write(n_write)            
            with open(trace_hash_path, 'wb') as f: f.write(trace_hash)
            with open(md5hmac_hash_path, 'wb') as f: f.write(md5hmac_hash)
            sha1hmac_path = os.path.join(commit_dir, 'sha1hmac'+str(my_seqno))
            with open(sha1hmac_path, 'wb') as f: f.write(sha1hmac)
            cr_path = os.path.join(commit_dir, 'cr'+str(my_seqno))
            with open(cr_path, 'wb') as f: f.write(cr)
            b64_sha1hmac = base64.b64encode(sha1hmac) 
            send_message('sha1hmac_for_MS:'+b64_sha1hmac)
            continue  
        #---------------------------------------------------------------------#
        elif msg.startswith('link:'):
            b64_link = msg[len('link:'):]
            try: link = base64.b64decode(b64_link)
            except: raise Exception ('base64 decode error in link')
            time.sleep(1) #just in case the upload server needs some time to prepare the file
            req = urllib2.Request(link)
            resp = urllib2.urlopen(req)
            linkdata = resp.read()
            with open(os.path.join(current_sessiondir, 'auditeetrace.zip'), 'wb') as f : f.write(linkdata)
            zipf = zipfile.ZipFile(os.path.join(current_sessiondir, 'auditeetrace.zip'), 'r')
            auditeetrace_dir = os.path.join(current_sessiondir, 'auditeetrace')
            zipf.extractall(auditeetrace_dir)
            response = 'success' #unless overridden by a failure in sanity check
            #sanity: all trace names must be unique and their hashes must correspond to the
            #hashes which the auditee committed to earlier
            adir_list = os.listdir(auditeetrace_dir)
            seqnos = []
            for one_trace in adir_list:
                if not one_trace.startswith('trace'): continue
                try: this_seqno = int(one_trace[len('trace'):])
                except: raise Exception ('WARNING: Could not cast trace\'s tail to int')
                if this_seqno in seqnos: 
                    raise Exception ('WARNING: multiple tracefiles names detected')
                saved_hash_path = os.path.join(commit_dir, 'tracehash'+str(this_seqno))
                if not os.path.exists(saved_hash_path): 
                    raise Exception ('WARNING: Auditee gave a trace number which doesn\'t have a committed hash')
                with open(saved_hash_path, 'rb') as f: saved_hash = f.read()
                with open(os.path.join(auditeetrace_dir, one_trace), 'rb') as f: tracedata = f.read()
                trace_hash = hashlib.sha256(tracedata).digest()
                if not saved_hash == trace_hash: 
                    raise Exception ('WARNING: Trace\'s hash doesn\'t match the hash committed to')
                md5hmac_path = os.path.join(auditeetrace_dir, 'md5hmac'+str(this_seqno))
                if not os.path.exists(md5hmac_path):
                    raise Exception ('WARNING: Could not find md5hmac in auditeetrace')
                with open(md5hmac_path, 'rb') as f: md5hmac_data = f.read()
                md5hmac_hash = hashlib.sha256(md5hmac_data).digest()
                with open(os.path.join(commit_dir, 'md5hmac_hash'+str(this_seqno)), 'rb') as f: commited_md5hmac_hash = f.read()
                if not md5hmac_hash == commited_md5hmac_hash:
                    raise Exception ('WARNING: mismatch in committed md5hmac hashes')
                domain_path = os.path.join(auditeetrace_dir, 'domain'+str(this_seqno))
                if not os.path.exists(domain_path):
                    raise Exception ('WARNING: Could not find domain in auditeetrace')                
                #elif no errors
                seqnos.append(this_seqno)
                continue
            send_message('response:'+response)
            if response == 'success':
                progressQueue.put(time.strftime('%H:%M:%S', time.localtime()) + ': The auditee has successfully finished the audit session')
            else:
                progressQueue.put(time.strftime('%H:%M:%S', time.localtime()) + ': WARNING!!! The auditee FAILED the audit session')
            progressQueue.put(time.strftime('%H:%M:%S', time.localtime()) + ': Decrypting  auditee\'s data')
            #decrypt  the tracefiles
            decr_dir = os.path.join(current_sessiondir, 'decrypted')
            os.makedirs(decr_dir)
            for one_trace in adir_list:
                if not one_trace.startswith('trace'): continue
                seqno = one_trace[len('trace'):]
                with open(os.path.join(auditeetrace_dir, 'md5hmac'+seqno), 'rb') as f: md5hmac = f.read()
                with open(os.path.join(commit_dir, 'sha1hmac'+seqno), 'rb') as f: sha1hmac = f.read()
                with open(os.path.join(commit_dir, 'cr'+seqno), 'rb') as f: cr = f.read()
                ms = shared.xor(md5hmac, sha1hmac)
                sslkeylog = os.path.join(decr_dir, 'sslkeylog'+seqno)
                ssldebuglog = os.path.join(decr_dir, 'ssldebuglog'+seqno)
                cr_hexl = binascii.hexlify(cr)
                ms_hexl = binascii.hexlify(ms)
                with open(sslkeylog, 'wb') as f: 
                    f.write('CLIENT_RANDOM ' + cr_hexl + ' ' + ms_hexl + '\n')
                try: output = subprocess.check_output([tshark_exepath, '-r', 
                                                    os.path.join(auditeetrace_dir, one_trace),
                                                     '-Y', 'ssl and http.content_type contains html', 
                                                     '-o', 'http.ssl.port:1025-65535', 
                                                     '-o', 'ssl.keylog_file:'+ sslkeylog,
                                                     '-o', 'ssl.ignore_ssl_mac_failed:False',
                                                     '-o', 'ssl.debug_file:' + ssldebuglog,
                                                     '-x'])
                except: #maybe an old tshark version, Replace -Y with -R
                    try: output = subprocess.check_output([tshark_exepath, '-r',
                                                           os.path.join(auditeetrace_dir, one_trace),
                                                          '-R', 'ssl and http.content_type contains html',
                                                          '-o', 'http.ssl.port:1025-65535', 
                                                          '-o', 'ssl.keylog_file:'+ sslkeylog,
                                                          '-o', 'ssl.ignore_ssl_mac_failed:False',
                                                          '-o', 'ssl.debug_file:' + ssldebuglog,
                                                          '-x'])
                    except: raise Exception ('Could not launch tshark')
                if output == '': raise Exception ("Failed to find HTML in escrowtrace")
                with open(ssldebuglog, 'rb') as f: debugdata = f.read()
                if debugdata.count('mac failed') > 0:
                    raise Exception('Mac check failed in tracefile')
                #output may contain multiple frames with HTML, we examine them one-by-one
                separator = re.compile('Frame ' + re.escape('(') + '[0-9]{2,7} bytes' + re.escape(')') + ':')
                #ignore the first split element which is always an empty string
                frames = re.split(separator, output)[1:]    
                html_paths = ''
                for index,oneframe in enumerate(frames):
                    html = shared.get_html_from_asciidump(oneframe)
                    path = os.path.join(decr_dir, 'html-'+seqno+'-'+str(index))
                    with open(path, 'wb') as f: f.write(html)
                #also create a file where the auditor can see the domain and pubkey
                with open (os.path.join(auditeetrace_dir, 'domain'+seqno), 'rb') as f: domain_data = f.read()
                with open (os.path.join(commit_dir, 'pubkey'+seqno), 'rb') as f: pubkey_data = f.read()
                write_data = domain_data + '\n\n' + 'The auditee claims that the server above presented the public key below\n' + 'Open the server address in your browser and check that the public key matches\n' + 'This step is mandatory to ascertain that the auditee hasn\'t tampered with the audit data\n' + pubkey_data
                with open(os.path.join(decr_dir, 'domain'+seqno), 'wb') as f: f.write(write_data)               
            progressQueue.put(time.strftime('%H:%M:%S', time.localtime()) + ': All decrypted HTML can be found in ' + decr_dir)
            progressQueue.put(time.strftime('%H:%M:%S', time.localtime()) + ': You may now close the browser.')
            continue
      
#Receive HTTP HEAD requests from FF extension. This is how the extension communicates with python backend.
class Handler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    #Using HTTP/1.0 instead of HTTP/1.1 is crucial, otherwise the minihttpd just keep hanging
    #https://mail.python.org/pipermail/python-list/2013-April/645128.html
    protocol_version = "HTTP/1.0"      
    
    def respond(self, headers):
        # we need to adhere to CORS and add extra headers in server replies        
            keys = [k for k in headers]
            self.send_response(200)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Expose-Headers', ','.join(keys))
            for key in headers:
                self.send_header(key, headers[key])
            self.end_headers()                    

    def do_HEAD(self):                
        print ('minihttp received ' + self.path + ' request',end='\r\n')
        # example HEAD string "/page_marked?accno=12435678&sum=1234.56&time=1383389835"    
        if self.path.startswith('/get_recent_keys'):
            my_pubkey_export, auditee_pubkey_export = get_recent_keys()
            self.respond({'response':'get_recent_keys', 'mypubkey':my_pubkey_export,
                                             'auditeepubkey':auditee_pubkey_export})
            return
        #----------------------------------------------------------------------#
        if self.path.startswith('/new_keypair'):
            my_pubkey_export = new_keypair()
            self.respond({'response':'new_keypair', 'pubkey':my_pubkey_export})                        
            return
        #----------------------------------------------------------------------#
        if self.path.startswith('/import_auditee_pubkey'):
            arg_str = self.path.split('?', 1)[1]
            if not arg_str.startswith('pubkey='):
                self.respond({'response':'import_auditee_pubkey', 'status':'wrong HEAD parameter'})                        
                return
            auditee_pubkey_b64modulus = arg_str[len('pubkey='):]            
            import_auditee_pubkey(auditee_pubkey_b64modulus)
            self.respond({'response':'import_auditee_pubkey', 'status':'success'})                                    
            return
       #----------------------------------------------------------------------# 
        if self.path.startswith('/start_peer_connection'):
            #connect, send hello to the auditor and get a hello in return
            rv = start_peer_messaging()
            self.respond({'response':'start_peer_connection', 'status':rv})
            return
        #----------------------------------------------------------------------#
        if self.path.startswith('/progress_update'):
            #receive this command in a loop, blocking for 30 seconds until there is something to respond with
            update = 'no update'
            time_started = int(time.time())
            while int(time.time()) - time_started < 30:
                try: 
                    update = progressQueue.get(block=False)
                    break #something in the queue
                except:
                    if bTerminateAllThreads: break
                    time.sleep(1) #nothing in the queue
            self.respond({'response':'progress_update', 'update':update})
            return
        #----------------------------------------------------------------------#
        else:
            self.respond({'response':'unknown command'})
            return
     
def import_auditee_pubkey(auditee_pubkey_b64modulus): 
    auditee_pubkey_modulus = base64.b64decode(auditee_pubkey_b64modulus)
    auditee_pubkey_modulus_int = int(auditee_pubkey_modulus.encode('hex'),16)
    global auditeePublicKey    
    auditeePublicKey = rsa.PublicKey(auditee_pubkey_modulus_int, 65537)         
    auditee_pubkey_pem = auditeePublicKey.save_pkcs1()                
    with open(os.path.join(current_sessiondir, 'auditeepubkey'), 'w') as f: f.write(auditee_pubkey_pem)
    #also save the key as recent, so that they could be reused in the next session
    if not os.path.exists(os.path.join(datadir, 'recentkeys')): os.makedirs(os.path.join(datadir, 'recentkeys'))
    with open(os.path.join(datadir, 'recentkeys' , 'auditeepubkey'), 'w') as f: f.write(auditee_pubkey_pem)
        
def get_recent_keys():
    global myPrivateKey
    global auditeePublicKey
    #this is the very first command that we expect in a new session.
    #If this is the very first time tlsnotary is run, there will be no saved keys
    #otherwise we load up the saved keys which the user can override with new keys if need be
    my_pubkey_export = auditee_pubkey_export = ''
    if os.path.exists(os.path.join(datadir, 'recentkeys')):
        if os.path.exists(os.path.join(datadir, 'recentkeys', 'myprivkey')) and os.path.exists(os.path.join(datadir, 'recentkeys', 'mypubkey')):
            with open(os.path.join(datadir, 'recentkeys', 'myprivkey'), 'r') as f: my_privkey_pem = f.read()
            with open(os.path.join(datadir, 'recentkeys', 'mypubkey'), 'r') as f: my_pubkey_pem = f.read()
            with open(os.path.join(current_sessiondir, 'myprivkey'), 'w') as f: f.write(my_privkey_pem)
            with open(os.path.join(current_sessiondir, 'mypubkey'), 'w') as f: f.write(my_pubkey_pem)
            myPrivateKey = rsa.PrivateKey.load_pkcs1(my_privkey_pem)
            my_pubkey = rsa.PublicKey.load_pkcs1(my_pubkey_pem)
            my_pubkey_export = base64.b64encode(shared.bigint_to_bytearray(my_pubkey.n))
        if os.path.exists(os.path.join(datadir, 'recentkeys', 'auditeepubkey')):
            with open(os.path.join(datadir, 'recentkeys', 'auditeepubkey'), 'r') as f: auditee_pubkey_pem = f.read()
            with open(os.path.join(current_sessiondir, 'auditorpubkey'), 'w') as f: f.write(auditee_pubkey_pem)
            auditeePublicKey = rsa.PublicKey.load_pkcs1(auditee_pubkey_pem)
            auditee_pubkey = rsa.PublicKey.load_pkcs1(auditee_pubkey_pem)
            auditee_pubkey_export = base64.b64encode(shared.bigint_to_bytearray(auditee_pubkey.n))
    return my_pubkey_export, auditee_pubkey_export
      
def new_keypair():
    global myPrivateKey
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
    my_pubkey = rsa.PublicKey.load_pkcs1(my_pubkey_pem)
    my_pubkey_export = base64.b64encode(shared.bigint_to_bytearray(my_pubkey.n))
    return my_pubkey_export

def registerAuditeeThread():
    global auditee_nick
    global google_modulus
    global google_exponent

    with open(os.path.join(current_sessiondir, 'mypubkey'), 'r') as f: my_pubkey_pem =f.read()
    myPublicKey = rsa.PublicKey.load_pkcs1(my_pubkey_pem)
    myModulus = shared.bigint_to_bytearray(myPublicKey.n)[:10]
    bIsAuditeeRegistered = False

    while not (bIsAuditeeRegistered or bTerminateAllThreads):
        msg = shared.receive_single_msg((':google_pubkey:',':client_hello:'))
        if not msg: continue
        if msg[0].startswith(':google_pubkey:') and auditee_nick != '': #we already got the first client_hello part
            try:
                b64_google_pubkey = msg[0][len(':google_pubkey:'):]
                google_pubkey =  base64.b64decode(b64_google_pubkey)
                google_modulus_byte = google_pubkey[:256]
                google_exponent_byte = google_pubkey[256:]
                google_modulus = int(google_modulus_byte.encode('hex'),16)
                google_exponent = int(google_exponent_byte.encode('hex'),16)
                print ('Auditee successfully verified')
                bIsAuditeeRegistered = True
                break
            except:
                print ('Error while processing google pubkey')
                auditee_nick=''#erase the nick so that the auditee could try registering again
                continue
        #if we got here, it must be a client hello
        b64_hello = msg[0][len(':client_hello:'):]
        try:
            hello = base64.b64decode(b64_hello)
            modulus = hello[:10] #this is the first 10 bytes of modulus of auditor's pubkey
            sig = hello[10:] #this is a sig for 'client_hello'. The auditor is expected to have received auditee's pubkey via other channels
            if modulus != myModulus : continue
            rsa.verify('client_hello', sig, auditeePublicKey)
            #we get here if there was no exception
            auditee_nick = msg[1]
        except:
            print ('Verification of a hello message failed')
            continue

    if not bIsAuditeeRegistered:
        return ('failure',)
    #else send back a hello message
    signed_hello = rsa.sign('server_hello', myPrivateKey, 'SHA-1')
    b64_signed_hello = base64.b64encode(signed_hello)

    #send twice because it was observed that the msg would not appear on the chan
    for x in range(2):
        shared.send_raw(':'+auditee_nick + ' server_hello:'+b64_signed_hello)
        time.sleep(2)

    progressQueue.put(time.strftime('%H:%M:%S', time.localtime()) + ': Auditee has been authorized. Awaiting data...')
    thread = threading.Thread(target= receivingThread)
    thread.daemon = True
    thread.start()
    thread = threading.Thread(target= process_messages)
    thread.daemon = True
    thread.start()
    

def start_peer_messaging():
    global my_nick
    #we should take the IRC settings from the config file
    #immediately before connecting, because in self-test mod
    #it can be reset by the auditee
    shared.config.read(shared.config_location)

    progressQueue.put(time.strftime('%H:%M:%S', time.localtime()) +\
    ': Connecting to '+shared.config.get('IRC','irc_server')+' and joining #'+shared.config.get('IRC','channel_name'))

    my_nick= 'user' + ''.join(random.choice('0123456789') for x in range(10))

    shared.start_connection(my_nick)
    #if we got here, no exceptions were thrown, which counts as success.

    thread = threading.Thread(target= registerAuditeeThread)
    thread.daemon = True
    thread.start()

    return 'success'

#use http server to talk to auditor.html
def http_server(parentthread):    
    #allow three attempts to start mini httpd in case if the port is in use
    bWasStarted = False
    print ('Starting http server to communicate with auditor panel')    
    for i in range(3):
        FF_to_backend_port = random.randint(1025,65535)
        #for the GET request, serve files only from within the datadir
        os.chdir(datadir)
        try: httpd = StoppableThreadedHttpServer(('127.0.0.1', FF_to_backend_port), Handler)
        except Exception, e:
            print ('Error starting mini http server. Maybe the port is in use?', e,end='\r\n')
            continue
        bWasStarted = True
        break        
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
  

def first_run_check():
    #On first run, unpack rsa and pyasn1 archives, check hashes
    rsa_dir = os.path.join(datadir, 'python', 'rsa-3.1.4')
    if not os.path.exists(rsa_dir):
        print ('Extracting rsa-3.1.4.tar.gz...')
        with open(os.path.join(datadir, 'python', 'rsa-3.1.4.tar.gz'), 'rb') as f: tarfile_data = f.read()
        #for md5 hash, see https://pypi.python.org/pypi/rsa/3.1.4
        if hashlib.md5(tarfile_data).hexdigest() != 'b6b1c80e1931d4eba8538fd5d4de1355':
            raise Exception('WRONG_HASH')
        os.chdir(os.path.join(datadir, 'python'))
        tar = tarfile.open(os.path.join(datadir, 'python', 'rsa-3.1.4.tar.gz'), 'r:gz')
        tar.extractall()
   
    pyasn1_dir = os.path.join(datadir, 'python', 'pyasn1-0.1.7')
    if not os.path.exists(pyasn1_dir):
        print ('Extracting pyasn1-0.1.7.tar.gz...')
        with open(os.path.join(datadir, 'python', 'pyasn1-0.1.7.tar.gz'), 'rb') as f: tarfile_data = f.read()
        #for md5 hash, see https://pypi.python.org/pypi/pyasn1/0.1.7
        if hashlib.md5(tarfile_data).hexdigest() != '2cbd80fcd4c7b1c82180d3d76fee18c8':
            raise Exception ('WRONG_HASH')
        os.chdir(os.path.join(datadir, 'python'))
        tar = tarfile.open(os.path.join(datadir, 'python', 'pyasn1-0.1.7.tar.gz'), 'r:gz')
        tar.extractall()
  

if __name__ == "__main__": 
    shared.load_program_config()
    first_run_check()
    #both on first and subsequent runs
    sys.path.append(os.path.join(datadir, 'python', 'rsa-3.1.4'))
    sys.path.append(os.path.join(datadir, 'python', 'pyasn1-0.1.7'))    
    import rsa
    import pyasn1
    from pyasn1.type import univ
    from pyasn1.codec.der import encoder, decoder       

    thread = shared.ThreadWithRetval(target= http_server)
    thread.daemon = True
    thread.start()
    #wait for minihttpd thread to indicate its status   
    bWasStarted = False
    for i in range(10):
        time.sleep(1)        
        if thread.retval == '': continue
        elif thread.retval[0] == 'failure': raise Exception('MINIHTTPD_FAILURE')
        elif thread.retval[0] == 'success':
            bWasStarted = True
            break
        else: raise Exception('MINIHTTPD_WRONG_RESPONSE')
    if bWasStarted == False: raise Exception('MINIHTTPD_START_TIMEOUT')
    FF_to_backend_port = thread.retval[1]
    
    daemon_mode = False
    if len(sys.argv) > 1:
        if sys.argv[1] == 'daemon':
            daemon_mode = True
            print('Running auditor in daemon mode')
        
    if OS=='mswin':
        prog64 = os.getenv('ProgramW6432')
        prog32 = os.getenv('ProgramFiles(x86)')
        progxp = os.getenv('ProgramFiles')                
        browser_exepath= tshark_exepath = ''
        if prog64:
            ff64 = os.path.join(prog64, "Mozilla Firefox",  "firefox.exe")
            if os.path.isfile(ff64): browser_exepath = ff64
            tshark64 = os.path.join(prog64, "Wireshark",  "tshark.exe" )
            if os.path.isfile(tshark64): tshark_exepath = tshark64            
        if prog32:            
            ff32 = os.path.join(prog32, "Mozilla Firefox",  "firefox.exe" )
            if os.path.isfile(ff32): browser_exepath = ff32
            tshark32 = os.path.join(prog32, "Wireshark",  "tshark.exe" )
            if  os.path.isfile(tshark32): tshark_exepath = tshark32            
        if progxp:
            ff32 = os.path.join(progxp, "Mozilla Firefox",  "firefox.exe" )
            if os.path.isfile(ff32): browser_exepath = ff32
            tshark32 = os.path.join(progxp, "Wireshark",  "tshark.exe" )
            if  os.path.isfile(tshark32): tshark_exepath = tshark32
        if not daemon_mode and browser_exepath == '': raise Exception(
            'Failed to find Firefox in your Program Files location')     
        if tshark_exepath == '':  raise Exception(
            'Failed to find Wireshark in your Program Files location')
    elif OS=='linux':
        if not daemon_mode: browser_exepath = 'firefox'
        tshark_exepath = 'tshark'
    elif OS=='macos':
        if not daemon_mode: browser_exepath = "open" #will open up the default browser
        tshark_exepath = '/Applications/Wireshark.app/Contents/Resources/bin/tshark'
        if not os.path.exists(tshark_exepath): raise Exception('TSHARK_NOT_FOUND')
                     
    if daemon_mode:
        my_pubkey_b64modulus, auditee_pubkey_b64modulus = get_recent_keys()
        if ('genkey' in sys.argv) or (my_pubkey_b64modulus == ''):
            my_pubkey_b64modulus = new_keypair()
            print ('Pass this key to the auditee and restart:')
            print (my_pubkey_b64modulus)
            exit(0)
        else:
            print ('Reusing your key from the previous session:')
            print (my_pubkey_b64modulus)
        #check if hiskey=OIAAHhdshdu89dah... was supplied
        key = [b[len('hiskey='):] for idx,b in enumerate(sys.argv) if b.startswith('hiskey=')]
        if len(key) == 1:
            auditee_pubkey_b64modulus = key[0]
            if len(auditee_pubkey_b64modulus) != 172:
                raise Exception ('His key must be 172 characters long')
            import_auditee_pubkey(auditee_pubkey_b64modulus)
            print('Imported hiskey from command line:')
            print(auditee_pubkey_b64modulus)
        elif auditee_pubkey_b64modulus != '':
            print ('Reusing his key from previous session:')
            print (auditee_pubkey_b64modulus)
        else: raise Exception ('You need to provide his key using hiskey=')
        start_peer_messaging()
    else:#not a deamon mode
        try: ff_proc = subprocess.Popen([browser_exepath, os.path.join(
            'http://127.0.0.1:' + str(FF_to_backend_port) + '/auditor.html')])
        except: raise Exception('BROWSER_START_ERROR')
    
    try:
        while True:
            time.sleep(1)
            if daemon_mode:
                try: print (progressQueue.get_nowait())
                except: pass      
    except KeyboardInterrupt:
        bTerminateAllThreads = True
