#!/usr/bin/env python
from __future__ import print_function

import base64
import BaseHTTPServer
import binascii
import codecs
import hashlib
import hmac
import os
import platform
import Queue
import random
import re
import select
import shutil
import signal
import SimpleHTTPServer
import socket
import subprocess
import sys
import tarfile
import threading
import time
import urllib2
import zipfile
 
installdir = os.path.dirname(os.path.realpath(__file__))
datadir = os.path.join(installdir, 'data')
nsslibdir = os.path.join(datadir, 'nsslibs')
sessionsdir = os.path.join(datadir, 'sessions')

sys.path.append(os.path.join(datadir, 'python', 'slowaes'))
from slowaes import AESModeOfOperation

m_platform = platform.system()
if m_platform == 'Windows':
    OS = 'mswin'
elif m_platform == 'Linux':
    OS = 'linux'
elif m_platform == 'darwin':
    OS = 'macos'
 
#exit codes
MINIHTTPD_FAILURE = 2
MINIHTTPD_WRONG_RESPONSE = 3
MINIHTTPD_START_TIMEOUT = 4
FIREFOX_MISSING= 1
FIREFOX_START_ERROR = 5
CANT_FIND_TORBROWSER = 6
TBB_INSTALLER_TOO_LONG = 7
WRONG_HASH = 8
CANT_FIND_XZ = 9

IRCsocket = socket._socketobject
recvQueue = Queue.Queue() #all messages from the auditor are placed here by receivingThread
ackQueue = Queue.Queue() #ack numbers are placed here
auditor_nick = '' #we learn auditor's nick as soon as we get a hello_server signed by the auditor
my_nick = '' #our nick is randomly generated on connection to IRC
channel_name = '#tlsnotary'
myPrivateKey = auditorPublicKey = None
google_modulus = 0
google_exponent = 0

current_sessiondir = ''
nss_patch_dir = ''

stcppipe_proc = None
bReceivingThreadStopFlagIsSet = False
secretbytes_amount=13

PMS_first_half = '' #made global because of google check. TODO: start creating classes
bIsStcppipeStarted = False
cr_list = [] #a list of all client_randoms for recorded pages. Used to narrow down stcppipe's dump to only those files which auditor needs.
md5hmac = '' #used in get_html_paths to construct the full MS after committing to a hash

def bigint_to_bytearray(bigint):
    m_bytes = []
    while bigint != 0:
        b = bigint%256
        m_bytes.insert( 0, b )
        bigint //= 256
    return bytearray(m_bytes)

def bigint_to_list(bigint):
    m_bytes = []
    while bigint != 0:
        b = bigint%256
        m_bytes.insert( 0, b )
        bigint //= 256
    return m_bytes


#a thread which returns a value. This is achieved by passing self as the first argument to a target function
#the target_function(parentthread, arg1, arg2) can then set, e.g parentthread.retval
class ThreadWithRetval(threading.Thread):
    def __init__(self, target, args=()):
        super(ThreadWithRetval, self).__init__(target=target, args = (self,)+args )
    retval = ''



#Receive HTTP HEAD requests from FF addon. This is how the addon communicates with python backend.
class HandlerClass(SimpleHTTPServer.SimpleHTTPRequestHandler):
    #Using HTTP/1.0 instead of HTTP/1.1 is crucial, otherwise the minihttpd just keep hanging
    #https://mail.python.org/pipermail/python-list/2013-April/645128.html
    protocol_version = "HTTP/1.0"      
    
    def do_HEAD(self):
        global current_sessiondir
        global myPrivateKey
        global auditorPublicKey
        global bIsStcppipeStarted
        
        print ('minihttp received ' + self.path + ' request',end='\r\n')
        # example HEAD string "/command?parameter=124value1&para2=123value2"    
        # we need to adhere to CORS and add extra Access-Control-* headers in server replies
        
        #--------------------------------------------------------------------------------------------------------------------------------------------#
        if self.path.startswith('/get_recent_keys'):
            #this is the very first command that addon issues
            #If this is the very first time tlsnotary is run, there will be no saved keys
            #otherwise we load up the saved keys which the user can overwrite later if need be
            my_privkey_pem = my_pubkey_pem = auditor_pubkey_pem = ''
            if os.path.exists(os.path.join(datadir, 'recentkeys')):
                if os.path.exists(os.path.join(datadir, 'recentkeys', 'myprivkey')) and os.path.exists(os.path.join(datadir, 'recentkeys', 'mypubkey')):
                    with open(os.path.join(datadir, 'recentkeys', 'myprivkey'), 'rb') as f: my_privkey_pem = f.read()
                    with open(os.path.join(datadir, 'recentkeys', 'mypubkey'), 'rb') as f: my_pubkey_pem = f.read()
                    with open(os.path.join(current_sessiondir, 'myprivkey'), 'wb') as f: f.write(my_privkey_pem)
                    with open(os.path.join(current_sessiondir, 'mypubkey'), 'wb') as f: f.write(my_pubkey_pem)
                    myPrivateKey = rsa.PrivateKey.load_pkcs1(my_privkey_pem)
                if os.path.exists(os.path.join(datadir, 'recentkeys', 'auditorpubkey')):
                    with open(os.path.join(datadir, 'recentkeys', 'auditorpubkey'), 'rb') as f: auditor_pubkey_pem = f.read()
                    with open(os.path.join(current_sessiondir, 'auditorpubkey'), 'wb') as f: f.write(auditor_pubkey_pem)
                    auditorPublicKey = rsa.PublicKey.load_pkcs1(auditor_pubkey_pem)
            #if pem keys were empty '' then slicing[:] will produce an empty string ''
            #Esthetical step: cut off the standard header and footer to make keys look smaller replacing newlines with underscores
            my_pubkey_pem_stub = my_pubkey_pem[40:-38].replace('\n', '_')
            auditor_pubkey_pem_stub = auditor_pubkey_pem[40:-38].replace('\n', '_')
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "response, mypubkey, auditorpubkey")
            self.send_header("response", "get_recent_keys")
            self.send_header("mypubkey", my_pubkey_pem_stub)
            self.send_header("auditorpubkey", auditor_pubkey_pem_stub)
            self.end_headers()
            return
             
        #--------------------------------------------------------------------------------------------------------------------------------------------#     
        if self.path.startswith('/new_keypair'):
            #generate a new keypair for me. Usually we can simple reuse the keys from the previous audit,
            #but for privacy reason the auditee may generate a new key
            pubkey, privkey = rsa.newkeys(1024)
            myPrivateKey = privkey
            my_pem_pubkey = pubkey.save_pkcs1()
            my_pem_privkey = privkey.save_pkcs1()

            with open(os.path.join(current_sessiondir, 'myprivkey'), 'wb') as f: f.write(my_pem_privkey)
            with open(os.path.join(current_sessiondir, 'mypubkey'), 'wb') as f: f.write(my_pem_pubkey)
            #also save the keys as recent, so that they could be reused in the next session
            if not os.path.exists(os.path.join(datadir, 'recentkeys')): os.makedirs(os.path.join(datadir, 'recentkeys'))
            with open(os.path.join(datadir, 'recentkeys' , 'myprivkey'), 'wb') as f: f.write(my_pem_privkey)
            with open(os.path.join(datadir, 'recentkeys', 'mypubkey'), 'wb') as f: f.write(my_pem_pubkey)

            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "response, pubkey")
            self.send_header("response", "new_keypair")
            my_pubkey_pem_stub = my_pem_pubkey[40:-38].replace('\n', '_')
            self.send_header("pubkey", my_pubkey_pem_stub)
            self.send_header("status", "success")
            self.end_headers()
            return
        
        #--------------------------------------------------------------------------------------------------------------------------------------------#
        if self.path.startswith('/import_auditor_pubkey'):
            #whatever key was pasted into the Auditor's key textarea ends up here.
            arg_str = self.path.split('?', 1)[1]
            if not arg_str.startswith('pubkey='):
                self.send_response(400)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Expose-Headers", "response, status")
                self.send_header("response", "import_auditor_pubkey")
                self.send_header("status", 'wrong HEAD parameter')
                self.end_headers()
                return
            #elif HEAD parameters were OK
            status = 'success' #this won't change unless there was an error
            auditor_pubkey_pem_stub = arg_str[len('pubkey='):]
            auditor_pubkey_pem_stub = auditor_pubkey_pem_stub.replace('_', '\n')
            auditor_pubkey_pem = '-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBA' + auditor_pubkey_pem_stub + 'AgMBAAE=\n-----END RSA PUBLIC KEY-----\n'
            try:
                auditorPublicKey = rsa.PublicKey.load_pkcs1(auditor_pubkey_pem)            
                with open(os.path.join(current_sessiondir, 'auditorpubkey'), 'wb') as f: f.write(auditor_pubkey_pem)
                #also save the key as recent, so that they could be reused in the next session
                if not os.path.exists(os.path.join(datadir, 'recentkeys')): os.makedirs(os.path.join(datadir, 'recentkeys'))
                with open(os.path.join(datadir, 'recentkeys' , 'auditorpubkey'), 'wb') as f: f.write(auditor_pubkey_pem)
            except:
                status = 'Error importing pubkey. Did you copy-paste it correctly?'

            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "response, status")
            self.send_header("response", "import_auditor_pubkey")
            self.send_header("status", status)
            self.end_headers()
            return
        
        #--------------------------------------------------------------------------------------------------------------------------------------------#
        if self.path.startswith('/start_irc'):
            rv = start_irc()
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "response, status")
            self.send_header("response", "start_irc")
            self.send_header("status", rv)
            self.end_headers()
            return
        
        #--------------------------------------------------------------------------------------------------------------------------------------------#
        if self.path.startswith('/start_recording'):
            if not bIsStcppipeStarted:
                bIsStcppipeStarted = True
                rv = start_recording()
            else:
                rv = ('success', 'success')
            if rv[0] != 'success':
                self.send_response(400)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Expose-Headers", "response, status")
                self.send_header("response", "start_recording")
                self.send_header("status", rv[0])
            else:
                self.send_response(200)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Expose-Headers", "response, status, proxy_port")
                self.send_header("response", "start_recording")
                self.send_header("status", rv[0])
                self.send_header("proxy_port", rv[1])
            self.end_headers()
            return
        
        #--------------------------------------------------------------------------------------------------------------------------------------------#
        if self.path.startswith('/stop_recording'):
            rv = stop_recording()
            if rv != 'success':
                self.send_response(400)
            else:
                self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "response, status, session_path")
            self.send_header("response", "stop_recording")
            self.send_header("session_path", current_sessiondir)
            self.send_header("status", rv)
            self.end_headers()
            return
        
        #--------------------------------------------------------------------------------------------------------------------------------------------#
        if self.path.startswith('/terminate'):
            rv = 'terminate()'
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "response, status")
            self.send_header("response", "terminate")
            self.send_header("status", rv)
            self.end_headers()
            return
        
        #--------------------------------------------------------------------------------------------------------------------------------------------#
        if self.path.startswith('/prepare_pms'):
            rv = prepare_pms()
            if rv != 'success':
                self.send_response(400)
            else:
                self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "response, status")
            self.send_header("response", "prepare_pms")
            self.send_header("status", rv)
            self.end_headers()
            return
        
        #--------------------------------------------------------------------------------------------------------------------------------------------#
        if self.path.startswith('/inform_backend'):
            prepare_to_delete_folder()
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "response, status")
            self.send_header("response", "inform_backend")
            self.send_header("status", 'success')
            self.end_headers()
            return
        
        #--------------------------------------------------------------------------------------------------------------------------------------------#
        if self.path.startswith('/send_link'):
            filelink = self.path.split('?', 1)[1]
            rv = send_link(filelink)
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "response, status")
            self.send_header("response", "send_link")
            self.send_header("status", rv)
            self.end_headers()
            return
        
        #--------------------------------------------------------------------------------------------------------------------------------------------#
        if self.path.startswith('/get_html_paths'):
            rv = get_html_paths()
            if rv[0] != 'success':
                self.send_response(400)
            else:
                b64_paths = base64.b64encode(rv[1])
                self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "response, status, html_paths")
            self.send_header("response", "get_html_paths")
            self.send_header("status", rv[0])
            self.send_header("html_paths", b64_paths)
            self.end_headers()
            return            
        
        #--------------------------------------------------------------------------------------------------------------------------------------------#
        else:
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "response")
            self.send_header("response", "unknown command")
            self.end_headers()
            return

def get_html_paths():
    cr = cr_list[-1]
    #find tracefile containing cr and commit to its hash as well as the hash of md5hmac (for MS)
    #Construct MS and decrypt HTML files to be presented to auditee for approval
    tracelog_dir = os.path.join(current_sessiondir, 'tracelog')
    tracelog_files = os.listdir(tracelog_dir)
    bFoundCR = False
    for one_trace in tracelog_files:
        with open(os.path.join(tracelog_dir, one_trace), 'rb') as f: data=f.read()
        if not data.count(cr) == 1: continue
        #else client random found
        bFoundCR = True
        break 
    if not bFoundCR: raise Exception ('Client random not found in trace files')
    #copy the tracefile to a new location, b/c stcppipe may still be appending it 
    commit_dir = os.path.join(current_sessiondir, 'commit')
    if not os.path.exists(commit_dir): os.makedirs(commit_dir)
    tracecopy_path = os.path.join(commit_dir, 'trace'+ str(len(cr_list)) )
    md5hmac_path = os.path.join(commit_dir, 'md5_hmac'+ str(len(cr_list)) )
    with open(md5hmac_path, 'wb') as f: f.write(md5hmac)
    shutil.copyfile(os.path.join(tracelog_dir, one_trace), tracecopy_path)
    #send the hash of tracefile and md5hmac
    with open(tracecopy_path, 'rb') as f: data=f.read()
    commit_hash = hashlib.sha256(data).digest()
    md5hmac_hash = hashlib.sha256(md5hmac).digest()  
    b64_commit_hash = base64.b64encode(commit_hash+md5hmac_hash)
    reply = send_and_recv('commit_hash:'+b64_commit_hash)
    if reply[0] != 'success':
        raise Exception ('Failed to receive a reply')
    if not reply[1].startswith('sha1hmac_for_MS:'):
        raise Exception ('bad reply. Expected sha1hmac_for_MS')
    b64_sha1hmac_for_MS = reply[1][len('sha1hmac_for_MS:'):]
    try: sha1hmac_for_MS = base64.b64decode(b64_sha1hmac_for_MS)
    except:  raise Exception ('base64 decode error in sha1hmac_for_MS')
    #construct MS
    ms = bytearray([ord(a) ^ ord(b) for a,b in zip(md5hmac, sha1hmac_for_MS)])[:48]
    sslkeylog = os.path.join(commit_dir, 'sslkeylog')
    cr_hexl = binascii.hexlify(cr)
    ms_hexl = binascii.hexlify(ms)
    skl_fd = open(sslkeylog, 'wb')
    skl_fd.write('CLIENT_RANDOM ' + cr_hexl + ' ' + ms_hexl + '\n')
    skl_fd.close()
    #use tshark to extract HTML
    output = subprocess.check_output(['tshark', '-r', tracecopy_path, '-Y', 'ssl and http.content_type contains html', '-o', 'http.ssl.port:1025-65535', '-o', 'ssl.keylog_file:'+ sslkeylog, '-x'])
    if output == '': raise Exception ("Failed to find HTML in escrowtrace")
    #output may contain multiple frames with HTML, we examine them one-by-one
    separator = re.compile('Frame ' + re.escape('(') + '[0-9]{2,7} bytes' + re.escape(')') + ':')
    #ignore the first split element which is always an empty string
    frames = re.split(separator, output)[1:]    
    html_paths = ''
    for index,oneframe in enumerate(frames):
        html = get_html_from_asciidump(oneframe)
        path = os.path.join(commit_dir, 'html-' + str(len(cr_list)) + '-' + str(index))
        with open(path, 'wb') as f: f.write(html)
        html_paths += path + "&"    
    return ('success', html_paths)
    
    
#look at tshark's ascii dump (option '-x') to better understand the parsing taking place
def get_html_from_asciidump(ascii_dump):
    hexdigits = set('0123456789abcdefABCDEF')
    binary_html = bytearray()

    if ascii_dump == '':
        print ('empty frame dump',end='\r\n')
        return -1

    #We are interested in
    # "Uncompressed entity body" for compressed HTML (both chunked and not chunked). If not present, then
    # "De-chunked entity body" for no-compression, chunked HTML. If not present, then
    # "Reassembled SSL" for no-compression no-chunks HTML in multiple SSL segments, If not present, then
    # "Decrypted SSL data" for no-compression no-chunks HTML in a single SSL segment.
    
    uncompr_pos = ascii_dump.rfind('Uncompressed entity body')
    if uncompr_pos != -1:
        for line in ascii_dump[uncompr_pos:].split('\n')[1:]:
            #convert ascii representation of hex into binary so long as first 4 chars are hexdigits
            if all(c in hexdigits for c in line [:4]):
                try: m_array = bytearray.fromhex(line[6:54])
                except: break
                binary_html += m_array
            else:
                #if first 4 chars are not hexdigits, we reached the end of the section
                break
        return binary_html
    
    #else      
    dechunked_pos = ascii_dump.rfind('De-chunked entity body')
    if dechunked_pos != -1:
        for line in ascii_dump[dechunked_pos:].split('\n')[1:]:
            if all(c in hexdigits for c in line [:4]):
                try: m_array = bytearray.fromhex(line[6:54])
                except: break
                binary_html += m_array
            else:
                break
        return binary_html
            
    #else
    reassembled_pos = ascii_dump.rfind('Reassembled SSL')
    if reassembled_pos != -1:
        for line in ascii_dump[reassembled_pos:].split('\n')[1:]:
            if all(c in hexdigits for c in line [:4]):
                try: m_array = bytearray.fromhex(line[6:54])
                except: break
                binary_html += m_array
            else:
                #http HEADER is delimited from HTTP body with '\r\n\r\n'
                if binary_html.find('\r\n\r\n') == -1:
                    return -1
                break
        return binary_html.split('\r\n\r\n', 1)[1]

    #else
    decrypted_pos = ascii_dump.rfind('Decrypted SSL data')
    if decrypted_pos != -1:       
        for line in ascii_dump[decrypted_pos:].split('\n')[1:]:
            if all(c in hexdigits for c in line [:4]):
                try: m_array = bytearray.fromhex(line[6:54])
                except: break
                binary_html += m_array
            else:
                #http HEADER is delimited from HTTP body with '\r\n\r\n'
                if binary_html.find('\r\n\r\n') == -1:
                    return -1
                break
        return binary_html.split('\r\n\r\n', 1)[1]    
    

def send_link(filelink):
    b64_link = base64.b64encode(filelink)
    reply = send_and_recv('link:'+b64_link)
    if not reply[0] == 'success' : return 'failure'
    if not reply[1].startswith('response:') : return 'failure'
    response = reply[1][len('response:'):]
    return response


def prepare_to_delete_folder_thread(parentthread):
    dirset = set(os.listdir(current_sessiondir))
    #don't run this CPU-overwhelming code for longer than 5 seconds
    time_started = int(time.time())
    parentthread.retval = 'ready'
    while True:
        if int(time.time()) - time_started > 5:
            print ('5 seconds elapsed while waiting for a new folder')
            return
        newdirset = set(os.listdir(current_sessiondir))
        diffset = newdirset - dirset
        if len(diffset) == 1:
            item_to_delete = list(diffset)[0]
            os.rmdir(os.path.join(current_sessiondir, item_to_delete))
            print ('removed folder ' + item_to_delete)
            return
            
#Launch a thread to delete a folder which is created by FF when Select File dialog opens up
def prepare_to_delete_folder():
    thread = ThreadWithRetval(target= prepare_to_delete_folder_thread)
    thread.daemon = True
    thread.start()
    #wait for the thread to signal that it is ready
    while True:
        time.sleep(0.1)
        if thread.retval == 'ready': break
    return 'success'


#prepare google-checked PMSs in advance of page reloading
def prepare_pms():
    global PMS_first_half
    bIsCheckSuccessfull = False
    
    for i in range(5): #try 5 times until google check succeeds
        #first 4 bytes of client random are unix time
        cr_time = bigint_to_bytearray(int(time.time()))
        gcr = cr_time + os.urandom(28)
        client_hello = '\x16\x03\x01\x00\x2d\x01\x00\x00\x29\x03\x01' + gcr + '\x00\x00\x02\x00\x35\x01\x00'
        tlssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tlssock.settimeout(10)
        tlssock.connect(('google.com', 443))
        tlssock.send(client_hello)
        #we must get 3 tls handshake messages in response:
        #sh --> server_hello, cert --> certificate, shd --> server_hello_done
        time.sleep(1)
        sh_cert_shd = tlssock.recv(8192*2)  #google sends a ridiculously long cert chain of 10KB+
        #server hello starts with 16 03 01 * * 02
        #certificate starts with 16 03 01 * * 0b
        shd = '\x16\x03\x01\x00\x04\x0e\x00\x00\x00'
        sh_magic = re.compile(b'\x16\x03\x01..\x02')
        if not re.match(sh_magic, sh_cert_shd):
            raise Exception ('Invalid server hello')
        if not sh_cert_shd.endswith(shd):
            raise Exception ('invalid server hello done')
        #find the beginning of certificate message
        cert_magic = re.compile(b'\x16\x03\x01..\x0b')
        cert_match = re.search(cert_magic, sh_cert_shd)
        if not cert_match:
            raise Exception ('Invalid certificate message')
        cert_start_position = cert_match.start()
        sh = sh_cert_shd[:cert_start_position]
        cert = sh_cert_shd[cert_start_position : -len(shd)]
        #extract google_server_random from server_hello
        gsr = sh[11:43]
        
        b64_gcr_gsr = base64.b64encode(gcr+gsr)
        reply = send_and_recv('gcr_gsr:'+b64_gcr_gsr)
        
        if reply[0] != 'success':
            raise Exception ('Failed to receive a reply for gcr+gsr:')
        if not reply[1].startswith('grsapms_ghmac:'):
            raise Exception ('bad reply. Expected rsapms_ghmac:')
    
        b64_grsapms_ghmac = reply[1][len('grsapms_ghmac:'):]
        try:
            grsapms_ghmac = base64.b64decode(b64_grsapms_ghmac)    
        except:
            raise Exception ('base64 decode error in grsapms_ghmac')
        
        RSA_PMS_second_half_google = grsapms_ghmac[:256]
        sha1hmac_google = grsapms_ghmac[256:304]
        PMS_first_half = '\x03\x01'+os.urandom(secretbytes_amount) + ('\x00' * (24-2-secretbytes_amount))
        
        label = "master secret"
        seed = gcr + gsr
        
        md5A1 = hmac.new(PMS_first_half,  label+seed, hashlib.md5).digest()
        md5A2 = hmac.new(PMS_first_half,  md5A1, hashlib.md5).digest()
        md5A3 = hmac.new(PMS_first_half,  md5A2, hashlib.md5).digest()
        
        md5hmac1 = hmac.new(PMS_first_half, md5A1 + label + seed, hashlib.md5).digest()
        md5hmac2 = hmac.new(PMS_first_half, md5A2 + label + seed, hashlib.md5).digest()
        md5hmac3 = hmac.new(PMS_first_half, md5A3 + label + seed, hashlib.md5).digest()
        md5hmac_google = (md5hmac1+md5hmac2+md5hmac3)[:48]
        
        #xor the two hmacs
        xored = [ord(a) ^ ord(b) for a,b in zip(md5hmac_google,sha1hmac_google)]
        gms = bytearray(xored)
        
        ms_first_half = gms[:24]
        ms_second_half = gms[24:]
        label = "key expansion"
        seed = gsr + gcr
        #this is not optimized in a loop on purpose. I want people to see exactly what is going on
        md5A1 = hmac.new(ms_first_half, label+seed, hashlib.md5).digest()
        md5A2 = hmac.new(ms_first_half, md5A1, hashlib.md5).digest()
        md5A3 = hmac.new(ms_first_half, md5A2, hashlib.md5).digest()
        md5A4 = hmac.new(ms_first_half, md5A3, hashlib.md5).digest()
        md5A5 = hmac.new(ms_first_half, md5A4, hashlib.md5).digest()
        md5A6 = hmac.new(ms_first_half, md5A5, hashlib.md5).digest()
        md5A7 = hmac.new(ms_first_half, md5A6, hashlib.md5).digest()
        md5A8 = hmac.new(ms_first_half, md5A7, hashlib.md5).digest()
        md5A9 = hmac.new(ms_first_half, md5A8, hashlib.md5).digest()
        
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
        
      
        sha1A1 = hmac.new(ms_second_half, label+seed, hashlib.sha1).digest()
        sha1A2 = hmac.new(ms_second_half, sha1A1, hashlib.sha1).digest()
        sha1A3 = hmac.new(ms_second_half, sha1A2, hashlib.sha1).digest()
        sha1A4 = hmac.new(ms_second_half, sha1A3, hashlib.sha1).digest()
        sha1A5 = hmac.new(ms_second_half, sha1A4, hashlib.sha1).digest()
        sha1A6 = hmac.new(ms_second_half, sha1A5, hashlib.sha1).digest()
        sha1A7 = hmac.new(ms_second_half, sha1A6, hashlib.sha1).digest()
        
        sha1hmac1 = hmac.new(ms_second_half, sha1A1 + label + seed, hashlib.sha1).digest()
        sha1hmac2 = hmac.new(ms_second_half, sha1A2 + label + seed, hashlib.sha1).digest()
        sha1hmac3 = hmac.new(ms_second_half, sha1A3 + label + seed, hashlib.sha1).digest()
        sha1hmac4 = hmac.new(ms_second_half, sha1A4 + label + seed, hashlib.sha1).digest()
        sha1hmac5 = hmac.new(ms_second_half, sha1A5 + label + seed, hashlib.sha1).digest()
        sha1hmac6 = hmac.new(ms_second_half, sha1A6 + label + seed, hashlib.sha1).digest()
        sha1hmac7 = hmac.new(ms_second_half, sha1A7 + label + seed, hashlib.sha1).digest()
        
        sha1hmac = sha1hmac1+sha1hmac2+sha1hmac3+sha1hmac4+sha1hmac5+sha1hmac6+sha1hmac7
        
        xored = [ord(a) ^ ord(b) for a,b in zip(md5hmac,sha1hmac)]
        gexpanded_keys = bytearray(xored)
        
        client_mac_key = gexpanded_keys[:20]
        client_encryption_key = gexpanded_keys[40:72]
        client_iv = gexpanded_keys[104:120]
        
        RSA_PMS_first_half_int_google = pow( int(('\x02'+('\x01'*156)+'\x00'+PMS_first_half+('\x00'*24)).encode('hex'), 16) + 1, google_exponent, google_modulus)
        RSA_PMS_second_half_int_google = int(RSA_PMS_second_half_google.encode('hex'), 16)
        enc_pms_int = (RSA_PMS_first_half_int_google*RSA_PMS_second_half_int_google) % google_modulus 
        encpms_google = bigint_to_bytearray(enc_pms_int)
        
        client_key_exchange = '\x16\x03\x01\x01\x06\x10\x00\x01\x02\x01\00' + encpms_google
        change_cipher_spec = '\x14\x03\01\x00\x01\x01'
        
        #calculate verify data. get hashes of all handshakes
        handshake_messages = client_hello[5:]+sh[5:]+cert[5:]+shd[5:]+client_key_exchange[5:]
        sha = hashlib.sha1(handshake_messages).digest()
        md5 = hashlib.md5(handshake_messages).digest()
        #calculate verify_data for Finished message
        #see RFC2246 7.4.9. Finished & 5. HMAC and the pseudorandom function
        label = "client finished"
        seed = md5 + sha
        ms_first_half = gms[:24]
        ms_second_half = gms[24:]
        
        md5A1 = hmac.new(ms_first_half, label+seed, hashlib.md5).digest()
        md5hmac1 = hmac.new(ms_first_half, md5A1 + label + seed, hashlib.md5).digest()
        
        sha1A1 = hmac.new(ms_second_half, label+seed, hashlib.sha1).digest()
        sha1hmac1 = hmac.new(ms_second_half, sha1A1 + label + seed, hashlib.sha1).digest()
        
        xored = [ord(a) ^ ord(b) for a,b in zip(md5hmac1,sha1hmac1)]
        verify_data = bytearray(xored[:12])
        
        hmac_for_verify_data = hmac.new(client_mac_key, '\x00\x00\x00\x00\x00\x00\x00\x00' + '\x16' + '\x03\x01' + '\x00\x10' + '\x14\x00\x00\x0c' + verify_data, hashlib.sha1).digest()
       
        moo = AESModeOfOperation()
        cleartext = '\x14\x00\x00\x0c' + verify_data + hmac_for_verify_data
        
        cleartext_list = bigint_to_list(int(str(cleartext).encode('hex'),16))
        client_encryption_key_list =  bigint_to_list(int(str(client_encryption_key).encode('hex'),16))
        client_iv_list =  bigint_to_list(int(str(client_iv).encode('hex'),16))
        
        padded_cleartext = cleartext + ('\x0b' * 12) #this is TLS CBC padding, it is not PKCS7
        try:
            mode, orig_len, encrypted_verify_data_and_hmac_for_verify_data = moo.encrypt( str(padded_cleartext), moo.modeOfOperation["CBC"], client_encryption_key_list, moo.aes.keySize["SIZE_256"], client_iv_list)
        except Exception, e: # TODO find out why I once got TypeError: 'NoneType' object is not iterable.  It helps to catch an exception here
            print ('Caught exception while doing slowaes encrypt: ', e)
            tlssock.close()
            continue
        
        finished = '\x16\x03\x01\x00\x30' + bytearray(encrypted_verify_data_and_hmac_for_verify_data)
        
        tlssock.send(client_key_exchange+change_cipher_spec+finished)
        time.sleep(1)
        response = tlssock.recv(8192)
        if not response.count(change_cipher_spec):
            #the response did not contain ccs == error alert received
            tlssock.close()
            continue
        tlssock.close()
        bIsCheckSuccessfull = False
        return 'success' #successfull pms check        
    #no dice after 5 tries
    raise Exception ('Could not check PMS with google after 5 tries')

    

#send a message and return the response received
def send_and_recv (data):
    if not hasattr(send_and_recv, "my_seq"):
        send_and_recv.my_seq = 0 #static variable. Initialized only on first function's run
  
    #empty queue from possible leftovers
    #try: ackQueue.get_nowait()
    #except: pass    #split up data longer than 400 bytes (IRC message limit is 512 bytes including the header data)
    #'\r\n' must go to the end of each message
    chunks = len(data)/400 + 1
    if len(data)%400 == 0: chunks -= 1 #avoid creating an empty chunk if data length is a multiple of 400
    for chunk_index in range(chunks) :
        send_and_recv.my_seq += 1
        chunk = data[400*chunk_index:400*(chunk_index+1)]
        
        for i in range (3):
            bWasMessageAcked = False
            ending = ' EOL ' if chunk_index+1==chunks else ' CRLF ' #EOL for the last chunk, otherwise CRLF
            irc_msg = 'PRIVMSG ' + channel_name + ' :' + auditor_nick + ' seq:' + str(send_and_recv.my_seq) + ' ' + chunk + ending +'\r\n'
            bytessent = IRCsocket.send(irc_msg)
            print('SENT:' + str(bytessent) + ' ' +  irc_msg)
        
            try: oneAck = ackQueue.get(block=True, timeout=5)
            except:  continue #send again because ack was not received
            if not str(send_and_recv.my_seq) == oneAck: continue
            #else: correct ack received
            bWasMessageAcked = True
            break
        if not bWasMessageAcked:
            return ('failure', '')
    
    #receive a response
    for i in range(3):
        try: onemsg = recvQueue.get(block=True, timeout=5)
        except:  continue #try to receive again
        return ('success', onemsg)
    return ('failure', '')


def stop_recording():
    global bReceivingThreadStopFlagIsSet
    os.kill(stcppipe_proc.pid, signal.SIGTERM)
    #TODO stop https proxy. 

    #trace* files in committed dir is what auditor needs
    zipf = zipfile.ZipFile(os.path.join(current_sessiondir, 'mytrace.zip'), 'w')
    commit_dir = os.path.join(current_sessiondir, 'commit')
    com_dir_files = os.listdir(commit_dir)
    for onefile in com_dir_files:
        if not onefile.startswith(('trace', 'md5_hmac')): continue
        zipf.write(os.path.join(commit_dir, onefile), onefile)
    zipf.close()
    return 'success'


    
#The NSS patch has created a new file in the nss_patch_dir
def process_new_uid(uid): 
    global md5hmac
    
    with  open(os.path.join(nss_patch_dir, 'der'+uid), 'rb') as fd: der = fd.read()
    #TODO: find out why on windows \r\n newline makes its way into der encoding
    if OS=='mswin': der = der.replace('\r\n', '\n')
    with  open(os.path.join(nss_patch_dir, 'cr'+uid), 'rb') as fd: cr = fd.read()
    with open(os.path.join(nss_patch_dir, 'sr'+uid), 'rb') as fd: sr = fd.read()
    cr_list.append(cr)
    
    #extract n and e from the pubkey
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
        n = bigint_to_bytearray(modulus_int)
        e = bigint_to_bytearray(exponent_int)
    except:
        print ('Error decoding der pubkey')
        return 'failure'
     
    label = "master secret"
    seed = cr + sr
    
    md5A1 = hmac.new(PMS_first_half,  label+seed, hashlib.md5).digest()
    md5A2 = hmac.new(PMS_first_half,  md5A1, hashlib.md5).digest()
    md5A3 = hmac.new(PMS_first_half,  md5A2, hashlib.md5).digest()
    
    md5hmac1 = hmac.new(PMS_first_half, md5A1 + label + seed, hashlib.md5).digest()
    md5hmac2 = hmac.new(PMS_first_half, md5A2 + label + seed, hashlib.md5).digest()
    md5hmac3 = hmac.new(PMS_first_half, md5A3 + label + seed, hashlib.md5).digest()
    md5hmac = md5hmac1+md5hmac2+md5hmac3
    
    md5hmac_for_MS_first_half = md5hmac[:24]
    md5hmac_for_MS_second_half = md5hmac[24:48]
                  
    b64_cr_sr_hmac_n_e= base64.b64encode(cr+sr+md5hmac_for_MS_first_half+n+e)
    reply = send_and_recv('cr_sr_hmac_n_e:'+b64_cr_sr_hmac_n_e)
    
    if reply[0] != 'success':
        print ('Failed to receive a reply for cr_sr_hmac_n_e:')
        return ('Failed to receive a reply for cr_sr_hmac_n_e:')
    if not reply[1].startswith('rsapms_hmacms_hmacek:'):
        print ('bad reply. Expected rsapms_hmacms_hmacek_grsapms_ghmac:')
        return 'bad reply. Expected rsapms_hmacms_hmacek_grsapms_ghmac:'
    b64_rsapms_hmacms_hmacek = reply[1][len('rsapms_hmacms_hmacek:'):]
    try:
        rsapms_hmacms_hmacek = base64.b64decode(b64_rsapms_hmacms_hmacek)    
    except:
        print ('base64 decode error in rsapms_hmacms_hmacek')
        return ('base64 decode error in rsapms_hmacms_hmacek')
  
    RSA_PMS_second_half = rsapms_hmacms_hmacek[:256]
    RSA_PMS_second_half_int = int(RSA_PMS_second_half.encode('hex'), 16)
    sha1hmac_for_MS_second_half = rsapms_hmacms_hmacek[256:280]
    md5hmac_for_ek = rsapms_hmacms_hmacek[280:416]
   
    #RSA encryption without padding: ciphertext = plaintext^e mod n
    RSA_PMS_first_half_int = pow( int(('\x02'+('\x01'*156)+'\x00'+PMS_first_half+('\x00'*24)).encode('hex'), 16) + 1, exponent_int, modulus_int)
    enc_pms_int = (RSA_PMS_second_half_int*RSA_PMS_first_half_int) % modulus_int 
    enc_pms = bigint_to_bytearray(enc_pms_int)
    with open(os.path.join(nss_patch_dir, 'encpms'+uid), 'wb') as f: f.write(enc_pms)
    with open(os.path.join(nss_patch_dir, 'encpms'+uid+'ready' ), 'wb') as f: f.close()
    
    MS_second_half = bytearray([ord(a) ^ ord(b) for a,b in zip(md5hmac_for_MS_second_half, sha1hmac_for_MS_second_half)])
    #master secret key expansion
    #see RFC2246 6.3. Key calculation & 5. HMAC and the pseudorandom function   
    #for AES-CBC-SHA  (in bytes): mac secret 20, write key 32, IV 16
    #hence we need to generate 2*(20+32+16)= 136 bytes
    # 7 sha hmacs * 20 = 140 and 9 md5 hmacs * 16 = 144
    label = "key expansion"
    seed = sr + cr
    #this is not optimized in a loop on purpose. I want people to see exactly what is going on   
    sha1A1 = hmac.new(MS_second_half,  label+seed, hashlib.sha1).digest()
    sha1A2 = hmac.new(MS_second_half,  sha1A1, hashlib.sha1).digest()
    sha1A3 = hmac.new(MS_second_half,  sha1A2, hashlib.sha1).digest()
    sha1A4 = hmac.new(MS_second_half,  sha1A3, hashlib.sha1).digest()
    sha1A5 = hmac.new(MS_second_half,  sha1A4, hashlib.sha1).digest()
    sha1A6 = hmac.new(MS_second_half,  sha1A5, hashlib.sha1).digest()
    sha1A7 = hmac.new(MS_second_half,  sha1A6, hashlib.sha1).digest()
    
    sha1hmac1 = hmac.new(MS_second_half, sha1A1 + label + seed, hashlib.sha1).digest()
    sha1hmac2 = hmac.new(MS_second_half, sha1A2 + label + seed, hashlib.sha1).digest()
    sha1hmac3 = hmac.new(MS_second_half, sha1A3 + label + seed, hashlib.sha1).digest()
    sha1hmac4 = hmac.new(MS_second_half, sha1A4 + label + seed, hashlib.sha1).digest()
    sha1hmac5 = hmac.new(MS_second_half, sha1A5 + label + seed, hashlib.sha1).digest()
    sha1hmac6 = hmac.new(MS_second_half, sha1A6 + label + seed, hashlib.sha1).digest()
    sha1hmac7 = hmac.new(MS_second_half, sha1A7 + label + seed, hashlib.sha1).digest()
    
    sha1hmac_for_ek = (sha1hmac1+sha1hmac2+sha1hmac3+sha1hmac4+sha1hmac5+sha1hmac6+sha1hmac7)[:136]
    
    expanded_keys = bytearray([ord(a) ^ ord(b) for a,b in zip(sha1hmac_for_ek, md5hmac_for_ek)])
    #server mac key == expanded_keys[20:40] contains random garbage from auditor
    
    with open(os.path.join(nss_patch_dir, 'expanded_keys'+uid), 'wb') as f: f.write(expanded_keys)
    with open(os.path.join(nss_patch_dir, 'expanded_keys'+uid+'ready'), 'wb') as f: f.close()
    
    
    #wait for nss to create md5 and then sha files
    while True:
        if not os.path.isfile(os.path.join(nss_patch_dir, 'sha'+uid)):
            time.sleep(0.1)
        else:
            time.sleep(0.1)
            break
    
    md5_digest = open(os.path.join(nss_patch_dir, 'md5'+uid), 'rb').read()
    sha_digest = open(os.path.join(nss_patch_dir, 'sha'+uid), 'rb').read()
    
    b64_verify_md5sha = base64.b64encode(md5_digest+sha_digest)
    reply = send_and_recv('verify_md5sha:'+b64_verify_md5sha)
    if reply[0] != 'success':
        print ('Failed to receive a reply')
        return ('Failed to receive a reply')
    if not reply[1].startswith('verify_hmac:'):
        print ('bad reply. Expected verify_hmac:')
        return 'bad reply. Expected verify_hmac:'
    b64_verify_hmac = reply[1][len('verify_hmac:'):]
    try:
        verify_hmac = base64.b64decode(b64_verify_hmac)    
    except:
        print ('base64 decode error')
        return ('base64 decode error')
    
    #calculate verify_data for Finished message
    #see RFC2246 7.4.9. Finished & 5. HMAC and the pseudorandom function
    label = "client finished"
    seed = md5_digest + sha_digest
 
    sha1A1 = hmac.new(MS_second_half,  label+seed, hashlib.sha1).digest()
    sha1hmac1 = hmac.new(MS_second_half, sha1A1 + label + seed, hashlib.sha1).digest()
    verify_data = [ord(a) ^ ord(b) for a,b in zip(verify_hmac, sha1hmac1)][:12]    
    
    with open(os.path.join(nss_patch_dir, 'verify_data'+uid), 'wb') as f: f.write(bytearray(verify_data))
    with open(os.path.join(nss_patch_dir, 'verify_data'+uid+'ready'), 'wb') as f: f.close()
    return 'success'
    
   
#scan the dir until a new file appears and then spawn a new processing thread
def nss_patch_dir_scan_thread():
    uidsAlreadyProcessed = []
    uid = ''
    #the other thread must delete the nss_patch_is_active file to signal that auditing session is over
    #while os.path.isfile(os.path.join(nss_patch_dir, 'nss_patch_is_active')):
    while True:
        time.sleep(0.1)
        bNewUIDFound = False
        files = os.listdir(nss_patch_dir)
        for onefile in files:
            #frontend creates all three files: der*,cr*, and sr*. We wait for the last file 'sr' to be created and proceed
            if not onefile.startswith('sr'): continue
            if onefile in uidsAlreadyProcessed: continue
            uid =onefile[2:]
            uidsAlreadyProcessed.append(onefile)
            bNewUIDFound = True
            break
        if bNewUIDFound == False:
            continue
        #else if new uid found
        rv = process_new_uid(uid)
        if rv != 'success':
            print ('Error occured while processing nss patch dir:' + rv)
            break

def new_connection_thread(socket_client, new_address):
    #extract destination address from the http header
    #the header has a form of: CONNECT encrypted.google.com:443 HTTP/1.1 some_other_stuff
    headers_str = socket_client.recv(8192)
    headers = headers_str.split()
    if len(headers) < 2:
        print ('Invalid or empty header received: ' + headers_str)
        socket_client.close()
        return
    if headers[0] != 'CONNECT':
        print ('Expected CONNECT in header but got ' + headers[0] + '. Please investigate')
        socket_client.close()
        return
    if headers[1].find(':') == -1:
        print ('Expected colon in the address part of the header but none found. Please investigate')
        socket_client.close()
        return
    split_result = headers[1].split(':')
    if len(split_result) != 2:
        print ('Expected only two values after splitting the header. Please investigate')
        socket_client.close()
        return
    host, port = split_result
    try:
        int_port = int(port)
    except:
        print ('Port is not a numerical value. Please investigate')
        socket_client.close()
        return
    try: host_ip = socket.gethostbyname(host)
    except: #happens when IP lookup fails for some IP6-only hosts
        socket_client.close()
        return
    socket_target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_target.connect((host_ip, int_port))
    print ('New connection to ' + host_ip + ' port ' + port)
    #tell Firefox that connection is established and it can start sending data
    socket_client.send('HTTP/1.1 200 Connection established\n' + 'Proxy-agent: tlsnotary https proxy\n\n')
    
    last_time_data_was_seen = int(time.time())
    while True:
        rlist, wlist, xlist = select.select((socket_client, socket_target), (), (socket_client, socket_target), 20)
        if len(rlist) == len(wlist) == len(xlist) == 0: #20 second timeout
            print ('Socket 60 second timeout. Terminating connection')
            socket_client.close()
            socket_target.close()
            return
        if len(xlist) > 0:
            print ('Socket exceptional condition. Terminating connection')
            socket_client.close()
            socket_target.close()
            return
        if len(rlist) == 0:
            print ('Python internal socket error: rlist should not be empty. Please investigate. Terminating connection')
            socket_client.close()
            socket_target.close()
            return
        #else rlist contains socket with data
        for rsocket in rlist:
            try:
                data = rsocket.recv(8192)
                if not data: 
                    #this worries me. Why did select() trigger if there was no data?
                    #this overwhelms CPU big time unless we sleep
                    if int(time.time()) - last_time_data_was_seen > 20: #prevent no-data sockets from looping endlessly
                        socket_client.close()
                        socket_target.close()
                        return
                    #else 20 seconds of datalessness have not elapsed
                    time.sleep(0.1)
                    continue 
                last_time_data_was_seen = int(time.time())
                if rsocket is socket_client:
                    socket_target.send(data)
                    continue
                elif rsocket is socket_target:
                    socket_client.send(data)
                    continue
            except Exception, e:
                print (e)
                socket_client.close()
                socket_target.close()
                return
         
        
def https_proxy_thread(parenthread, port):
    socket_proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        socket_proxy.bind(('localhost', port))
        parenthread.retval = 'success'
    except: #socket is in use
        parenthread.retval = 'failure'
        return
    print ('HTTPS proxy is serving on port ' + str(port))
    socket_proxy.listen(5) #5 requests can be queued
    while True:
        #block until a new connection appears
        print ('listening for a new connection')
        new_socket, new_address = socket_proxy.accept()
        print ('new connection  accepted')
        thread = threading.Thread(target= new_connection_thread, args=(new_socket, new_address))
        thread.daemon = True
        thread.start()
        


def start_recording():
    global stcppipe_proc
   
    #start the https proxy and make sure the port is not in use
    bWasStarted = False
    for i in range(3):
        HTTPS_proxy_port =  random.randint(1025,65535)
        thread = ThreadWithRetval(target= https_proxy_thread, args=(HTTPS_proxy_port, ))
        thread.daemon = True
        thread.start()
        time.sleep(1)
        if thread.retval != 'success':
            continue
        #else retval == 'success'
        bWasStarted = True
        break
    if bWasStarted == False:
        return ('failure to start HTTPS proxy')
    print ('Started HTTPS proxy on port ' + str(HTTPS_proxy_port))

    #start stcppipe making sure the port is not in use
    bWasStarted = False
    logdir = os.path.join(current_sessiondir, 'tracelog')
    os.makedirs(logdir)
    for i in range(3):
        FF_proxy_port = random.randint(1025,65535)
        if OS=='mswin': stcppipe_exename = 'stcppipe.exe'
        elif OS=='linux': stcppipe_exename = 'stcppipe_linux'
        elif OS=='macos': stcppipe_exename = 'stcppipe_mac'
        stcppipe_proc = subprocess.Popen([os.path.join(datadir, 'stcppipe', stcppipe_exename), '-d', logdir, '-b', '127.0.0.1', str(HTTPS_proxy_port), str(FF_proxy_port)])
        time.sleep(1)
        if stcppipe_proc.poll() != None:
            print ('Maybe the port was in use, trying again with a new port')
            continue
        else:
            bWasStarted = True
            break
    if bWasStarted == False:
        return ('failure to start stcppipe')
    print ('stcppipe is piping from port ' + str(FF_proxy_port) + ' to port ' + str(HTTPS_proxy_port))
    
    #finally let nss patch know we are ready and start monitoring
    with open(os.path.join(nss_patch_dir, 'nss_patch_is_active'), "wb") as f: f.close()
    thread = threading.Thread(target= nss_patch_dir_scan_thread)
    thread.daemon = True
    thread.start()
    return ('success', FF_proxy_port)



#respond to PING messages and put all the other messages onto the recvQueue
def receivingThread(my_nick, auditor_nick, IRCsocket):
    if not hasattr(receivingThread, "last_seq_which_i_acked"):
        receivingThread.last_seq_which_i_acked = 100000 #static variable. Initialized only on first function's run
    
    first_chunk='' #we put the first chunk here and do a new loop iteration to pick up the second one
    second_chunk=''
    while not bReceivingThreadStopFlagIsSet:
        buffer = ''
        try: buffer = IRCsocket.recv(1024)
        except: continue #1 sec timeout
        if not buffer: continue
        #sometimes the IRC server may pack multiple PRIVMSGs into one message separated with /r/n/
        messages = buffer.split('\r\n')
        for onemsg in messages:
            msg = onemsg.split()
            if len(msg) == 0: continue  #stray newline
            if msg[0] == "PING": #check if server have sent ping command
                IRCsocket.send("PONG %s" % msg[1]) #answer with pong as per RFC 1459
                continue
            if not len(msg) >= 5: continue
            if not (msg[1] == 'PRIVMSG' and msg[2] == channel_name and msg[3] == ':'+my_nick ): continue
            exclamaitionMarkPosition = msg[0].find('!')
            nick_from_message = msg[0][1:exclamaitionMarkPosition]
            if not auditor_nick == nick_from_message: continue
            print ('RECEIVED:' + buffer)
            if len(msg)==5 and msg[4].startswith('ack:'):
                ackQueue.put(msg[4][len('ack:'):])
                continue
            if not (len(msg)==7 and msg[4].startswith('seq:')): continue
            his_seq = int(msg[4][len('seq:'):])
            if his_seq <=  receivingThread.last_seq_which_i_acked: 
                #the other side is out of sync, send an ack again
                IRCsocket.send('PRIVMSG ' + channel_name + ' :' + auditor_nick + ' ack:' + str(his_seq) + ' \r\n')
                continue
            if not his_seq == receivingThread.last_seq_which_i_acked +1: continue #we did not receive the next seq in order
            #else we got a new seq      
            if first_chunk == '' and  not msg[5].startswith((
                'grsapms_ghmac', 'rsapms_hmacms_hmacek', 'verify_hmac:', 'logsig:', 'response:', 'sha1hmac_for_MS')) : continue         
            #check if this is the first chunk of a chunked message. Only 2 chunks are supported for now
            #'CRLF' is used at the end of the first chunk, 'EOL' is used to show that there are no more chunks
            if msg[-1]=='CRLF':
                if first_chunk != '':
                    if second_chunk !='': #we already have two chunks, no more are allowed
                        continue
                    second_chunk = msg[5]
                else:
                    first_chunk = msg[5]
                IRCsocket.send('PRIVMSG ' + channel_name + ' :' + auditor_nick + ' ack:' + str(his_seq) + ' \r\n')
                receivingThread.last_seq_which_i_acked = his_seq
                continue #go pickup another chunk
            elif msg[-1]=='EOL' and first_chunk != '': #last chunk arrived
                print ('second chunk arrived')
                assembled_message = first_chunk + second_chunk + msg[5]
                recvQueue.put(assembled_message)
                first_chunk=''
                second_chunk=''
                IRCsocket.send('PRIVMSG ' + channel_name + ' :' + auditor_nick + ' ack:' + str(his_seq) + ' \r\n')
                receivingThread.last_seq_which_i_acked = his_seq
            elif msg[-1]=='EOL':
                recvQueue.put(msg[5])
                IRCsocket.send('PRIVMSG ' + channel_name + ' :' + auditor_nick + ' ack:' + str(his_seq) + ' \r\n')
                receivingThread.last_seq_which_i_acked = his_seq
               


def start_irc():
    global my_nick
    global auditor_nick
    global IRCsocket
    global google_modulus
    global google_exponent
    
    my_nick= 'user' + ''.join(random.choice('0123456789') for x in range(10))
    
    IRCsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    IRCsocket.connect(('chat.freenode.net', 6667))
    IRCsocket.send("USER %s %s %s %s" % ('these', 'arguments', 'are', 'optional') + '\r\n')
    IRCsocket.send("NICK " + my_nick + '\r\n')  
    IRCsocket.send("JOIN %s" % channel_name + '\r\n')
    
    # ----------------------------------BEGIN get the certficate for google.com and extract modulus/exponent
    tlssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tlssock.settimeout(10)
    tlssock.connect(('google.com', 443))
    cr_time = bigint_to_bytearray(int(time.time()))
    cr_google = cr_time + os.urandom(28)
    client_hello = '\x16\x03\x01\x00\x2d\x01\x00\x00\x29\x03\x01' + cr_google + '\x00\x00\x02\x00\x35\x01\x00'
    tlssock.send(client_hello)
    time.sleep(1)
    serverhello_certificate_serverhellodone = tlssock.recv(8192*2)    #google sends a ridiculously long cert chain of 10KB+
    #server hello starts with 16 03 01 * * 02
    #certificate starts with 16 03 01 * * 0b
    serverhellodone = '\x16\x03\x01\x00\x04\x0e\x00\x00\x00'
    
    if not re.match(re.compile(b'\x16\x03\x01..\x02'), serverhello_certificate_serverhellodone):
        print ('Invalid server hello from google')
        return 'failure'
    if not serverhello_certificate_serverhellodone.endswith(serverhellodone):
        print ('invalid server hello done from google')
        return 'failure'
    #find the beginning of certificate message
    cert_match = re.search(re.compile(b'\x16\x03\x01..\x0b'), serverhello_certificate_serverhellodone)
    if not cert_match:
        print ('Invalid certificate message from google')
        return 'failure'
    cert_start_position = cert_match.start()
    certificate = serverhello_certificate_serverhellodone[cert_start_position : -len(serverhellodone)]
    #extract modulus and exponent from the certificate
    cert_len = int(certificate[12:15].encode('hex'),16)
    google_cert = certificate[15:15+cert_len]
    try:       
        rv  = decoder.decode(google_cert, asn1Spec=univ.Sequence())
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
        google_modulus = int(modulus)
        google_exponent = int(exponent)
        google_n = bigint_to_bytearray(google_modulus)
        google_e = bigint_to_bytearray(google_exponent)
    except:
        print ('Error decoding der pubkey from google')
        return 'failure'
    # ----------------------------------END get the certficate for google.com and extract modulus/exponent

       
    modulus = bigint_to_bytearray(auditorPublicKey.n)[:10]
    signed_hello = rsa.sign('client_hello', myPrivateKey, 'SHA-1')
    b64_hello = base64.b64encode(modulus+signed_hello)
    b64_google_pubkey = base64.b64encode(google_n+google_e)
    #hello contains the first 10 bytes of modulus of the auditor's pubkey
    #this is how the auditor knows on IRC that we are addressing him. Thus we allow multiple audit sessions simultaneously
    IRCsocket.settimeout(1)
    bIsAuditorRegistered = False
    for attempt in range(6): #try for 6*10 secs to find the auditor
        if bIsAuditorRegistered == True: break #previous iteration successfully regd the auditor
        time_attempt_began = int(time.time())
        IRCsocket.send('PRIVMSG ' + channel_name + ' :client_hello:'+b64_hello +' \r\n')
        time.sleep(1)
        IRCsocket.send('PRIVMSG ' + channel_name + ' :google_pubkey:'+b64_google_pubkey +' \r\n')
        while not bIsAuditorRegistered:
            if int(time.time()) - time_attempt_began > 10: break
            buffer = ''
            try: buffer = IRCsocket.recv(1024)
            except: continue #1 sec timeout
            if not buffer: continue
            print (buffer)
            messages = buffer.split('\r\n')  #sometimes the IRC server may pack multiple PRIVMSGs into one message separated with /r/n/
            for onemsg in messages:
                msg = onemsg.split()
                if len(msg)==0 : continue  #stray newline
                if msg[0] == "PING":
                    IRCsocket.send("PONG %s" % msg[1]) #answer with pong as per RFC 1459
                    continue
                if not len(msg) == 5: continue
                if not (msg[1]=='PRIVMSG' and msg[2]==channel_name and msg[3]==':'+my_nick and msg[4].startswith('server_hello:')): continue
                b64_signed_hello = msg[4][len('server_hello:'):]
                try:
                    signed_hello = base64.b64decode(b64_signed_hello)
                    rsa.verify('server_hello', signed_hello, auditorPublicKey)
                    #if no exception:
                    exclamaitionMarkPosition = msg[0].find('!')
                    auditor_nick = msg[0][1:exclamaitionMarkPosition]
                    bIsAuditorRegistered = True
                    print ('Auditor successfully verified')
                    break
                except:
                    print ('hello verification failed. Are you sure you have the correct auditor\'s pubkey?')
                    continue
    if not bIsAuditorRegistered:
        print ('Failed to register auditor within 60 seconds')
        return 'failure'
    
    thread = threading.Thread(target= receivingThread, args=(my_nick, auditor_nick, IRCsocket))
    thread.daemon = True
    thread.start()
    return 'success'
    
    
    
def start_firefox(FF_to_backend_port):
    global current_sessiondir
    global nss_patch_dir
    
    #sanity check
    if os.path.exists(os.path.join(datadir, 'firefoxcopy', 'firefox.exe' if OS=='mswin' else 'firefox')):
        firefox_exepath = os.path.join(datadir, 'firefoxcopy', 'firefox.exe' if OS=='mswin' else 'firefox')
    else:
        exit (FIREFOX_MISSING)
 
    import stat
    os.chmod(firefox_exepath,stat.S_IRWXU)
    if not os.path.isdir(os.path.join(datadir, 'logs')): os.makedirs(os.path.join(datadir, 'logs'))
    if not os.path.isfile(os.path.join(datadir, 'logs', 'firefox.stdout')): open(os.path.join(datadir, 'logs', 'firefox.stdout'), 'w').close()
    if not os.path.isfile(os.path.join(datadir, 'logs', 'firefox.stderr')): open(os.path.join(datadir, 'logs', 'firefox.stderr'), 'w').close()    
    if not os.path.isfile(os.path.join(datadir, 'FF-profile', 'extensions.ini')):            
        try:
            #show addon bar
            with codecs.open(os.path.join(datadir, 'FF-profile', 'localstore.rdf'), 'w') as f2:
                f2.write('<?xml version="1.0"?><RDF:RDF xmlns:NC="http://home.netscape.com/NC-rdf#" xmlns:RDF="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><RDF:Description RDF:about="chrome://browser/content/browser.xul"><NC:persist RDF:resource="chrome://browser/content/browser.xul#addon-bar" collapsed="false"/></RDF:Description></RDF:RDF>')    
        except Exception,e:
            return ('File open error', )
          
    #create a session dir
    time_str = time.strftime("%d-%b-%Y-%H-%M-%S", time.gmtime())
    current_sessiondir = os.path.join(sessionsdir, time_str)
    os.makedirs(current_sessiondir)

    os.putenv("FF_to_backend_port", str(FF_to_backend_port))
    os.putenv("FF_first_window", "true")   #prevents extension's confusion when websites open multiple FF windows
    nss_patch_dir = os.path.join(current_sessiondir, 'nsspatchdir')
    os.makedirs(nss_patch_dir)
    #we need a trailing slash to relieve the patch from figuring out which path delimiter to use (nix vs win)
    os.putenv('NSS_PATCH_DIR', os.path.join(nss_patch_dir, ''))
    os.putenv('HOME', current_sessiondir) #This is a mega-ugly hack
    #we want the tracefile upload dialog to open to the dir where the trace zip is located so that the user
    #doesnt have to click his way through all the nested folders
    #FF always opens the dialog in $HOME/Desktop (creating the dir Desktop if not present)
    #second part of this hack is a function in the addon which monitors the presence of Desktop dir and
    #immediately deletes it, which forces FF to open the dialog to the $HOME dir
    
    print ("Starting a new instance of Firefox with Paysty's profile",end='\r\n')
    try:
        ff_proc = subprocess.Popen([firefox_exepath,'-no-remote', '-profile', os.path.join(datadir, 'FF-profile')], stdout=open(os.path.join(datadir, 'logs', "firefox.stdout"),'w'), stderr=open(os.path.join(datadir, 'logs', "firefox.stderr"), 'w'))
    except Exception,e:
        return ("Error starting Firefox: %s" %e,)
    return ('success', ff_proc)


class StoppableHttpServer (BaseHTTPServer.HTTPServer):
    """http server that reacts to self.stop flag"""
    retval = ''
    def serve_forever (self):
        """Handle one request at a time until stopped. Optionally return a value"""
        self.stop = False
        while not self.stop:
                self.handle_request()
        return self.retval;
    

#use miniHTTP server to receive commands from Firefox addon and respond to them
def minihttp_thread(parentthread):    
    #allow three attempts to start mini httpd in case if the port is in use
    bWasStarted = False
    for i in range(3):
        FF_to_backend_port = random.randint(1025,65535)
        print ('Starting mini http server to communicate with Firefox plugin')
        try:
            httpd = StoppableHttpServer(('127.0.0.1', FF_to_backend_port), HandlerClass)
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
    #Let the invoking thread know that we started successfully
    parentthread.retval = ('success', FF_to_backend_port)
    sa = httpd.socket.getsockname()
    print ("Serving HTTP on", sa[0], "port", sa[1], "...",end='\r\n')
    httpd.serve_forever()
    return
    
    
if __name__ == "__main__":
    
    #On first run, unpack rsa and pyasn1 archives, check hashes
    rsa_dir = os.path.join(datadir, 'python', 'rsa-3.1.4')
    if not os.path.exists(rsa_dir):
        print ('Extracting rsa-3.1.4.tar.gz')
        with open(os.path.join(datadir, 'python', 'rsa-3.1.4.tar.gz')) as f: tarfile_data = f.read()
        #for md5 hash, see https://pypi.python.org/pypi/rsa/3.1.4
        if hashlib.md5(tarfile_data).hexdigest() != 'b6b1c80e1931d4eba8538fd5d4de1355':
            print ('Wrong hash')
            exit(WRONG_HASH)
        os.chdir(os.path.join(datadir, 'python'))
        tar = tarfile.open(os.path.join(datadir, 'python', 'rsa-3.1.4.tar.gz'), 'r:gz')
        tar.extractall()
    #both on first and subsequent runs
    sys.path.append(os.path.join(datadir, 'python', 'rsa-3.1.4'))
    import rsa
    #init global vars
    myPrivateKey = rsa.key.PrivateKey
    auditorPublicKey = rsa.key.PublicKey
    
    pyasn1_dir = os.path.join(datadir, 'python', 'pyasn1-0.1.7')
    if not os.path.exists(pyasn1_dir):
        print ('Extracting pyasn1-0.1.7.tar.gz')
        with open(os.path.join(datadir, 'python', 'pyasn1-0.1.7.tar.gz')) as f: tarfile_data = f.read()
        #for md5 hash, see https://pypi.python.org/pypi/pyasn1/0.1.7
        if hashlib.md5(tarfile_data).hexdigest() != '2cbd80fcd4c7b1c82180d3d76fee18c8':
            print ('Wrong hash')
            exit(WRONG_HASH)
        os.chdir(os.path.join(datadir, 'python'))
        tar = tarfile.open(os.path.join(datadir, 'python', 'pyasn1-0.1.7.tar.gz'), 'r:gz')
        tar.extractall()
    #both on first and subsequent runs
    sys.path.append(os.path.join(datadir, 'python', 'pyasn1-0.1.7'))
    import pyasn1
    from pyasn1.type import univ
    from pyasn1.codec.der import encoder, decoder    
    
    #On first run, make sure that torbrowser installfile is in the same directory and extract it
    if not os.path.exists(os.path.join(datadir, 'firefoxcopy')):
        print ('Extracting Firefox ...')
        if OS=='linux':
            #github doesn't allow to upload .tar.xz, so we add extension now
            if platform.machine() == 'x86_64':
                zipname = 'firefox-linux64'
            else:
                zipname = 'firefox-linux32'
            fullpath = os.path.join(installdir, zipname)
            if os.path.exists(fullpath): 
                os.rename(fullpath, fullpath + ".tar.xz")
            elif not os.path.exists(fullpath + ".tar.xz"):
                print ('Couldn\'t find either '+zipname+' or '+zipname+'.tar.xz'+' Make sure one of them is located in the installdir')
                exit (CANT_FIND_TORBROWSER)            
            torbrowser_zip_path = fullpath + '.tar.xz'              
            try:
                subprocess.check_output(['xz', '-d', '-k', torbrowser_zip_path]) #extract and keep the sourcefile
            except:
                print ('Could not extract ' + torbrowser_zip_path + '.Make sure xz is installed on your system')
                exit (CANT_FIND_XZ)
            #by default the result of the extraction will be tor-browser-linux32-3.5.2.1_en-US.tar
            if platform.machine() == 'x86_64':
                tarball_path = os.path.join(installdir, 'firefox-linux64.tar')
            else:
                tarball_path = os.path.join(installdir, 'firefox-linux32.tar')
            tbbtar = tarfile.open(tarball_path)
            #tarball extracts into current working dir
            os.mkdir(os.path.join(datadir, 'tmpextract'))
            os.chdir(os.path.join(datadir, 'tmpextract'))
            tbbtar.extractall()
            tbbtar.close()
            os.remove(tarball_path)
            #change working dir away from the deleted one, otherwise FF will not start
            os.chdir(datadir)
            shutil.copytree(os.path.join(datadir, 'tmpextract', 'tor-browser_en-US', 'Browser'), os.path.join(datadir, 'firefoxcopy'))
            shutil.rmtree(os.path.join(datadir, 'tmpextract'))
            
        if OS=='mswin':
            exename = 'torbrowser-install-3.5.2.1_en-US.exe'
            tbbinstaller_exe_path = os.path.join(installdir, exename)
            if not os.path.exists(tbbinstaller_exe_path):
                print ('Couldn\'t find '+exename+' Make sure it is located in the installdir')
                exit (CANT_FIND_TORBROWSER)
            os.chdir(installdir) #installer silently extract into the current working dir
            tbbinstaller_proc = subprocess.Popen([tbbinstaller_exe_path, '/S', '/D='+os.path.join(datadir, 'tmpextract')]) #silently extract into destination
            bInstallerFinished = False
            for i in range(30): #give the installer 30 secs to extract the files and exit
                if tbbinstaller_proc.poll() != None:
                    bInstallerFinished = True
                    break
                else:
                    time.sleep(1)
            if not bInstallerFinished:
                print ('Tor Browser Bundle installer was taking too long to extract the files')
                exit (TBB_INSTALLER_TOO_LONG)
            #Copy the extracted files into the data folder and delete the extracted files to keep datadir organized
            shutil.copytree(os.path.join(datadir, 'tmpextract', 'Browser'), os.path.join(datadir, 'firefoxcopy'))
            shutil.rmtree(os.path.join(datadir, 'tmpextract'))
               
        if OS=='macos':
            zipname = 'TorBrowserBundle-3.5.2.1-osx32_en-US.zip'
            if os.path.exists(os.path.join(installdir, zipname)):
                torbrowser_zip_path = os.path.join(installdir, zipname)
            else:
                print ('Couldn\'t find '+zipname+' Make sure it is located in the installdir')
                exit (CANT_FIND_TORBROWSER)
                tbbzip = zipfile.ZipFile(torbrowser_zip_path, 'r')
                tbbzip.extractall(os.path.join(datadir, 'tmpextract'))
                #files get extracted in a root dir Browser
                shutil.copytree(os.path.join(datadir, 'tmpextract', 'TorBrowserBundle_en-US.app', 'Contents', 'MacOS', 'TorBrowser.app', 'Contents', 'MacOS'), os.path.join(datadir, 'firefoxcopy'))
                shutil.rmtree(os.path.join(datadir, 'tmpextract'))

      
    thread = ThreadWithRetval(target= minihttp_thread)
    thread.daemon = True
    thread.start()
    #wait for minihttpd thread to indicate its status and FF_to_backend_port  
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
        
    ff_retval = start_firefox(FF_to_backend_port)
    if ff_retval[0] != 'success':
        print ('Error while starting Firefox: '+ ff_retval[0], end='\r\n')
        exit(FIREFOX_START_ERROR)
    #elif Firefox started successfully
    ff_proc = ff_retval[1]    
    
    while True:
        time.sleep(1)
        if ff_proc.poll() != None:
            #FF window was closed, shut down all subsystems and exit gracefully
            request = urllib2.Request("http://127.0.0.1:" +str(FF_to_backend_port)+ "/terminate")
            request.get_method = lambda : 'HEAD'            
            urllib2.urlopen(request)
            break
