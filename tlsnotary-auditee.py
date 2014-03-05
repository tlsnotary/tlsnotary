#!/usr/bin/env python
from __future__ import print_function

import base64
import BaseHTTPServer
import codecs
import hashlib
import os
import platform
import Queue
import random
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

platform = platform.system()
if platform == 'Windows':
    OS = 'mswin'
elif platform == 'Linux':
    OS = 'linux'
elif platform == 'darwin':
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
recvQueue = Queue.Queue() #all IRC messages are placed here by receivingThread
countQueue = Queue.Queue() #ordinal number of an IRC message is placed here by count_my_messages_thread
auditor_nick = '' #we learn auditor's nick as soon as we get a hello_server signed by the auditor
my_nick = '' #our nick is randomly generated on connection to IRC
channel_name = '#tlsnotary'
myPrivateKey = auditorPublicKey = None

current_sessiondir = ''
nss_patch_dir = ''

stcppipe_proc = None
bReceivingThreadStopFlagIsSet = False



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
        
        print ('minihttp received ' + self.path + ' request',end='\r\n')
        # example HEAD string "/command?parameter=124value1&para2=123value2"    
        # we need to adhere to CORS and add extra Access-Control-* headers in server replies
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
             
             
        if self.path.startswith('/new_keypair'):
            #generate a new keypair for me. Usually we can simple reuse the keys from the previous audit,
            #but for privacy reason the auditee may generate a new key
            pubkey, privkey = rsa.newkeys(1024)
            myPrivateKey = privkey
            my_pem_pubkey = pubkey.save_pkcs1()
            my_pem_privkey = privkey.save_pkcs1()
            #------------------------------------------
            with open(os.path.join(current_sessiondir, 'myprivkey'), 'wb') as f: f.write(my_pem_privkey)
            with open(os.path.join(current_sessiondir, 'mypubkey'), 'wb') as f: f.write(my_pem_pubkey)
            #also save the keys as recent, so that they could be reused in the next session
            if not os.path.exists(os.path.join(datadir, 'recentkeys')): os.makedirs(os.path.join(datadir, 'recentkeys'))
            with open(os.path.join(datadir, 'recentkeys' , 'myprivkey'), 'wb') as f: f.write(my_pem_privkey)
            with open(os.path.join(datadir, 'recentkeys', 'mypubkey'), 'wb') as f: f.write(my_pem_pubkey)
            #---------------------------------------------
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "response, pubkey")
            self.send_header("response", "new_keypair")
            my_pubkey_pem_stub = my_pem_pubkey[40:-38].replace('\n', '_')
            self.send_header("pubkey", my_pubkey_pem_stub)
            self.send_header("status", "success")
            self.end_headers()
            return

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
            #-----------------------------------------
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "response, status")
            self.send_header("response", "import_auditor_pubkey")
            self.send_header("status", status)
            self.end_headers()
            return
        
        if self.path.startswith('/start_irc'):
            rv = start_irc()
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "response, status")
            self.send_header("response", "start_irc")
            self.send_header("status", rv)
            self.end_headers()
            return
        
        if self.path.startswith('/start_recording'):
            rv = start_recording()
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

#the calling function is responsible for IRC-formatting the message to be sent
#send a message and return the response received
def send_and_recv (msg_type, data, waitfactor=1):
    if not hasattr(send_and_recv, "seq"):
        send_and_recv.seq = 0 #static variable. Initialized only on first function's run
    send_and_recv.seq += 1
    bIsHelloMessage = False
    if msg_type == 'client_hello':
        bIsHelloMessage = True
        destination = 'broadcast'
    else:
        destination = auditor_nick
    send_message('PRIVMSG ' + channel_name + ' :' + destination + ' seq:' + str(send_and_recv.seq) + ' ' + msg_type + ':' + data + '\r\n', str(send_and_recv.seq))
    reply = recv(send_and_recv.seq, bIsHelloMessage, waitfactor=waitfactor)
    if reply[0] != 'success':
        return ('failure', )
    msg = reply[1]
    #all sanity checks on the received message were performed in recv()
    return ('success', msg)


#take out messages from the queue which were placed there by the receiving thread
def recv(seq, bIsHelloMessage=False, waitfactor=1):
    time_started = int(time.time())
    while True:
        if int(time.time()) - time_started > 5*waitfactor:
            #our seq was not ack'ed in 5 seconds
            return ('failure', )
        #in recvQueue messages are already split up by /r/n
        try: onemsg = recvQueue.get(block=True, timeout=1)
        except: continue #timeout triggered
        msg = onemsg.split()
        if not len(msg) == 6: continue
        if not msg[4].startswith('ack:'): continue
        if not str(seq) == msg[4][len('ack:'):]: continue
        #else sanity-check the message
        if not (msg[1]=='PRIVMSG' and msg[2]==channel_name and msg[3]==':'+my_nick):
            print ('Malformed message')
            continue
        if not bIsHelloMessage:
            #we only accept messages from the auditor's nick
            #msg[0] looks like (without quotes) ":supernick!some_other_info"
            exclamaitionMarkPosition = msg[0].find('!')
            auditor_nick_from_message = msg[0][1:exclamaitionMarkPosition]
            if auditor_nick != auditor_nick_from_message:
                print ('Some stranger impersonated the auditor. Ignoring')
                continue
        if bIsHelloMessage: #for hello message we also return the auditor nick:
            exclamaitionMarkPosition = msg[0].find('!')
            auditor_nick_from_message = msg[0][1:exclamaitionMarkPosition]
            return ('success', (msg[5], auditor_nick_from_message))
        else:
            return ('success', msg[5])



def stop_recording():
    global bReceivingThreadStopFlagIsSet
    
    #tell NSS to resume normal operation mode
    os.remove(os.path.join(nss_patch_dir, 'nss_patch_is_active'))
    #stop stcppipe
    os.kill(stcppipe_proc.pid, signal.SIGTERM)
    #TODO stop https proxy. 
    
    #zip up all trace files, sign the zip and give the sig to the auditor
    zipf = zipfile.ZipFile(os.path.join(current_sessiondir, 'mytrace.zip'), 'w')
    for root, dirs, files in os.walk(os.path.join(current_sessiondir, 'tracelog')):
        for onefile in files:
            zipf.write(os.path.join(root, onefile), onefile)
    zipf.close()
    with open(os.path.join(current_sessiondir, 'mytrace.zip'), 'rb') as f: zipdata = f.read()
    zip_hash = hashlib.sha256(zipdata).hexdigest()

    signed_zip_hash = rsa.sign(zip_hash, myPrivateKey, 'SHA-1')
    b64_signed_zip_hash = base64.b64encode(zip_hash + signed_zip_hash)
    with open(os.path.join(current_sessiondir, 'my_signed_hash.txt'), 'wb') as f: f.write(zip_hash + '\n' + b64_signed_zip_hash)    
 
    reply = send_and_recv('zipsig', b64_signed_zip_hash, waitfactor=4)
    if reply[0] != 'success':
        print ('Failed to receive a reply')
        return ('Failed to receive a reply')
    if not reply[1].startswith('logsig:'):
        print ('bad reply')
        return ('bad reply')
    
    #stop IRC receiving thread
    bReceivingThreadStopFlagIsSet = True
    
    b64_logsig  = reply[1][len('logsig:'):]
    try:
        logsig = base64.b64decode(b64_logsig)
        shahash = logsig[:64]
        sig = logsig[64:]
        #sanity check. is the signature correct?
        rsa.verify(shahash, sig, auditorPublicKey)
    except:
        print ('Verification of the auditor\'s hash failed')
        return 'Verification of the auditor\'s hash failed'
    with open(os.path.join(current_sessiondir, 'auditor_signed_hash.txt'), 'wb') as f: f.write(shahash + '\n' + sig)
    return 'success'
    
#The NSS patch has created a new file in the nss_patch_dir
def process_new_uid(uid):  
    with  open(os.path.join(nss_patch_dir, 'der'+uid), 'rb') as fd: der = fd.read()
    #TODO: find out why on windows \r\n newline makes its way into der encoding
    if OS=='mswin': der = der.replace('\r\n', '\n')
    with  open(os.path.join(nss_patch_dir, 'cr'+uid), 'rb') as fd: cr = fd.read()
    with open(os.path.join(nss_patch_dir, 'sr'+uid), 'rb') as fd: sr = fd.read()  
    b64_der = base64.b64encode(der)  
    b64_crsr = base64.b64encode(cr+sr)
    
    reply = send_and_recv('der', b64_der)
    if reply[0] != 'success':
        print ('Failed to receive a reply')
        return ('Failed to receive a reply')
    if not reply[1].startswith('encpms:'):
        print ('bad reply')
        return 'bad reply'
    b64_encpms = reply[1][len('encpms:'):]
    try:
        enc_pms = base64.b64decode(b64_encpms)    
    except:
        print ('base64 decode error')
        return ('base64 decode error')
    with open(os.path.join(nss_patch_dir, 'encpms'+uid), 'wb') as f: f.write(enc_pms)
    with open(os.path.join(nss_patch_dir, 'encpms'+uid+'ready' ), 'wb') as f: f.close()

       
    reply = send_and_recv('crsr', b64_crsr)
    if reply[0] != 'success':
        print ('Failed to receive a reply')
        return ('Failed to receive a reply')
    if not reply[1].startswith('ek:'):
        print ('bad reply')
        return  'bad reply' 
    b64_expanded_keys = reply[1][len('ek:'):]
    try:
        expanded_keys = base64.b64decode(b64_expanded_keys)
    except:
        print ('base64 decode error')
        return ('base64 decode error')
    with open(os.path.join(nss_patch_dir, 'expanded_keys'+uid), 'wb') as f: f.write(expanded_keys)
    with open(os.path.join(nss_patch_dir, 'expanded_keys'+uid+'ready'), 'wb') as f: f.close()
    
    #wait for nss to create the files
    while True:
        if not os.path.isfile(os.path.join(nss_patch_dir, 'md5'+uid)) or not os.path.isfile(os.path.join(nss_patch_dir, 'sha'+uid)):
            time.sleep(0.1)
        else:
            time.sleep(0.1)
            break
    
    md5_digest = open(os.path.join(nss_patch_dir, 'md5'+uid), 'rb').read()
    sha_digest = open(os.path.join(nss_patch_dir, 'sha'+uid), 'rb').read()
    b64_md5sha = base64.b64encode(md5_digest+sha_digest)
    reply = send_and_recv('md5sha', b64_md5sha)
    if reply[0] != 'success':
        print ('Failed to receive a reply')
        return ('Failed to receive a reply')
    if not reply[1].startswith('verify_data:'):
        print ('bad reply')
        return 'bad reply'
    b64_verify_data = reply[1][len('verify_data:'):]
    try:
        verify_data = base64.b64decode(b64_verify_data)    
    except:
        print ('base64 decode error')
        return ('base64 decode error')
    with open(os.path.join(nss_patch_dir, 'verify_data'+uid), 'wb') as f: f.write(verify_data)
    with open(os.path.join(nss_patch_dir, 'verify_data'+uid+'ready'), 'wb') as f: f.close()
    return 'success'
     
#scan the dir until a new file appears and then spawn a new processing thread
def nss_patch_dir_scan_thread():
    uidsAlreadyProcessed = []
    uid = ''
    #the other thread must delete the nss_patch_is_active file to signal that auditing session is over
    while os.path.isfile(os.path.join(nss_patch_dir, 'nss_patch_is_active')):
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
    #extract destnation address from the http header
    #the header has a form of: CONNECT encrypted.google.com:443 HTTP/1.1 some_other_stuff
    headers_str = socket_client.recv(8192)
    headers = headers_str.split()
    if len(headers) < 2:
        print ('Invalid or empty header received. Please investigate')
        return
    if headers[0] != 'CONNECT':
        print ('Expected CONNECT in header but got ' + headers[0] + '. Please investigate')
        return
    if headers[1].find(':') == -1:
        print ('Expected colon in the address part of the header but none found. Please investigate')
        return
    split_result = headers[1].split(':')
    if len(split_result) != 2:
        print ('Expected only two values after splitting the header. Please investigate')
        return
    host, port = split_result
    try:
        int_port = int(port)
    except:
        print ('Port is not a numerical value. Please investigate')
        return
    host_ip = socket.gethostbyname(host)
    socket_target = socket.socket(socket.AF_INET)
    socket_target.connect((host_ip, int_port))
    print ('New connection to ' + host_ip + ' port ' + port)
    #tell Firefox that connection established and it can start sending data
    socket_client.send('HTTP/1.1 200 Connection established\n' + 'Proxy-agent: tlsnotary https proxy\n\n')
    
    while True:
        rlist, wlist, xlist = select.select((socket_client, socket_target), (), (socket_client, socket_target), 120)
        if len(rlist) == len(wlist) == len(xlist) == 0: #120 second timeout
            print ('Socket 120 second timeout. Terminating connection')
            return
        if len(xlist) > 0:
            print ('Socket exceptional condition. Terminating connection')
            return
        if len(rlist) == 0:
            print ('Python internal socket error: rlist should not be empty. Please investigate. Terminating connection')
            return
        #else rlist contains socket with data
        for rsocket in rlist:
            try:
                data = rsocket.recv(8192)
            except Exception, e:
                print (e)
                return
            if not data: 
                #this worries me. Why did select() trigger if there was no data?
                #this overwhelms CPU big time unless we sleep
                time.sleep(0.1)
                continue 
            if rsocket is socket_client:
                socket_target.send(data)
                continue
            elif rsocket is socket_target:
                socket_client.send(data)
                continue
        
        
def https_proxy_thread(parenthread, port):
    socket_proxy = socket.socket(socket.AF_INET)
    try:
        socket_proxy.bind(('localhost', port))
        parenthread.retval = 'success'
    except: #socket is in use
        parenthread.retval = 'failure'
        return
    print ('HTTPS proxy is serving on port ' + str(port))
    socket_proxy.listen(0) #process new connections immediately
    while True:
        #block until a new connection appears
        new_socket, new_address = socket_proxy.accept()
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
def receivingThread():
    while not bReceivingThreadStopFlagIsSet:
        buffer = ''
        try: buffer = IRCsocket.recv(1024)
        except: continue #1 sec timeout
        if not buffer: continue
        print (buffer)
        #sometimes the IRC server may pack multiple PRIVMSGs into one message separated with /r/n/
        messages = buffer.split('\r\n')
        for onemsg in messages:
            msg = onemsg.split()
            if len(msg)==0 :
                #stray newline
                continue
            if msg[0] == "PING": #check if server have sent ping command
                IRCsocket.send("PONG %s" % msg[1]) #answer with pong as per RFC 1459
                continue
            else:
                recvQueue.put(onemsg)


#Freenode was observed to drop messages, that's why we
#listen for auditee's messages and count them. Used to prevent the loss of messages.
def count_my_messages_thread(nick, IRCsocket):
    while True:
        buffer = ''
        try: buffer = IRCsocket.recv(1024)
        except: continue #1 sec timeout
        if not buffer: continue
        #sometimes the IRC server may pack multiple PRIVMSGs into one message separated with \r\n
        messages = buffer.split('\r\n')
        for onemsg in messages:
            msg = onemsg.split()
            if len(msg)==0 : continue  #stray newline
            if msg[0] == "PING": #check if server have sent ping command
                IRCsocket.send("PONG %s" % msg[1]) #answer with pong as per RFC 1459
                continue
            else:
                if not len(msg) == 6: continue
                #check if the message was sent by me (the auditee)
                exclamaitionMarkPosition = msg[0].find('!')
                auditee_nick_from_message = msg[0][1:exclamaitionMarkPosition]
                if not nick == auditee_nick_from_message: continue
                #extract the seq No and put it on the Queue
                if not msg[4].startswith('seq:'): continue
                seqno = msg[4][len('seq:'):]
                countQueue.put(seqno)
                print('SHADOW THREAD PUT ' + seqno + ' on the queue')


def send_message(msg, seq):
    #try 3 times * 10 seconds to send a message and have my shadow user pick it up and put it on the countQueue
    for i in range (3):
        bytessent = IRCsocket.send(msg)
        print('SENT: ' + str(bytessent) + ' ' + msg)
        try:
            seq_check = countQueue.get(block=True, timeout=10)
            if seq == seq_check:
                return
        except: #nothing showed up on the queue
            continue


def start_irc():
    global my_nick
    global auditor_nick
    global IRCsocket
    
    my_nick= 'user' + ''.join(random.choice('0123456789') for x in range(10))
    
    #-------------------------------------------------
    #connect a shadow user which does nothing but counts our messages on the channel
    #this is needed because I observed that even though I dispatch messages to Freenode,
    #sometimes (very rarely, though) they fail to appear on the channel
    shadow_nick= 'user' + ''.join(random.choice('0123456789') for x in range(10))    
    shadow_IRCsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    shadow_IRCsocket.settimeout(10)
    shadow_IRCsocket.connect(('chat.freenode.net', 6667))
    shadow_IRCsocket.send("USER %s %s %s %s" % ('op', 'ti', 'on', 'al') + '\r\n')
    shadow_IRCsocket.send("NICK " + shadow_nick + '\r\n')  
    shadow_IRCsocket.send("JOIN %s" % channel_name + '\r\n')
    
    thread = threading.Thread(target= count_my_messages_thread, args=(my_nick, shadow_IRCsocket))
    thread.daemon = True
    thread.start()    
    #-------------------------------------------------
    #connect the actual real user who will talk to the auditor
    IRCsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    IRCsocket.settimeout(10)
    IRCsocket.connect(('chat.freenode.net', 6667))
    thread = threading.Thread(target= receivingThread)
    thread.daemon = True
    thread.start()
    IRCsocket.send("USER %s %s %s %s" % ('these', 'arguments', 'are', 'optional') + '\r\n')
    IRCsocket.send("NICK " + my_nick + '\r\n')  
    IRCsocket.send("JOIN %s" % channel_name + '\r\n')
    modulus_hash = hashlib.sha256(str(auditorPublicKey.n)).hexdigest()
    signed_hello = rsa.sign('client_hello', myPrivateKey, 'SHA-1')
    b64_hello = base64.b64encode(modulus_hash+signed_hello)
    #hello contains the hash of the auditor's pubkey's n value (modulus)
    #this is how the auditor knows on IRC that we are addressing him. Thus we allow multiple audit sessions simultaneously    
    reply = send_and_recv('client_hello', b64_hello)
    if not reply[0] == 'success':
        print (reply[0])
        return reply[0]
    if not reply[1][0].startswith('server_hello:'):
        print ('unexpected reply')
        return 'unexpected reply'
    b64_signed_hello = reply[1][0][len('server_hello'):]
    try:
        signed_hello = base64.b64decode(b64_signed_hello)
        rsa.verify('server_hello', signed_hello, auditorPublicKey)
    except:
        print ('hello verification failed. Are you sure you have the correct auditor\'s pubkey?')
        return 'hello verification failed. Are you sure you have the correct auditor\'s pubkey?'
    auditor_nick = reply[1][1] #recv() recognizes a hello message  and returns the auditor nick
    print ('Auditor successfully verified')
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
    
    
    #On first run, make sure that torbrowser installfile is in the same directory and extract it
    if not os.path.exists(os.path.join(datadir, 'firefoxcopy')):
        print ('Extracting Tor Browser Bundle ...')
        if OS=='linux':
            zipname = 'tor-browser-linux32-3.5.2.1_en-US.tar.xz'
            if os.path.exists(os.path.join(installdir, zipname)):
                torbrowser_zip_path = os.path.join(installdir, zipname)
            else:
                print ('Couldn\'t find '+zipname+' Make sure it is located in the installdir')
                exit (CANT_FIND_TORBROWSER)
            try:
                subprocess.check_output(['xz', '-d', '-k', torbrowser_zip_path]) #extract and keep the sourcefile
            except:
                print ('Could not extract ' + torbrowser_zip_path + '.Make sure xz is installed on your system')
                exit (CANT_FIND_XZ)
            #by default the result of the extraction will be tor-browser-linux32-3.5.2.1_en-US.tar
            tarball_path = os.path.join(installdir, 'tor-browser-linux32-3.5.2.1_en-US.tar')
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
