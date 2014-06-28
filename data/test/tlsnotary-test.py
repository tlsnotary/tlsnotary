#!/usr/bin/env python
from __future__ import print_function

import BaseHTTPServer
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
import threading
import time
import urllib2
import urllib
import zipfile
 
auditor_pid = auditee_pid = 0
testFinished = False
testRetval = -1
 
testdir = os.path.dirname(os.path.realpath(__file__))
installdir = os.path.dirname(os.path.dirname(testdir))
datadir = os.path.join(installdir, 'data')
sessionsdir = os.path.join(datadir, 'auditee', 'sessions')
auditor_sessionsdir = os.path.join(datadir, 'auditor','sessions')
#for reference (this is what is in the testing add-on)
tlsnCipherSuiteNames=["security.ssl3.rsa_aes_128_sha","security.ssl3.rsa_aes_256_sha",\
"security.ssl3.rsa_rc4_128_md5","security.ssl3.rsa_rc4_128_sha"]
website_list_file=""
website_list=[]
cs_list=[]

m_platform = platform.system()
if m_platform == 'Windows':
    OS = 'mswin'
elif m_platform == 'Linux':
    OS = 'linux'
elif m_platform == 'Darwin':
    OS = 'macos'

PINL = '\r\n' if OS == 'mswin' else '\n'

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
TSHARK_NOT_FOUND = 10


def cleanup_and_exit():
    if testRetval != 0: #there was an error, leave the auditee's browser running for some post-mortem analysis
        os.kill(auditor_pid, signal.SIGTERM)
        exit(1)
    else:
        os.kill(auditor_pid, signal.SIGTERM)
        os.kill(auditee_pid, signal.SIGTERM)
        exit(0)


#logging, primitively
def log_to_file(message,bdir='.',p=False):
    msg = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())+': '+message+PINL
    with open(os.path.join(bdir,'tlsnotarytestlog'),'a') as f:
        f.write(msg)
    if p:
        print (msg)

#helper functions for accessing the session directory just written to.
def subdir_path(d):
    return filter(os.path.isdir, [os.path.join(d,f) for f in os.listdir(d)])

def latest_dir(d):
    return max(subdir_path(d), key=os.path.getmtime)

#a thread which returns a value. This is achieved by passing self as the first argument to a target function
#the target_function(parentthread, arg1, arg2) can then set, e.g parentthread.retval
class ThreadWithRetval(threading.Thread):
    def __init__(self, target, args=()):
        super(ThreadWithRetval, self).__init__(target=target, args = (self,)+args )
    retval = ''

class StoppableHttpServer (BaseHTTPServer.HTTPServer):
    """http server that reacts to self.stop flag"""
    retval = ''
    def serve_forever (self):
        """Handle one request at a time until stopped. Optionally return a value"""
        self.stop = False
        while not self.stop:
                self.handle_request()
        return self.retval;


#Receive HTTP HEAD requests from FF addon. This is how the addon communicates with python backend.
class HandlerClass(SimpleHTTPServer.SimpleHTTPRequestHandler):
    #Using HTTP/1.0 instead of HTTP/1.1 is crucial, otherwise the minihttpd just keep hanging
    #https://mail.python.org/pipermail/python-list/2013-April/645128.html
    protocol_version = "HTTP/1.0"      

    def do_HEAD(self):
        global website_list
        global cs_list
        print ('minihttp received ' + self.path + ' request',end='\r\n')
        # example HEAD string "/command?parameter=124value1&para2=123value2"
        # we need to adhere to CORS and add extra Access-Control-* headers in server replies
       
        if self.path.startswith('/type_filepath'):
            rv = type_filepath()
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "response, status")
            self.send_header("response", "type_filepath")
            self.send_header("status", rv)
            self.end_headers()
            return

        if self.path.startswith('/get_websites'):
            #'get websites' doubles as a request to start (note for now
            # multiple runs will only randomise ciphersuites, *not* change the list of websites to be
            # tested; to do that you have to restart this backend script.
            start_run()
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "response, status")
            self.send_header("response", "get_websites")
            print ('website list is:',website_list)
            self.send_header("url_list", ','.join(website_list))
            self.send_header("cs_list",','.join(cs_list))
            self.end_headers()
            return

        if self.path.startswith('/log_error'):
            arg_str = self.path.split('?', 1)[1]
            if not arg_str.startswith('errmsg='):
                print("Received erroneous request from testing frontend")
            err_msg = arg_str[len('errmsg='):]
            log_to_file("Front end sent error condition: "+urllib.unquote(err_msg),p=True)
            global testFinished
            global testRetval
            testFinished = True
            testRetval = 1            
            cleanup_and_exit()

        if self.path.startswith('/end_test'):
            perform_final_check()
            #we won't bother to respond


def type_filepath():
    retval = subprocess.check_output(['./xdotoolscript.sh'],shell=True)
    #I *think* xdotool returns nothing on success; TODO check so as to be
    #able to report something meaningful to the front end.
    if not retval:
        retval = 'success'
    return retval

def perform_final_check():

    auditor_md5s={}
    auditee_md5s={}

    #very hacky, but otherwise we have to talk to tlsnotary extension itself
    auditee_session_dir = latest_dir(sessionsdir)
    auditor_session_dir = latest_dir(auditor_sessionsdir)

    log_to_file("Reading from these directories: "+auditee_session_dir+", and "+auditor_session_dir)

    auditor_decrypted_dir = os.path.join(auditor_session_dir,'decrypted')
    auditee_decrypted_dir = os.path.join(auditee_session_dir,'commit')

    #auditor first
    while True:
        time.sleep(10) #allow to decrypt all files
        if os.path.exists(auditee_decrypted_dir): break
    for i in os.listdir(auditor_decrypted_dir):
        if os.path.isfile(os.path.join(auditor_decrypted_dir,i)) and i.startswith('html'):
            with open(os.path.join(auditor_decrypted_dir,i),'rb') as f: dh = f.read()
            auditor_md5s[i] = hashlib.md5(dh).hexdigest()

    #now auditee
    for i in os.listdir(auditee_decrypted_dir):
        if os.path.isfile(os.path.join(auditee_decrypted_dir,i)) and i.startswith('html'):
            with open(os.path.join(auditor_decrypted_dir,i),'rb') as f: dh = f.read()
            auditee_md5s[i] = hashlib.md5(dh).hexdigest()

    bCheckFailed = False
    if not auditee_md5s: 
        log_to_file("No html found in auditee session directory: "+auditee_decrypted_dir)
        bCheckFailed = True
    if not auditor_md5s: 
        log_to_file("No html found in auditor session directory: "+auditor_decrypted_dir)
        bCheckFailed = True

    if (auditee_md5s != auditor_md5s):
        log_to_file('Hash mismatch: Auditor: '+str(auditor_md5s)+', Auditee: '+str(auditee_md5s))
        log_to_file("hash mismatch, test run failed.",p=True)
        bCheckFailed = True
    else:
        log_to_file('Hashes matched: Auditor: '+str(auditor_md5s)+', Auditee: '+str(auditee_md5s))
        log_to_file('TlsNotary test run successful! See log for details.',p=True)
    log_to_file("**************END TEST RUN*************************")
    global testFinished
    global testRetval  
    testFinished = True
    if bCheckFailed: testRetval = 1
    else: testRetval = 0
    cleanup_and_exit()
    

#use miniHTTP server to receive commands from Firefox addon and respond to them
def minihttp_thread(parentthread):    
    #allow three attempts to start mini httpd in case if the port is in use
    bWasStarted = False
    for i in range(3):
        FF_to_backend_port = 27777 #random.randint(1025,65535)
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
    
def start_run():
    global website_list_file
    global website_list
    global cs_list
    website_list = []
    cs_list = []
    with open(website_list_file) as f:
        wfl=filter(None,f.read().splitlines())
        for a in wfl:
            #url and cipher suite details are split by whitespace
            url,code = a.split()
            website_list.append(url)
            #accepted ciphersuites (indexed by tlsnCipherSuiteList above)
            #are separated by commas:
            acceptable_ciphersuites = code.split(',')
            #choose one of the given numbers at random
            cs_list.append(random.choice(acceptable_ciphersuites))
    log_to_file("*********START TEST*****************")
    log_to_file("Starting new run for these websites:")
    log_to_file(','.join(website_list))
    log_to_file("and these cipher suites:")
    log_to_file(','.join(cs_list))
    log_to_file("************************************")


def start_auditor(parentthread):
    global auditor_pid
    global auditee_pid
    print ("Starting the auditor")
    #initiate an auditor window in daemon mode
    auditor_py = os.path.join(installdir, 'data', 'auditor', 'tlsnotary-auditor.py')
    auditor_proc = subprocess.Popen(['python', auditor_py,'daemon'])
    auditor_pid = auditor_proc.pid


def start_auditee(parentthread):
    global auditee_pid    
    print ("Starting the auditee")
    auditee_py = os.path.join(installdir, 'data', 'auditee', 'tlsnotary-auditee.py')
    auditee_proc = subprocess.Popen(['python', auditee_py, 'test'])
    auditee_pid = auditee_proc.pid

if __name__ == "__main__":

    global website_list_file
    website_list_file = sys.argv[1]

    #start auditor
    thread_auditor = ThreadWithRetval(target= start_auditor)
    thread_auditor.daemon = True
    thread_auditor.start()

    #start auditee
    thread_auditee = ThreadWithRetval(target= start_auditee)
    thread_auditee.daemon = True
    thread_auditee.start()

    #start backend http server
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

    while True:
        if testFinished == True:
            cleanup_and_exit()
        time.sleep(1)        
