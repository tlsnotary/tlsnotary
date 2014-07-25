#!/usr/bin/env python
from __future__ import print_function

from base64 import b64decode, b64encode
import BaseHTTPServer
import binascii
import codecs
from hashlib import md5, sha1, sha256
import hmac
import os
from os.path import join
import platform
import Queue
import random
import re
import select
import shutil
import signal
import SimpleHTTPServer
import socket
from subprocess import Popen, check_output
import sys
import tarfile
import threading
import time
import zipfile
try: import wingdbstub
except: pass
datadir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.dirname(datadir))

installdir = os.path.dirname(os.path.dirname(datadir))
sessionsdir = join(datadir, 'sessions')
time_str = time.strftime('%d-%b-%Y-%H-%M-%S', time.gmtime())
current_sessiondir = join(sessionsdir, time_str)
nss_patch_dir = join(current_sessiondir, 'nsspatchdir')
os.makedirs(nss_patch_dir)

m_platform = platform.system()
if m_platform == 'Windows': OS = 'mswin'
elif m_platform == 'Linux': OS = 'linux'
elif m_platform == 'Darwin': OS = 'macos'

recvQueue = Queue.Queue() #all messages from the auditor are placed here by receivingThread
ackQueue = Queue.Queue() #ack numbers are placed here
auditor_nick = '' #we learn auditor's nick as soon as we get a hello_server signed by the auditor
my_nick = '' #our nick is randomly generated on connection
myPrvKey = myPubKey = auditorPubKey = None
rsModulus = None
rsExponent = None
tlsnSession = None
stcppipe_proc = None
tshark_exepath = editcap_exepath= ''
firefox_pid = stcppipe_pid = selftest_pid = 0

cr_list = [] #a list of all client_randoms for recorded pages used by tshark to search for html only in audited tracefiles.
auditee_mac_check = False #tmp var
get_html_paths_retval = None #tmp  var
uidsAlreadyProcessed = [] #for nss patch thread to check for new audits. Why was this made a global var?    

def import_auditor_pubkey(auditor_pubkey_b64modulus):
    global auditorPubKey                      
    try:
        auditor_pubkey_modulus = b64decode(auditor_pubkey_b64modulus)
        auditor_pubkey_modulus_int =  shared.ba2int(auditor_pubkey_modulus)
        auditorPubKey = rsa.PublicKey(auditor_pubkey_modulus_int, 65537)
        auditor_pubkey_pem = auditorPubKey.save_pkcs1()
        with open(join(current_sessiondir, 'auditorpubkey'), 'wb') as f: f.write(auditor_pubkey_pem)
        #also save the key as recent, so that they could be reused in the next session
        if not os.path.exists(join(datadir, 'recentkeys')): os.makedirs(join(datadir, 'recentkeys'))
        with open(join(datadir, 'recentkeys' , 'auditorpubkey'), 'wb') as f: f.write(auditor_pubkey_pem)
        return ('success')
    except Exception,e:
        print (e)
        return ('failure')

def newkeys():
    global myPrvKey,myPubKey
    #Usually the auditee would reuse a keypair from the previous session
    #but for privacy reasons the auditee may want to generate a new key
    myPubKey, myPrvKey = rsa.newkeys(1024)

    my_pem_pubkey = myPubKey.save_pkcs1()
    my_pem_privkey = myPrvKey.save_pkcs1()
    with open(join(current_sessiondir, 'myprivkey'), 'wb') as f: f.write(my_pem_privkey)
    with open(join(current_sessiondir, 'mypubkey'), 'wb') as f: f.write(my_pem_pubkey)
    #also save the keys as recent, so that they could be reused in the next session
    if not os.path.exists(join(datadir, 'recentkeys')): os.makedirs(join(datadir, 'recentkeys'))
    with open(join(datadir, 'recentkeys', 'myprivkey'), 'wb') as f: f.write(my_pem_privkey)
    with open(join(datadir, 'recentkeys', 'mypubkey'), 'wb') as f: f.write(my_pem_pubkey)
    pubkey_export = b64encode(shared.bigint_to_bytearray(myPubKey.n))
    return pubkey_export

#Receive HTTP HEAD requests from FF addon
class HandlerClass(SimpleHTTPServer.SimpleHTTPRequestHandler):
    #HTTP/1.0 instead of HTTP/1.1 is crucial, otherwise the http server just keep hanging
    #https://mail.python.org/pipermail/python-list/2013-April/645128.html
    protocol_version = 'HTTP/1.0'      

    def respond(self, headers):
        # we need to adhere to CORS and add extra Access-Control-* headers in server replies                
        keys = [k for k in headers]
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Expose-Headers', ','.join(keys))
        for key in headers:
            self.send_header(key, headers[key])
        self.end_headers()        
    
    def do_HEAD(self):      
        print ('minihttp received ' + self.path + ' request',end='\r\n')
        # example HEAD string "/command?parameter=124value1&para2=123value2"    
        if self.path.startswith('/get_recent_keys'):
            #the very first command from addon 
            #on tlsnotary frst run, there will be no saved keys
            #otherwise we load up the keys saved from previous session
            my_prvkey_pem = my_pubkey_pem = auditor_pubkey_pem = ''
            if os.path.exists(join(datadir, 'recentkeys')):
                if os.path.exists(join(datadir, 'recentkeys', 'myprivkey')) and os.path.exists(join(datadir, 'recentkeys', 'mypubkey')):
                    with open(join(datadir, 'recentkeys', 'myprivkey'), 'rb') as f: my_prvkey_pem = f.read()
                    with open(join(datadir, 'recentkeys', 'mypubkey'), 'rb') as f: my_pubkey_pem = f.read()
                    with open(join(current_sessiondir, 'myprivkey'), 'wb') as f: f.write(my_prvkey_pem)
                    with open(join(current_sessiondir, 'mypubkey'), 'wb') as f: f.write(my_pubkey_pem)
                    global myPrvKey                    
                    myPrvKey = rsa.PrivateKey.load_pkcs1(my_prvkey_pem)
                if os.path.exists(join(datadir, 'recentkeys', 'auditorpubkey')):
                    with open(join(datadir, 'recentkeys', 'auditorpubkey'), 'rb') as f: auditor_pubkey_pem = f.read()
                    with open(join(current_sessiondir, 'auditorpubkey'), 'wb') as f: f.write(auditor_pubkey_pem)
                    global auditorPubKey                    
                    auditorPubKey = rsa.PublicKey.load_pkcs1(auditor_pubkey_pem)
                global myPubKey
                myPubKey = rsa.PublicKey.load_pkcs1(my_pubkey_pem)
                my_pubkey_export = b64encode(shared.bigint_to_bytearray(myPubKey.n))
                if auditor_pubkey_pem == '': auditor_pubkey_export = ''
                else: auditor_pubkey_export = b64encode(shared.bigint_to_bytearray(auditorPubKey.n))
                self.respond({'response':'get_recent_keys', 'mypubkey':my_pubkey_export,
                         'auditorpubkey':auditor_pubkey_export})
            else:
                self.respond({'response':'get_recent_keys', 'mypubkey':'', 'auditorpubkey':''})                
            return            
        #---------------------------------------------------------------------#     
        if self.path.startswith('/new_keypair'):
            pubkey_export = newkeys()
            self.respond({'response':'new_keypair', 'pubkey':pubkey_export,
                                 'status':'success'})
            return        
        #----------------------------------------------------------------------#
        if self.path.startswith('/import_auditor_pubkey'):
            arg_str = self.path.split('?', 1)[1]
            if not arg_str.startswith('pubkey='):
                self.respond({'response':'import_auditor_pubkey', 'status':'wrong HEAD parameter'})
                return
            #else
            auditor_pubkey_b64modulus = arg_str[len('pubkey='):]            
            status = import_auditor_pubkey(auditor_pubkey_b64modulus)           
            self.respond({'response':'import_auditor_pubkey', 'status':status})
            return        
        #----------------------------------------------------------------------#
        if self.path.startswith('/start_peer_connection'):
            rv = start_peer_messaging()
            rv2 = peer_handshake()
            self.respond({'response':'start_peer_connection', 'status':rv,'pms_status':rv2})
            return       
        #----------------------------------------------------------------------#
        if self.path.startswith('/start_recording'):
            rv = start_recording()
            if rv[0] != 'success':
                self.respond({'response':'start_recording', 'status':rv[0]})
                return
            else:
                self.respond({'response':'start_recording', 'status':rv[0], 'proxy_port':rv[1]})
                return        
        #----------------------------------------------------------------------#
        if self.path.startswith('/stop_recording'):
            rv = stop_recording()
            self.respond({'response':'stop_recording', 'status':rv,
                          'session_path':join(current_sessiondir, 'mytrace')})
            return      
        #----------------------------------------------------------------------#
        if self.path.startswith('/prepare_pms'):
            rv = prepare_pms()
            self.respond({'response':'prepare_pms', 'status':rv[0]})
            return             
        #----------------------------------------------------------------------#
        if self.path.startswith('/send_link'):
            filelink = self.path.split('?', 1)[1]
            rv = send_link(filelink)
            self.respond({'response':'send_link', 'status':rv})
            return      
        #----------------------------------------------------------------------#
        if self.path.startswith('/get_html_paths'):

            b64_paths = ''            
            arg_str = self.path.split('?', 1)[1]
            if not arg_str.startswith('domain='):
                self.respond({'response':'get_html_paths', 'status':'wrong HEAD parameter', 'html_paths':b64_paths})
                return
            #else
            b64domain = arg_str[len('pubkey='):]
            domain = b64decode(b64domain)
            #the html paths were calculated earlier, as soon as the
            #connection was shut down:
            rv = get_html_paths_retval

            #commit the domain into the commit directory defined by the last cr (should be only one):
            commit_dir = join(current_sessiondir, 'commit')
            if not os.path.exists(commit_dir):
                raise Exception('Commit directory missing when trying to write domain file')
            domain_path = join(commit_dir, 'domain'+ str(len(cr_list)))
            with open(domain_path, 'wb') as f: f.write(domain)

            if rv[0] == 'success': b64_paths = b64encode(rv[1])
            status = 'success' if rv[0] == 'success' else rv[1]
            self.respond({'response':'get_html_paths', 'status':status, 'html_paths':b64_paths})
            return                  
        #----------------------------------------------------------------------#
        if self.path.startswith('/selftest'):
            auditor_py = join(installdir, 'data', 'auditor', 'tlsnotary-auditor.py')
            output = check_output([sys.executable, auditor_py, 'daemon', 'genkey'])
            auditor_key = output.split()[-1]
            import_auditor_pubkey(auditor_key)
            print ('Imported auditor key')
            print (auditor_key)
            my_newkey = newkeys()
            proc = Popen([sys.executable, auditor_py, 'daemon', 'hiskey='+my_newkey])
            global selftest_pid
            selftest_pid = proc.pid
            self.respond({'response':'selftest', 'status':'success'})
            return
        #----------------------------------------------------------------------#
        if self.path.startswith('/get_advanced'):
            self.respond({'irc_server':shared.config.get('IRC','irc_server'),
            'channel_name':shared.config.get('IRC','channel_name'),'irc_port':shared.config.get('IRC','irc_port')})
            return

        #----------------------------------------------------------------------#
        if self.path.startswith('/set_advanced'):
            args = self.path.split('?')[1].split(',')
            #TODO can make this more generic when there are lots of arguments;
            if not (args[0].split('=')[0] == 'server_val' and args[1].split('=')[0] == 'channel_val' \
                and args[2].split('=')[0] == 'port_val' and args[0].split('=')[1] and \
                args[1].split('=')[1] and args[2].split('=')[1]):
                print ('Failed to reset the irc config. Server was:',args[0].split('=')[1], \
                ' and channel was: ', args[1].split('=')[1])
                return
                #to consider: front end is not listening anyway, so no point responding.
                #raise Exception("Invalid format of advanced update request")
            shared.config.set('IRC','irc_server',args[0].split('=')[1])
            shared.config.set('IRC','channel_name',args[1].split('=')[1])
            shared.config.set('IRC','irc_port',args[2].split('=')[1])
            with open(shared.config_location,'wb') as f: shared.config.write(f)
            return
        #----------------------------------------------------------------------#
        if self.path.startswith('/auditee_mac_check'):
            global auditee_mac_check
            auditee_mac_check = False
            while not auditee_mac_check: time.sleep(1) #will be set to True when mac check completes
            self.respond({'response':'auditee_mac_check', 'status':'success'})
            return
        #----------------------------------------------------------------------#        
        else:
            self.respond({'response':'unknown command'})
            return

def get_html_paths():
    #there may be an edge case when the request fails to trigger the nss patch
    #FIXME: find a more elegant way to handle such a scenario
    if not hasattr(get_html_paths, 'prev_cr'):
        get_html_paths.prev_cr = 0 #static variable. Initialized only on first function's run    
    if len(cr_list) == 0: #when the edge case is the 1st recorded page in session
        return ('failure', 'Failed to record HTML')
    cr = cr_list[-1]
    if cr == get_html_paths.prev_cr: #no new cr was added since the previous invocation
        return ('failure', 'Failed to record HTML')
    get_html_paths.prev_cr = cr
    #find tracefile containing cr and commit to its hash as well as the hash of md5hmac (for MS)
    #Construct MS and decrypt HTML files to be presented to auditee for approval
    tracelog_dir = join(current_sessiondir, 'tracelog')
    tracelog_files = os.listdir(tracelog_dir)
    bFoundCR = False
    for one_trace in tracelog_files:
        with open(join(tracelog_dir, one_trace), 'rb') as f: data=f.read()
        if not data.count(cr) == 1: continue
        #else client random found
        bFoundCR = True
        break
    if not bFoundCR: raise Exception ('Client random not found in trace files')
    #copy the tracefile to a new location, b/c stcppipe may still be appending it
    commit_dir = join(current_sessiondir, 'commit')
    if not os.path.exists(commit_dir): os.makedirs(commit_dir)
    tracecopy_path = join(commit_dir, 'trace'+ str(len(cr_list)) )
    md5hmac_path = join(commit_dir, 'md5hmac'+ str(len(cr_list)) )
    with open(md5hmac_path, 'wb') as f: f.write(tlsnSession.pAuditee)
    #copy the tracefile to a new location, b/c stcppipe may still be appending it
    shutil.copyfile(join(tracelog_dir, one_trace), tracecopy_path)
    #Remove the data from the auditee to the auditor (except handshake) from the copied
    #trace using editcap. (To address the small possibility of data leakage from request urls)
    output = check_output([tshark_exepath,'-r',tracecopy_path,'-Y',
                                    'ssl.handshake.certificate',
				    '-o','http.ssl.port:1025-65535',
				    '-T','fields',
                                   '-e','tcp.srcport'])
    if not output:
        raise Exception("No certificate found in trace.")
    #gather the trace frames which were sent from the same port as the certificate
    output = check_output([tshark_exepath,'-r',tracecopy_path,'-Y',
                                    'ssl.handshake or tcp.srcport=='+output.strip(),
				    '-o','http.ssl.port:1025-65535',
                                    '-T','fields','-e','frame.number'])
    if not output:
        raise Exception("Error parsing trace for server frames")

    #output should now contain the list of frames which were from the server
    frames_to_send = [x.strip() for x in output.split('\n')]
    #create a new version of the trace without sent data
    trimmed_trace_path = os.path.join(commit_dir,'trace_trimmed'+str(len(cr_list)))
    output = check_output([editcap_exepath,'-r',tracecopy_path,trimmed_trace_path]+frames_to_send)

    #overwrite trace to be committed , but keep a backup of the original
    backup_full_trace_path = os.path.join(current_sessiondir, 'backup_trace'+str(len(cr_list)))
    shutil.move(tracecopy_path,backup_full_trace_path)
    shutil.move(trimmed_trace_path,tracecopy_path)    
      
    #send the hash of tracefile and md5hmac
    with open(tracecopy_path, 'rb') as f: data=f.read()
    commit_hash = sha256(data).digest()
    md5hmac_hash = sha256(tlsnSession.pAuditee).digest()
    reply = send_and_recv('commit_hash:'+commit_hash+md5hmac_hash)
    if reply[0] != 'success': raise Exception ('Failed to receive a reply')
    if not reply[1].startswith('sha1hmac_for_MS:'):
        raise Exception ('bad reply. Expected sha1hmac_for_MS')
    sha1hmac_for_MS = reply[1][len('sha1hmac_for_MS:'):]

    #construct MS
    ms = shared.xor(tlsnSession.pAuditee, sha1hmac_for_MS)[:48]
    sslkeylog = join(commit_dir, 'sslkeylog' + str(len(cr_list)))
    ssldebuglog = join(commit_dir, 'ssldebuglog' + str(len(cr_list)))    
    cr_hexl = binascii.hexlify(cr)
    ms_hexl = binascii.hexlify(ms)
    skl_fd = open(sslkeylog, 'wb')
    skl_fd.write('CLIENT_RANDOM ' + cr_hexl + ' ' + ms_hexl + '\n')
    skl_fd.close()
    #use tshark to extract HTML
    try: output = check_output([tshark_exepath, '-r', tracecopy_path,
                                          '-Y', 'ssl and http.content_type contains html',
                                          '-o', 'http.ssl.port:1025-65535', 
                                          '-o', 'ssl.keylog_file:'+ sslkeylog,
                                          '-o', 'ssl.ignore_ssl_mac_failed:False',
                                          '-o', 'ssl.debug_file:' + ssldebuglog,
                                          '-x'])
    except: #maybe this is an old tshark version, change -Y to -R
        try: output = check_output([tshark_exepath, '-r', tracecopy_path,
                                              '-R', 'ssl and http.content_type contains html', 
                                               '-o', 'http.ssl.port:1025-65535', 
                                               '-o', 'ssl.keylog_file:'+ sslkeylog,
                                               '-o', 'ssl.ignore_ssl_mac_failed:False',
                                               '-o', 'ssl.debug_file:' + ssldebuglog,
                                               '-x'])
        except: raise Exception('Failed to launch tshark')
    if output == '': return ('failure', 'Failed to find HTML in escrowtrace')
    with open(ssldebuglog, 'rb') as f: debugdata = f.read()
    if debugdata.count('mac failed') > 0: raise Exception('Mac check failed in tracefile')
    #output may contain multiple frames with HTML, we examine them one-by-one
    separator = re.compile('Frame ' + re.escape('(') + '[0-9]{2,7} bytes' + re.escape(')') + ':')
    #ignore the first split element which is always an empty string
    frames = re.split(separator, output)[1:]    
    html_paths = ''
    for index,oneframe in enumerate(frames):
        html = shared.get_html_from_asciidump(oneframe)
        path = join(commit_dir, 'html-' + str(len(cr_list)) + '-' + str(index))
        with open(path, 'wb') as f: f.write(html)
        html_paths += path + '&'
    global get_html_paths_retval
    get_html_paths_retval = ('success',html_paths)
    return get_html_paths_retval 

def send_link(filelink):
    reply = send_and_recv('link:'+filelink)
    if not reply[0] == 'success' : return 'failure'
    if not reply[1].startswith('response:') : return 'failure'
    response = reply[1][len('response:'):]
    return response

#Because there is a 1 in 6 chance that the encrypted PMS will contain zero bytes in its
#padding, we first try the encrypted PMS with google.com and see if it gets rejected.
#return my first half of PMS which will be used in the actual audited connection to the server
def prepare_pms():    
    for i in range(5): #try 5 times until google check succeeds
        #first 4 bytes of client random are unix time
        googleSession = shared.TLSNSSLClientSession('google.com')
        if not googleSession: raise Exception("Client session construction failed in prepare_pms")
        tlssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tlssock.settimeout(10)
        tlssock.connect((googleSession.serverName, googleSession.sslPort))
        tlssock.send(googleSession.handshakeMessages[0])
        #we must get 3 concatenated tls handshake messages in response:
        #sh --> server_hello, cert --> certificate, shd --> server_hello_done
        time.sleep(1)
        sh_cert_shd = tlssock.recv(8192*2)  #google sends a ridiculously long cert chain of 10KB+
        if not googleSession.processServerHello(sh_cert_shd):
            raise Exception("Failure in processing of server Hello from " + googleSession.serverName)
        #give auditor cr&sr and get an encrypted second half of PMS,
        #and shahmac that needs to be xored with my md5hmac to get MS
        reply = send_and_recv('gcr_gsr:'+googleSession.clientRandom+googleSession.serverRandom)
        if reply[0] != 'success': raise Exception ('Failed to receive a reply for gcr_gsr:')
        if not reply[1].startswith('grsapms_ghmac:'):
            raise Exception ('bad reply. Expected grsapms_ghmac:')
        grsapms_ghmac = reply[1][len('grsapms_ghmac:'):]
        rsapms2 = grsapms_ghmac[:256]
        shahmac = grsapms_ghmac[256:304]
        googleSession.pAuditor = shahmac
        data = googleSession.completeHandshake(rsapms2)
        tlssock.send(data)
        time.sleep(1)
        response = tlssock.recv(8192)
        tlssock.close()
        if not response.count(googleSession.handshakeMessages[5]):
            #the response did not contain ccs == error alert received
            print ("PMS trial failed, server response was: ")
            print (binascii.hexlify(response))
            continue
        #else ccs was in the response
        global tlsnSession
        tlsnSession.auditeeSecret = googleSession.auditeeSecret
        return ('success',None) #successfull pms check
    #no dice after 5 tries
    raise Exception ('Could not prepare PMS with google after 5 tries')

    
#send a message and return the response received
def send_and_recv (data):
    if not ('success' == shared.tlsn_send_msg(data,auditorPubKey,ackQueue,auditor_nick,seq_init=None)):
        return ('failure','')
    #receive a response (these are collected into the recvQueue by the receiving thread)
    for i in range(3):
        try: onemsg = recvQueue.get(block=True, timeout=5)
        except:  continue #try to receive again
        return ('success', onemsg)
    return ('failure', '')

def sendspace_getlink(mfile):
    reply = requests.get('https://www.sendspace.com/', timeout=5)
    url_start = reply.text.find('<form method="post" action="https://') + len('<form method="post" action="')
    url_len = reply.text[url_start:].find('"')
    url = reply.text[url_start:url_start+url_len]
    
    sig_start = reply.text.find('name="signature" value="') + len('name="signature" value="')
    sig_len = reply.text[sig_start:].find('"')
    sig = reply.text[sig_start:sig_start+sig_len]
    
    progr_start = reply.text.find('name="PROGRESS_URL" value="') + len('name="PROGRESS_URL" value="')
    progr_len = reply.text[progr_start:].find('"')
    progr = reply.text[progr_start:progr_start+progr_len]
    
    r=requests.post(url, files={'upload_file[]': open(mfile, 'rb')}, data={
        'signature':sig, 'PROGRESS_URL':progr, 'js_enabled':'0', 
        'upload_files':'', 'terms':'1', 'file[]':'', 'description[]':'',
        'recpemail_fcbkinput':'recipient@email.com', 'ownemail':'', 'recpemail':''}, timeout=5)
    
    link_start = r.text.find('"share link">') + len('"share link">')
    link_len = r.text[link_start:].find('</a>')
    link = r.text[link_start:link_start+link_len]
    
    dl_req = requests.get(link)
    dl_start = dl_req.text.find('"download_button" href="') + len('"download_button" href="')
    dl_len = dl_req.text[dl_start:].find('"')
    dl_link = dl_req.text[dl_start:dl_start+dl_len]
    return dl_link


def pipebytes_post(key, mfile):
    #the server responds only when the recepient picks up the file
    requests.post('http://host03.pipebytes.com/put.py?key='+key+'&r='+
                  ('%.16f' % random.uniform(0,1)), files={'file': open(mfile, 'rb')})    


def pipebytes_getlink(mfile):
    reply1 = requests.get('http://host03.pipebytes.com/getkey.php?r='+
                          ('%.16f' % random.uniform(0,1)), timeout=5)
    key = reply1.text
    reply2 = requests.post('http://host03.pipebytes.com/setmessage.php?r='+
                           ('%.16f' % random.uniform(0,1))+'&key='+key, {'message':''}, timeout=5)
    thread = threading.Thread(target= pipebytes_post, args=(key, mfile))
    thread.daemon = True
    thread.start()
    time.sleep(1)               
    reply4 = requests.get('http://host03.pipebytes.com/status.py?key='+key+
                          '&touch=yes&r='+('%.16f' % random.uniform(0,1)), timeout=5)
    return ('http://host03.pipebytes.com/get.py?key='+key)

def stop_recording():
    os.kill(stcppipe_proc.pid, signal.SIGTERM)
    #trace* files in committed dir is what auditor needs
    tracedir = join(current_sessiondir, 'mytrace')
    os.makedirs(tracedir)
    zipf = zipfile.ZipFile(join(tracedir, 'mytrace.zip'), 'w')
    commit_dir = join(current_sessiondir, 'commit')
    com_dir_files = os.listdir(commit_dir)
    for onefile in com_dir_files:
        if not onefile.startswith(('trace', 'md5hmac', 'domain')): continue
        zipf.write(join(commit_dir, onefile), onefile)
    zipf.close()
    try: link = sendspace_getlink(join(tracedir, 'mytrace.zip'))
    except:
        try: link = pipebytes_getlink(join(tracedir, 'mytrace.zip'))
        except: return 'failure'
    return send_link(link)
       
#The NSS patch has created a new file in the nss_patch_dir
def new_audited_connection(uid): 
    with  open(join(nss_patch_dir, 'der'+uid), 'rb') as fd: der = fd.read()
    #TODO: find out why on windows \r\n newline makes its way into der encoding
    if OS=='mswin': der = der.replace('\r\n', '\n')
    with  open(join(nss_patch_dir, 'cr'+uid), 'rb') as fd: tlsnSession.clientRandom = fd.read()
    with open(join(nss_patch_dir, 'sr'+uid), 'rb') as fd: tlsnSession.serverRandom = fd.read()

    #get the cipher suite
    with open(join(nss_patch_dir, 'cipher_suite'+uid), 'rb') as fd: cs = fd.read()
    #cipher suite 2 bytes long in network byte order, we need only the first byte
    cipher_suite_first_byte = cs[:1]
    tlsnSession.chosenCipherSuite =  shared.ba2int(cipher_suite_first_byte)

    cr_list.append(tlsnSession.clientRandom)

    tlsnSession.extractModAndExp(der)
    if not tlsnSession.auditeeSecret: raise Exception("Cannot start the audited TLS session without the auditeeSecret already set.")
    tlsnSession.setAuditeeSecret() #will set the enc pms first half
    md5hmac_1_for_MS = tlsnSession.pAuditee[:24]
    cr_sr_hmac_n_e= cipher_suite_first_byte+tlsnSession.clientRandom+tlsnSession.serverRandom+ \
                md5hmac_1_for_MS+tlsnSession.serverModLength+\
                shared.bigint_to_bytearray(tlsnSession.serverModulus)+\
                shared.bigint_to_bytearray(tlsnSession.serverExponent)
    reply = send_and_recv('cr_sr_hmac_n_e:'+cr_sr_hmac_n_e)
    if reply[0] != 'success': return ('Failed to receive a reply for cr_sr_hmac_n_e:')
    if not reply[1].startswith('rsapms_hmacms_hmacek:'):
        return 'bad reply. Expected rsapms_hmacms_hmacek:'
    rsapms_hmacms_hmacek = reply[1][len('rsapms_hmacms_hmacek:'):]
    ml = shared.ba2int(tlsnSession.serverModLength)
    RSA_PMS2 = rsapms_hmacms_hmacek[:ml]
    tlsnSession.encSecondHalfPMS = shared.ba2int(RSA_PMS2)
    enc_pms = shared.bigint_to_bytearray(tlsnSession.setEncryptedPMS())
    with open(join(nss_patch_dir, 'encpms'+uid), 'wb') as f: f.write(enc_pms)
    with open(join(nss_patch_dir, 'encpms'+uid+'ready' ), 'wb') as f: f.close()

    tlsnSession.setMasterSecretHalf(half=2,providedPValue = rsapms_hmacms_hmacek[ml:ml+24])
    tlsnSession.pMasterSecretAuditor = rsapms_hmacms_hmacek[ml+24:ml+24+tlsnSession.cipherSuites[tlsnSession.chosenCipherSuite][-1]]
    expanded_keys = tlsnSession.doKeyExpansion()

    with open(join(nss_patch_dir, 'expanded_keys'+uid), 'wb') as f: f.write(expanded_keys)
    with open(join(nss_patch_dir, 'expanded_keys'+uid+'ready'), 'wb') as f: f.close()     

    #wait for nss patch to create md5 and then sha files
    while True:
        if not os.path.isfile(join(nss_patch_dir, 'sha'+uid)):
            time.sleep(0.1)
        else:
            time.sleep(0.1)
            break  

    with open(join(nss_patch_dir, 'md5'+uid), 'rb') as f: md5_digest = f.read()
    with open(join(nss_patch_dir, 'sha'+uid), 'rb') as f: sha_digest = f.read()
    
    reply = send_and_recv('verify_md5sha:'+md5_digest+sha_digest)
    if reply[0] != 'success': return ('Failed to receive a reply')
    if not reply[1].startswith('verify_hmac:'): return ('bad reply. Expected verify_hmac:')
    verify_hmac = reply[1][len('verify_hmac:'):]
    verify_data = tlsnSession.getVerifyDataForFinished(sha_verify=sha_digest,md5_verify=md5_digest,\
                                                                half=2,providedPValue=verify_hmac)

    with open(join(nss_patch_dir, 'verify_data'+uid), 'wb') as f: f.write(bytearray(verify_data))
    with open(join(nss_patch_dir, 'verify_data'+uid+'ready'), 'wb') as f: f.close()
    return 'success'
    
   
#scan the dir until a new file appears and then spawn a new processing thread
def nsspatch_dir_scan():
    uid = ''
    bNewUIDFound = False    
    while True:
        time.sleep(0.1)
        files = os.listdir(nss_patch_dir)
        for onefile in files:
            #patch creates files: der*,cr*, and sr*. Proceed when sr* was created
            if not onefile.startswith('sr'): continue
            if onefile in uidsAlreadyProcessed: continue
            uid =onefile[2:]
            uidsAlreadyProcessed.append(onefile)
            bNewUIDFound = True
            break
        if bNewUIDFound == False: continue
        #else if new uid found
        rv = new_audited_connection(uid)
        bNewUIDFound = False            
        if rv != 'success':
            print ('Error occured while processing nss patch dir:' + rv)
            break


def shutdown_sockets(sockets):
    for one_socket in sockets:
        try:
            one_socket.shutdown(socket.SHUT_RDWR)
            one_socket.close()    
        except: pass


#The only job of tcpproxy_new_connection_thread is to allow a GET request from
#the browser and prevent the HTTP response from the server from being delivered
#back into the browser. This is a just-in-case measure to prevent a potentially
#tampered-with HTTP response from injecting anything into the browser.
#We will know that the record was not tampered with by checking its MAC
def tcpproxy_new_connection_thread(socket_browser, socket_stcppipe):
    bDataFromServerSeen = False
    databuffer = ''
    last_time_data_was_seen_from_server = 0    
    while True:
        rlist, wlist, xlist = select.select((socket_browser, socket_stcppipe), (), (socket_browser, socket_stcppipe), 1)
        if len(rlist) == len(wlist) == len(xlist) == 0: #timeout
            if not bDataFromServerSeen: continue
            #TODO dont rely on a fixed timeout because on a slow Chinese connection  it may take longer than that
            #instead every 3 seconds try to decrypt html from the trace and if html is
            #available then terminate this thread
            if int(time.time()) - last_time_data_was_seen_from_server < 3: continue
            #dont send databuf anywhere, the server response is already in the trace
            print ('tcpproxy: Server responded')
            rv = get_html_paths() #here is where MAC check is done
            if not rv[0]=='success':
                raise Exception('Decryption failed in tcpproxy')
            global auditee_mac_check
            auditee_mac_check = True
            #This delay is to ensure the browser doesn't show
            #a "Connection Reset" message.
            #TODO we can to wait until the browser has performed the 'stop' action
            #rather than use a hardcoded time; however this is not an urgent change since
            #it is not a function of unreliable network latency.
            time.sleep(5)
            shutdown_sockets([socket_browser, socket_stcppipe])
            return
        if len(xlist) > 0:
            print ('Socket exceptional condition. Terminating connection')
            shutdown_sockets([socket_browser])
            return
        if len(rlist) == 0:
            print ('Python internal socket error: rlist should not be empty. Please investigate. Terminating connection')
            shutdown_sockets([socket_browser])
            return
        #else rlist contains socket with data
        for rsocket in rlist:        
            try:
                data = rsocket.recv( 1024*1024 )
                if not data:  #socket closed
                    if not databuffer:
                        #TODO: try ro reload the page one more time
                        raise Exception('Server closed the socket and sent no data')
                    #else the server sent a response and closed the socket
                    #TODO: the code below is copy-pasted from above.
                    print ('tcpproxy: Server responded')                    
                    rv = get_html_paths() #here is where MAC check is done
                    if not rv[0]=='success':
                        raise Exception('Decryption failed in tcpproxy')
                    global auditee_mac_check
                    auditee_mac_check = True
                    time.sleep(1.5)
                    shutdown_sockets([socket_browser, socket_stcppipe])
                    return
                if rsocket is socket_browser:
                    socket_stcppipe.send(data)
                    continue
                elif rsocket is socket_stcppipe:
                    last_time_data_was_seen_from_server = int(time.time())
                    if bDataFromServerSeen: #this is yet another application data packet
                        databuffer += data
                        continue
                    elif data.count('\x17\x03\x01'): #this is the first appdata packet after the handshake
                        bDataFromServerSeen = True
                        databuffer += data
                        continue
                    #else not application data but a handshake
                    socket_browser.send(data)
                    continue                    
            except Exception, e:
                print('exception in tcpproxy', e)
                shutdown_sockets([socket_browser])                
                return


def httpsproxy_new_connection_thread(socket_stcppipe_out):
    #extract destination address from the http header
    #the header has a form of: CONNECT encrypted.google.com:443 HTTP/1.1 some_other_stuff
    headers_str = socket_stcppipe_out.recv(8192)
    headers = headers_str.split()
    if len(headers) < 2:
        print ('Invalid or empty header received: ' + headers_str)
        shutdown_sockets([socket_stcppipe_out])
        return
    if headers[0] != 'CONNECT':
        print ('Expected CONNECT in header but got ' + headers[0] + '. Please investigate')
        shutdown_sockets([socket_stcppipe_out])
        return
    if headers[1].find(':') == -1:
        print ('Expected colon in the address part of the header but none found. Please investigate')
        shutdown_sockets([socket_stcppipe_out])
        return
    split_result = headers[1].split(':')
    if len(split_result) != 2:
        print ('Expected only two values after splitting the header. Please investigate')
        shutdown_sockets([socket_stcppipe_out])
        return
    host, port = split_result
    try: int_port = int(port)
    except:
        print ('Port is not a numerical value. Please investigate')
        shutdown_sockets([socket_stcppipe_out])
        return
    try: host_ip = socket.gethostbyname(host)
    except: #happens when IP lookup fails for some IP6-only hosts
        shutdown_sockets([socket_stcppipe_out])
        return
    socket_webserver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_webserver.connect((host_ip, int_port))
    print ('New connection to ' + host_ip + ' port ' + port)
    #tell browser that connection is established and it can start sending data
    socket_stcppipe_out.send('HTTP/1.1 200 Connection established\n' + 'Proxy-agent: tlsnotary https proxy\n\n')

    while True:
        rlist, wlist, xlist = select.select((socket_stcppipe_out, socket_webserver), (), (socket_stcppipe_out, socket_webserver), 60)
        if len(rlist) == len(wlist) == len(xlist) == 0: #timeout
            print ('Socket 60 second timeout. Terminating connection')
            shutdown_sockets([socket_stcppipe_out, socket_webserver])
            return
        if len(xlist) > 0:
            print ('Socket exceptional condition. Terminating connection')
            shutdown_sockets([socket_stcppipe_out, socket_webserver])
            return
        if len(rlist) == 0:
            print ('Python internal socket error: rlist should not be empty. Please investigate. Terminating connection')
            shutdown_sockets([socket_stcppipe_out, socket_webserver])
            return
        #else rlist contains socket with data
        for rsocket in rlist:
            try:
                data = rsocket.recv(1024*1024)
                if not data: #socket closed
                    shutdown_sockets([socket_stcppipe_out, socket_webserver])
                    return
                if rsocket is socket_stcppipe_out:
                    socket_webserver.send(data)
                    continue
                elif rsocket is socket_webserver:
                    socket_stcppipe_out.send(data)
                    continue
            except Exception, e:
                print ('exception in httpsproxy', e)
                shutdown_sockets([socket_stcppipe_out, socket_webserver])
                return
    
    
   
def tcpproxy_thread(parenthread, FF_proxy_port, stcppipe_in_port):
    socket_tcpproxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try: socket_tcpproxy.bind(('localhost', FF_proxy_port))
    except: #socket is in use
        parenthread.retval = 'failure'
        return
    parenthread.retval = 'success'
    print ('tcpproxy: from browser proxy port ' + str(FF_proxy_port) + ' to stcppipe_in port ' + str(stcppipe_in_port))
    socket_tcpproxy.listen(5)
    new_socket, new_address = socket_tcpproxy.accept() #blocks until a connection
    socket_stcppipe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_stcppipe.connect(('127.0.0.1', stcppipe_in_port))
    #process only one connection 
    thread = threading.Thread(target= tcpproxy_new_connection_thread, args=(new_socket, socket_stcppipe))
    thread.daemon = True
    thread.start()   
              
def httpsproxy_thread(parenthread, port):
    socket_proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try: socket_proxy.bind(('localhost', port))
    except: #socket is in use
        parenthread.retval = 'failure'
        return
    parenthread.retval = 'success'    
    print ('https proxy is serving on port ' + str(port))
    socket_proxy.listen(5)    
    new_socket, new_address = socket_proxy.accept() #block until new connection
    #process only one connection
    thread = threading.Thread(target= httpsproxy_new_connection_thread, args=(new_socket,))
    thread.daemon = True
    thread.start()
        
def start_recording():
    global stcppipe_proc
    global stcppipe_pid

    #stcppipe may still be running from the previous audit
    if stcppipe_pid != 0:
        try: os.kill(stcppipe_pid, signal.SIGTERM)
        except: pass #stcppipe not runnng

    #start the https proxy and make sure the port is not in use
    bWasStarted = False
    for i in range(3):
        HTTPS_proxy_port =  random.randint(1025,65535)
        thread = shared.ThreadWithRetval(target= httpsproxy_thread, args=(HTTPS_proxy_port, ))
        thread.daemon = True
        thread.start()
        time.sleep(1)
        if thread.retval != 'success': continue
        bWasStarted = True
        break
    if bWasStarted == False: return ('failure to start HTTPS proxy')
    
    #start stcppipe making sure the port is not in use
    bWasStarted = False
    logdir = join(current_sessiondir, 'tracelog')
    if not os.path.exists(logdir): os.makedirs(logdir)

    if not hasattr(start_recording, 'first_run_happened'):  #do this only once on first run
        if OS=='mswin': start_recording.stcppipe_exename  = 'stcppipe.exe'
        elif OS=='linux': 
            if platform.architecture()[0] == '64bit': 
                start_recording.stcppipe_exename  = 'stcppipe64_linux'
            else: start_recording.stcppipe_exename  = 'stcppipe_linux'
        elif OS=='macos': 
            if platform.architecture()[0] == '64bit':
                start_recording.stcppipe_exename  = 'stcppipe64_mac'
            else: start_recording.stcppipe_exename  = 'stcppipe_mac'
    stcppipe_exename = start_recording.stcppipe_exename
    
    for i in range(3):
        stcppipe_in_port = random.randint(1025,65535)
        stcppipe_proc = Popen([join(datadir, 'stcppipe', stcppipe_exename),'-d',
                               logdir, '-b', '127.0.0.1', str(HTTPS_proxy_port), str(stcppipe_in_port)])
        time.sleep(1)
        if stcppipe_proc.poll() != None:
            print ('Maybe the port was in use, trying again with a new port')
            continue
        else:
            bWasStarted = True
            break
    if bWasStarted == False: return ('failure to start stcppipe')
    print ('stcppipe: from tcpproxy out port ' + str(stcppipe_in_port) + ' to httpsproxy in port ' + str(HTTPS_proxy_port))
    stcppipe_pid = stcppipe_proc.pid 
    
    #start the  tcpproxy and make sure the port is not in use
    bWasStarted = False
    for i in range(3):
        FF_proxy_port = random.randint(1025,65535)         
        thread = shared.ThreadWithRetval(target= tcpproxy_thread, args=(FF_proxy_port, stcppipe_in_port))
        thread.daemon = True
        thread.start()
        time.sleep(1)
        if thread.retval != 'success': continue
        bWasStarted = True
        break
    if bWasStarted == False: return ('failure to start sleep proxy')
    
    if not hasattr(start_recording, 'first_run_happened'):
        thread = threading.Thread(target= nsspatch_dir_scan)
        thread.daemon = True
        thread.start()        
        start_recording.first_run_happened = True #static variable. Initialized only on first function's run
    
    return ('success', FF_proxy_port)

#respond to PING messages and put all the other messages onto the recvQueue
def receivingThread(my_nick, auditor_nick):
    shared.tlsn_msg_receiver(my_nick,auditor_nick,ackQueue,recvQueue,shared.message_types_from_auditor,myPrvKey)
               
def start_peer_messaging():
    global my_nick
    my_nick= 'user' + ''.join(random.choice('0123456789') for x in range(10))
    shared.tlsn_initialise_messaging(my_nick)
    #if we got here, no exceptions were thrown, which counts as success.
    return 'success'

def get_reliable_site_certificate():
    global rsModulus
    global rsExponent

    #TODO this is currently only valid for google.com
    #Intention is to make it more flexible and robust.
    rsSession = shared.TLSNSSLClientSession('google.com',443)

    tlssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tlssock.settimeout(10)
    tlssock.connect((rsSession.serverName, rsSession.sslPort))
    tlssock.send(rsSession.handshakeMessages[0])
    time.sleep(1)
    sh_cert_shd = tlssock.recv(8192*2)    #google sends a ridiculously long cert chain of 10KB+

    rsSession.processServerHello(sh_cert_shd)

    if not rsSession.extractCertificate(): print ("Failed to extract certificate")
    rsModulus, rsExponent = rsSession.extractModAndExp()
    if not rsModulus: print ("Failed to extract pubkey")

def peer_handshake():
    global my_nick
    global auditor_nick
    global auditorPubKey
    get_reliable_site_certificate()

    #hello contains the first 10 bytes of modulus of the auditor's pubkey
    #this is how the auditor knows that we are addressing him.
    modulus = shared.bigint_to_bytearray(auditorPubKey.n)[:10]
    signed_hello = rsa.sign('client_hello', myPrvKey, 'SHA-1')
    #format the 'reliable site' pubkey
    rs_n = shared.bigint_to_bytearray(rsModulus)
    rs_e = shared.bigint_to_bytearray(rsExponent)

    bIsAuditorRegistered = False
    for attempt in range(6): #try for 6*10 secs to find the auditor
        if bIsAuditorRegistered == True: break #previous iteration successfully regd the auditor
        time_attempt_began = int(time.time())
        shared.tlsn_send_single_msg(' :client_hello:',modulus+signed_hello,auditorPubKey)
        time.sleep(1)
        shared.tlsn_send_single_msg(' :google_pubkey:',rs_n+rs_e,auditorPubKey)
        signed_hello_message_dict = {}
        full_signed_hello = ''
        while not bIsAuditorRegistered:
            if int(time.time()) - time_attempt_began > 20: break
            x = shared.tlsn_receive_single_msg('server_hello:',myPrvKey,my_nick)
            if not x: continue
            returned_msg,returned_auditor_nick = x
            hdr, seq, signed_hello, ending = returned_msg
            signed_hello_message_dict[seq] = signed_hello
            if 'EOL' in ending:
                sh_message_len = seq + 1
                if range(sh_message_len) == signed_hello_message_dict.keys():
                    for i in range(sh_message_len):
                        full_signed_hello += signed_hello_message_dict[i]
                    try:
                        rsa.verify('server_hello', full_signed_hello, auditorPubKey)
                        auditor_nick = returned_auditor_nick
                        bIsAuditorRegistered = True
                        print ('Auditor successfully verified')
                    except: raise
                            #return ('Failed to verify the auditor. Are you sure you have the correct auditor\'s pubkey?')

    if not bIsAuditorRegistered:
        print ('Failed to register auditor within 60 seconds')
        return 'failure'

    thread = threading.Thread(target= receivingThread, args=(my_nick, auditor_nick))
    thread.daemon = True
    thread.start()
    return 'success'
       
def start_firefox(FF_to_backend_port):    
    if OS=='linux':
        firefox_exepath = join(datadir, 'firefoxcopy', 'firefox')
        if not os.path.exists(firefox_exepath): raise Exception('firefox missing')
    if OS=='mswin':
        firefox_exepath = join(datadir, 'firefoxcopy', 'firefox.exe')
        if not os.path.exists(firefox_exepath): raise Exception('firefox missing')
    if OS=='macos':
        firefox_exepath = join(datadir, 'firefoxcopy', 'Contents', 'MacOS', 
                                       'TorBrowser.app', 'Contents', 'MacOS', 'firefox')
        if not os.path.exists(firefox_exepath): raise Exception('firefox missing')  
    import stat
    os.chmod(firefox_exepath,stat.S_IRWXU)
    logs_dir = join(datadir, 'logs')
    if not os.path.isdir(logs_dir): os.makedirs(logs_dir)
    with open(join(logs_dir, 'firefox.stdout'), 'w') as f: pass
    with open(join(logs_dir, 'firefox.stderr'), 'w') as f: pass
    ffprof_dir = join(datadir, 'FF-profile')
    if not os.path.exists(ffprof_dir): os.makedirs(ffprof_dir)
    #show addon bar
    with codecs.open(join(ffprof_dir, 'localstore.rdf'), 'w') as f:
        f.write('<?xml version="1.0"?>'
                '<RDF:RDF xmlns:NC="http://home.netscape.com/NC-rdf#" xmlns:RDF="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
                '<RDF:Description RDF:about="chrome://browser/content/browser.xul">'
                '<NC:persist RDF:resource="chrome://browser/content/browser.xul#addon-bar" collapsed="false"/>'
                '</RDF:Description></RDF:RDF>')        
    bundles_dir = join(os.path.dirname(firefox_exepath), 'distribution', 'bundles')
    if not os.path.exists(bundles_dir):
        os.makedirs(bundles_dir)
        addons = os.listdir(join(datadir, 'FF-addon'))
        for oneaddon in addons:
            shutil.copytree(join(datadir, 'FF-addon', oneaddon), 
                            join(bundles_dir, oneaddon))
    with open(join(ffprof_dir, 'prefs.js'), 'w') as f:
        f.writelines([
        'user_pref("browser.startup.homepage", "chrome://tlsnotary/content/auditee.html");\n',
        'user_pref("browser.startup.homepage_override.mstone", "ignore");\n', #prevents welcome page
        'user_pref("browser.rights.3.shown", true);\n', 
        'user_pref("app.update.auto", false);\n',
        'user_pref("app.update.enabled", false);\n',
        'user_pref("browser.shell.checkDefaultBrowser", false);\n',
        'user_pref("browser.search.update", false);\n',
        'user_pref("browser.link.open_newwindow", 3);\n', #open new window in a new tab
        'user_pref("browser.link.open_newwindow.restriction", 0);\n', #enforce the above rule without exceptions
        'user_pref("extensions.lastAppVersion", "100.0.0");\n',
        'user_pref("extensions.checkCompatibility.4.*", false);\n',
        'user_pref("extensions.update.autoUpdate", false);\n',
        'user_pref("extensions.update.enabled", false);\n',
        'user_pref("extensions.enabledScopes", 0);\n', #prevent from looking for system addons
        'user_pref("datareporting.healthreport.service.enabled", false);\n',
        'user_pref("datareporting.healthreport.uploadEnabled", false);\n',
        'user_pref("datareporting.policy.dataSubmissionEnabled", false);\n'
		'user_pref("gfx.direct2d.disabled", true);\n'
		'user_pref("layers.acceleration.disabled", true);\n'
        'user_pref("browser.sessionstore.resume_from_crash", false);\n'
        'user_pref("network.proxy.socks_remote_dns", false);\n'
        ])        
    os.putenv('FF_to_backend_port', str(FF_to_backend_port))
    os.putenv('FF_first_window', 'true')   #prevents addon confusion when websites open multiple FF windows
    #keep trailing slash to tell the patch which path delimiter to use (nix vs win)
    os.putenv('NSS_PATCH_DIR', join(nss_patch_dir, ''))
    if ('test' in sys.argv): 
        print ('****************************TESTING MODE********************************')
        os.putenv('TLSNOTARY_TEST', 'true')
    
    print ('Starting a new instance of Firefox with tlsnotary profile',end='\r\n')
    try: ff_proc = Popen([firefox_exepath,'-no-remote', '-profile', ffprof_dir],
                                   stdout=open(join(logs_dir, 'firefox.stdout'),'w'), 
                                   stderr=open(join(logs_dir, 'firefox.stderr'), 'w'))
    except Exception,e: return ('Error starting Firefox: %s' %e,)
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
    
#HTTP server to talk with Firefox addon
def http_server(parentthread):    
    #allow three attempts in case if the port is in use
    bWasStarted = False
    for i in range(3):
        FF_to_backend_port = random.randint(1025,65535)
        print ('Starting http server to communicate with Firefox addon')
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
    #Let the invoking thread know that we started successfully
    parentthread.retval = ('success', FF_to_backend_port)
    sa = httpd.socket.getsockname()
    print ('Serving HTTP on', sa[0], 'port', sa[1], '...',end='\r\n')
    httpd.serve_forever()
    return
           
def quit(sig=0, frame=0):
    if stcppipe_pid != 0:
        try: os.kill(stcppipe_pid, signal.SIGTERM)
        except: pass #stcppipe not runnng
    if firefox_pid != 0:
        try: os.kill(firefox_pid, signal.SIGTERM)
        except: pass #firefox not runnng
    if selftest_pid != 0:
        try: os.kill(selftest_pid, signal.SIGTERM)
        except: pass #selftest not runnng    
    exit(1)
    
def first_run_check():
    #On first run, extract rsa,pyasn1,firefox and check hashes
    rsa_dir = join(datadir, 'python', 'rsa-3.1.4')
    if not os.path.exists(rsa_dir):
        print ('Extracting rsa-3.1.4.tar.gz...')
        with open(join(datadir, 'python', 'rsa-3.1.4.tar.gz'), 'rb') as f: tarfile_data = f.read()
        #for md5 hash, see https://pypi.python.org/pypi/rsa/3.1.4
        if md5(tarfile_data).hexdigest() != 'b6b1c80e1931d4eba8538fd5d4de1355':
            raise Exception ('Wrong hash')
        os.chdir(join(datadir, 'python'))
        tar = tarfile.open(join(datadir, 'python', 'rsa-3.1.4.tar.gz'), 'r:gz')
        tar.extractall()
        tar.close()
      
    pyasn1_dir = join(datadir, 'python', 'pyasn1-0.1.7')
    if not os.path.exists(pyasn1_dir):
        print ('Extracting pyasn1-0.1.7.tar.gz...')
        with open(join(datadir, 'python', 'pyasn1-0.1.7.tar.gz'), 'rb') as f: tarfile_data = f.read()
        #for md5 hash, see https://pypi.python.org/pypi/pyasn1/0.1.7
        if md5(tarfile_data).hexdigest() != '2cbd80fcd4c7b1c82180d3d76fee18c8':
            raise Exception ('Wrong hash')
        os.chdir(join(datadir, 'python'))
        tar = tarfile.open(join(datadir, 'python', 'pyasn1-0.1.7.tar.gz'), 'r:gz')
        tar.extractall()
        tar.close()
        
    requests_dir = join(datadir, 'python', 'requests-2.3.0')
    if not os.path.exists(requests_dir):
        print ('Extracting requests-2.3.0.tar.gz...')
        with open(join(datadir, 'python', 'requests-2.3.0.tar.gz'), 'rb') as f: tarfile_data = f.read()
        #for md5 hash, see https://pypi.python.org/pypi/requests/2.3.0
        if md5(tarfile_data).hexdigest() != '7449ffdc8ec9ac37bbcd286003c80f00':
            raise Exception ('Wrong hash')
        os.chdir(join(datadir, 'python'))
        tar = tarfile.open(join(datadir, 'python', 'requests-2.3.0.tar.gz'), 'r:gz')
        tar.extractall()
        tar.close()    
    
    if not os.path.exists(join(datadir, 'firefoxcopy')):
        print ('Extracting Firefox ...')
        if OS=='linux':
            #github doesn't allow to upload .tar.xz, so we add extension now
            zipname = 'firefox-linux'
            zipname += '64' if platform.machine() == 'x86_64' else '32'
            fullpath = join(installdir, zipname)
            if os.path.exists(fullpath): 
                os.rename(fullpath, fullpath + '.tar.xz')
            elif not os.path.exists(fullpath + '.tar.xz'):
                raise Exception ('Couldn\'t find either '+zipname+' or '+ 
                                 zipname+'.tar.xz in '+installdir)
            browser_zip_path = fullpath + '.tar.xz'              
            try:
                check_output(['xz', '-d', '-k', browser_zip_path]) #extract and keep the sourcefile
            except:
                raise Exception ('Could not extract ' + browser_zip_path +
                                 '.Make sure xz is installed on your system')
            #The result of the extraction will be firefox-linux*.tar
            tarball_path = join(installdir, 'firefox-linux')
            tarball_path += '64.tar' if platform.machine() == 'x86_64' else '32.tar'
            m_tarfile = tarfile.open(tarball_path)
            #tarball extracts into current working dir
            os.makedirs(join(datadir, 'tmpextract'))
            os.chdir(join(datadir, 'tmpextract'))
            m_tarfile.extractall()
            m_tarfile.close()
            os.remove(tarball_path)
            #change working dir away from the deleted one, otherwise FF will not start
            os.chdir(datadir)
            source_dir = join(datadir, 'tmpextract', 'tor-browser_en-US', 'Browser')
            shutil.copytree(source_dir, join(datadir, 'firefoxcopy'))
            shutil.rmtree(join(datadir, 'tmpextract'))
            
        if OS=='mswin':
            exename = 'firefox-windows'
            installer_exe_path = join(installdir, exename)
            if not os.path.exists(installer_exe_path):
                raise Exception ('Couldn\'t find '+exename+'  in '+installdir)
            os.chdir(installdir) #installer silently extract into the current working dir XXX: do we need this line?
            installer_proc = Popen(installer_exe_path + ' /S' + ' /D='+join(datadir, 'tmpextract')) #silently extract into destination
            bInstallerFinished = False
            for i in range(30): #give the installer 30 secs to extract the files and exit
                time.sleep(1)                
                if installer_proc.poll() == None: continue
                #else
                bInstallerFinished = True
                break
            if not bInstallerFinished:
                raise Exception ('Installer took too long to extract files')
            #Copy the extracted files and delete them to keep datadir organized
            source_dir = join(datadir, 'tmpextract', 'Browser')
            shutil.copytree(source_dir, join(datadir, 'firefoxcopy'))
            shutil.rmtree(join(datadir, 'tmpextract'))
               
        if OS=='macos':
            zipname = 'firefox-macosx'
            if os.path.exists(join(installdir, zipname)):
                browser_zip_path = join(installdir, zipname)
            else:
                raise Exception ('Couldn\'t find '+zipname+' in '+installdir)
            m_zipfile = zipfile.ZipFile(browser_zip_path, 'r')
            m_zipfile.extractall(join(datadir, 'tmpextract'))
            #files get extracted in a root dir Browser
            source_dir = join(datadir, 'tmpextract', 'TorBrowserBundle_en-US.app')
            shutil.copytree(source_dir, join(datadir, 'firefoxcopy'))
            shutil.rmtree(join(datadir, 'tmpextract'))    
    
if __name__ == "__main__":
    first_run_check()
    sys.path.append(join(datadir, 'python', 'rsa-3.1.4'))
    sys.path.append(join(datadir, 'python', 'pyasn1-0.1.7'))
    sys.path.append(join(datadir, 'python', 'slowaes'))
    sys.path.append(join(datadir, 'python', 'requests-2.3.0'))    
    import rsa
    import pyasn1
    import requests
    from pyasn1.type import univ
    from pyasn1.codec.der import encoder, decoder
    from slowaes import AESModeOfOperation        
    import shared
    shared.load_program_config()
    global tlsnSession
    tlsnSession = shared.TLSNSSLClientSession('dummy.com')
    if OS=='linux':
        if not (check_output(['which','tshark']) and check_output(['which','editcap'])):
            raise Exception("Please install tshark and editcap before running tlsnotary")
        tshark_exepath = 'tshark'
        editcap_exepath = 'editcap'
    elif OS=='mswin':
        prog64 = os.getenv('ProgramW6432')
        prog32 = os.getenv('ProgramFiles(x86)')
        progxp = os.getenv('ProgramFiles')        
        if prog64:
            tshark64 = join(prog64, 'Wireshark',  'tshark.exe' )
            editcap64 = join(prog64, 'Wireshark', 'editcap.exe' )            
            if os.path.isfile(tshark64): tshark_exepath = tshark64
            if os.path.isfile(editcap64): editcap_exepath = editcap64            
        if prog32:
            tshark32 = join(prog32, 'Wireshark',  'tshark.exe' )
            editcap32 = join(prog32, 'Wireshark', 'editcap.exe' )            
            if os.path.isfile(tshark32): tshark_exepath = tshark32
            if os.path.isfile(editcap32): editcap_exepath = editcap32
        if progxp:
            tshark32 = join(progxp, 'Wireshark',  'tshark.exe' )
            editcap32 = join(progxp, 'Wireshark', 'editcap.exe' )            
            if os.path.isfile(tshark32): tshark_exepath = tshark32
            if os.path.isfile(editcap32): editcap_exepath = editcap32        
        if tshark_exepath == '' or editcap_exepath == '': raise Exception(
            'Failed to find Wireshark components tshark/editcap in your Program Files')
    elif OS=='macos':
        tshark_osx = '/Applications/Wireshark.app/Contents/Resources/bin/tshark'
        editcap_osx = '/Applications/Wireshark.app/Contents/Resources/bin/editcap'        
        if os.path.isfile(tshark_osx): tshark_exepath = tshark_osx
        else: raise  Exception('Failed to find wireshark in your Applications folder')
        if os.path.isfile(editcap_osx): editcap_exepath = editcap_osx
        else: raise  Exception('Failed to find Wireshark component editcap in your Applications folder')

    thread = shared.ThreadWithRetval(target= http_server)
    thread.daemon = True
    thread.start()
    #wait for minihttpd thread to indicate its status and FF_to_backend_port  
    bWasStarted = False
    for i in range(10):
        time.sleep(1)        
        if thread.retval == '': continue
        #else
        if thread.retval[0] != 'success': raise Exception (
            'Failed to start minihttpd server. Please investigate')
        #else
        bWasStarted = True
        break
    if bWasStarted == False:
        raise Exception ('minihttpd failed to start in 10 secs. Please investigate')
    FF_to_backend_port = thread.retval[1]
        
    ff_retval = start_firefox(FF_to_backend_port)
    if ff_retval[0] != 'success': raise Exception (
        'Error while starting Firefox: '+ ff_retval[0])
    ff_proc = ff_retval[1]
    firefox_pid = ff_proc.pid    
    
    signal.signal(signal.SIGTERM, quit)
    try:
        while True:
            time.sleep(1)
            if ff_proc.poll() != None: quit() #FF was closed
    except KeyboardInterrupt: quit()            
