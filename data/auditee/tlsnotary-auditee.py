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
os.makedirs(current_sessiondir)

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
tshark_exepath = editcap_exepath= ''
firefox_pid = selftest_pid = 0
firefox_install_path = None

cr_list = [] #a list of all client_randoms for recorded pages used by tshark to search for html only in audited tracefiles.


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
            arg_str = self.path.split('?',1)[1]
            if not arg_str.startswith('b64headers='):
                self.respond({'response':'prepare_pms', 'status':'wrong HEAD parameter'})
                return
            b64headers = arg_str[len('b64headers='):]
            sha1_and_headers = b64decode(b64headers)
            #the sha1 of the pubkey in colon separated hex is snuck in at the front of the headers
            raw_pk = sha1_and_headers[:59]
            processed_pk = binascii.unhexlify(raw_pk.replace(':',''))
            
            rv = prepare_pms(sha1_and_headers[59:], processed_pk)
            if rv[0] == 'success': html_paths = b64encode(rv[1])
            self.respond({'response':'prepare_pms', 'status':rv[0],'html_paths':html_paths})
            return             
        #----------------------------------------------------------------------#
        if self.path.startswith('/send_link'):
            filelink = self.path.split('?', 1)[1]
            rv = send_link(filelink)
            self.respond({'response':'send_link', 'status':rv})
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
        else:
            self.respond({'response':'unknown command'})
            return

def send_link(filelink):
    reply = send_and_recv('link:'+filelink)
    if not reply[0] == 'success' : return 'failure'
    if not reply[1].startswith('response:') : return 'failure'
    response = reply[1][len('response:'):]
    return response

#Because there is a 1 in 6 chance that the encrypted PMS will contain zero bytes in its
#padding, we first try the encrypted PMS with google.com and see if it gets rejected.
#return my first half of PMS which will be used in the actual audited connection to the server
def prepare_pms(headers,claimed_pub_key):
    for i in range(5): #try 5 times until reliable site check succeeds
        #first 4 bytes of client random are unix time
        pmsSession = shared.TLSNSSLClientSession(shared.config.get('SSL','reliable_site'),\
                                            int(shared.config.get('SSL','reliable_site_ssl_port')))
        if not pmsSession: raise Exception("Client session construction failed in prepare_pms")
        tlssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tlssock.settimeout(int(shared.config.get("General","tcp_socket_timeout")))
        tlssock.connect((pmsSession.serverName, pmsSession.sslPort))
        tlssock.send(pmsSession.handshakeMessages[0])
        #we must get 3 concatenated tls handshake messages in response:
        #sh --> server_hello, cert --> certificate, shd --> server_hello_done
        if not pmsSession.processServerHello(shared.recv_socket(tlssock)):
            raise Exception("Failure in processing of server Hello from " + pmsSession.serverName)
        #give auditor cr&sr and get an encrypted second half of PMS,
        #and shahmac that needs to be xored with my md5hmac to get MS
        reply = send_and_recv('gcr_gsr:'+pmsSession.clientRandom+pmsSession.serverRandom)
        if reply[0] != 'success': raise Exception ('Failed to receive a reply for gcr_gsr:')
        if not reply[1].startswith('grsapms_ghmac:'):
            raise Exception ('bad reply. Expected grsapms_ghmac:')
        grsapms_ghmac = reply[1][len('grsapms_ghmac:'):]
        rsapms2 = grsapms_ghmac[:256]
        shahmac = grsapms_ghmac[256:304]
        pmsSession.pAuditor = shahmac
        data = pmsSession.completeHandshake(rsapms2)
        tlssock.send(data)
        response = shared.recv_socket(tlssock)
        tlssock.close()
        if not response:
            print ("PMS trial failed")
            continue
        if not response.count(pmsSession.handshakeMessages[5]):
            #the response did not contain ccs == error alert received
            print ("PMS trial failed, server response was: ")
            print (binascii.hexlify(response))
            continue
        #else ccs was in the response
        html_path = audit_page(headers,pmsSession.auditeeSecret,claimed_pub_key)
        return ('success',html_path) #successfull pms check
    #no dice after 5 tries
    raise Exception ('Could not prepare PMS with ', shared.config.get('SSL','reliable_site'), ' after 5 tries')

    
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
    #trace* files in committed dir is what auditor needs
    tracedir = join(current_sessiondir, 'mytrace')
    os.makedirs(tracedir)
    zipf = zipfile.ZipFile(join(tracedir, 'mytrace.zip'), 'w')
    commit_dir = join(current_sessiondir, 'commit')
    com_dir_files = os.listdir(commit_dir)
    for onefile in com_dir_files:
        if not onefile.startswith(('response', 'md5hmac', 'domain','IV','cs')): continue
        zipf.write(join(commit_dir, onefile), onefile)
    zipf.close()
    try: link = sendspace_getlink(join(tracedir, 'mytrace.zip'))
    except:
        try: link = pipebytes_getlink(join(tracedir, 'mytrace.zip'))
        except: return 'failure'
    return send_link(link)

def parse_headers(headers):
    header_lines = headers.split('\r\n') #no new line issues; it was constructed like that
    server = header_lines[1].split(':')[1].strip()
    #gzip is disabled; TODO this can be configurable
    modified_headers = '\r\n'.join([x for x in header_lines if 'gzip' not in x])
    return (server,modified_headers)


def audit_page(headers,pms_secret,claimed_pub_key):
    tlssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tlssock.settimeout(int(shared.config.get("General","tcp_socket_timeout")))
    server_name, headers = parse_headers(headers)
    tlsnSession = shared.TLSNSSLClientSession(server_name,ccs=5,audit=True)
    tlsnSession.auditeeSecret = pms_secret
    tlssock.connect((tlsnSession.serverName, tlsnSession.sslPort))
    tlssock.send(tlsnSession.handshakeMessages[0])
    sh_cert_shd = shared.recv_socket(tlssock)
    if not tlsnSession.processServerHello(sh_cert_shd): #this will set the serverRandom
        raise Exception("Failure in processing of server Hello from " + tlsnSession.serverName)
    #TODO extract the cipher suite byte from the response
    cr_list.append(tlsnSession.clientRandom)
    tlsnSession.extractCertificate()
    tlsnSession.extractModAndExp()
    #before going further, verify that we're getting the same pubkey as
    #firefox; if so, we leverage their cert checking functions. If not, we
    #abort.
    #get SHA-1 of certificate (DER format is passed over the wire) from active connection
    our_pub_key = sha1(tlsnSession.serverCertificate).digest()
    if not our_pub_key == claimed_pub_key:
        print ("Tlsnotary session certificate hash was:",binascii.hexlify(our_pub_key))
        print ("Browser certificate hash was: ",binascii.hexlify(claimed_pub_key))
        raise Exception("WARNING! The server is presenting an invalid certificate. "+ \
                        "This is most likely an error, although it could be a hacking attempt. Audit aborted.")
    else:
        print ("Browser verifies that the server certificate is valid, continuing audit.")
    
    tlsnSession.setAuditeeSecret()
    md5hmac_1_for_MS = tlsnSession.pAuditee[:24]
    cr_sr_hmac_n_e= chr(tlsnSession.chosenCipherSuite)+tlsnSession.clientRandom+tlsnSession.serverRandom+ \
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
    tlsnSession.setMasterSecretHalf(half=2,providedPValue = rsapms_hmacms_hmacek[ml:ml+24])
    tlsnSession.pMasterSecretAuditor = rsapms_hmacms_hmacek[ml+24:ml+24+tlsnSession.cipherSuites[tlsnSession.chosenCipherSuite][-1]]
    tlsnSession.doKeyExpansion() #we don't bother to record expanded_keys here, no longer needed for NSS patch
    sha_digest,md5_digest = tlsnSession.getHandshakeHashes()
    reply = send_and_recv('verify_md5sha:'+md5_digest+sha_digest)
    if reply[0] != 'success': return ('Failed to receive a reply')
    if not reply[1].startswith('verify_hmac:'): return ('bad reply. Expected verify_hmac:')
    verify_hmac= reply[1][len('verify_hmac:'):]
    data =  tlsnSession.getCKECCSF(providedPValue=verify_hmac)
    tlssock.send(data)
    response = shared.recv_socket(tlssock)
    sha_digest2,md5_digest2 = tlsnSession.getHandshakeHashes(isForServer = True)
    reply = send_and_recv('verify_md5sha2:'+md5_digest2+sha_digest2)
    if reply[0] != 'success':return("Failed to receive a reply")
    if not reply[1].startswith('verify_hmac2:'):return("bad reply. Expected verify_hmac2:")
    verify_hmac2 = reply[1][len('verify_hmac2:'):]
    if not tlsnSession.processServerCCSFinished(response,providedPValue = verify_hmac2):
        raise Exception ("Could not finish handshake with server successfully. Audit aborted")
    headers += '\r\n'
    encrypted_request = tlsnSession.buildRequest(headers)
    tlssock.send(encrypted_request)
    response = shared.recv_socket(tlssock)
    if not response: raise Exception ("Received no response to request, cannot continue audit.")
    tlsnSession.storeServerAppDataRecords(response)
    tlssock.close()

    #store the response in the session directory
    sf = str(len(cr_list))

    #send a commitment of the response (and md5hmac?)
    commit_dir = join(current_sessiondir, 'commit')
    if not os.path.exists(commit_dir): os.makedirs(commit_dir)
    response_path = join(commit_dir, 'response'+ sf )
    with open(response_path,'wb') as f: f.write(response)
    IV_path = join(commit_dir,'IV' + sf )
    #the IV data is not actually an IV, it's the current cipher state
    if tlsnSession.chosenCipherSuite in [47,53]: IV_data = tlsnSession.serverFinished[-16:]
    else: IV_data = bytearray(tlsnSession.serverRC4State[0])+chr(tlsnSession.serverRC4State[1])+chr(tlsnSession.serverRC4State[2])
    with open(IV_path,'wb') as f: f.write(IV_data)
    cs_path = join(commit_dir,'cs' + sf )
    with open(cs_path,'wb') as f: f.write(str(tlsnSession.chosenCipherSuite))
    md5hmac_path = join(commit_dir, 'md5hmac'+ sf )
    with open(md5hmac_path, 'wb') as f: f.write(tlsnSession.pAuditee)
    domain_path = join(commit_dir,'domain' + sf)
    with open(domain_path,'wb') as f: f.write(tlsnSession.serverName)
    #send the hash of tracefile and md5hmac
    with open(response_path, 'rb') as f: data=f.read()
    commit_hash = sha256(data).digest()
    md5hmac_hash = sha256(tlsnSession.pAuditee).digest()
    reply = send_and_recv('commit_hash:'+commit_hash+md5hmac_hash)
    if reply[0] != 'success': raise Exception ('Failed to receive a reply')
    if not reply[1].startswith('sha1hmac_for_MS:'):
        raise Exception ('bad reply. Expected sha1hmac_for_MS')
    sha1hmac_for_MS = reply[1][len('sha1hmac_for_MS:'):]
    #re-populate the session with valid secrets
    tlsnSession.pAuditor = sha1hmac_for_MS
    tlsnSession.setMasterSecretHalf() #without arguments sets the whole MS
    tlsnSession.doKeyExpansion()
    #do mac verification
    #TODO currently little hack to reset the last ciphertext block to the IV
    #should not be needed when remove the above unnecessary decryption
    tlsnSession.lastServerCiphertextBlock = tlsnSession.serverFinished[-16:]
    tlsnSession.serverSeqNo = 0

    plaintext,bad_mac = tlsnSession.processServerAppDataRecords(checkFinished=True)

    if bad_mac: print ("WARNING! Plaintext is not authenticated.")
    #successful authenticated decryption. Commit the html to disk.
    #TODO strip the headers from the html?
    with open(join(commit_dir,'html-'+sf),'wb') as f: f.write(plaintext)
    with open(join(current_sessiondir,'session_dump'+sf),'wb') as f: f.write(tlsnSession.dump())
    #send back a html path to the browser (only one)
    return join(commit_dir,'html-'+sf)

def start_recording():
    return ('success')

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

    rsSession = shared.TLSNSSLClientSession(shared.config.get('SSL','reliable_site'),\
                                    int(shared.config.get('SSL','reliable_site_ssl_port')))

    tlssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tlssock.settimeout(int(shared.config.get("General","tcp_socket_timeout")))
    tlssock.connect((rsSession.serverName, rsSession.sslPort))
    tlssock.send(rsSession.handshakeMessages[0])
    rsSession.processServerHello(shared.recv_socket(tlssock))

    #TODO: fallback to alternatives if one site fails
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
        shared.tlsn_send_single_msg(' :google_pubkey:',rs_n+rs_e,auditorPubKey)
        signed_hello_message_dict = {}
        full_signed_hello = ''
        while not bIsAuditorRegistered:
            if int(time.time()) - time_attempt_began > 20: break
            #ignore decryption errors here, as above, the message may be
            #from someone else's handshake
            x = shared.tlsn_receive_single_msg('server_hello:',myPrvKey,my_nick,iDE=True)
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
    #sanity check
    if OS=='linux':
        if firefox_install_path=='/usr/lib/firefox':
            firefox_exepath='firefox'
        else:
            firefox_exepath=join(firefox_install_path,'firefox')

    elif OS=='mswin':
        if not os.path.isfile(join(firefox_install_path,'firefox.exe')):
            exit(FIREFOX_MISSING)
        firefox_exepath = join(firefox_install_path,'firefox.exe')
    
    elif OS=='macos':
        firefox_exepath='open'

    logs_dir = join(datadir, 'logs')
    if not os.path.isdir(logs_dir): os.makedirs(logs_dir)
    with open(join(logs_dir, 'firefox.stdout'), 'w') as f: pass
    with open(join(logs_dir, 'firefox.stderr'), 'w') as f: pass
    ffprof_dir = join(datadir, 'FF-profile')
    if not os.path.exists(ffprof_dir): os.makedirs(ffprof_dir)
    #show addon bar
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

    with codecs.open(join(ffprof_dir, 'localstore.rdf'), 'w') as f:
        f.write('<?xml version="1.0"?>'
                '<RDF:RDF xmlns:NC="http://home.netscape.com/NC-rdf#" xmlns:RDF="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
                '<RDF:Description RDF:about="chrome://browser/content/browser.xul">'
                '<NC:persist RDF:resource="chrome://browser/content/browser.xul#addon-bar" collapsed="false"/>'
                '</RDF:Description></RDF:RDF>')        
    bundles_dir = os.path.join(firefox_install_path, 'distribution', 'bundles')
    if not os.path.exists(bundles_dir):
        os.makedirs(bundles_dir)
    if not os.path.exists(join(bundles_dir, 'tlsnotary@tlsnotary')):    
        shutil.copytree(join(datadir, 'FF-addon', 'tlsnotary@tlsnotary'),
                            join(bundles_dir, 'tlsnotary@tlsnotary'))
    if not os.path.exists(join(bundles_dir, 'ClassicThemeRestorer@ArisT2Noia4dev.xpi_FILES')):
        shutil.copytree(join(datadir, 'FF-addon', 'ClassicThemeRestorer@ArisT2Noia4dev.xpi_FILES'),
                            join(bundles_dir, 'ClassicThemeRestorer@ArisT2Noia4dev.xpi_FILES'))


    os.putenv('FF_to_backend_port', str(FF_to_backend_port))
    os.putenv('FF_first_window', 'true')   #prevents addon confusion when websites open multiple FF windows
    #keep trailing slash to tell the patch which path delimiter to use (nix vs win)

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
    if firefox_pid != 0:
        try: os.kill(firefox_pid, signal.SIGTERM)
        except: pass #firefox not runnng
    if selftest_pid != 0:
        try: os.kill(selftest_pid, signal.SIGTERM)
        except: pass #selftest not runnng    
    exit(1)
    
def first_run_check():
    #On first run, extract rsa,pyasn1,requests and check hashes
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
    global firefox_install_path
    if len(sys.argv) > 1: firefox_install_path = sys.argv[1]
    if not firefox_install_path:
        if OS=='linux':
            firefox_install_path = '/usr/lib/firefox'
        elif OS=='mswin':
            prog64 = os.getenv('ProgramW6432')
            prog32 = os.getenv('ProgramFiles(x86)')
            progxp = os.getenv('ProgramFiles')
            print ("Env vars:",prog64,prog32,progxp)
            if os.path.exists(join(prog64,'Mozilla Firefox')):
                firefox_install_path = join(prog64,'Mozilla Firefox')
            elif os.path.exists(join(prog32,'Mozilla Firefox')):
                firefox_install_path = join(prog32,'Mozilla Firefox')
            elif os.path.exists(join(progxp,'Mozilla Firefox')):
                firefox_install_path = join(progxp,'Mozilla Firefox')
            if not firefox_install_path:
                raise Exception('Could not set firefox install path')
        elif OS=='macos':
            firefox_install_path = join("Applications","Firefox.app")
    print ("Firefox install path is: ",firefox_install_path)
    if not os.path.exists(firefox_install_path): raise Exception ("Could not find Firefox installation")
    
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
