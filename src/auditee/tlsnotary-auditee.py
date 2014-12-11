#!/usr/bin/env python
from __future__ import print_function

#Main auditee script.
#This script acts as 
#1. An installer, setting up keys, browser and browser extensions.
#2. A marshaller, passing messages between (a) the javascript/html
#   front end, (b) the Python back-end, including crypto functions
#   and (c) the peer messaging between auditor and auditee.
#3. Performs actual crypto audit functions.

from base64 import b64decode, b64encode
from hashlib import md5, sha1, sha256
from os.path import join
from subprocess import Popen, check_output
import binascii, hmac, os, platform,  tarfile
import Queue, random, re, shutil, signal, sys, time
import SimpleHTTPServer, socket, threading, zipfile
try: import wingdbstub
except: pass

#file system setup.
data_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.dirname(data_dir))
install_dir = os.path.dirname(os.path.dirname(data_dir))
sessions_dir = join(data_dir, 'sessions')
time_str = time.strftime('%d-%b-%Y-%H-%M-%S', time.gmtime())
current_session_dir = join(sessions_dir, time_str)
os.makedirs(current_session_dir)

#OS detection
m_platform = platform.system()
if m_platform == 'Windows': OS = 'mswin'
elif m_platform == 'Linux': OS = 'linux'
elif m_platform == 'Darwin': OS = 'macos'

#Globals
recv_queue = Queue.Queue() #all messages from the auditor are placed here by receiving_thread
ack_queue = Queue.Queue() #ack numbers are placed here
cert_queue = Queue.Queue() #used to pass the cert from the browser
certs_and_enc_pms = {} # contains 'certificate bytes' and corresponding encrypted PMS prepared in advance
b_peer_connected = False #toggled to True when p2p connection is establishe
b_comm_channel_busy = False #used as a semaphore between threads to sends messages in an orderly way
auditor_nick = '' #we learn auditor's nick as soon as we get a ao_hello signed by the auditor
my_nick = '' #our nick is randomly generated on connection
my_prv_key = my_pub_key = auditor_pub_key = None
rs_modulus = None
rs_exponent = None
rs_choice = None
firefox_pid = selftest_pid = 0
audit_no = 0 #we may be auditing multiple URLs. This var keeps track of how many
#successful audits there were so far and is used to index html files audited.
paillier_private_key = None #Auditee's private key. Used for paillier_scheme.
#Generated only once and is reused until the end of the auditing session
b_paillier_privkey_being_generated = True #toggled to False when finished generating the Paillier privkey

#TESTING only vars
testing = False #toggled when we are running a test suite (developer only)
aes_ciphertext_queue = Queue.Queue() #testing only: receive one ciphertext 
aes_cleartext_queue = Queue.Queue() #testing only: and put one cleartext
b_awaiting_cleartext = False #testing only: used for sanity check on HandlerClass_aes
test_driver_pid = 0 #testing only: testdriver's PID used to kill it at quit_clean()
test_auditor_pid = 0 #testing only: auditor's PID used to kill it at quit_clean()

#RSA key management for peer messaging
def import_auditor_pubkey(auditor_pubkey_b64modulus):
    global auditor_pub_key                      
    try:
        auditor_pubkey_modulus = b64decode(auditor_pubkey_b64modulus)
        auditor_pubkey_modulus_int =  shared.ba2int(auditor_pubkey_modulus)
        auditor_pub_key = rsa.PublicKey(auditor_pubkey_modulus_int, 65537)
        auditor_pubkey_pem = auditor_pub_key.save_pkcs1()
        with open(join(current_session_dir, 'auditorpubkey'), 'wb') as f: f.write(auditor_pubkey_pem)
        #also save the key as recent, so that they could be reused in the next session
        if not os.path.exists(join(data_dir, 'recentkeys')): os.makedirs(join(data_dir, 'recentkeys'))
        with open(join(data_dir, 'recentkeys' , 'auditorpubkey'), 'wb') as f: f.write(auditor_pubkey_pem)
        return ('success')
    except Exception,e:
        print (e)
        return ('failure')

def newkeys():
    global my_prv_key,my_pub_key
    #Usually the auditee would reuse a keypair from the previous session
    #but for privacy reasons the auditee may want to generate a new key
    my_pub_key, my_prv_key = rsa.newkeys(1024)

    my_pem_pubkey = my_pub_key.save_pkcs1()
    my_pem_privkey = my_prv_key.save_pkcs1()
    with open(join(current_session_dir, 'myprivkey'), 'wb') as f: f.write(my_pem_privkey)
    with open(join(current_session_dir, 'mypubkey'), 'wb') as f: f.write(my_pem_pubkey)
    #also save the keys as recent, so that they could be reused in the next session
    if not os.path.exists(join(data_dir, 'recentkeys')): os.makedirs(join(data_dir, 'recentkeys'))
    with open(join(data_dir, 'recentkeys', 'myprivkey'), 'wb') as f: f.write(my_pem_privkey)
    with open(join(data_dir, 'recentkeys', 'mypubkey'), 'wb') as f: f.write(my_pem_pubkey)
    pubkey_export = b64encode(shared.bi2ba(my_pub_key.n))
    return pubkey_export


#Receive AES cleartext and send ciphertext to browser
class HandlerClass_aes(SimpleHTTPServer.SimpleHTTPRequestHandler):
    #Using HTTP/1.0 instead of HTTP/1.1 is crucial, otherwise the minihttpd just keep hanging
    #https://mail.python.org/pipermail/python-list/2013-April/645128.html
    protocol_version = "HTTP/1.0"      
    
    def do_HEAD(self):
        print ('aes_http received ' + self.path[:80] + ' request',end='\r\n')
        # example HEAD string "/command?parameter=124value1&para2=123value2"
        # we need to adhere to CORS and add extra Access-Control-* headers in server replies

        if self.path.startswith('/ready_to_decrypt'):
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "response, ciphertext, key, iv")
            self.send_header("response", "ready_to_decrypt")
            #wait for sth to appear in the queue
            ciphertext, key, iv = aes_ciphertext_queue.get()
            self.send_header("ciphertext", b64encode(ciphertext))
            self.send_header("key", b64encode(key))
            self.send_header("iv", b64encode(iv))
            global b_awaiting_cleartext
            b_awaiting_cleartext = True            
            self.end_headers()
            return
        
        if self.path.startswith('/cleartext='):
            if not b_awaiting_cleartext:
                print ('OUT OF ORDER:' + self.path)
                raise Exception ('received a cleartext request out of order')
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "response")
            self.send_header("response", "cleartext")
            cleartext = b64decode(self.path[len('/cleartext='):])
            aes_cleartext_queue.put(cleartext)
            b_awaiting_cleartext = False            
            self.end_headers()
            return
        
    #overriding BaseHTTPServer.py's method to cap the output
    def log_message(self, fmt, *args):
        sys.stderr.write("%s - - [%s] %s\n" %
                                  (self.client_address[0],
                                   self.log_date_time_string(),
                                   (fmt%args)[:80]))        


#Receive HTTP HEAD requests from FF addon
class HandleBrowserRequestsClass(SimpleHTTPServer.SimpleHTTPRequestHandler):
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
    
    def new_keypair(self):
        pubkey_export = newkeys()
        self.respond({'response':'new_keypair', 'pubkey':pubkey_export,
                             'status':'success'})     
        
    def import_auditor_pubkey(self, args):
        if not args.startswith('pubkey='):
            self.respond({'response':'import_auditor_pubkey', 'status':'wrong HEAD parameter'})
            return
        #else
        auditor_pubkey_b64modulus = args[len('pubkey='):]            
        status = import_auditor_pubkey(auditor_pubkey_b64modulus)           
        self.respond({'response':'import_auditor_pubkey', 'status':status})
        return
    
    def start_peer_connection(self):
        if int(shared.config.get("General","use_paillier_scheme")):
            paillier_gen_privkey()
        rv = start_peer_messaging()
        rv2 = peer_handshake()
        global b_peer_connected
        b_peer_connected = True            
        self.respond({'response':'start_peer_connection', 'status':rv,'pms_status':rv2})
        return
    
    def stop_recording(self):
        rv = stop_recording()
        self.respond({'response':'stop_recording', 'status':rv,
                      'session_path':join(current_session_dir, 'mytrace')})
        return
    
    def start_audit(self, args):
        #set TLS version according to user preference
        if int(shared.config.get("General","tls_11")):
            shared.set_tlsver('\x03\x02')        
        arg1, arg2, arg3 = args.split('&')
        if not arg1.startswith('b64dercert=') or not arg2.startswith('b64headers=') or not arg3.startswith('ciphersuite='):
            self.respond({'response':'start_audit', 'status':'wrong HEAD parameter'})
            return
        b64dercert = arg1[len('b64dercert='):]            
        b64headers = arg2[len('b64headers='):]
        cs = arg3[len('ciphersuite='):] #used for testing, empty otherwise        
        dercert = b64decode(b64dercert)
        headers = b64decode(b64headers)
        
        server_name, modified_headers = parse_headers(headers)
        use_paillier_scheme = False
        if int(shared.config.get("General","use_paillier_scheme")):
            use_paillier_scheme = True                
        if not use_paillier_scheme:
            if testing: 
                tlsn_session = shared.TLSNClientSession(server_name, ccs=int(cs))
            else: 
                tlsn_session = shared.TLSNClientSession(server_name)
        else: #use_paillier_scheme
            if testing: 
                tlsn_session = shared.TLSNClientSession_Paillier(server_name, ccs=int(cs))
            else: 
                tlsn_session = shared.TLSNClientSession_Paillier(server_name)                

        global b_comm_channel_busy
        while b_comm_channel_busy:
            time.sleep(0.1)
        b_comm_channel_busy = True
        #if the enc_pms hasn't yet been prepared
        if not dercert in certs_and_enc_pms:
            print ('Preparing enc_pms')
            if not use_paillier_scheme:
                pms_secret, pms_padding_secret = prepare_pms()
                prepare_encrypted_pms(tlsn_session, dercert, pms_secret, pms_padding_secret)
            else: #use_paillier_scheme:
                paillier_prepare_encrypted_pms(tlsn_session, dercert)
        else:
            print ('Encrypted PMS was already prepared')
            pms_secret, pms_padding_secret, enc_pms = certs_and_enc_pms[dercert]
            #remove dercert - we must not reuse it, because server mac will be revealed at the end of audit
            certs_and_enc_pms.pop(dercert)
            tlsn_session.auditee_secret = pms_secret
            tlsn_session.auditee_padding_secret = pms_padding_secret
            tlsn_session.enc_pms = enc_pms
        
        print ('Peforming handshake with server')
        tls_sock = shared.create_sock(tlsn_session.server_name,tlsn_session.ssl_port)
        tlsn_session.start_handshake(tls_sock)
        #compare this ongoing audit's cert to the one 
        #we used from the browser in prepare_encrypted_pms
        verify_server(dercert, tlsn_session)
        retval = negotiate_crippled_secrets(tlsn_session, tls_sock)
        if not retval == 'success': 
            raise Exception(retval)
        b_comm_channel_busy = False                        
        if not retval == 'success': 
            raise Exception(retval)
        print ('Getting data from server')            
        response = make_tlsn_request(modified_headers,tlsn_session,tls_sock)
        global audit_no
        audit_no += 1 #we want to increase only after server responded with data
        sf = str(audit_no)
        rv = decrypt_html(commit_session(tlsn_session, response,sf), tlsn_session, sf)
        if rv[0] == 'success': html_paths = b64encode(rv[1])
        self.respond({'response':'start_audit', 'status':rv[0],'html_paths':html_paths})
        return           
    
    def send_link(self, args):
        rv = send_link(args)
        self.respond({'response':'send_link', 'status':rv})
        return              
          
    def selftest(self):
        auditor_py = join(install_dir, 'src', 'auditor', 'tlsnotary-auditor.py')
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
    
    def get_advanced(self):
        self.respond({'irc_server':shared.config.get('IRC','irc_server'),
        'channel_name':shared.config.get('IRC','channel_name'),'irc_port':shared.config.get('IRC','irc_port')})
        return        
    
    def set_advanced(self, args):
        args = args.split(',')
        #TODO can make this more generic when there are lots of arguments;
        if not (args[0].split('=')[0] == 'server_val' and args[1].split('=')[0] == 'channel_val' \
            and args[2].split('=')[0] == 'port_val' and args[0].split('=')[1] and \
            args[1].split('=')[1] and args[2].split('=')[1]):
            print ('Failed to reset the irc config. Server was:',args[0].split('=')[1], \
            ' and channel was: ', args[1].split('=')[1])
            return
        shared.config.set('IRC','irc_server',args[0].split('=')[1])
        shared.config.set('IRC','channel_name',args[1].split('=')[1])
        shared.config.set('IRC','irc_port',args[2].split('=')[1])
        with open(shared.config_location,'wb') as f: shared.config.write(f)
        return        
    
    def send_certificate(self, b64cert):
        #we don't want to cache enc_pmss as it would take too long in paillier scheme
        if int(shared.config.get("General","use_paillier_scheme")):
            return
        cert_queue.put(b64cert)
        #no need to respond, nobody cares
        return        
     
    def get_recent_keys(self):
        #the very first command from addon 
        #on tlsnotary frst run, there will be no saved keys
        #otherwise we load up the keys saved from previous session
        my_prvkey_pem = my_pubkey_pem = auditor_pubkey_pem = ''
        if os.path.exists(join(data_dir, 'recentkeys')):
            if os.path.exists(join(data_dir, 'recentkeys', 'myprivkey')) and os.path.exists(join(data_dir, 'recentkeys', 'mypubkey')):
                with open(join(data_dir, 'recentkeys', 'myprivkey'), 'rb') as f: my_prvkey_pem = f.read()
                with open(join(data_dir, 'recentkeys', 'mypubkey'), 'rb') as f: my_pubkey_pem = f.read()
                with open(join(current_session_dir, 'myprivkey'), 'wb') as f: f.write(my_prvkey_pem)
                with open(join(current_session_dir, 'mypubkey'), 'wb') as f: f.write(my_pubkey_pem)
                global my_prv_key                    
                my_prv_key = rsa.PrivateKey.load_pkcs1(my_prvkey_pem)
            if os.path.exists(join(data_dir, 'recentkeys', 'auditorpubkey')):
                with open(join(data_dir, 'recentkeys', 'auditorpubkey'), 'rb') as f: auditor_pubkey_pem = f.read()
                with open(join(current_session_dir, 'auditorpubkey'), 'wb') as f: f.write(auditor_pubkey_pem)
                global auditor_pub_key                    
                auditor_pub_key = rsa.PublicKey.load_pkcs1(auditor_pubkey_pem)
            global my_pub_key
            my_pub_key = rsa.PublicKey.load_pkcs1(my_pubkey_pem)
            my_pubkey_export = b64encode(shared.bi2ba(my_pub_key.n))
            if auditor_pubkey_pem == '': auditor_pubkey_export = ''
            else: auditor_pubkey_export = b64encode(shared.bi2ba(auditor_pub_key.n))
            self.respond({'response':'get_recent_keys', 'mypubkey':my_pubkey_export,
                     'auditorpubkey':auditor_pubkey_export})
        else:
            self.respond({'response':'get_recent_keys', 'mypubkey':'', 'auditorpubkey':''})                
        return                        
    
    def do_HEAD(self):
        request = self.path
        print ('browser sent ' + request[:80] + '... request',end='\r\n')
        # example HEAD string "/command?parameter=124value1&para2=123value2"
        if request.startswith('/get_recent_keys'):
            self.get_recent_keys()
        elif request.startswith('/new_keypair'):
            self.new_keypair()
        elif request.startswith('/import_auditor_pubkey'):
            self.import_auditor_pubkey(request.split('?', 1)[1])        
        elif request.startswith('/start_peer_connection'):
            self.start_peer_connection()
        elif request.startswith('/stop_recording'):
            self.stop_recording()
        elif request.startswith('/start_audit'):
            self.start_audit(request.split('?', 1)[1])
        elif request.startswith('/send_link'):
            self.send_link(request.split('?', 1)[1])
        elif request.startswith('/selftest'):
            self.selftest()
        elif request.startswith('/get_advanced'):
            self.get_advanced()
        elif request.startswith('/set_advanced'):
            self.set_advanced(request.split('?', 1)[1])
        elif request.startswith('/send_certificate'):
            self.send_certificate(request.split('?', 1)[1])      
        else:
            self.respond({'response':'unknown command'})

    #overriding BaseHTTPRequestHandler's method to cap the output
    def log_message(self, fmt, *args):
        sys.stderr.write("%s - - [%s] %s\n" %
                                  (self.client_address[0],
                                   self.log_date_time_string(),
                                   (fmt%args)[:80]))
        

def paillier_gen_privkey_thread():
    global paillier_private_key
    paillier_private_key = shared.Paillier(privkey_bits=4096+8)
    global b_paillier_privkey_being_generated
    b_paillier_privkey_being_generated = False

def paillier_gen_privkey():
    thread = threading.Thread(target=paillier_gen_privkey_thread)
    thread.daemon = True
    thread.start()    


#loops on the cert_queue and prepares enc_pms
def process_certificate_queue():
    #wait for peer to connect before sending
    while not b_peer_connected:
        time.sleep(0.1)
    #when peer is connected we dont want to immediately send certs (if any)
    #because auditor needs a couple of seconds to setup
    time.sleep(2)
    use_paillier_scheme = False
    if int(shared.config.get("General","use_paillier_scheme")):
        use_paillier_scheme = True                    
    while True:
        #dummy class only to get enc_pms, use new one each iteration just in case     
        b64cert = cert_queue.get()
        #we don't want to pre-compute for more than 1 certificate as this will
        #confuse the auditor. However, the auditor code can be changed to 
        #accomodate >1 cert but I see no urgent need for that
        if len(certs_and_enc_pms) > 0: continue
        cert_der = b64decode(b64cert)
        #don't process duplicates
        if cert_der in certs_and_enc_pms: continue
        cert_der = b64decode(b64cert)
        global b_comm_channel_busy
        while b_comm_channel_busy:
            time.sleep(0.1)
        b_comm_channel_busy = True
        #make sure the cert wasnt cached while we were waiting
        if len(certs_and_enc_pms) > 0:
            b_comm_channel_busy = False            
            continue
        print ('Preparing enc_pms in advance')        
        if not use_paillier_scheme:
            tls_crypto = shared.TLSNClientSession()
            pms_secret, pms_padding_secret = prepare_pms()
            prepare_encrypted_pms(tls_crypto, cert_der, pms_secret, pms_padding_secret)
        else:
            tls_crypto = shared.TLSNClientSession_Paillier()   
            pms_secret = tls_crypto.auditee_secret
            pms_padding_secret = tls_crypto.auditee_padding_secret
            paillier_prepare_encrypted_pms(tls_crypto, cert_der)
        certs_and_enc_pms[cert_der] = (pms_secret, pms_padding_secret, tls_crypto.enc_pms)
        b_comm_channel_busy = False        


#Because there is a 1 in ? chance that the encrypted PMS will contain zero bytes in its
#padding, we first try the encrypted PMS with a reliable site and see if it gets rejected.
#TODO the probability seems to have increased too much w.r.t. random padding, investigate
def prepare_pms():
    for i in range(7): #try 7 times until reliable site check succeeds
        #first 4 bytes of client random are unix time
        pms_session = shared.TLSNClientSession(rs_choice,shared.reliable_sites[rs_choice][0], ccs=53)
        if not pms_session: 
            raise Exception("Client session construction failed in prepare_pms")
        tls_sock = shared.create_sock(pms_session.server_name,pms_session.ssl_port)
        pms_session.start_handshake(tls_sock)
        reply = send_and_recv('rcr_rsr:'+\
            pms_session.client_random+pms_session.server_random)
        if reply[0] != 'success': 
            raise Exception ('Failed to receive a reply for rcr_rsr:')
        if not reply[1].startswith('rrsapms_rhmac'):
            raise Exception ('bad reply. Expected rrsapms_rhmac:')
        reply_data = reply[1][len('rrsapms_rhmac:'):]
        rsapms2 = reply_data[:256]
        pms_session.p_auditor = reply_data[256:304]
        response = pms_session.complete_handshake(tls_sock,rsapms2)
        tls_sock.close()
        if not response:
            print ("PMS trial failed")
            continue
        #judge success/fail based on whether a properly encoded 
        #Change Cipher Spec record is returned by the server (we could
        #also check the server finished, but it isn't necessary)
        if not response.count(shared.TLSRecord(shared.chcis,f='\x01').serialized):
            print ("PMS trial failed, retrying. (",binascii.hexlify(response),")")
            continue
        return (pms_session.auditee_secret,pms_session.auditee_padding_secret)
    #no dice after 7 tries
    raise Exception ('Could not prepare PMS with ', rs_choice, ' after 7 tries. Please '+\
                     'double check that you are using a valid public key modulus for this site; '+\
                     'it may have expired.')


def prepare_encrypted_pms(tlsn_session, cert_der, pms_secret, pms_padding_secret):
    tlsn_session.auditee_secret, tlsn_session.auditee_padding_secret = pms_secret, pms_padding_secret
    n_int, e_int = tlsn_session.extract_mod_and_exp(cert_der)
    n = shared.bi2ba(n_int)
    e = shared.bi2ba(e_int)
    len_n = shared.bi2ba(len(n))
    reply = send_and_recv('n_e:'+len_n+n+e)
    if reply[0] != 'success': return ('Failed to receive a reply for n_e:')
    if not reply[1].startswith('rsapms:'):
        return 'bad reply. Expected rsapms:'
    rsapms = reply[1][len('rsapms:'):]
    tlsn_session.server_modulus = shared.ba2int(n)
    tlsn_session.server_mod_length = len_n
    tlsn_session.enc_second_half_pms = shared.ba2int(rsapms)
    tlsn_session.set_enc_first_half_pms()
    tlsn_session.set_encrypted_pms()    


def paillier_prepare_encrypted_pms(tlsn_session, cert_der):
    N_int, e_int = tlsn_session.extract_mod_and_exp(cert_der)
    N_ba = shared.bi2ba(N_int)
    if len(N_ba) > 256:
        raise Exception ('''Can not audit the website with a pubkey length more than 256 bytes.
        Please set use_paillier_scheme = 0 in tlsnotary.ini and rerun tlsnotary''')
    if b_paillier_privkey_being_generated:
        print ('Waiting for Paillier key to finish generating before continuing')
        while b_paillier_privkey_being_generated:
            time.sleep(0.1)
        print ('Paillier private key generated! Continuing.')  
    print ('Preparing enc_pms using Paillier. This usually takes 2 minutes')
    assert paillier_private_key
    scheme = shared.Paillier_scheme_auditee(paillier_private_key)
    data_for_auditor = scheme.get_data_for_auditor(tlsn_session.auditee_padded_rsa_half, N_ba)
    data_file = join(current_session_dir, 'paillier_data')
    with open(data_file, 'wb') as f: f.write(data_for_auditor)
    try: 
        link = shared.sendspace_getlink(data_file, requests.get, requests.post)
    except:
        raise Exception('Could not use sendspace')  
    reply = send_and_recv('p_link:'+link, timeout=200)
    if reply[0] != 'success':
        raise Exception ('Failed to receive a reply for p_link:')
    
    for i in range(8):
        if not reply[1].startswith('p_round_or'+str(i)+':'):
            return 'bad reply. Expected p_round_or'+str(i)+':'
        E_ba = reply[1][len('p_round_or'+str(i)+':'):]
        F_ba = shared.bi2ba( scheme.do_round(i, shared.ba2int(E_ba)), fixed=513)
        reply = send_and_recv('p_round_ee'+str(i)+':'+F_ba)
        if reply[0] != 'success': 
            raise Exception ('Failed to receive a reply for p_round_ee'+str(i)+':')
   
    if not reply[1].startswith('p_round_or8:'):
        raise Exception ('bad reply. Expected p_round_or8:')
    PSum_ba = reply[1][len('p_round_or8:'):]
    enc_pms = scheme.do_ninth_round(shared.ba2int(PSum_ba))    
    tlsn_session.enc_pms = enc_pms

    
#peer messaging protocol
def send_and_recv (data,timeout=5):
    if not ('success' == shared.tlsn_send_msg(data,auditor_pub_key,ack_queue,auditor_nick,seq_init=None)):
        return ('failure','')
    #receive a response (these are collected into the recv_queue by the receiving thread)
    for i in range(3):
        try: onemsg = recv_queue.get(block=True, timeout=timeout)
        except:  continue 
        return ('success', onemsg)
    return ('failure', '')

#complete audit function
def stop_recording():
    trace_dir = join(current_session_dir, 'mytrace')
    os.makedirs(trace_dir)
    zipf = zipfile.ZipFile(join(trace_dir, 'mytrace.zip'), 'w')
    commit_dir = join(current_session_dir, 'commit')
    com_dir_files = os.listdir(commit_dir)
    for onefile in com_dir_files:
        if not onefile.startswith(('response', 'md5hmac', 'domain','IV','cs')): continue
        zipf.write(join(commit_dir, onefile), onefile)
    zipf.close()
    path = join(trace_dir, 'mytrace.zip')
    ul_sites = [shared.sendspace_getlink, shared.pipebytes_getlink, 
                shared.qfs_getlink, shared.loadto_getlink]
    #try a random upload site until we either succeed or deplete the list of sites
    while True:
        if not len(ul_sites):
            raise Exception ('Could not use any of the available upload websites.')
        idx = random.randint(0, len(ul_sites)-1)
        try:
            print ('Uploading trace using ' +  str(ul_sites[idx]))
            link = ul_sites[idx](path, requests.get, requests.post)
            break #success
        except:
            print ('Error sending file using ' + str(ul_sites[idx]) + " Trying another site.")
            ul_sites.pop(idx)
    return send_link(link)

#reconstruct correct http headers
#for passing to TLSNotary custom ssl session
def parse_headers(headers):
    header_lines = headers.split('\r\n') #no new line issues; it was constructed like that
    server = header_lines[1].split(':')[1].strip()
    if int(shared.config.get("General","gzip_disabled")) != 0:
        modified_headers = '\r\n'.join([x for x in header_lines if 'gzip' not in x])
    else:
        modified_headers = '\r\n'.join(header_lines)
        
    return (server,modified_headers)

def verify_server(claimed_cert, tlsn_session):
    '''Verify the server certificate by comparing that provided
    with the one that firefox already verified.'''     
    our_cert_sha = sha1(tlsn_session.server_certificate.asn1cert).digest()
    claimed_cert_sha = sha1(claimed_cert).digest()
    if not our_cert_sha == claimed_cert_sha:
        print ("Tlsnotary session certificate hash was:",binascii.hexlify(our_cert_sha))
        print ("Browser certificate hash was: ",binascii.hexlify(claimed_cert_sha))
        raise Exception("WARNING! The server is presenting an invalid certificate. "+ \
                        "This is most likely an error, although it could be a hacking attempt. Audit aborted.")
    else:
        print ("Browser verifies that the server certificate is valid, continuing audit.")    
        
def negotiate_crippled_secrets(tlsn_session, tls_sock):
    '''Negotiate with auditor in order to create valid session keys
    (except server mac is garbage as auditor withholds it)'''
    assert tlsn_session.handshake_hash_md5
    assert tlsn_session.handshake_hash_sha
    tlsn_session.set_auditee_secret()
    cs_cr_sr_hmacms_verifymd5sha = chr(tlsn_session.chosen_cipher_suite) + tlsn_session.client_random + \
        tlsn_session.server_random + tlsn_session.p_auditee[:24] +  tlsn_session.handshake_hash_md5 + \
        tlsn_session.handshake_hash_sha
    reply = send_and_recv('cs_cr_sr_hmacms_verifymd5sha:'+cs_cr_sr_hmacms_verifymd5sha)
    if reply[0] != 'success': return ('Failed to receive a reply for cs_cr_sr_hmacms_verifymd5sha:')
    if not reply[1].startswith('hmacms_hmacek_hmacverify:'):
        return 'bad reply. Expected hmacms_hmacek_hmacverify: but got reply[1]'
    reply_data = reply[1][len('hmacms_hmacek_hmacverify:'):]
    expanded_key_len = shared.tlsn_cipher_suites[tlsn_session.chosen_cipher_suite][-1]
    assert len(reply_data) == 24+expanded_key_len+12
    hmacms = reply_data[:24]    
    hmacek = reply_data[24:24 + expanded_key_len]
    hmacverify = reply_data[24 + expanded_key_len:24 + expanded_key_len+12]   
    tlsn_session.set_master_secret_half(half=2,provided_p_value = hmacms)
    tlsn_session.p_master_secret_auditor = hmacek
    tlsn_session.do_key_expansion()
    tlsn_session.send_client_finished(tls_sock,provided_p_value=hmacverify)
    sha_digest2,md5_digest2 = tlsn_session.set_handshake_hashes(server=True)
    reply = send_and_recv('verify_md5sha2:'+md5_digest2+sha_digest2)
    if reply[0] != 'success':return("Failed to receive a reply for verify_md5sha2")
    if not reply[1].startswith('verify_hmac2:'):return("bad reply. Expected verify_hmac2:")
    if not tlsn_session.check_server_ccs_finished(provided_p_value = reply[1][len('verify_hmac2:'):]):
        raise Exception ("Could not finish handshake with server successfully. Audit aborted")
    return 'success'    
    
def make_tlsn_request(headers,tlsn_session,tls_sock):
    '''Send TLS request including http headers and receive server response.'''
    tlsn_session.build_request(tls_sock,headers)
    response = shared.recv_socket(tls_sock) #not handshake flag means we wait on timeout
    if not response: 
        raise Exception ("Received no response to request, cannot continue audit.")
    tlsn_session.store_server_app_data_records(response)
    tls_sock.close()    
    return response 

def commit_session(tlsn_session,response,sf):
    '''Commit the encrypted server response and other data to auditor'''
    commit_dir = join(current_session_dir, 'commit')
    if not os.path.exists(commit_dir): os.makedirs(commit_dir)
    #Serialization of RC4 'IV' requires concatenating the box,x,y elements of the RC4 state tuple
    IV = shared.rc4_state_to_bytearray(tlsn_session.IV_after_finished) \
        if tlsn_session.chosen_cipher_suite in [4,5] else tlsn_session.IV_after_finished
    stuff_to_be_committed  = {'response':response,'IV':IV,
                              'cs':str(tlsn_session.chosen_cipher_suite),
                              'md5hmac':tlsn_session.p_auditee,'domain':tlsn_session.server_name}
    for k,v in stuff_to_be_committed.iteritems():
        with open(join(commit_dir,k+sf),'wb') as f: f.write(v)    
    commit_hash = sha256(response).digest()
    md5hmac_hash = sha256(tlsn_session.p_auditee).digest()
    reply = send_and_recv('commit_hash:'+commit_hash+md5hmac_hash)
    if reply[0] != 'success': 
        raise Exception ('Failed to receive a reply') 
    if not reply[1].startswith('sha1hmac_for_MS:'):
        raise Exception ('bad reply. Expected sha1hmac_for_MS')    
    return reply[1][len('sha1hmac_for_MS:'):]


def decrypt_html(sha1hmac, tlsn_session,sf):
    '''Receive correct server mac key and then decrypt server response (html),
    (includes authentication of response). Submit resulting html for browser
    for display (optionally render by stripping http headers).'''
    tlsn_session.p_auditor = sha1hmac
    tlsn_session.set_master_secret_half() #without arguments sets the whole MS
    tlsn_session.do_key_expansion() #also resets encryption connection state
    
    if int(shared.config.get("General","decrypt_with_slowaes")) or \
       not tlsn_session.chosen_cipher_suite in [47,53]:
        #either using slowAES or a RC4 ciphersuite
        plaintext,bad_mac = tlsn_session.process_server_app_data_records()
        if bad_mac: print ("WARNING! Plaintext is not authenticated.")        
    else: #AES ciphersuite and not using slowaes        
        ciphertexts = tlsn_session.get_ciphertexts()
        raw_plaintexts = []
        for one_ciphertext in ciphertexts:
            aes_ciphertext_queue.put(one_ciphertext)
            raw_plaintext = aes_cleartext_queue.get()
            #crypto-js knows only how to remove pkcs7 padding but not cbc padding
            #which is one byte longer than pkcs7. We remove it manually
            raw_plaintexts.append(raw_plaintext[:-1])
        plaintext = tlsn_session.mac_check_plaintexts(raw_plaintexts)

    plaintext = shared.dechunk_http(plaintext)
    if int(shared.config.get("General","gzip_disabled")) == 0:    
        plaintext = shared.gunzip_http(plaintext)

    with open(join(current_session_dir,'session_dump'+sf),'wb') as f: f.write(tlsn_session.dump())
    commit_dir = join(current_session_dir, 'commit')
    html_path = join(commit_dir,'html-'+sf)
    with open(html_path,'wb') as f: f.write('\xef\xbb\xbf'+plaintext) #see "Byte order mark"
    if not int(shared.config.get("General","prevent_render")):
        html_path = join(commit_dir,'forbrowser-'+sf+'.html')
        with open(html_path,'wb') as f:
            f.write('\r\n\r\n'.join(plaintext.split('\r\n\r\n')[1:]))
    return ('success',html_path)

#peer messaging receive thread
def receiving_thread(my_nick, auditor_nick):
    shared.tlsn_msg_receiver(my_nick,auditor_nick,ack_queue,recv_queue,shared.message_types_from_auditor,my_prv_key)

#set up temporary user id and initialise peer messaging
def start_peer_messaging():
    global my_nick
    my_nick= 'user' + ''.join(random.choice('0123456789') for x in range(10))
    shared.tlsn_initialise_messaging(my_nick)
    #if we got here, no exceptions were thrown, which counts as success.
    return 'success'

#perform handshake with auditor over peer messaging channel.
def peer_handshake():
    global my_nick
    global auditor_nick
    global rs_choice
    shared.import_reliable_sites(join(install_dir,'src','shared'))
    #hello contains the first 10 bytes of modulus of the auditor's pubkey
    #this is how the auditor knows that we are addressing him.
    modulus = shared.bi2ba(auditor_pub_key.n)[:10]
    signed_hello = rsa.sign('ae_hello'+my_nick, my_prv_key, 'SHA-1')
    rs_choice = random.choice(shared.reliable_sites.keys())
    print ("Chosen site: ",rs_choice)
    rs_n = shared.reliable_sites[rs_choice][1].decode('hex')
    rs_e = shared.bi2ba(65537,fixed=4)

    b_is_auditor_registered = False
    for attempt in range(6): #try for 6*5 secs to find the auditor
        if b_is_auditor_registered == True: break #previous iteration successfully regd the auditor
        time_attempt_began = int(time.time())
        shared.tlsn_send_single_msg(' :ae_hello:',modulus+signed_hello,auditor_pub_key)
        shared.tlsn_send_single_msg(' :rs_pubkey:',rs_n+rs_e+rs_choice,auditor_pub_key)
        signed_hello_message_dict = {}
        full_signed_hello = ''
        while not b_is_auditor_registered:
            if int(time.time()) - time_attempt_began > 5: break
            #ignore decryption errors here, as above, the message may be
            #from someone else's handshake
            x = shared.tlsn_receive_single_msg('ao_hello:',my_prv_key,my_nick,ide=True)
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
                        rsa.verify('ao_hello'+returned_auditor_nick, full_signed_hello, auditor_pub_key)
                        auditor_nick = returned_auditor_nick
                        b_is_auditor_registered = True
                        print ('Auditor successfully verified')
                    except: 
                        raise
                            #return ('Failed to verify the auditor. Are you sure you have the correct auditor\'s pubkey?')

    if not b_is_auditor_registered:
        print ('Failed to register auditor within 60 seconds')
        return 'failure'

    thread = threading.Thread(target= receiving_thread, args=(my_nick, auditor_nick))
    thread.daemon = True
    thread.start()
    return 'success'

#Make a local copy of firefox, find the binary, install the new profile
#and start up firefox with that profile.
def start_firefox(FF_to_backend_port, firefox_install_path, AES_decryption_port):
    #find the binary *before* copying; acts as sanity check
    ffbinloc = {'linux':['firefox'],'mswin':['firefox.exe'],'macos':['Contents','MacOS','firefox']}
    assert os.path.isfile(join(*([firefox_install_path]+ffbinloc[OS]))),\
           "Firefox executable not found - invalid Firefox application directory."
        
    local_ff_copy = join(data_dir,'Firefox.app') if OS=='macos' else join(data_dir,'firefoxcopy')  
    
    #check if FF-addon/tlsnotary@tlsnotary files were modified. If so, get a fresh 
    #firefoxcopy and FF-profile. This is useful for developers, otherwise
    #we forget to do it manually and end up chasing wild geese
    filehashes = []
    for root, dirs, files in os.walk(join(data_dir, 'FF-addon', 'tlsnotary@tlsnotary')):
        for onefile in files:
            with open(join(root, onefile), 'rb') as f: filehashes.append(md5(f.read()).hexdigest())
    #sort hashes and get the final hash
    filehashes.sort()
    final_hash = md5(''.join(filehashes)).hexdigest()
    hash_path = join(data_dir, 'ffaddon.md5')
    if not os.path.exists(hash_path):
        with open(hash_path, 'wb') as f: f.write(final_hash)
    else:
        with open(hash_path, 'rb') as f: saved_hash = f.read()
        if saved_hash != final_hash:
            print('''FF-addon directory changed since last invocation. 
            Replacing some of your Firefox\'s copy folders''')
            try:
                shutil.rmtree(local_ff_copy)
                shutil.rmtree(join(data_dir, 'FF-profile'))
            except:
                pass
            with open(hash_path, 'wb') as f: f.write(final_hash)            
            
             
    if not os.path.exists(local_ff_copy):
        try:
            shutil.copytree(firefox_install_path, local_ff_copy, symlinks=True)        
        except  Exception,e:   
            #we dont want a half-copied dir. Delete everything and rethrow
            shutil.rmtree(local_ff_copy)
            raise e
        
    firefox_exepath = join(*([local_ff_copy]+ffbinloc[OS]))
    
    logs_dir = join(data_dir, 'logs')
    if not os.path.isdir(logs_dir): os.makedirs(logs_dir)
    with open(join(logs_dir, 'firefox.stdout'), 'w') as f: pass
    with open(join(logs_dir, 'firefox.stderr'), 'w') as f: pass
    ffprof_dir = join(data_dir, 'FF-profile')
    if not os.path.exists(ffprof_dir): os.makedirs(ffprof_dir)
    shutil.copyfile(join(data_dir,'prefs.js'),join(ffprof_dir,'prefs.js'))
    shutil.copyfile(join(data_dir,'localstore.rdf'),join(ffprof_dir,'localstore.rdf'))
    if OS=='macos':
        bundles_dir = os.path.join(local_ff_copy, 'Contents','MacOS','distribution', 'bundles')
    else:
        bundles_dir = os.path.join(local_ff_copy, 'distribution', 'bundles')
    if not os.path.exists(bundles_dir):
        os.makedirs(bundles_dir)    
    for ext_dir in ['tlsnotary@tlsnotary']:
        if not os.path.exists(join(bundles_dir,ext_dir)):
            shutil.copytree(join(data_dir, 'FF-addon', ext_dir),join(bundles_dir, ext_dir))                  
    os.putenv('FF_to_backend_port', str(FF_to_backend_port))
    os.putenv('FF_first_window', 'true')   #prevents addon confusion when websites open multiple FF windows
    if int(shared.config.get("General","decrypt_with_slowaes")) == 0:
        os.putenv('TLSNOTARY_USING_BROWSER_AES_DECRYPTION', 'true')
        os.putenv('TLSNOTARY_AES_DECRYPTION_PORT', str(AES_decryption_port))

    if testing:
        print ('****************************TESTING MODE********************************')
        os.putenv('TLSNOTARY_TEST', 'true')
    
    print ('Starting a new instance of Firefox with tlsnotary profile',end='\r\n')
    try: ff_proc = Popen([firefox_exepath,'-no-remote', '-profile', ffprof_dir],
                                   stdout=open(join(logs_dir, 'firefox.stdout'),'w'), 
                                   stderr=open(join(logs_dir, 'firefox.stderr'), 'w'))
    except Exception,e: return ('Error starting Firefox: %s' %e,)
    return ('success', ff_proc)
    
#HTTP server to talk with Firefox addon
def http_server(parentthread):    
    #allow three attempts in case if the port is in use
    b_was_started = False
    for i in range(3):
        FF_to_backend_port = random.randint(1025,65535)
        print ('Starting http server to communicate with Firefox addon')
        try:
            httpd = shared.StoppableHttpServer(('127.0.0.1', FF_to_backend_port), HandleBrowserRequestsClass)
            b_was_started = True
            break
        except Exception, e:
            print ('Error starting mini http server. Maybe the port is in use?', e,end='\r\n')
            continue
    if b_was_started == False:
        #retval is a var that belongs to our parent class which is ThreadWithRetval
        parentthread.retval = ('failure',)
        return
    #Let the invoking thread know that we started successfully
    parentthread.retval = ('success', FF_to_backend_port)
    sa = httpd.socket.getsockname()
    print ('Serving HTTP on', sa[0], 'port', sa[1], '...',end='\r\n')
    httpd.serve_forever()
    return


#Used only for testing
#use miniHTTP server to receive commands from Firefox addon and respond to them
def aes_decryption_thread(parentthread):    
    #allow three attempts to start mini httpd in case if the port is in use
    b_was_started = False
    for i in range(3):
        AES_decryption_port = random.randint(1025,65535)
        print ('Starting AES decryption server')
        try:
            aes_httpd = shared.StoppableHttpServer(('127.0.0.1', AES_decryption_port), HandlerClass_aes)
            b_was_started = True
            break
        except Exception, e:
            print ('Error starting AES decryption server. Maybe the port is in use?', e,end='\r\n')
            continue
    if b_was_started == False:
        #retval is a var that belongs to our parent class which is ThreadWithRetval
        parentthread.retval = ('failure',)
        return
    #elif minihttpd started successfully
    #Let the invoking thread know that we started successfully
    parentthread.retval = ('success', AES_decryption_port)
    sa = aes_httpd.socket.getsockname()
    print ("decrypting AES on", sa[0], "port", sa[1], "...",end='\r\n')
    aes_httpd.serve_forever()
    return



#Sending links (urls) to files passed from auditee to
#auditor over peer messaging
def send_link(filelink):
    #we must be very generous with the timeout because
    #the auditor must do his decryption (which could be AES).
    #For single page audits this will very rarely be an issue,
    #but for multi-page or auto testing, it certainly could be.
    reply = send_and_recv('link:'+filelink,timeout=200) 
    if not reply[0] == 'success' : return 'failure'
    if not reply[1].startswith('response:') : return 'failure'
    response = reply[1][len('response:'):]
    return response

#cleanup
def quit_clean(sig=0, frame=0):
    if testing:
        try: os.kill(test_auditor_pid, signal.SIGTERM)
        except: pass #happens when test terminated itself
        try: os.kill(test_driver_pid, signal.SIGTERM)
        except: pass #happens when test terminated itself
    if firefox_pid != 0:
        try: os.kill(firefox_pid, signal.SIGTERM)
        except: pass #firefox not runnng
    if selftest_pid != 0:
        try: os.kill(selftest_pid, signal.SIGTERM)
        except: pass #selftest not runnng    
    exit(1)

#unpack and check validity of Python modules
def first_run_check(modname,modhash):
    if not modhash: return
    mod_dir = join(data_dir, 'python', modname)
    if not os.path.exists(mod_dir):
        print ('Extracting '+modname + '.tar.gz...')
        with open(join(data_dir, 'python', modname+'.tar.gz'), 'rb') as f: tarfile_data = f.read()
        if md5(tarfile_data).hexdigest() !=  modhash:
            raise Exception ('Wrong hash')
        os.chdir(join(data_dir, 'python'))
        tar = tarfile.open(join(data_dir, 'python', modname+'.tar.gz'), 'r:gz')
        tar.extractall()
        tar.close()


#Used during testing only.
#It is best to start testing from this file rather than a standalone one.
#This will increase the likelihood of debugger stopping on breakpoints
def start_testing():
    import subprocess    
    #initiate an auditor window in daemon mode
    print ("TESTING: starting auditor")    
    auditor_py = os.path.join(install_dir, 'src', 'auditor', 'tlsnotary-auditor.py')
    auditor_proc = subprocess.Popen(['python', auditor_py,'daemon'])
    global test_auditor_pid 
    test_auditor_pid = auditor_proc.pid    
    print ("TESTING: starting testdriver")
    testdir = join(install_dir, 'src', 'test')
    test_py = join(testdir, 'tlsnotary-test.py')
    site_list = join (testdir, 'websitelist.txt')
    #testdriver kills ee/or when test ends, passing PIDs
    test_proc = subprocess.Popen(filter(None,['python', test_py, site_list, str(os.getpid()), str(test_auditor_pid)]))
    global test_driver_pid
    test_driver_pid = test_proc.pid
            

 
if __name__ == "__main__":
    if ('test' in sys.argv): testing = True    
    #for md5 hash, see https://pypi.python.org/pypi/<module name>/<module version>
    modules_to_load = {'rsa-3.1.4':'b6b1c80e1931d4eba8538fd5d4de1355',\
                       'pyasn1-0.1.7':'2cbd80fcd4c7b1c82180d3d76fee18c8',\
                       'slowaes':'','requests-2.3.0':'7449ffdc8ec9ac37bbcd286003c80f00'}
    for x,h in modules_to_load.iteritems():
        first_run_check(x,h)
        sys.path.append(join(data_dir, 'python', x))
        
    import rsa
    import pyasn1
    import requests
    from pyasn1.type import univ
    from pyasn1.codec.der import encoder, decoder
    from slowaes import AESModeOfOperation        
    import shared
    shared.load_program_config()
        
    firefox_install_path = None
    if len(sys.argv) > 1: firefox_install_path = sys.argv[1]
    if firefox_install_path == 'test': firefox_install_path = None
    
    if not firefox_install_path:
        if OS=='linux':
            if not os.path.exists('/usr/lib/firefox'):
                raise Exception ("Could not set firefox install path")
            firefox_install_path = '/usr/lib/firefox'
        elif OS=='mswin':
            bFound = False
            prog64 = os.getenv('ProgramW6432')
            prog32 = os.getenv('ProgramFiles(x86)')
            progxp = os.getenv('ProgramFiles')			
            if prog64:
                if os.path.exists(join(prog64,'Mozilla Firefox')):
                    firefox_install_path = join(prog64,'Mozilla Firefox')
                    bFound = True
            if not bFound and prog32:
                if os.path.exists(join(prog32,'Mozilla Firefox')):
                    firefox_install_path = join(prog32,'Mozilla Firefox')
                    bFound = True
            if not bFound and progxp:
                if os.path.exists(join(progxp,'Mozilla Firefox')):
                    firefox_install_path = join(progxp,'Mozilla Firefox')
                    bFound = True
            if not bFound:
                raise Exception('Could not set firefox install path')
        elif OS=='macos':
            if not os.path.exists(join("/","Applications","Firefox.app")):
                raise Exception('''Could not set firefox install path. 
                Please make sure Firefox is in your Applications folder''')
            firefox_install_path = join("/","Applications","Firefox.app")
        else:
            raise Exception("Unrecognised operating system.")
        
    print ("Firefox install path is: ",firefox_install_path)
    if not os.path.exists(firefox_install_path): 
        raise Exception ("Could not find Firefox installation")
    
    thread = shared.ThreadWithRetval(target= http_server)
    thread.daemon = True
    thread.start()
    #wait for minihttpd thread to indicate its status and FF_to_backend_port  
    b_was_started = False
    for i in range(10):
        time.sleep(1)        
        if thread.retval == '': continue
        #else
        if thread.retval[0] != 'success': 
            raise Exception (
            'Failed to start minihttpd server. Please investigate')
        #else
        b_was_started = True
        break
    if b_was_started == False:
        raise Exception ('minihttpd failed to start in 10 secs. Please investigate')
    FF_to_backend_port = thread.retval[1]
    
    thread = threading.Thread(target=process_certificate_queue)
    thread.daemon = True
    thread.start()
    
    AES_decryption_port = None
    if int(shared.config.get("General","decrypt_with_slowaes")) == 0:
        #We want AES decryption to be done fast in browser's JS instead of in python.
        #We start a server which sends ciphertexts to browser                
        thread_aes = shared.ThreadWithRetval(target=aes_decryption_thread)
        thread_aes.daemon = True
        thread_aes.start()            
        #wait for minihttpd thread to indicate its status  
        b_was_started = False
        for i in range(10):
            time.sleep(1)        
            if thread_aes.retval == '': continue
            #else
            if thread_aes.retval[0] != 'success': 
                raise Exception (
                'Failed to start minihttpd server. Please investigate')
            #else
            b_was_started = True
            AES_decryption_port = thread_aes.retval[1]
            break
        if b_was_started == False:
            raise Exception ('minihttpd failed to start in 10 secs. Please investigate')        
          
    ff_retval = start_firefox(FF_to_backend_port, firefox_install_path, AES_decryption_port)
    if ff_retval[0] != 'success': 
        raise Exception (
        'Error while starting Firefox: '+ ff_retval[0])
    ff_proc = ff_retval[1]
    firefox_pid = ff_proc.pid    
    
   
        
        
    signal.signal(signal.SIGTERM, quit_clean)

    if testing: start_testing()

    try:
        while True:
            time.sleep(1)
            if ff_proc.poll() != None: quit_clean() #FF was closed
    except KeyboardInterrupt: quit_clean()            
