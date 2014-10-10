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
datadir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.dirname(datadir))
installdir = os.path.dirname(os.path.dirname(datadir))
sessionsdir = join(datadir, 'sessions')
time_str = time.strftime('%d-%b-%Y-%H-%M-%S', time.gmtime())
current_sessiondir = join(sessionsdir, time_str)
os.makedirs(current_sessiondir)

#OS detection
m_platform = platform.system()
if m_platform == 'Windows': OS = 'mswin'
elif m_platform == 'Linux': OS = 'linux'
elif m_platform == 'Darwin': OS = 'macos'

#Globals
recvQueue = Queue.Queue() #all messages from the auditor are placed here by receivingThread
ackQueue = Queue.Queue() #ack numbers are placed here
auditor_nick = '' #we learn auditor's nick as soon as we get a ao_hello signed by the auditor
my_nick = '' #our nick is randomly generated on connection
myPrvKey = myPubKey = auditorPubKey = None
rsModulus = None
rsExponent = None
rsChoice = None
firefox_pid = selftest_pid = 0
audit_no = 0 #we may be auditing multiple URLs. This var keeps track of how many 
#successful audits there were so far and is used to index html files audited.

#RSA key management for peer messaging
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
    pubkey_export = b64encode(shared.bi2ba(myPubKey.n))
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
                my_pubkey_export = b64encode(shared.bi2ba(myPubKey.n))
                if auditor_pubkey_pem == '': auditor_pubkey_export = ''
                else: auditor_pubkey_export = b64encode(shared.bi2ba(auditorPubKey.n))
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
            raw_pk = sha1_and_headers[:59]
            processed_pk = binascii.unhexlify(raw_pk.replace(':',''))
            pms_secret,pms_padding_secret = prepare_pms()
            server_name, modified_headers = parse_headers(sha1_and_headers[59:])
            tlssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tlssock.settimeout(int(shared.config.get("General","tcp_socket_timeout")))            
            tlsnSession = setUpTLSSession(pms_secret, pms_padding_secret,server_name,tlssock)
            verifyServer(processed_pk, tlsnSession)
            retval = negotiateCrippledSecrets(tlsnSession)
            if not retval == 'success': raise Exception(retval)
            retval = negotiateVerifyAndFinishHandshake(tlsnSession,tlssock)
            if not retval == 'success': raise Exception(retval)
            response = makeTLSNRequest(modified_headers,tlsnSession,tlssock)
            global audit_no
            audit_no += 1 #we want to increase only after server responded with data
            sf = str(audit_no)
            rv = decryptHTML(commitSession(tlsnSession, response,sf), tlsnSession, sf)
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
            shared.config.set('IRC','irc_server',args[0].split('=')[1])
            shared.config.set('IRC','channel_name',args[1].split('=')[1])
            shared.config.set('IRC','irc_port',args[2].split('=')[1])
            with open(shared.config_location,'wb') as f: shared.config.write(f)
            return
        #----------------------------------------------------------------------#
        else:
            self.respond({'response':'unknown command'})
            return

#Because there is a 1 in ? chance that the encrypted PMS will contain zero bytes in its
#padding, we first try the encrypted PMS with a reliable site and see if it gets rejected.
#TODO the probability seems to have increased too much w.r.t. random padding, investigate
def prepare_pms():
    for i in range(7): #try 7 times until reliable site check succeeds
        #first 4 bytes of client random are unix time
        pmsSession = shared.TLSNSSLClientSession(rsChoice,shared.reliable_sites[rsChoice][0])
        if not pmsSession: raise Exception("Client session construction failed in prepare_pms")
        tlssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tlssock.settimeout(int(shared.config.get("General","tcp_socket_timeout")))
        tlssock.connect((pmsSession.serverName, pmsSession.sslPort))
        tlssock.send(pmsSession.handshakeMessages[0])
        if not pmsSession.processServerHello(shared.recv_socket(tlssock,isHandshake=True)):
            raise Exception("Failure in processing of server Hello from " + pmsSession.serverName)
        reply = send_and_recv('rcr_rsr:'+pmsSession.clientRandom+pmsSession.serverRandom)
        if reply[0] != 'success': raise Exception ('Failed to receive a reply for rcr_rsr:')
        if not reply[1].startswith('rrsapms_rhmac:'):
            raise Exception ('bad reply. Expected rrsapms_rhmac:')
        rrsapms_rhmac = reply[1][len('rrsapms_rhmac:'):]
        rsapms2 = rrsapms_rhmac[:256]
        shahmac = rrsapms_rhmac[256:304]
        pmsSession.pAuditor = shahmac
        tlssock.send(pmsSession.completeHandshake(rsapms2))
        response = shared.recv_socket(tlssock,isHandshake=True)
        tlssock.close()
        if not response:
            print ("PMS trial failed")
            continue
        if not response.count(pmsSession.handshakeMessages[5]):
            print ("PMS trial failed, server response was: ")
            print (binascii.hexlify(response))
            continue
        return (pmsSession.auditeeSecret,pmsSession.auditeePaddingSecret)
    #no dice after 7 tries
    raise Exception ('Could not prepare PMS with ', rsChoice, ' after 7 tries. Please '+\
                     'double check that you are using a valid public key modulus for this site; '+\
                     'it may have expired.')

    
#peer messaging protocol
def send_and_recv (data,timeout=5):
    if not ('success' == shared.tlsn_send_msg(data,auditorPubKey,ackQueue,auditor_nick,seq_init=None)):
        return ('failure','')
    #receive a response (these are collected into the recvQueue by the receiving thread)
    for i in range(3):
        try: onemsg = recvQueue.get(block=True, timeout=timeout)
        except:  continue 
        return ('success', onemsg)
    return ('failure', '')

#complete audit function
def stop_recording():
    tracedir = join(current_sessiondir, 'mytrace')
    os.makedirs(tracedir)
    zipf = zipfile.ZipFile(join(tracedir, 'mytrace.zip'), 'w')
    commit_dir = join(current_sessiondir, 'commit')
    com_dir_files = os.listdir(commit_dir)
    for onefile in com_dir_files:
        if not onefile.startswith(('response', 'md5hmac', 'domain','IV','cs')): continue
        zipf.write(join(commit_dir, onefile), onefile)
    zipf.close()
    try: link = shared.sendspace_getlink(join(tracedir, 'mytrace.zip'),requests.get,requests.post)
    except:
        try: link = shared.pipebytes_getlink(join(tracedir, 'mytrace.zip'))
        except: return 'failure'
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
    
def setUpTLSSession(pms_secret,pms_padding_secret,server_name,tlssock):
    '''Construct ssl client session object and do
    client hello, server hello, server hello done, certificate
    initial phase of handshake.'''
    tlsnSession = shared.TLSNSSLClientSession(server_name,ccs=5,audit=True)
    tlsnSession.auditeeSecret,tlsnSession.auditeePaddingSecret = pms_secret,pms_padding_secret
    tlssock.connect((tlsnSession.serverName, tlsnSession.sslPort))
    tlssock.send(tlsnSession.handshakeMessages[0])
    response = shared.recv_socket(tlssock,isHandshake=True)
    #a nasty but necessary hack: check whether server hello, cert, server hello done
    #is complete; if not, go back to server for more. This arises because we don't
    #know how the three handshake messages were packaged into records (1,2 or 3).
    while not response.endswith(shared.h_shd+shared.bi2ba(0,fixed=3)):
        response += shared.recv_socket(tlssock,isHandshake=True)
    if not tlsnSession.processServerHello(response):
        raise Exception("Failure in processing of server Hello from " + tlsnSession.serverName)
    tlsnSession.extractModAndExp()    
    return tlsnSession

def verifyServer(claimed_cert_sha,tlsnSession):
    '''Verify the server certificate by comparing that provided
    with the one that firefox already verified.'''
    our_cert_sha = sha1(tlsnSession.serverCertificate).digest()
    if not our_cert_sha == claimed_cert_sha:
        print ("Tlsnotary session certificate hash was:",binascii.hexlify(our_cert_sha))
        print ("Browser certificate hash was: ",binascii.hexlify(claimed_cert_sha))
        raise Exception("WARNING! The server is presenting an invalid certificate. "+ \
                        "This is most likely an error, although it could be a hacking attempt. Audit aborted.")
    else:
        print ("Browser verifies that the server certificate is valid, continuing audit.")    
        
def negotiateCrippledSecrets(tlsnSession):
    '''Negotiate with auditor in order to create valid session keys
    (except server mac is garbage as auditor withholds it)'''
    tlsnSession.setAuditeeSecret()
    cr_sr_hmac_n_e= chr(tlsnSession.chosenCipherSuite)+tlsnSession.clientRandom+tlsnSession.serverRandom+ \
                tlsnSession.pAuditee[:24]+tlsnSession.serverModLength+\
                shared.bi2ba(tlsnSession.serverModulus)+\
                shared.bi2ba(tlsnSession.serverExponent)
    reply = send_and_recv('cr_sr_hmac_n_e:'+cr_sr_hmac_n_e)
    if reply[0] != 'success': return ('Failed to receive a reply for cr_sr_hmac_n_e:')
    if not reply[1].startswith('rsapms_hmacms_hmacek:'):
        return 'bad reply. Expected rsapms_hmacms_hmacek:'
    rsapms_hmacms_hmacek = reply[1][len('rsapms_hmacms_hmacek:'):]
    ml = shared.ba2int(tlsnSession.serverModLength)
    RSA_PMS2 = rsapms_hmacms_hmacek[:ml]
    tlsnSession.encSecondHalfPMS = shared.ba2int(RSA_PMS2)
    tlsnSession.setEncryptedPMS()
    tlsnSession.setMasterSecretHalf(half=2,providedPValue = rsapms_hmacms_hmacek[ml:ml+24])
    tlsnSession.pMasterSecretAuditor = rsapms_hmacms_hmacek[ml+24:ml+24+tlsnSession.cipherSuites[tlsnSession.chosenCipherSuite][-1]]
    tlsnSession.doKeyExpansion()    
    return 'success'

def negotiateVerifyAndFinishHandshake(tlsnSession,tlssock):
    '''Complete handshake (includes negotiation of verify data 
    with auditor).'''
    sha_digest,md5_digest = tlsnSession.getHandshakeHashes()
    reply = send_and_recv('verify_md5sha:'+md5_digest+sha_digest)
    if reply[0] != 'success': return ('Failed to receive a reply')
    if not reply[1].startswith('verify_hmac:'): return ('bad reply. Expected verify_hmac:')
    data =  tlsnSession.getCKECCSF(providedPValue=reply[1][len('verify_hmac:'):])
    tlssock.send(data)
    response = shared.recv_socket(tlssock,isHandshake=True)
    #in case the server sent only CCS; wait until we get Finished also
    while response.count(shared.hs+shared.tlsver) != 1:
        response += shared.recv_socket(tlssock,isHandshake=True)
    sha_digest2,md5_digest2 = tlsnSession.getHandshakeHashes(isForServer = True)
    reply = send_and_recv('verify_md5sha2:'+md5_digest2+sha_digest2)
    if reply[0] != 'success':return("Failed to receive a reply")
    if not reply[1].startswith('verify_hmac2:'):return("bad reply. Expected verify_hmac2:")
    if not tlsnSession.processServerCCSFinished(response,providedPValue = reply[1][len('verify_hmac2:'):]):
        raise Exception ("Could not finish handshake with server successfully. Audit aborted")
    return 'success'

def makeTLSNRequest(headers,tlsnSession,tlssock):
    '''Send TLS request including http headers and receive server response.'''
    headers += '\r\n'
    tlssock.send(tlsnSession.buildRequest(headers))
    response = shared.recv_socket(tlssock) #not handshake flag means we wait on timeout
    if not response: raise Exception ("Received no response to request, cannot continue audit.")
    tlsnSession.storeServerAppDataRecords(response)
    tlssock.close()    
    return response 

def commitSession(tlsnSession,response,sf):
    '''Commit the encrypted server response and other data to auditor'''
    commit_dir = join(current_sessiondir, 'commit')
    #the IV data is not actually an IV, it's the current cipher state
    if tlsnSession.chosenCipherSuite in [47,53]: IV_data = tlsnSession.serverFinished[-16:]
    else: IV_data = bytearray(tlsnSession.serverRC4State[0])+\
        chr(tlsnSession.serverRC4State[1])+chr(tlsnSession.serverRC4State[2])    
    if not os.path.exists(commit_dir): os.makedirs(commit_dir)
    stuff_to_be_committed  = {'response':response,'IV':IV_data,'cs':str(tlsnSession.chosenCipherSuite),\
                              'md5hmac':tlsnSession.pAuditee,'domain':tlsnSession.serverName}
    for k,v in stuff_to_be_committed.iteritems():
        with open(join(commit_dir,k+sf),'wb') as f: f.write(v)    
    commit_hash = sha256(response).digest()
    md5hmac_hash = sha256(tlsnSession.pAuditee).digest()
    reply = send_and_recv('commit_hash:'+commit_hash+md5hmac_hash)
    if reply[0] != 'success': raise Exception ('Failed to receive a reply') 
    if not reply[1].startswith('sha1hmac_for_MS:'):
            raise Exception ('bad reply. Expected sha1hmac_for_MS')    
    return reply[1][len('sha1hmac_for_MS:'):]


def decryptHTML(sha1hmac, tlsnSession,sf):
    '''Receive correct server mac key and then decrypt server response (html),
    (includes authentication of response). Submit resulting html for browser
    for display (optionally render by stripping http headers).'''
    tlsnSession.pAuditor = sha1hmac
    tlsnSession.setMasterSecretHalf() #without arguments sets the whole MS
    tlsnSession.doKeyExpansion()
    plaintext,bad_mac = tlsnSession.processServerAppDataRecords(checkFinished=True)
    if bad_mac: print ("WARNING! Plaintext is not authenticated.")
    plaintext = shared.dechunkHTTP(plaintext)
    with open(join(current_sessiondir,'session_dump'+sf),'wb') as f: f.write(tlsnSession.dump())
    commit_dir = join(current_sessiondir, 'commit')
    html_path = join(commit_dir,'html-'+sf)
    with open(html_path,'wb') as f: f.write('\xef\xbb\xbf'+plaintext) #see "Byte order mark"
    if not int(shared.config.get("General","prevent_render")):
        html_path = join(commit_dir,'forbrowser-'+sf+'.html')
        with open(html_path,'wb') as f:
            f.write('\r\n\r\n'.join(plaintext.split('\r\n\r\n')[1:]))
    return ('success',html_path)

#peer messaging receive thread
def receivingThread(my_nick, auditor_nick):
    shared.tlsn_msg_receiver(my_nick,auditor_nick,ackQueue,recvQueue,shared.message_types_from_auditor,myPrvKey)

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
    global auditorPubKey
    global rsChoice
    shared.import_reliable_sites(join(installdir,'data','shared'))
    #hello contains the first 10 bytes of modulus of the auditor's pubkey
    #this is how the auditor knows that we are addressing him.
    modulus = shared.bi2ba(auditorPubKey.n)[:10]
    signed_hello = rsa.sign('ae_hello'+my_nick, myPrvKey, 'SHA-1')
    rsChoice = random.choice(shared.reliable_sites.keys())
    print ("Chosen site: ",rsChoice)
    rs_n = shared.reliable_sites[rsChoice][1].decode('hex')
    rs_e = shared.bi2ba(65537,fixed=4)

    bIsAuditorRegistered = False
    for attempt in range(6): #try for 6*10 secs to find the auditor
        if bIsAuditorRegistered == True: break #previous iteration successfully regd the auditor
        time_attempt_began = int(time.time())
        shared.tlsn_send_single_msg(' :ae_hello:',modulus+signed_hello,auditorPubKey)
        shared.tlsn_send_single_msg(' :rs_pubkey:',rs_n+rs_e+rsChoice,auditorPubKey)
        signed_hello_message_dict = {}
        full_signed_hello = ''
        while not bIsAuditorRegistered:
            if int(time.time()) - time_attempt_began > 20: break
            #ignore decryption errors here, as above, the message may be
            #from someone else's handshake
            x = shared.tlsn_receive_single_msg('ao_hello:',myPrvKey,my_nick,iDE=True)
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
                        rsa.verify('ao_hello'+returned_auditor_nick, full_signed_hello, auditorPubKey)
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

#Make a local copy of firefox, find the binary, install the new profile
#and start up firefox with that profile.
def start_firefox(FF_to_backend_port, firefox_install_path):
    #find the binary *before* copying; acts as sanity check
    ffbinloc = {'linux':['firefox'],'mswin':['firefox.exe'],'macos':['Contents','MacOS','firefox']}
    assert os.path.isfile(join(*([firefox_install_path]+ffbinloc[OS]))),\
           "Firefox executable not found - invalid Firefox application directory."
        
    local_ff_copy = join(datadir,'Firefox.app') if OS=='macos' else join(datadir,'firefoxcopy')
    if not os.path.exists(local_ff_copy):
        #on my fresh ubuntu 14.04 the file 'hyphenation' is a broken link which
        #causes shutil.copytree to throw an Exception
        #Some other links may be broken on other systems
        #Let's find the list of all broken links anf ignore them when copying
        broken_links = []
        for root, dirs, files in os.walk(firefox_install_path):         
            for name  in dirs+files:
                path = join(root, name)
                if not os.path.islink(path): continue
                #check if link's broken
                target_relpath = os.readlink(path)
                target_path = os.path.realpath(join(root, target_relpath))
                if not os.path.exists(path): broken_links.append(path)
        if len(broken_links):
            def ignore_callback(directory, files):
                """Return a non-empty ignore list only for broken links"""
                if not  files: #this is a callback for one directory only
                    if directory in broken_links: return (directory)
                    else: return ()
                #else this is a callback for a list of files
                files_fullpaths = [join(directory, onefile) for onefile in files]
                ignore_fullpath = list(set(broken_links) & set(files_fullpaths))
                if ignore_fullpath: #we need a list of basenames, not full paths
                    return [os.path.basename(onepath) for onepath in ignore_fullpath]
                else: return ()
        try:
            #enable the callback only if there is actually a broken link            
            shutil.copytree(firefox_install_path, local_ff_copy, 
                        ignore=ignore_callback if len(broken_links) else None)
        except  Exception,e:   
            #we dont want a half-copied dir. Delete everything and rethrow
            shutil.rmtree(local_ff_copy)
            raise e
        
    firefox_exepath = join(*([local_ff_copy]+ffbinloc[OS]))
    
    logs_dir = join(datadir, 'logs')
    if not os.path.isdir(logs_dir): os.makedirs(logs_dir)
    with open(join(logs_dir, 'firefox.stdout'), 'w') as f: pass
    with open(join(logs_dir, 'firefox.stderr'), 'w') as f: pass
    ffprof_dir = join(datadir, 'FF-profile')
    if not os.path.exists(ffprof_dir): os.makedirs(ffprof_dir)
    shutil.copyfile(join(datadir,'prefs.js'),join(ffprof_dir,'prefs.js'))
    shutil.copyfile(join(datadir,'localstore.rdf'),join(ffprof_dir,'localstore.rdf'))
    if OS=='macos':
        bundles_dir = os.path.join(local_ff_copy, 'Contents','MacOS','distribution', 'bundles')
    else:
        bundles_dir = os.path.join(local_ff_copy, 'distribution', 'bundles')
    if not os.path.exists(bundles_dir):
        os.makedirs(bundles_dir)    
    for ext_dir in ['tlsnotary@tlsnotary','ClassicThemeRestorer@ArisT2Noia4dev']:
        if not os.path.exists(join(bundles_dir,ext_dir)):
            shutil.copytree(join(datadir, 'FF-addon', ext_dir),join(bundles_dir, ext_dir))                  
    os.putenv('FF_to_backend_port', str(FF_to_backend_port))
    os.putenv('FF_first_window', 'true')   #prevents addon confusion when websites open multiple FF windows

    if ('test' in sys.argv): 
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
    bWasStarted = False
    for i in range(3):
        FF_to_backend_port = random.randint(1025,65535)
        print ('Starting http server to communicate with Firefox addon')
        try:
            httpd = shared.StoppableHttpServer(('127.0.0.1', FF_to_backend_port), HandlerClass)
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
def quit(sig=0, frame=0):
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
    mod_dir = join(datadir, 'python', modname)
    if not os.path.exists(mod_dir):
        print ('Extracting '+modname + '.tar.gz...')
        with open(join(datadir, 'python', modname+'.tar.gz'), 'rb') as f: tarfile_data = f.read()
        if md5(tarfile_data).hexdigest() !=  modhash:
            raise Exception ('Wrong hash')
        os.chdir(join(datadir, 'python'))
        tar = tarfile.open(join(datadir, 'python', modname+'.tar.gz'), 'r:gz')
        tar.extractall()
        tar.close()
   
if __name__ == "__main__":
    #for md5 hash, see https://pypi.python.org/pypi/<module name>/<module version>
    modules_to_load = {'rsa-3.1.4':'b6b1c80e1931d4eba8538fd5d4de1355',\
                       'pyasn1-0.1.7':'2cbd80fcd4c7b1c82180d3d76fee18c8',\
                       'slowaes':'','requests-2.3.0':'7449ffdc8ec9ac37bbcd286003c80f00'}
    for x,h in modules_to_load.iteritems():
        first_run_check(x,h)
        sys.path.append(join(datadir, 'python', x))
        
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
                raise Exception("Could not set firefox install path")
            firefox_install_path = join("/","Applications","Firefox.app")
        else:
            raise Exception("Unrecognised operating system.")
        
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
        
    ff_retval = start_firefox(FF_to_backend_port, firefox_install_path)
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
