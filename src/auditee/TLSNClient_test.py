import sys, tarfile, os, binascii
from os.path import join


#Testing of the tlsnotary client session operation
data_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.dirname(data_dir))

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
from shared.tlsn_ssl import TLSNClientSession as TLSNClientSession
shared.load_program_config()
    
def test_run():
    test_session = shared.TLSNClientSession(server='www.mozilla.org')
    sckt = shared.create_sock(test_session.server_name,test_session.ssl_port)
    test_session.start_handshake(sckt)
    test_session.set_auditee_secret()
    test_session.set_auditor_secret()    
    test_session.extract_mod_and_exp()
    test_session.set_enc_first_half_pms()
    test_session.set_enc_second_half_pms()
    test_session.set_encrypted_pms()
    
    test_session.set_master_secret_half()
    test_session.do_key_expansion()
    
    test_session.client_key_exchange = shared.tlsn_ssl.TLSClientKeyExchange(serialized=None,encryptedPMS=test_session.enc_pms)
    test_session.change_cipher_spec = shared.tlsn_ssl.TLSChangeCipherSpec()
    test_session.handshake_messages[4] = test_session.client_key_exchange.serialized
    test_session.handshake_messages[5] = test_session.change_cipher_spec.serialized
    test_session.set_handshake_hashes()    
    
    verify_data = test_session.get_verify_data_for_finished()
    test_session.client_finished = shared.tlsn_ssl.TLSFinished(serialized=None, verify_data=verify_data)
    test_session.handshake_messages[6] = test_session.client_finished.serialized
    print ("We are about to send the final three handshake messages,")
    print ("They are: ")
    print ([binascii.hexlify(x) for x in test_session.handshake_messages[4:7]])
    #Note that the three messages cannot be packed into one record; 
    #change cipher spec is *not* a handshake message
    shared.tlsn_ssl.tls_sender(sckt,test_session.handshake_messages[4],shared.tlsn_ssl.hs)
    shared.tlsn_ssl.tls_sender(sckt,test_session.handshake_messages[5],shared.tlsn_ssl.chcis) 
    #client finished must be sent encrypted
    #print ('We are about to send finished.')
    #print ('The handshake messages are: ', self.handshake_messages[:5])
    shared.tlsn_ssl.tls_sender(sckt,test_session.handshake_messages[6],shared.tlsn_ssl.hs, conn=test_session.client_connection_state)
    records=[]
    while len(records) < 2:
        rspns = shared.recv_socket(sckt,True)
        x, remaining = shared.tlsn_ssl.tls_record_decoder(rspns)
        assert not remaining, "Server sent spurious non-TLS response"
        records.extend(x)
    test_session.server_ccs = [x for x in records if x.content_type == shared.tlsn_ssl.chcis][0]
    print ("We got this server ccs: ", binascii.hexlify(test_session.server_ccs.fragment))
    sf = [x for x in records if x.content_type == shared.tlsn_ssl.hs][0]
    print ("Cipher suite chosen was: ", test_session.chosen_cipher_suite)
    print ("Server finished is: ", binascii.hexlify(sf.fragment))
    print ("We got rspns: ", binascii.hexlify(rspns))
    with open('testharness','wb') as f: f.write(test_session.dump())
    test_session.server_finished = \
        shared.tlsn_ssl.tls_record_fragment_decoder(shared.tlsn_ssl.hs,sf.fragment, \
                                                    conn=test_session.server_connection_state, \
                                                    ignore_bad_mac=True)[0]
    #store the IV immediately after decrypting Finished; this will be needed
    #by auditor in order to replay the decryption
    test_session.IV_after_finished = test_session.server_connection_state.IV
    sha_verify, md5_verify = test_session.set_handshake_hashes(server=True)
    verify_data_check = test_session.get_verify_data_for_finished(sha_verify=sha_verify,\
                                                md5_verify=md5_verify, is_for_client=False)
    print ("Got this from server: ", binascii.hexlify(test_session.server_finished.verify_data))
    print ("Got this from check: ",binascii.hexlify(verify_data_check))