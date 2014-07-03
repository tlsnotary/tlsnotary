
#TLSNotary's own messaging protocol abstraction layer
#Notes about the protocol:
#1. *All* messages are encrypted - this is possible even though
#   the parties may need to conduct a handshake, as the pub keys
#   are exchanged in advance on a side channel.
#2. All messages start with one of two header types:
#   (a)'client_hello' or 'google_pubkey' or 'server_hello' sent during
#   handshake
#   (b) userid = 'user'+a 10 digit random integer
#   The remainder of the message is whitespace separated
#3. Messages are separated into chunks of size msg_chunk_size,
#   read from the config file. Messages are ended by 'EOL' or 'CRLF',
#   with CRLF indicating that another chunk is to be expected.
#4. Messages whose header is 'userid' have the format: seqno:<seqno> encrypted_chunk [EOL/CRLF]
#5. encrypted_chunk is base64 encoded. The decrypted form has the format: msg_type:msg
#6. Messages with sequence number are acked.
#7. Sequence numbers and acks are *not* encrypted.

#Import the implementation module; a more advanced version
#can read a choice of implementation from config and switch based on that
from irc_messaging import *

from tlsn_crypto import *
from tlsn_common import *
import time

msg_chunk_size = None
initialized = False

#valid types of tlsnotary message to be passed on the private message channel
message_types_from_auditor = ('grsapms_ghmac', 'rsapms_hmacms_hmacek', 'verify_hmac', 'response', 'sha1hmac_for_MS')
message_types_from_auditee =  ('cr_sr_hmac_n_e', 'gcr_gsr', 'verify_md5sha', 'zipsig', 'link', 'commit_hash')


def tlsn_initialise_messaging(my_nick):
    '''Instantiate the connection for user my_nick and set up any parameters'''
    global msg_chunk_size
    msg_chunk_size = int(config.get('General','msg_chunk_size'))
    global initialized
    initialized = True
    start_connection(my_nick)


#does not implement any of: seqnos, acks, recv/ack queues, chunking, encryption, encoding
def tlsn_send_raw(data):
    if not initialized:
        raise Exception("TLSN Messaging not yet instantiated")
    return send_raw(data)


def tlsn_send_single_msg(header,data,pk,ctrprty_nick=None):
    '''send a message without acks/seq nos, but including chunking,
    encoding and encryption; just for handshakes.
    message sent is data, then encrypted and encoded and chunked data.
    If ctrprty_nick is included, this nick is included in the header to direct the message.
    (Only one side of the handshake needs this).
    '''
    header = header if not ctrprty_nick else ':'+ctrprty_nick + ' ' + header
    chunks = len(data)/msg_chunk_size + 1
    if len(data)%msg_chunk_size == 0: chunks -= 1 #avoid creating an empty chunk if data length is a multiple of chunk_size

    for chunk_index in range(chunks) :
        chunk = data[msg_chunk_size*chunk_index:msg_chunk_size*(chunk_index+1)]
        encrypted_encoded_chunk = ee(str(chunk_index)+chunk,pk)
        ending = 'EOL' if chunk_index == chunks-1 else 'CRLF'
        tlsn_send_raw(header+' '+encrypted_encoded_chunk+' '+ending)
        time.sleep(0.5)

def tlsn_send_msg(data,pk,ackQ,recipient,seq_init=100000,raw=False):
    '''Send a message <data> on an already negotiated connection ;
    wait for an acknowledgement by polling for it on Queue ackQ
    Messages are sent with sequence numbers initialised at seq_init,
    or 0 if seq_init is undef.
    Messages larger than chunk_size are split into chunks with line endings.
    After chunking, messages are encrypted to public key pk then base64 encoded.
    CRLF and EOL are appended to the end of chunks according to tlsnotary's messaging protocol.
    Return 'success' only if message was sent and ack received correctly, otherwise 'failure'.
    '''
    if not initialized:
        raise Exception("TLSN Messaging not yet instantiated")

    if not hasattr(tlsn_send_msg, "my_seq"):
        if not seq_init: seq_init = 0
        tlsn_send_msg.my_seq = seq_init #static variable. Initialized only on first function's run

    #split up data longer than chunk_size bytes
    chunks = len(data)/msg_chunk_size + 1
    if len(data)%msg_chunk_size == 0: chunks -= 1 #avoid creating an empty chunk if data length is a multiple of chunk_size

    for chunk_index in range(chunks) :
        tlsn_send_msg.my_seq += 1
        chunk = data[msg_chunk_size*chunk_index:msg_chunk_size*(chunk_index+1)]
        #encrypt and base 64 encode the chunk; if we have used a sensible chunk size
        #this will neither cause a problem for RSA nor for IRC
        encrypted_encoded_chunk = ee(chunk,pk)

        ending = ' EOL ' if chunk_index+1==chunks else ' CRLF ' #EOL for the last chunk, otherwise CRLF
        msg_to_send = ' :' + recipient + ' seq:' + str(tlsn_send_msg.my_seq) + ' ' + encrypted_encoded_chunk + ending

        if not raw:
            for i in range (3):
                bWasMessageAcked = False
                #empty the ack queue. Not using while True: because sometimes an endless loop would happen TODO: find out why
                for j in range(5):
                    try: ackQ.get_nowait()
                    except: pass
                bytes_sent = tlsn_send_raw(msg_to_send)
                try:
                    ack_check = ackQ.get(block=True, timeout=3)
                except: continue #send again because ack was not received
                #print ('ack check is: ',ack_check)
                if not str(tlsn_send_msg.my_seq) == ack_check: continue
                #else: correct ack received
                #print ('message was acked')
                bWasMessageAcked = True
                break

            if not bWasMessageAcked:
                return 'failure'
        else:
            tlsn_send_raw(msg_to_send)

    return 'success'



def tlsn_receive_single_msg(header, pk, my_nick=None):
    '''Non blocking receipt of a single message statelessly
    filtered on a message header, optionally prefixed by a username
    NB This is for handshake messages. All other messaging is handled
    by the tlsn_msg_receiver loop.
    'header' is not currently used but could be to filter.
    Messages received are filtered by header 'my_nick' if defined, otherwise
    all messages are received.
    Messages are decrypted using private key pk and base64 decoded
    Sequence number, plaintext message, ending and (if relevant) nick of sending party
    are returned.
    '''
    if not initialized:
        raise Exception("TLSN Messaging not yet instantiated")

    retval = receive_single_msg(my_nick)
    if not retval:
        return False
    if len(retval) != 2:
        raise Exception ("Invalid return from messaging implementation module")

    msg_array,ctrprty_nick = retval
    header = msg_array[1] if my_nick else msg_array[0]
    encrypted_encoded_msg = msg_array[2] if my_nick else msg_array[1]
    ending = msg_array[-1]
    try:
        msg = dd(encrypted_encoded_msg,pk)
        seq = msg[0]
        msg = ''.join(msg[1:])
    except:
        raise Exception ("Failure in decryption or decoding of message: ", encrypted_encoded_msg)

    return ((header,int(seq),msg,ending),ctrprty_nick)


def tlsn_msg_receiver(my_nick,counterparty_nick,ackQueue,recvQueue,message_headers,pk,seq_init=100000):
    '''Intended to be run as a thread; puts msgs sent to my_nick from counterparty_nick
    onto the Queue recvQueue, and sends acknowledgements onto ackQueue, filtering out
    messages whose headers/topics are not in message_headers, and using sequence numbering
    starting from seq_init (or 0 if seq_init is undef).
    Messages are received in chunks and decrypted using private key pk and base64 decoded, then
    reassembled according to line endings CRLF and EOL, as per tlsnotary's
    messaging protocol.
    '''
    if not initialized:
        raise Exception("TLSN Messaging not yet instantiated")
    #TODO this can be changed now
    if not hasattr(tlsn_msg_receiver, 'last_seq_which_i_acked'):
        if not seq_init: seq_init=0
        tlsn_msg_receiver.last_seq_which_i_acked = seq_init #static variable. Initialized only on first function's run

    chunks = []
    while True:
        eemsg = msg_receiver(my_nick,counterparty_nick)
        if not eemsg: continue #note that the timeout is in the implementation layer

        #acknowledgements are not our business here; put them on the queue
        if eemsg[0].startswith('ack'):
            #acks are not encrypted
            ackQueue.put(eemsg[0][len('ack:'):])
            continue

        if len(eemsg) !=3: continue
        if not eemsg[0].startswith('seq'): continue #wrong format; old server hellos will do this

        msg_decrypted = dd(eemsg[1],pk)
        #print ("decrypted message is: ",msg_decrypted)
        if len(chunks) == 0:
            msg = [msg_decrypted.split(':')[0]] + [':'.join(msg_decrypted.split(':')[1:])]+[eemsg[2]]
        else:
            msg = [None,msg_decrypted,eemsg[2]]

        his_seq = int(eemsg[0][len('seq:'):])
        if his_seq <=  tlsn_msg_receiver.last_seq_which_i_acked:
            #the other side is out of sync, send an ack again
            send_raw(' :' + counterparty_nick + ' ack:' + str(his_seq))
            continue

        #we did not receive the next seq in order
        if not his_seq == tlsn_msg_receiver.last_seq_which_i_acked +1: continue

        #else we got a new seq
        if len(chunks)==0: #a new message is starting
            if not msg[0].startswith(message_headers) : continue
            hdr = msg[0]

        #'CRLF' is used at the end of the first chunk, 'EOL' is used to show that there are no more chunks
        chunks.append(msg[1])
        send_raw(' :' + counterparty_nick + ' ack:' + str(his_seq))
        tlsn_msg_receiver.last_seq_which_i_acked = his_seq
        if msg[-1]=='EOL':
            assembled_message = ''.join(chunks)
            recvQueue.put(hdr+':'+assembled_message)
            chunks = []
