import socket
IRCsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
chunk_size = 350
import socket
from tlsn_common import *
verbose = False

'''log to console'''
def ltc(msg):
    if verbose:
        print (msg)

def start_connection(my_nick):
    '''Connects to IRC using my_nick as nick and the settings for IRC
    in the config file in shared.config_location.
    No return - failure will be indicated by Exceptions.
    '''
    IRCsocket.connect((config.get('IRC','irc_server'), int(config.get('IRC','irc_port'))))
    IRCsocket.send('USER %s %s %s %s' % ('these', 'arguments', 'are', 'optional') + '\r\n')
    IRCsocket.send('NICK ' + my_nick + '\r\n')
    IRCsocket.send('JOIN %s' % ('#'+config.get('IRC','channel_name')) + '\r\n')
    IRCsocket.settimeout(1)


def send_raw(data):
    '''Sending a single message without authentication or acks
    '''
    IRCsocket.send('PRIVMSG ' + '#' + config.get('IRC','channel_name') +' ' + data +' \r\n')

def send_msg(data,ackQ,recipient,seq_init=100000):
    '''Send a message <data> on an already negotiated connection ;
    wait for an acknowledgement by polling for it on Queue ackQ
    Messages are sent with sequence numbers initialised at seq_init,
    or 0 if seq_init is undef.
    Messages larger than chunk_size are split into chunks with line endings
    CRLF and EOL according to tlsnotary's messaging protocol.
    Return 'success' only if message was sent and ack received correctly, otherwise 'failure'.
    '''
    if not hasattr(send_msg, "my_seq"):
        if not seq_init: seq_init = 0
        send_msg.my_seq = seq_init #static variable. Initialized only on first function's run

    #split up data longer than chunk_size bytes (IRC message limit is 512 bytes including the header data)
    #'\r\n' must go to the end of each message
    chunks = len(data)/chunk_size + 1
    if len(data)%chunk_size == 0: chunks -= 1 #avoid creating an empty chunk if data length is a multiple of chunk_size

    for chunk_index in range(chunks) :
        send_msg.my_seq += 1
        chunk = data[chunk_size*chunk_index:chunk_size*(chunk_index+1)]
        for i in range (3):
            bWasMessageAcked = False
            ending = ' EOL ' if chunk_index+1==chunks else ' CRLF ' #EOL for the last chunk, otherwise CRLF
            irc_msg = 'PRIVMSG ' +'#' + config.get('IRC','channel_name') + ' :' + recipient + ' seq:' + str(send_msg.my_seq) + ' ' + chunk + ending +' \r\n'
            #empty the ack queue. Not using while True: because sometimes an endless loop would happen TODO: find out why
            for j in range(5):
                try: ackQ.get_nowait()
                except: pass
            bytessent = IRCsocket.send(irc_msg)
            ltc('SENT: ' + str(bytessent) + ' ' + irc_msg)
            try:
                ack_check = ackQ.get(block=True, timeout=3)
            except: continue #send again because ack was not received
            if not str(send_msg.my_seq) == ack_check: continue
            #else: correct ack received
            bWasMessageAcked = True
            break

        if not bWasMessageAcked:
            return 'failure'
    return 'success'


def receive_single_msg(msg_type,my_nick=None):
    '''Receive a single message of tlsnotary format either sent directly to this
    nick (meaning message length is 5 including nick), or not specifically
    to this nick (message length is 4), of type msg_type, or of one of the
    types in tuple (of strings) msg_type.
    Non blocking receipt; if no message is found or the message doesn't match,
    returns False.
    If a matching message is found, returns (<msg>,<nick of sending counterparty>)
    Note that the returned <msg> still contains the msg_type at the beginning
    '''
    msg_len = 5 if my_nick else 4

    buffer = ''
    try: buffer = IRCsocket.recv(1024)
    except: return False
    if not buffer: return False
    ltc(buffer)

    #sometimes the IRC server may pack multiple PRIVMSGs into one message separated with /r/n/
    messages = buffer.split('\r\n')
    for onemsg in messages:
        msg = onemsg.split()
        if len(msg)==0 : continue  #stray newline
        if ping_pong(msg): continue
        if not ((len(msg) == 5 and my_nick) or (len(msg) == 4 and not my_nick)): continue

        #NB, since startswith() accepts tuples or strings, either are acceptable as argument
        correct_without_nick = (msg[1]=='PRIVMSG' and msg[2]=='#' + config.get('IRC','channel_name') \
                                        and msg[3].startswith(msg_type))
        correct_with_nick = my_nick and (msg[1]=='PRIVMSG' and msg[2]=='#' + config.get('IRC','channel_name') \
                                        and msg[3]==':'+my_nick and msg[4].startswith(msg_type))
        if not ((my_nick and correct_with_nick) or (correct_without_nick)):
            continue
        return (msg[msg_len-1],find_nick(msg))

    #no messages were a match
    return False

def ping_pong(msg):
    '''Answer with PONG as per RFC 1459'''
    if msg[0] == "PING":
        IRCsocket.send("PONG %s" % msg[1])
        return True
    return False

def find_nick(msg):
    '''Returns message sender's nick from the tlsnotary/IRC message format'''
    exclamationMarkPosition = msg[0].find('!')
    return msg[0][1:exclamationMarkPosition]

def msg_receiver(my_nick,counterparty_nick,ackQueue,recvQueue,message_headers,seq_init=100000):
    '''Intended to be run as a thread; puts msgs sent to my_nick from counterparty_nick
    onto the Queue recvQueue, and sends acknowledgements onto ackQueue, filtering out
    messages whose headers/topics are not in message_headers, and using sequence numbering
    starting from seq_init (or 0 if seq_init is undef).
    Messages are received in chunk size according to line endings CRLF and EOL, as per tlsnotary's
    messaging protocol.
    '''
    #TODO this can be changed now
    if not hasattr(msg_receiver, 'last_seq_which_i_acked'):
        if not seq_init: seq_init=0
        msg_receiver.last_seq_which_i_acked = seq_init #static variable. Initialized only on first function's run

    chunks = []
    while True:
        buffer = ''
        try: buffer = IRCsocket.recv(1024)
        except: continue #1 sec timeout
        if not buffer: continue

        #sometimes the IRC server may pack multiple PRIVMSGs into one message separated with /r/n/
        messages = buffer.split('\r\n')

        for onemsg in messages:
            msg = onemsg.split()
            if len(msg) == 0: continue  #stray newline

            if ping_pong(msg): continue

            #filter irrelevant chan messages
            if not len(msg) >= 5: continue
            if not (msg[1] == 'PRIVMSG' and msg[2] == '#' + config.get('IRC','channel_name') and msg[3] == ':'+my_nick ): continue
            if not counterparty_nick == find_nick(msg): continue

            #this is one of our messages; output to console
            ltc('RECEIVED:' + buffer)

            #acknowledgements are not our business here; put them on the queue
            if len(msg)==5 and msg[4].startswith('ack:'):
                ackQueue.put(msg[4][len('ack:'):])
                continue

            #wrongly formatted message; ignore (TODO: needs a warning?)
            if not (len(msg)==7 and msg[4].startswith('seq:')): continue

            his_seq = int(msg[4][len('seq:'):])
            if his_seq <=  msg_receiver.last_seq_which_i_acked:
                #the other side is out of sync, send an ack again
                IRCsocket.send('PRIVMSG ' + '#' + config.get('IRC','channel_name') + ' :' + counterparty_nick + ' ack:' + str(his_seq) + ' \r\n')
                continue

            #we did not receive the next seq in order
            if not his_seq == msg_receiver.last_seq_which_i_acked +1: continue

            #else we got a new seq
            if len(chunks)==0 and not msg[5].startswith(message_headers) : continue

            #'CRLF' is used at the end of the first chunk, 'EOL' is used to show that there are no more chunks
            chunks.append(msg[5])
            IRCsocket.send('PRIVMSG ' + '#' + config.get('IRC','channel_name') + ' :' + counterparty_nick + ' ack:' + str(his_seq) + ' \r\n')
            msg_receiver.last_seq_which_i_acked = his_seq
            if msg[-1]=='EOL':
                assembled_message = ''.join(chunks)
                recvQueue.put(assembled_message)
                chunks = []

