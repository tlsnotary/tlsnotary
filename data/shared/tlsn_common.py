from __future__ import print_function
from ConfigParser import SafeConfigParser
import os
import threading
import select, socket, time
#General utility objects used by both auditor and auditee.

config = SafeConfigParser()

config_location = os.path.join(os.path.dirname(os.path.realpath(__file__)),'tlsnotary.ini')

required_options = {'IRC':['irc_server','irc_port','channel_name']}

def load_program_config():    
    loadedFiles = config.read([config_location])
    #detailed sanity checking :
    #did the file exist?
    if len(loadedFiles) != 1:
        raise Exception("Could not find config file: "+config_location)
    #check for sections
    for s in required_options:
        if s not in config.sections():
            raise Exception("Config file does not contain the required section: "+s)
    #then check for specific options
    for k,v in required_options.iteritems():
        for o in v:
            if o not in config.options(k):
                raise Exception("Config file does not contain the required option: "+o)


def recv_socket(sckt):
    bDataFromServerSeen = False
    databuffer = ''
    last_time_data_was_seen_from_server = 0
    while True:
        rlist, wlist, xlist = select.select((sckt,), (), (sckt,), 1)
        if len(rlist) ==  len(xlist) == 0: #timeout
            if not bDataFromServerSeen: continue
            #TODO dont rely on a fixed timeout 
            if int(time.time()) - last_time_data_was_seen_from_server < int(config.get("General","server_response_timeout")): continue
            return databuffer
        if len(xlist) > 0:
            print ('Socket exceptional condition. Terminating connection')
            return ''
        if len(rlist) == 0:
            print ('Python internal socket error: rlist should not be empty. Please investigate. Terminating connection')
            return ''
        #else rlist contains socket with data
        #(actually, only one socket involved)
        for rsocket in rlist:
            data = rsocket.recv( 1024*1024 )
            if not data: #socket closed
                if not databuffer:
                    print('Server closed the socket and sent no data')
                    return None
                #else the server sent a response and closed the socket
                return databuffer
            bDataFromServerSeen = True
            last_time_data_was_seen_from_server = int(time.time())
            databuffer += data
            

#a thread which returns a value. This is achieved by passing self as the first argument to a target function
#the target_function(parentthread, arg1, arg2) can then set, e.g parentthread.retval
class ThreadWithRetval(threading.Thread):
    def __init__(self, target, args=()):
        super(ThreadWithRetval, self).__init__(target=target, args = (self,)+args )
    retval = ''

def bigint_to_bytearray(bigint,fixed=None):
    m_bytes = []
    while bigint != 0:
        b = bigint%256
        m_bytes.insert( 0, b )
        bigint //= 256
    if fixed:
        padding = fixed - len(m_bytes)
        if padding > 0: m_bytes = [0]*padding + m_bytes
    return bytearray(m_bytes)


def xor(a,b):
    return bytearray([ord(a) ^ ord(b) for a,b in zip(a,b)])

def bigint_to_list(bigint):
    m_bytes = []
    while bigint != 0:
        b = bigint%256
        m_bytes.insert( 0, b )
        bigint //= 256
    return m_bytes

#convert bytearray into int
def ba2int(byte_array):
    return int(str(byte_array).encode('hex'), 16)
