from __future__ import print_function
from ConfigParser import SafeConfigParser
from SocketServer import ThreadingMixIn
import os, binascii
import threading, BaseHTTPServer
import select, socket, time
#General utility objects used by both auditor and auditee.

config = SafeConfigParser()

config_location = os.path.join(os.path.dirname(os.path.realpath(__file__)),'tlsnotary.ini')

required_options = {'IRC':['irc_server','irc_port','channel_name']}

#file transfer functions - currently only used for sending
#ciphertext to auditor
def sendspace_getlink(mfile,rg,rp):
    reply = rg('https://www.sendspace.com/', timeout=5)
    url_start = reply.text.find('<form method="post" action="https://') + len('<form method="post" action="')
    url_len = reply.text[url_start:].find('"')
    url = reply.text[url_start:url_start+url_len]
    
    sig_start = reply.text.find('name="signature" value="') + len('name="signature" value="')
    sig_len = reply.text[sig_start:].find('"')
    sig = reply.text[sig_start:sig_start+sig_len]
    
    progr_start = reply.text.find('name="PROGRESS_URL" value="') + len('name="PROGRESS_URL" value="')
    progr_len = reply.text[progr_start:].find('"')
    progr = reply.text[progr_start:progr_start+progr_len]
    
    r=rp(url, files={'upload_file[]': open(mfile, 'rb')}, data={
        'signature':sig, 'PROGRESS_URL':progr, 'js_enabled':'0', 
        'upload_files':'', 'terms':'1', 'file[]':'', 'description[]':'',
        'recpemail_fcbkinput':'recipient@email.com', 'ownemail':'', 'recpemail':''}, timeout=5)
    
    link_start = r.text.find('"share link">') + len('"share link">')
    link_len = r.text[link_start:].find('</a>')
    link = r.text[link_start:link_start+link_len]
    
    dl_req = rg(link)
    dl_start = dl_req.text.find('"download_button" href="') + len('"download_button" href="')
    dl_len = dl_req.text[dl_start:].find('"')
    dl_link = dl_req.text[dl_start:dl_start+dl_len]
    return dl_link

#pipebytes is not currently used; a backup for failure of sendspace.
def pipebytes_post(key, mfile,rp):
    #the server responds only when the recepient picks up the file
    rp('http://host03.pipebytes.com/put.py?key='+key+'&r='+
                  ('%.16f' % random.uniform(0,1)), files={'file': open(mfile, 'rb')})    


def pipebytes_getlink(mfile,rg,rp):
    reply1 = rg('http://host03.pipebytes.com/getkey.php?r='+
                          ('%.16f' % random.uniform(0,1)), timeout=5)
    key = reply1.text
    reply2 = rp('http://host03.pipebytes.com/setmessage.php?r='+
                           ('%.16f' % random.uniform(0,1))+'&key='+key, {'message':''}, timeout=5)
    thread = threading.Thread(target= pipebytes_post, args=(key, mfile))
    thread.daemon = True
    thread.start()
    time.sleep(1)               
    reply4 = rg('http://host03.pipebytes.com/status.py?key='+key+
                          '&touch=yes&r='+('%.16f' % random.uniform(0,1)), timeout=5)
    return ('http://host03.pipebytes.com/get.py?key='+key)

#end file transfer functions

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

def checkCompleteRecords(d):
    assert d[1:3]=='\x03\x01',"invalid ssl data"
    l = ba2int(d[3:5])
    if len(d)< l+5: return False
    elif len(d)==l+5: return True
    else: return checkCompleteRecords(d[l+5:])
    
def recv_socket(sckt,isHandshake=False):
    last_time_data_was_seen_from_server = 0
    data_from_server_seen = False
    databuffer=''
    while True:
        rlist, wlist, xlist = select.select((sckt,), (), (sckt,), 1)
        if len(rlist) == len(xlist) == 0: #timeout
            #TODO dont rely on a fixed timeout 
            delta = int(time.time()) - last_time_data_was_seen_from_server
            if not data_from_server_seen: continue
            if  delta < int(config.get("General","server_response_timeout")): continue
            return databuffer #we timed out on the socket read 
        if len(xlist) > 0:
            print ('Socket exceptional condition. Terminating connection')
            return ''
        if len(rlist) == 0:
            print ('Python internal socket error: rlist should not be empty. Please investigate. Terminating connection')
            return ''
        for rsckt in rlist:
            data = rsckt.recv(1024*32)
            if not data:
                if not databuffer:
                    print ("Server closed the socket and sent no data")
                    return None
                else:
                    return databuffer
            data_from_server_seen = True  
            databuffer += data
            if isHandshake: 
                if checkCompleteRecords(databuffer): return databuffer #else, just continue loop
            last_time_data_was_seen_from_server = int(time.time())
        
            

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

#processes each http request in a separate thread
#we need threading in order to send progress updates to the frontend in a non-blocking manner
class StoppableThreadedHttpServer (ThreadingMixIn, BaseHTTPServer.HTTPServer):
    """http server that reacts to self.stop flag"""
    retval = ''
    def serve_forever (self):
        """Handle one request at a time until stopped. Optionally return a value"""
        self.stop = False
        self.socket.setblocking(1)
        while not self.stop:
                self.handle_request()
        return self.retval;
    
def bi2ba(bigint,fixed=None):
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
        

