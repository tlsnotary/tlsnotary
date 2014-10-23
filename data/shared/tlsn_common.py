from __future__ import print_function
from ConfigParser import SafeConfigParser
from SocketServer import ThreadingMixIn
import os, binascii, itertools, re
import threading, BaseHTTPServer
import select, socket, time
#General utility objects used by both auditor and auditee.

config = SafeConfigParser()

config_location = os.path.join(os.path.dirname(os.path.realpath(__file__)),'tlsnotary.ini')

required_options = {'IRC':['irc_server','irc_port','channel_name']}

reliable_sites = {}

#file transfer functions - currently only used for sending
#ciphertext to auditor
def sendspace_getlink(mfile,rg,rp):
    reply = rg('https://www.sendspace.com/', timeout=25)
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
        'recpemail_fcbkinput':'recipient@email.com', 'ownemail':'', 'recpemail':''}, timeout=25)
    
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


def import_reliable_sites(d):
    '''Read in the site names and ssl ports from the config file,
    and then read in the corresponding pubkeys in browser hex format from
    the file pubkeys.txt in directory d. Then combine this data into the reliable_sites global dict'''
    sites = [x.strip() for x in config.get('SSL','reliable_sites').split(',')]
    ports = [int(x.strip()) for x in config.get('SSL','reliable_sites_ssl_ports').split(',')]
    assert len(sites) == len(ports), "Error, tlsnotary.ini file contains a mismatch between reliable sites and ports"    
    #import hardcoded pubkeys
    with open(os.path.join(d,'pubkeys.txt'),'rb') as f: plines = f.readlines()
    raw_pubkeys= []
    pubkeys = []
    while len(plines):
        next_raw_pubkey = list(itertools.takewhile(lambda x: x.startswith('#') != True,plines))
        k = len(next_raw_pubkey)
        plines = plines[k+1:]
        if k > 0 : raw_pubkeys.append(''.join(next_raw_pubkey))
    for rp in raw_pubkeys: 
        pubkeys.append(re.sub(r'\s+','',rp))
    for i,site in enumerate(sites):
        reliable_sites[site] = [ports[i]]
        reliable_sites[site].append(pubkeys[i])

def checkCompleteRecords(d):
    '''Given a response d from a server,
    we want to know if its contents represents
    a complete set of records, however many.'''
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
    
    
def gunzipHTTP(http_data):
    import gzip
    import StringIO
    http_header = http_data[:http_data.find('\r\n\r\n')+len('\r\n\r\n')]
    #\s* below means any amount of whitespaces
    if re.search(r'content-encoding:\s*deflate', http_header, re.IGNORECASE):
        #TODO manually resend the request with compression disabled
        raise Exception('Please set gzip_disabled = 1 in tlsnotary.ini and rerun the audit')
    if not re.search(r'content-encoding:\s*gzip', http_header, re.IGNORECASE):
        return http_data #nothing to gunzip
    http_body = http_data[len(http_header):]
    ungzipped = http_header
    gzipped = StringIO.StringIO(http_body)
    f = gzip.GzipFile(fileobj=gzipped, mode="rb")
    ungzipped += f.read()    
    return ungzipped
    
       
def dechunkHTTP(http_data):
    '''Dechunk only if http_data is chunked otherwise return http_data unmodified'''
    http_header = http_data[:http_data.find('\r\n\r\n')+len('\r\n\r\n')]
    #\s* below means any amount of whitespaces
    if not re.search(r'transfer-encoding:\s*chunked', http_header, re.IGNORECASE):
        return http_data #nothing to dechunk
    http_body = http_data[len(http_header):]
    
    dechunked = http_header
    cur_offset = 0
    chunk_len = -1 #initialize with a non-zero value
    while True:  
        new_offset = http_body[cur_offset:].find('\r\n')
        if new_offset==-1:  #pre-caution against endless looping
            raise Exception('Incorrectly formed chunked http detected')
        chunk_len_hex  = http_body[cur_offset:cur_offset+new_offset]
        chunk_len = int(chunk_len_hex, 16)
        if chunk_len ==0: break #for properly-formed html we should break here
        cur_offset += new_offset+len('\r\n')   
        dechunked += http_body[cur_offset:cur_offset+chunk_len]
        cur_offset += chunk_len+len('\r\n')    
    return dechunked


def random_int(bits):
    '''Returns a random cryptographically secure int of specified bitlength'''
    bytes_no, extra_bits = divmod(bits, 8)
    if extra_bits: bytes_no += 1
    rand_int = ba2int(os.urandom(bytes_no))
    if extra_bits:
        rand_int >>= (8-extra_bits)
    return rand_int
