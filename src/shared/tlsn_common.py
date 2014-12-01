from __future__ import print_function
from ConfigParser import SafeConfigParser
from SocketServer import ThreadingMixIn
from struct import pack
import os, binascii, itertools, re, random
import threading, BaseHTTPServer
import select, time, socket
#General utility objects used by both auditor and auditee.

config = SafeConfigParser()

config_location = os.path.join(os.path.dirname(os.path.realpath(__file__)),'tlsnotary.ini')

required_options = {'IRC':['irc_server','irc_port','channel_name']}

reliable_sites = {}
smallprimes = (2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101)            


#file transfer functions - currently only used for sending
#ciphertext to auditor
def sendspace_getlink(mfile,rg,rp):
    reply = rg('https://www.sendspace.com/', timeout=25)
    url_start_pos = reply.text.find('<form method="post" action="https://') + len('<form method="post" action="')
    if url_start_pos == -1:
        print ('sendspace.com changed its API. Please let the developers know')        
        raise Exception ('sendspace.com changed its API. Please let the developers know')        
    url_len = reply.text[url_start_pos:].find('"')
    url = reply.text[url_start_pos:url_start_pos+url_len]
    
    sig_start_pos = reply.text.find('name="signature" value="') + len('name="signature" value="')
    if sig_start_pos == -1:
        print ('sendspace.com changed its API. Please let the developers know')        
        raise Exception ('sendspace.com changed its API. Please let the developers know')        
    sig_len = reply.text[sig_start_pos:].find('"')
    sig = reply.text[sig_start_pos:sig_start_pos+sig_len]
    
    progr_start_pos = reply.text.find('name="PROGRESS_URL" value="') + len('name="PROGRESS_URL" value="')
    if progr_start_pos == -1:
        print ('sendspace.com changed its API. Please let the developers know')        
        raise Exception ('sendspace.com changed its API. Please let the developers know')        
    progr_len = reply.text[progr_start_pos:].find('"')
    progr = reply.text[progr_start_pos:progr_start_pos+progr_len]
    
    r=rp(url, files={'upload_file[]': open(mfile, 'rb')}, data={
        'signature':sig, 'PROGRESS_URL':progr, 'js_enabled':'0', 
        'upload_files':'', 'terms':'1', 'file[]':'', 'description[]':'',
        'recpemail_fcbkinput':'recipient@email.com', 'ownemail':'', 'recpemail':''}, timeout=25)
    
    link_start_pos = r.text.find('"share link">') + len('"share link">')
    if link_start_pos == -1:
        print ('sendspace.com changed its API. Please let the developers know')        
        raise Exception ('sendspace.com changed its API. Please let the developers know')        
    link_len = r.text[link_start_pos:].find('</a>')
    link = r.text[link_start_pos:link_start_pos+link_len]
    
    dl_req = rg(link)
    dl_start_pos = dl_req.text.find('"download_button" href="') + len('"download_button" href="')
    if dl_start_pos == -1:
        print ('sendspace.com changed its API. Please let the developers know')        
        raise Exception ('sendspace.com changed its API. Please let the developers know')        
    dl_len = dl_req.text[dl_start_pos:].find('"')
    dl_link = dl_req.text[dl_start_pos:dl_start_pos+dl_len]
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
    #check that key is a string of integers
    try:
        int(key)
    except:
        print ('pipebytes.com changed its API. Please let the developers know')        
        raise Exception ('pipebytes.com changed its API. Please let the developers know')        
    rp('http://host03.pipebytes.com/setmessage.php?r='+
                           ('%.16f' % random.uniform(0,1))+'&key='+key, {'message':''}, timeout=5)
    thread = threading.Thread(target= pipebytes_post, args=(key, mfile, rp))
    thread.daemon = True
    thread.start()
    time.sleep(1)               
    rg('http://host03.pipebytes.com/status.py?key='+key+
                          '&touch=yes&r='+('%.16f' % random.uniform(0,1)), timeout=5)
    return ('http://host03.pipebytes.com/get.py?key='+key)

def qfs_getlink(mfile, rg, rp):
    reply1 = rp('http://qfs.mobi/upload.aspx', files={'file': open(mfile, 'rb')})
    html = reply1.text
    magicstr = 'has been uploaded to'
    magicstr_pos = html.find(magicstr)
    if magicstr == -1:
        print ('qfs.mobi changed its API. Please let the developers know')        
        raise Exception ('qfs.mobi changed its API. Please let the developers know')
    start = magicstr_pos + len(magicstr)
    open_quote = start + html[start:].find('href="') + len('href="')
    close_quote = open_quote + html[open_quote+1:].find('"')
    url1 = html[open_quote:close_quote+1]
    
    html = rg(url1).text
    magicstr = '/downloadCached'
    magicstr_pos = html.find(magicstr)
    if magicstr == -1:
        print ('qfs.mobi changed its API. Please let the developers know')        
        raise Exception ('qfs.mobi changed its API. Please let the developers know')
    open_quote = magicstr_pos
    close_quote = open_quote + html[open_quote+1:].find('"')
    url_part = html[open_quote:close_quote+1]
    full_url = 'http://qfs.mobi'+url_part.replace('amp;','')
    return full_url
    
def loadto_getlink(mfile, rg, rp):
    html = rg('http://load.to').text
    magicstr = 'enctype="multipart/form-data" action="'
    magicstr_pos = html.find(magicstr)
    if magicstr == -1:
        print ('load.to changed its API. Please let the developers know')        
        raise Exception ('load.to changed its API. Please let the developers know')
    start =  magicstr_pos + len(magicstr)
    open_quote = start
    close_quote = open_quote + html[open_quote+1:].find('"')
    posturl = html[open_quote:close_quote+1]
        
    postreply = rp(posturl, files={'upfile_0': open(mfile, 'rb')},
                  data ={'imbedded_progress_bar':'0', 'upload_range':'1', 'email':'',
                         'filecomment':'', 'submit':'Upload'})
    posthtml = postreply.text
    
    magicstr = 'Download:'
    magicstr_pos = posthtml.find(magicstr)
    if magicstr_pos == -1:
        print ('load.to changed its API. Please let the developers know')        
        raise Exception ('load.to changed its API. Please let the developers know')
    start =  magicstr_pos + len(magicstr)
    open_quote = start + posthtml[start:].find('href="') + len('href="')
    close_quote = open_quote + posthtml[open_quote+1:].find('"')
    dlurl = posthtml[open_quote:close_quote+1]
    
    dlpagehtml = rg(dlurl).text
    magicstr = 'form method="post" action="'
    magicstr_pos = dlpagehtml.find(magicstr)
    if magicstr_pos == -1:
        print ('load.to changed its API. Please let the developers know')        
        raise Exception ('load.to changed its API. Please let the developers know')
    start =magicstr_pos + len(magicstr)
    open_quote = start
    close_quote = open_quote + dlpagehtml[open_quote+1:].find('"')
    finaldllink = dlpagehtml[open_quote:close_quote+1]
    return finaldllink    

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

def check_complete_records(d):
    '''Given a response d from a server,
    we want to know if its contents represents
    a complete set of records, however many.'''
    assert d[1:3]=='\x03\x01',"invalid ssl data"
    l = ba2int(d[3:5])
    if len(d)< l+5: return False
    elif len(d)==l+5: return True
    else: return check_complete_records(d[l+5:])

def create_sock(server,prt):
    returned_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    returned_sock.settimeout(int(config.get("General","tcp_socket_timeout"))) 
    returned_sock.connect((server, prt))    
    return returned_sock
    
def recv_socket(sckt,is_handshake=False):
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
            if is_handshake: 
                if check_complete_records(databuffer): return databuffer #else, just continue loop
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
        return self.retval
 

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
        return self.retval
    
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
    
    
def gunzip_http(http_data):
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
    
       
def dechunk_http(http_data):
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

def random_non_zero(byte_len):
    ba = os.urandom(byte_len)
    while True:
        pos = ba.find('\x00')
        if pos == -1:
            break
        ba = ba[:pos]+os.urandom(1)+ba[pos+1:]
    return ba

def generate_prime(bits):
    s = 0
    hundreds = 0
    while True:
        #time.sleep(0.1) #go easy on the CPU if speed is not critical
        s += 1
        if s == 100:
            hundreds += 1
            s = 0
            print('Finding prime. Try no ' + str(hundreds*100))
        #get and odd int
        candidate = read_random_int(bits) | 1
        if is_probably_prime(candidate, 40):
            return candidate

def is_probably_prime(candidate, k):
    for prime in smallprimes:
        if candidate % prime == 0:     
            return False
    for i in xrange(k):
        test = random.randrange(2, candidate - 1) | 1
        if rabin_miller_witness(test, candidate):
            return False
    return True

#copied from https://github.com/mikeivanov/paillier/blob/master/primes.py
def rabin_miller_witness(test, candidate):
    """Using Rabin-Miller witness test, will return True if candidate is
       definitely not prime (composite), False if it may be prime."""    
    return 1 not in ipow(test, candidate-1, candidate)    

#copied from https://github.com/mikeivanov/paillier/blob/master/primes.py
def ipow(a, b, n):
    """calculates (a**b) % n via binary exponentiation, yielding itermediate
       results as Rabin-Miller requires"""
    A = a = long(a % n)
    yield A
    t = 1L
    while t <= b:
        t <<= 1   
    # t = 2**k, and t > b
    t >>= 2
    while t:
        A = (A * A) % n
        if t & b:
            A = (A * a) % n
        yield A
        t >>= 1
        
#copied from pyrsa
def extended_gcd(a, b):
    '''Returns a tuple (r, i, j) such that r = gcd(a, b) = ia + jb
    '''
    # r = gcd(a,b) i = multiplicitive inverse of a mod b
    #      or      j = multiplicitive inverse of b mod a
    # Neg return values for i or j are made positive mod b or a respectively
    # Iterateive Version is faster and uses much less stack space
    x = 0
    y = 1
    lx = 1
    ly = 0
    oa = a                             #Remember original a/b to remove 
    ob = b                             #negative values from return results
    while b != 0:
        q = a // b
        (a, b)  = (b, a % b)
        (x, lx) = ((lx - (q * x)),x)
        (y, ly) = ((ly - (q * y)),y)
    if (lx < 0): lx += ob              #If neg wrap modulo orignal b
    if (ly < 0): ly += oa              #If neg wrap modulo orignal a
    return (a, lx, ly)                 #Return only positive values

#copied from pyrsa
def inverse(x, n):
    '''Returns x^-1 (mod n)'''
    (divider, inv, _) = extended_gcd(x, n)
    if divider != 1:
        raise ValueError("x (%d) and n (%d) are not relatively prime" % (x, n))
    return inv
 
#copied from pyrsa
def read_random_bits(nbits):
    '''Reads 'nbits' random bits.

    If nbits isn't a whole number of bytes, an extra byte will be appended with
    only the lower bits set.
    '''

    nbytes, rbits = divmod(nbits, 8)

    # Get the random bytes
    random_data = os.urandom(nbytes)

    # Add the remaining random bits
    if rbits > 0:
        random_value = ord(os.urandom(1))
        random_value >>= (8 - rbits)
        #random_data = byte(random_value) + random_data
        random_data = pack("B", random_value) + random_data

    return random_data

#copied from pyrsa
def read_random_int(nbits):
    '''Reads a random integer of approximately nbits bits.
    '''

    random_data = read_random_bits(nbits)
    #value = transform.bytes2int(random_data)
    value = int(binascii.hexlify(random_data), 16)
    

    # Ensure that the number is large enough to just fill out the required
    # number of bits.
    value |= 1 << (nbits - 1)

    return value

#copied from pyrsa
def randint(max_value):
    '''Returns a random integer x with 1 <= x <= max_value
    
    May take a very long time in specific situations. If max_value needs N bits
    to store, the closer max_value is to (2 ** N) - 1, the faster this function
    is.
    '''

    #bit_size = common.bit_size(max_value)
    bit_size = int(max_value).bit_length()

    tries = 0
    while True:
        value = read_random_int(bit_size)
        if value <= max_value:
            break

        if tries and tries % 10 == 0:
            # After a lot of tries to get the right number of bits but still
            # smaller than max_value, decrease the number of bits by 1. That'll
            # dramatically increase the chances to get a large enough number.
            bit_size -= 1
        tries += 1

    return value
 