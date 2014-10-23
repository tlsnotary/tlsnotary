from __future__ import print_function
from ConfigParser import SafeConfigParser
from SocketServer import ThreadingMixIn
from struct import pack
import os, binascii, itertools, re, random
import threading, BaseHTTPServer
import select, socket, time
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
        candidate = randint(2**bits) | 1
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
    randomdata = os.urandom(nbytes)

    # Add the remaining random bits
    if rbits > 0:
        randomvalue = ord(os.urandom(1))
        randomvalue >>= (8 - rbits)
        #randomdata = byte(randomvalue) + randomdata
        randomdata = pack("B", randomvalue) + randomdata

    return randomdata

#copied from pyrsa
def read_random_int(nbits):
    '''Reads a random integer of approximately nbits bits.
    '''

    randomdata = read_random_bits(nbits)
    #value = transform.bytes2int(randomdata)
    value = int(binascii.hexlify(randomdata), 16)
    

    # Ensure that the number is large enough to just fill out the required
    # number of bits.
    value |= 1 << (nbits - 1)

    return value

#copied from pyrsa
def randint(maxvalue):
    '''Returns a random integer x with 1 <= x <= maxvalue
    
    May take a very long time in specific situations. If maxvalue needs N bits
    to store, the closer maxvalue is to (2 ** N) - 1, the faster this function
    is.
    '''

    #bit_size = common.bit_size(maxvalue)
    bit_size = int(maxvalue).bit_length()

    tries = 0
    while True:
        value = read_random_int(bit_size)
        if value <= maxvalue:
            break

        if tries and tries % 10 == 0:
            # After a lot of tries to get the right number of bits but still
            # smaller than maxvalue, decrease the number of bits by 1. That'll
            # dramatically increase the chances to get a large enough number.
            bit_size -= 1
        tries += 1

    return value
 