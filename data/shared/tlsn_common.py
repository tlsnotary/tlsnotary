from __future__ import print_function
from ConfigParser import SafeConfigParser
import os
import threading

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


#a thread which returns a value. This is achieved by passing self as the first argument to a target function
#the target_function(parentthread, arg1, arg2) can then set, e.g parentthread.retval
class ThreadWithRetval(threading.Thread):
    def __init__(self, target, args=()):
        super(ThreadWithRetval, self).__init__(target=target, args = (self,)+args )
    retval = ''

def bigint_to_bytearray(bigint):
    m_bytes = []
    while bigint != 0:
        b = bigint%256
        m_bytes.insert( 0, b )
        bigint //= 256
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

#look at tshark's ascii dump (option '-x') to better understand the parsing taking place
def get_html_from_asciidump(ascii_dump):
    hexdigits = set('0123456789abcdefABCDEF')
    binary_html = bytearray()

    if ascii_dump == '':
        print ('empty frame dump',end='\r\n')
        return -1

    #We are interested in
    # "Uncompressed entity body" for compressed HTML (both chunked and not chunked). If not present, then
    # "De-chunked entity body" for no-compression, chunked HTML. If not present, then
    # "Reassembled SSL" for no-compression no-chunks HTML in multiple SSL segments, If not present, then
    # "Decrypted SSL data" for no-compression no-chunks HTML in a single SSL segment.

    uncompr_pos = ascii_dump.rfind('Uncompressed entity body')
    if uncompr_pos != -1:
        for line in ascii_dump[uncompr_pos:].split('\n')[1:]:
            #convert ascii representation of hex into binary so long as first 4 chars are hexdigits
            if all(c in hexdigits for c in line [:4]):
                try: m_array = bytearray.fromhex(line[6:54])
                except: break
                binary_html += m_array
            else:
                #if first 4 chars are not hexdigits, we reached the end of the section
                break
        return binary_html

    #else
    dechunked_pos = ascii_dump.rfind('De-chunked entity body')
    if dechunked_pos != -1:
        for line in ascii_dump[dechunked_pos:].split('\n')[1:]:
            if all(c in hexdigits for c in line [:4]):
                try: m_array = bytearray.fromhex(line[6:54])
                except: break
                binary_html += m_array
            else:
                break
        return binary_html

    #else
    reassembled_pos = ascii_dump.rfind('Reassembled SSL')
    if reassembled_pos != -1:
        for line in ascii_dump[reassembled_pos:].split('\n')[1:]:
            if all(c in hexdigits for c in line [:4]):
                try: m_array = bytearray.fromhex(line[6:54])
                except: break
                binary_html += m_array
            else:
                #http HEADER is delimited from HTTP body with '\r\n\r\n'
                if binary_html.find('\r\n\r\n') == -1:
                    return -1
                break
        return binary_html.split('\r\n\r\n', 1)[1]

    #else
    decrypted_pos = ascii_dump.rfind('Decrypted SSL data')
    if decrypted_pos != -1:
        for line in ascii_dump[decrypted_pos:].split('\n')[1:]:
            if all(c in hexdigits for c in line [:4]):
                try: m_array = bytearray.fromhex(line[6:54])
                except: break
                binary_html += m_array
            else:
                #http HEADER is delimited from HTTP body with '\r\n\r\n'
                if binary_html.find('\r\n\r\n') == -1:
                    return -1
                break
        return binary_html.split('\r\n\r\n', 1)[1]

def get_ciphertext_from_asciidump(ascii_dump):
    '''Explanation
    Relies on tshark's -x hex/ascii dump output format as of 1.10.7
    Given tshark -x output ascii_dump, return the complete ciphertext
    extraced from the reassembled TCP segments, with ssl record headers stripped.
    The returned ciphertext is formatted as a list of integers, suitable for input into
    AES decryption.
    NB the input tshark -x dump should *not* be generated with an sslkeylogfile (I am
    not sure that it wouldn't work, but it's not intended).
    This ciphertext generation is intended to be carried by an auditee who does *not*
    have access to the master secrets.
    '''

    #sanity checks
    if not ascii_dump:
        raise Exception("Cannot find ciphertext; tshark ascii dump appears to be empty.")

    ciphertext = ''

    for data_chunk in re.split('Reassembled TCP \([0-9]+ bytes\):',ascii_dump)[1:]:
        rtcp_ciphertext = ''
        remaining = filter(None,data_chunk.split('\n'))
        #TODO make this easier on the eye.
        linenums = [i for i,x in enumerate(remaining) if (not all(c in string.hexdigits for c in x[:4])) or ('0000'==x[:4] and i != 0)]
        cipher_lines = remaining[:min(linenums)] if len(linenums) else remaining
        for cipher_line in cipher_lines:
            try:
                rtcp_ciphertext += cipher_line.split('  ')[1].replace(' ','').decode('hex')
            except:
                print ("Failed to extract ciphertext from this line: ",cipher_line)
                raise
        #remove the ssl record header (170301XXXX)
        ciphertext += rtcp_ciphertext[5:]
    if not ciphertext:
        raise Exception("Could not find ciphertext in hex-ascii dump")

    ciphertext = map(ord,ciphertext)
    return ciphertext
