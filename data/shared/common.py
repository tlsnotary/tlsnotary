from ConfigParser import SafeConfigParser
import os
config = SafeConfigParser()

config_location = os.path.join('data','shared','tlsnotary.ini')

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
            raise Exception("Config file tlsnotary.ini does not contain the required section: "+s)
    #then check for specific options
    for k,v in required_options.iteritems():
        for o in v:
            if o not in config.options(k):
                raise Exception("Config file tlsnotary.ini does not contain the required option: "+o)
