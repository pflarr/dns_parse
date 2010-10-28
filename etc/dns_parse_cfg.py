# The parse_dns_pcap python script applies the 'dns_parse' parser to each new 
# file in a directory containing dns pcaps. The file names should contain time
# stamps such that a reversed sort of the files by name will put the newest 
# files at the front of the list.
PCAP_DIR = '/var/dns_pcaps/'
# The NETWORKS list contains the file name prefixes for different sets of 
# pcap files in the PCAP directory that need to be parsed. Each prefix will
# be kept track of separately.
NETWORKS = ['tap1', 'tap2']
# Where to store state information on which file was last read.
STATE_DIR = '/var/spool/dns_parse/'
# additional options to pass to DNS parse
#OPTIONS = "-m'<delim>'"
#OPTIONS = "-m''"
# Where to output the parsed DNS data. This log file is appended too directly (not via syslog), if
# that matters.
LOG_FILE = '/var/log/dns_parsed'
# Where to output any errors. 
ERROR_LOG = '/var/log/dns_parser_errors'

