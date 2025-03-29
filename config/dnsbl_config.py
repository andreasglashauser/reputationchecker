from models.dnsbl import DNSBLService

DNSBL_SERVICES = {
    'spamhaus': DNSBLService(
        name='spamhaus',
        dnsbl='zen.spamhaus.org',
        description='Spamhaus ZEN (includes SBL, XBL, and PBL)',
        category='spam',
        special=True
    ),
    'barracuda': DNSBLService(
        name='barracuda',
        dnsbl='b.barracudacentral.org',
        description='Barracuda Reputation Block List',
        category='spam',
        special=True
    ),
    'spamcop': DNSBLService(
        name='spamcop',
        dnsbl='bl.spamcop.net',
        description='SpamCop Blocking List',
        category='spam',
        special=True
    ),
    'dronebl': DNSBLService(
        name='dronebl',
        dnsbl='dnsbl.dronebl.org',
        description='DroneBL (Botnet Detection)',
        category='botnet',
        special=True
    ),
    'tor': DNSBLService(
        name='tor',
        dnsbl='tor.dan.me.uk',
        description='Tor Exit Node List',
        category='anonymization'
    ),    
    'blocklist_de': DNSBLService(
        name='blocklist_de',
        dnsbl='bl.blocklist.de',
        description='Blocklist.de (Scanner/Probe Detection)',
        category='scanner',
        special=True
    ),
    'cinsscore': DNSBLService(
        name='cinsscore',
        dnsbl='cinsscore.com',
        description='CINSscore (Bad IPs)',
        category='badips',
        special=True
    ),
    'swinog (dnsrbl)': DNSBLService(
        name='swinog (dnsrbl)',
        dnsbl='dnsrbl.swinog.ch',
        description='Realtime blacklist assembled by spamtraps',
        category='spam',
    ),
    'swinog (spamrbl)': DNSBLService(
        name='swinog (spamrbl)',
        dnsbl='spamrbl.swinog.ch',
        description='IP-adresses from catched spammails',
        category='spam',
    ),  
    'swinog (uribl)': DNSBLService(
        name='swinog (uribl)',
        dnsbl='uribl.swinog.ch',
        description='Realtime blacklist built from spamtrap sources',
        category='spam',
    ),  
    'lashback': DNSBLService(
        name='lashback',
        dnsbl='blacklist.lashback.com',
        description='world\'s largest unsubscribe intelligence database',
        category='spam',
    ),  
    'spamrats': DNSBLService(
        name='spamrats',
        dnsbl='all.spamrats.com',
        description='Spamrats ALL',
        category='badips',
        special=True
    ),
    'mailspike': DNSBLService(
        name='mailspike',
        dnsbl='bl.mailspike.net',
        description='Mailspike Reputation Service',
        category='reputation',
        special=True
    ),
    'sem-backscatter': DNSBLService(
        name='sem-backscatter',
        dnsbl='backscatter.spameatingmonkey.net',
        description='SpamEatingMonkey Backscatter',
        category='spam',
    ),
    'sem-black': DNSBLService(
        name='sem-black',
        dnsbl='bl.spameatingmonkey.net',
        description='SpamEatingMonkey Black',
        category='spam',
    ),
    'psbl-surriel': DNSBLService(
        name='psbl-surriel',
        dnsbl='psbl.surriel.com',
        description='Passive Spam Block List',
        category='spam',
    ),
    'hostkarma': DNSBLService(
        name='hostkarma',
        dnsbl='hostkarma.junkemailfilter.com',
        description='Hostkarma (Junk Email Filter)',
        category='reputation',
        special=True
    ),
} 