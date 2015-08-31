# analyze_web_in_python
This is a rewrite of analyze_web.rb in python

The website retrieval is done using python requests module

It practically gets all the url contained within the website ([url]) and submit them to virustotal to get available report

Usage - ./analyze_web.rb [user-agent] [url]

USER-AGENT:
ie - 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)'

ff - 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20120101 Firefox/29.0'

chrome - 'Mozilla/5.0 (Windows NT 4.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36'
The field for url needs to be defined with a schema with either http:// or https://

USAGE:
Example - ./analyze_web.py ie http://company.com
Example - ./analyze_web.py ff http://company.com
Example - ./analyze_web.py chrome http://company.com

If you prefer to use the python interpreter, you could import the module as well

Making use of the two functions get_url() and query_vt() as shown below

1) get_url(<ua>, <url>)
2) query_vt([<suspected malicious url>])

Example 
(I want to get all the url contain in www.github.com) - 

>>> import analyze_web
>>> test = analyze_web.get_url('Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)', 'https://www.github.com')
>>> for i in test:
...     print i
... 
https://status.github.com/
https://github.com
https://chrome.google.com
https://github.com/pricing
.
.
.


(I want to submit one or more url to virustotal) -

>>> analyze_web.query_vt(['precisiamowolfi.samatter.com', 'flagman-gpm.com'])
Total url to be queried : 2
Estimate time will be 0.0 minutes as I am using non premium API key...


permalink : https://www.virustotal.com/url/80ee3e8b3acb86f28905ae425b1e1744af3c4498c5a37822625c58d592c11e16/analysis/1440893581/
resource : precisiamowolfi.samatter.com
url : http://precisiamowolfi.samatter.com/
response_code : 1
scan_date : 2015-08-30 00:13:01
scan_id : 80ee3e8b3acb86f28905ae425b1e1744af3c4498c5a37822625c58d592c11e16-1440893581
verbose_msg : Scan finished, scan information embedded in this object
filescan_id : None
positives : 5
total : 63
Google Safebrowsing : malware site
Kaspersky : malware site
BitDefender : malware site
Sophos : malicious site
Fortinet : malware site


permalink : https://www.virustotal.com/url/ca73d77275ff7e8d07b04f17bace61fe302ee27c9a91925f722685ddc7b33926/analysis/1440987066/
resource : flagman-gpm.com
url : http://flagman-gpm.com/
response_code : 1
scan_date : 2015-08-31 02:11:06
scan_id : ca73d77275ff7e8d07b04f17bace61fe302ee27c9a91925f722685ddc7b33926-1440987066
verbose_msg : Scan finished, scan information embedded in this object
filescan_id : None
positives : 1
total : 63
CRDF : malicious site
>>> 


