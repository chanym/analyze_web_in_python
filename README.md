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

Please remove the brackets [.] and replace with . when submitting the url as a parameter

Please remember to insert "http://" or "https://" if you are running analyze_web.py in the shell.

Example - ./analyze_web.py ie http://company[.]com

Example - ./analyze_web.py ff http://company[.]com

Example - ./analyze_web.py chrome http://company[.]com


If you prefer to use the python interpreter, you could import the module as well

Making use of the two functions get_url() and query_vt() as shown below

1) get_url(<ua>, <url>)

2) query_vt([<suspected malicious url>])

The parameter "suspected malicious url" does not need to include "http://" or "https://" for the query_vt() function




