#!/usr/bin/python

import sys, re, requests, math, time

def usage():
	print("""Usage - ./analyze_web.rb [user-agent] [url]
\nUSER-AGENT:\n
ie - 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)'
ff - 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20120101 Firefox/29.0'
chrome - 'Mozilla/5.0 (Windows NT 4.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36'
\nThe field for url needs to be defined with a schema with either http:// or https://
\nExample - ./analyze_web.py ie http://company.com
Example - ./analyze_web.py ff http://company.com
Example - ./analyze_web.py chrome http://company.com""")

def get_url(uagent, url):
    '''get all url contained within the given webpage'''
    total = []
    all_url = []
    #(connect, read) tuple for cr_timeout
    connect_timeout = 2.0
    try:
        page = requests.get(url, headers = {'user-agent': uagent}, timeout=(connect_timeout, 10.0))
        page.encoding = 'ISO-8859-1'

        for x in page.text.split():
            if re.search(r'href="', x):
                total.append(x.split('href="')[1].split('"')[0])
            if re.search(r'href=\'', x):
                total.append(x.split('href=\'')[1].split('\'')[0])
            if re.search(r'src="', x):
                total.append(x.split('src="')[1].split('"')[0])
            if re.search(r'src=\'', x):
                total.append(x.split('src=\'')[1].split('\'')[0])

        for z in set(total):
            if re.search(r'^http|^https', z):
                all_url.append(z)

        return all_url
    except requests.exceptions.ConnectionError as e:
        print("Domain could not be resolved...")
        quit()
    except requests.exceptions.ConnectTimeout as e:
        print("Slow response from website.. timeout in 2 seconds")
        quit()
    except requests.exceptions.ReadTimeout as e:
        print("Waited too long between bytes")
        quit()

def query_vt(sites):
    '''submit url in list to virustotal to get report if available'''
    count = 0
    num = 0
    print("Total url to be queried : {0}".format(len(sites)))
    print("Estimate time will be {0} minutes as I am using non premium API key...".format(math.ceil(len(sites)/4)))
    #For submitting url to be scan - "https://www.virustotal.com/vtapi/v2/url/scan"
    #For retrieving scan repor - "https://www.virustotal.com/vtapi/v2/url/report"
    #Please refer to https://www.virustotal.com/en/documentation/public-api for more info
    vt_url = "https://www.virustotal.com/vtapi/v2/url/report"

    while num < len(sites):
        if count < 4:
            vt_key = {"resource": sites[num],
                      "apikey": "7668d5f491cc5d768bc49e89e6ae2bd610cf901dd034b9203b42342840d19c3b"}
            vt_response = requests.post(vt_url, data=vt_key)
            vt_result = vt_response.json()
            count += 1
            num += 1
            if vt_result['response_code'] == 1:
                keys = vt_result.keys()
                print "\n"
                for r in keys:
                    if r == 'scans':
                        scan_keys = vt_result['scans'].keys()
                        for s in scan_keys:
                            if vt_result['scans'][s]['detected']:
                                print("{0} : {1}".format(s, vt_result['scans'][s]['result']))
                    else:    
                        print ("{0} : {1}".format(r, vt_result[r]))
                if vt_result['positives'] == 0:
                    print("No scans detected this site is malicious... except that somebody have submit this url to be scan before")

            else:
                print ("\nurl: {0}\nresult: {1}\n".format(vt_result['resource'], vt_result['verbose_msg']))
        else:
            time.sleep(60)
            count = 0

def main():
    print("\n** URL scraper found in website and check against Virustotal **\n\n")
    if len(sys.argv) != 3 or not re.search(r'\bie\b|\bff\b|\bchrome\b', sys.argv[1]) or not re.search(r'^http://|^https://', sys.argv[2]):
        usage()
        quit()

    #You can specify your own user agent by adding to the hash below and change according in line 10 condition
    ua = {'ie': 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)',
    'ff': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20120101 Firefox/29.0',
    'chrome': 'Mozilla/5.0 (Windows NT 4.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36'} 

    uagent = ua[sys.argv[1]]
    url = sys.argv[2]
    all_sites = get_url(uagent, url)

    if len(all_sites) == 0:
        print("There are no url to be queried... perhaps the site to be checked against is not available")
        quit()
    else:
        query_vt(all_sites)			

if __name__ == "__main__":
    main()


