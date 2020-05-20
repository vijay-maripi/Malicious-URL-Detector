from urllib.parse import urlparse
import re
import urllib
import urllib.request  #changing import urllib2 to import urllib.request
from xml.dom import minidom
import csv
import pygeoip as pygeoip
import unicodedata
#import testingFeatureExtractionFunction as tfe

opener = urllib.request.build_opener()  #changing urllib2.build_opener() to urllib.request.build_opener()
opener.addheaders = [('User-agent', 'Mozilla/5.0')]
print(opener)

nf = -1


def Tokenise(url):
    if url == '':
        return [0, 0, 0]
    token_word = re.split('\W+', url)
    print("*****token_word:",token_word)
    no_ele = sum_len = largest = 0
    for ele in token_word:
        l = len(ele)
        sum_len += l
        if l > 0:  ## for empty element exclusion in average length
            no_ele += 1
        if largest < l:
            largest = l
    try:

        return [float(sum_len) / no_ele, no_ele, largest]
    except:
        return [0, no_ele, largest]


def find_ele_with_attribute(dom, ele, attribute):
    print("******************************")#remove
    #see here see here next you should change here 
    for subelement in dom.getElementsByTagName(ele):
        print(subelement)
        if subelement.hasAttribute(attribute):
            print('====',subelement.attributes[attribute].value,'====')
            return subelement.attributes[attribute].value
    return nf


#this function is modified as below
def sitepopularity(host):
    xmlpath = 'http://data.alexa.com/data?cli=10&dat=snbamz&url=' + host
    print(xmlpath," this is the original url: http://data.alexa.com/data?cli=10&dat=snbamz&url= that is replaced by new url above")
    if(xmlpath!=" "):
        xml = urllib.request.urlopen(xmlpath)
        dom = minidom.parse(xml)
        rank_host = find_ele_with_attribute(dom, 'REACH', 'RANK')
        print("********rank host:************",rank_host)
        rank_country = find_ele_with_attribute(dom, 'COUNTRY', 'RANK')
        print("********rank country:*********",rank_country)
        return [rank_host, rank_country]

    else:
        return [nf, nf]
'''

def sitepopularity(host):
    rank_host= tfe.feaEx(host,'REACH','RANK')
    print("********rank host:************",rank_host)
    rank_country= tfe.feaEx(host,'COUNTRY','RANK')
    print("********rank country:*********",rank_country)
    return [rank_host, rank_country]
'''
def Security_sensitive(tokens_words):
    sec_sen_words = ['confirm', 'account', 'banking', 'secure', 'ebayisapi', 'webscr', 'login', 'signin']
    cnt = 0
    for ele in sec_sen_words:
        if (ele in tokens_words):
            cnt += 1;

    return cnt


def exe_in_url(url):
    if url.find('.exe') != -1:
        return 1
    return 0


def Check_IPaddress(tokens_words):
    cnt = 0;
    for ele in tokens_words:
        if str(ele).isnumeric():
            cnt += 1
        else:
            if cnt >= 4:
                return 1
            else:
                cnt = 0;
    if cnt >= 4:
        return 1
    return 0


def getASN(host):
    try:
        g = pygeoip.GeoIP('GeoIPASNum.dat')
        asn = int(g.org_by_name(host).split()[0][2:])
        return asn
    except:
        return nf


'''def web_content_features(url):
    wfeatures={}
    total_cnt=0
    try:        
        source_code = str(opener.open(url))
        #print source_code[:500]

        wfeatures['src_html_cnt']=source_code.count('<html')
        wfeatures['src_hlink_cnt']=source_code.count('<a href=')
        wfeatures['src_iframe_cnt']=source_code.count('<iframe')
        #suspicioussrc_ javascript functions count

        wfeatures['src_eval_cnt']=source_code.count('eval(')
        wfeatures['src_escape_cnt']=source_code.count('escape(')
        wfeatures['src_link_cnt']=source_code.count('link(')
        wfeatures['src_underescape_cnt']=source_code.count('underescape(')
        wfeatures['src_exec_cnt']=source_code.count('exec(')
        wfeatures['src_search_cnt']=source_code.count('search(')

        for key in wfeatures:
            if(key!='src_html_cnt' and key!='src_hlink_cnt' and key!='src_iframe_cnt'):
                total_cnt+=wfeatures[key]
        wfeatures['src_total_jfun_cnt']=total_cnt

    except Exception, e:
        print "Error"+str(e)+" in downloading page "+url 
        default_val=nf

        wfeatures['src_html_cnt']=default_val
        wfeatures['src_hlink_cnt']=default_val
        wfeatures['src_iframe_cnt']=default_val
        wfeatures['src_eval_cnt']=default_val
        wfeatures['src_escape_cnt']=default_val
        wfeatures['src_link_cnt']=default_val
        wfeatures['src_underescape_cnt']=default_val
        wfeatures['src_exec_cnt']=default_val
        wfeatures['src_search_cnt']=default_val
        wfeatures['src_total_jfun_cnt']=default_val    

    return wfeatures'''


def safebrowsing(url):
    api_key = "ABQIAAAA8C6Tfr7tocAe04vXo5uYqRTEYoRzLFR0-nQ3fRl5qJUqcubbrw"
    name = "URL_check"
    ver = "1.0"

    req = {}
    req["client"] = name
    req["apikey"] = api_key
    req["appver"] = ver
    req["pver"] = "3.0"
    req["url"] = url  # change to check type of url

    try:
        params = urllib.urlencode(req)
        req_url = "https://sb-ssl.google.com/safebrowsing/api/lookup?" + params
        res = urllib.request.urlopen(req_url)
        # print res.code
        # print res.read()
        if res.code == 204:
            print
            "safe"
            return 0
        elif res.code == 200:
            print
            "The queried URL is either phishing, malware or both, see the response body for the specific type."
            return 1
        elif res.code == 204:
            print
            "The requested URL is legitimate, no response body returned."
        elif res.code == 400:
            print
            "Bad Request The HTTP request was not correctly formed."
        elif res.code == 401:
            print
            "Not Authorized The apikey is not authorized"
        else:
            print
            "Service Unavailable The server cannot handle the request. Besides the normal server failures, it could also indicate that the client has been throttled by sending too many requests"
    except:
        return -1


def feature_extract(url_input):
    Feature = {}
    tokens_words = re.split('\W+', url_input)  # Extract bag of words stings delimited by (.,/,?,,=,-,_)
    print(tokens_words,len(tokens_words))

    # token_delimit1=re.split('[./?=-_]',url_input)
    # print token_delimit1,len(token_delimit1)

    obj = urlparse(url_input)
    host = obj.netloc #<scheme>://<netloc>/<path>;<params>?<query>#<fragment>
    #netloc is what the first level domain (FLD)
    path = obj.path
    print(host)
    print(path)

    Feature['URL'] = url_input
    print("host host:",url_input)

    Feature['rank_host'], Feature['rank_country'] = sitepopularity(url_input)

    Feature['host'] = obj.netloc
    Feature['path'] = obj.path

    Feature['Length_of_url'] = len(url_input)
    Feature['Length_of_host'] = len(host)
    Feature['No_of_dots'] = url_input.count('.')

    Feature['avg_token_length'], Feature['token_count'], Feature['largest_token'] = Tokenise(url_input)
    Feature['avg_domain_token_length'], Feature['domain_token_count'], Feature['largest_domain'] = Tokenise(host)
    Feature['avg_path_token'], Feature['path_token_count'], Feature['largest_path'] = Tokenise(path)

    Feature['sec_sen_word_cnt'] = Security_sensitive(tokens_words)
    Feature['IPaddress_presence'] = Check_IPaddress(tokens_words)

    print
    host
    print
    getASN(host)
    Feature['exe_in_url'] = exe_in_url(url_input)
    Feature['ASNno'] = getASN(host)
    Feature['safebrowsing'] = safebrowsing(url_input)
    """wfeatures=web_content_features(url_input)

    for key in wfeatures:
        Feature[key]=wfeatures[key]
    """
    # debug
    # for key in Feature:
    #     print key +':'+str(Feature[key])
    print(Feature)
    return Feature


print("feature extraction is running.......")
