from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from array import array
from java.io import PrintWriter
from burp import IBurpCollaboratorClientContext
from burp import IBurpCollaboratorInteraction
import re
import threading
import os,time,base64,struct


urlpattern = re.compile(r'(http|https|ftp)(:|%3A)(\/|\%2F){2}(\w+[^\s&]+)(\.[^\s&]+){1,}',re.I|re.M|re.U)
ctpat = re.compile(r'Content-Length:\s*\d+',re.I)


import random
import string

def get_random_string(length):
    # Random string with the combination of lower and upper case
    letters = string.ascii_letters
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str.lower()


def b2i(b):
    return int(struct.unpack("B", b)[0])

class BurpExtender(IBurpExtender, IScannerCheck,IBurpCollaboratorClientContext):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("ssrfscanner")
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        self.collaboratorContext = callbacks.createBurpCollaboratorClientContext()
        # global GcollaboratorContext,Gstdout 
        # GcollaboratorContext = self.collaboratorContext
        # Gstdout = self.stdout
        
        self.ssrfpayload = self.collaboratorContext.generatePayload(True)


        # register ourselves as a custom scanner check
        callbacks.registerScannerCheck(self)


    # helper method to search a response for occurrences of a literal match string
    # and return a list of start/end offsets

    def _get_matches(self, response, match):
        matches = []
        start = 0
        reslen = len(response)
        matchlen = len(match)
        while start < reslen:
            start = self._helpers.indexOf(response, match, True, start, reslen)
            if start == -1:
                break
            matches.append(array('i', [start, start + matchlen]))
            start += matchlen

        return matches

    def dealmatch(self,matchobj):
        #self.stdout.println("[ssrfpayload:]"+self.randomstr + '.'+self.ssrfpayload+'/')

        return matchobj.group(0).replace(matchobj.group(4),self.randomstr + '.'+self.ssrfpayload+'/')

    #
    # implement IScannerCheck
    #

    def doPassiveScan(self, baseRequestResponse):
        # look for matches of our passive check grep string
        #matches = self._get_matches(baseRequestResponse.getResponse(), GREP_STRING_BYTES)


        #if (len(matches) == 0):
        #    return None
        self.randomstr = get_random_string(5)
        url = self._helpers.analyzeRequest(baseRequestResponse).getUrl()
        
        urlpath = url.getPath()
        if('.js' in  urlpath or '.css' in urlpath or '.font' in urlpath or '.jpg' in urlpath or '.js' in urlpath or '.png' in urlpath or '.webp' in urlpath or '.gif' in urlpath or '.svg' in urlpath):
            return None

        OldReq = self._helpers.bytesToString(baseRequestResponse.getRequest())
        OrigLen = len(OldReq)


        #self.stdout.println("Scanning: "+(url.getHost()+url.getPath()).replace("/","").replace("\\","").replace("&",""))
        #self.stdout.println("[url]: "+url.toString())
        #self.stdout.println(self.ssrfpayload)
        randomssrfpayload = self.randomstr + '.'+self.ssrfpayload
        #self.stdout.println("[random payload]: "+randomssrfpayload)
        #self.stdout.println("OLd:"+OldReq)
        #self.ssrfpayload = "zzz."+self.collaboratorContext.generatePayload(True)
        firstlineindex = OldReq.index("\r\n")

        firstlinelist = OldReq[:firstlineindex].split("?",2)
        NewReq = ""
        if len(firstlinelist) == 2:
            NewReq = "".join((firstlinelist[0],'?',re.sub(urlpattern,self.dealmatch,firstlinelist[1]),OldReq[firstlineindex:]))
        else:
            NewReq = OldReq


        #NewReq = "".join((re.sub(urlpattern,self.dealmatch,OldReq[:firstlineindex]),OldReq[firstlineindex:]))

        #headers,body = NewReq.split("\r\n\r\n")
        postindex = NewReq.index("\r\n\r\n")
        headers = NewReq[0:postindex]
        body = NewReq[postindex:]
        #print(body)
        if len(body) > 4:
            NewReq = "".join((headers,re.sub(urlpattern,self.dealmatch,body)))
            newbodyindex = NewReq.index("\r\n\r\n")
            newbody = NewReq[newbodyindex+4:]
            #newheaders,newbody = NewReq.split("\r\n\r\n")
            NewReq = re.sub(ctpat,"Content-Length: "+str(len(newbody)),NewReq)

        if(len(NewReq) == OrigLen):
            return None

        #self.stdout.println("New:"+NewReq)
        #NewReq = OldReq.replace(Rurl, PreviousPath+"/"+p)
        self.stdout.println("[url]: "+url.toString())
        self.stdout.println("[random payload]: "+randomssrfpayload)

        checkRequestResponse = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), self._helpers.stringToBytes(NewReq))
        #collresult = self.collaboratorContext.fetchAllCollaboratorInteractions()
        collresult = self.collaboratorContext.fetchCollaboratorInteractionsFor(self.ssrfpayload)
        self.stdout.println(len(collresult))
        if(len(collresult) == 0):
            return None
        vulnflag = False
        othervulnflag = False
        otherdomain = ""
        issueresult = []
        domainresult = []
        for coll in collresult:
            self.stdout.println(coll.getProperties())
            type = coll.getProperty('type')
            if type == 'DNS':
                rq = base64.b64decode(coll.getProperty('raw_query'))
                #self.stdout.println(rq)
                index = 12
                domains = ""
                count = 10
                while count > 0:
                    curindex = index + 1
                    #self.stdout.println(curindex)
                    curlen = b2i(rq[index])
                    endindex = curindex + curlen 
                    partdomain = ''.join(chr (b2i(x)) for x in rq[curindex:endindex])
                    domains += partdomain 
                    if(partdomain == 'net'):
                        break
                    domains += '.'
                    index = endindex
                    count = count -1
                
                self.stdout.println("[SSRF----------------------------------]:"+domains)
                #self.stdout.println("[SSRF---------------RAND-STR-------------------]:"+randomssrfpayload)
                if not vulnflag and domains == randomssrfpayload:
                    #self.stdout.println("[SSRF---------------EXACTLY----------------]:"+domains)
                    vulnflag = True
                    issueresult.append(CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(baseRequestResponse, None, None)],
                    "SSRF",
                    "The response contains the string: " + randomssrfpayload,
                    "High","Certain"))
                elif domains != "" and domains != randomssrfpayload:
                    self.stdout.println("[SSRF---------------YOU-SHOULD-CHECK-IT-YOURSELF----------------]:"+domains)
                    #self.stdout.println(domains != self.ssrfpayload)
                    othervulnflag = True
                    otherdomain = domains
                    if domains not in domainresult:
                        domainresult.append(domains)
                        issueresult.append(CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        [self._callbacks.applyMarkers(baseRequestResponse, None, None)],
                        "SSRFOther",
                        "Found %s please check history for vuln" % otherdomain,
                        "High","Tentative"))

            
            #self._helpers.base64Encode

        # report the issue

        if vulnflag or othervulnflag:
            return issueresult


    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # make a request containing our injection test in the insertion point

        return None



    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # This method is called when multiple issues are reported for the same URL 
        # path by the same extension-provided check. The value we return from this 
        # method determines how/whether Burp consolidates the multiple issues
        # to prevent duplication
        #
        # Since the issue name is sufficient to identify our issues as different,
        # if both issues have the same name, only report the existing issue
        # otherwise report both issues
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1

        return 0

#
# class implementing IScanIssue to hold our custom scan issue details
#
class CustomScanIssue (IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity, confidence):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
