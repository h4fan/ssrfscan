from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from array import array
from java.io import PrintWriter
from burp import IBurpCollaboratorClientContext
from burp import IBurpCollaboratorInteraction
import re
import threading
import os,time,base64



urlpattern = re.compile(r'(http|https|ftp)(:\/\/|\%3A\%2F\%2F)(\w+[^\s&]+)(\.[^\s&]+){1,}',re.I|re.M|re.U)
ctpat = re.compile(r'Content-Length:\s*\d+',re.I)


import random
import string

def get_random_string(length):
    # Random string with the combination of lower and upper case
    letters = string.ascii_letters
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str



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
        callbacks.setExtensionName("Url ssrf scanner")
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        self.collaboratorContext = callbacks.createBurpCollaboratorClientContext()
        # global GcollaboratorContext,Gstdout 
        # GcollaboratorContext = self.collaboratorContext
        # Gstdout = self.stdout
        
        self.ssrfpayload = self.collaboratorContext.generatePayload(True)


        # register ourselves as a custom scanner check
        callbacks.registerScannerCheck(self)
        # t = threading.Thread(target=BurpExtender.collabcheck)
        # t.start()
        # t.join()
    
    # @staticmethod
    # def collabcheck():
    #     global GcollaboratorContext,Gstdout 
    #     Gstdout.println("aaaaaaaa"+os.getpid())
        # while(True):
        #     Gstdout.println('subprocess:' + os.getpid())
        #     collaresult = GcollaboratorContext.fetchAllCollaboratorInteractions()
        #     Gstdout.println('checking:' + collaresult)
        #     time.sleep(10)
        


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
        #self.stdout.println("[match:]"+matchobj.group(0))

        return matchobj.group(0).replace(matchobj.group(3),self.randomstr + '.'+self.ssrfpayload+'/')

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
        if('.js' in  urlpath or '.css' in urlpath or '.font' in urlpath or '.jpg' in urlpath or '.js' in urlpath or '.png' in urlpath or '.webp' in urlpath or '.gif' in urlpath):
            return None

        OldReq = self._helpers.bytesToString(baseRequestResponse.getRequest())
        OrigLen = len(OldReq)


        #self.stdout.println("Scanning: "+(url.getHost()+url.getPath()).replace("/","").replace("\\","").replace("&",""))
        self.stdout.println("url: "+url.toString())
        self.stdout.println(self.ssrfpayload)
        self.stdout.println("[random payload]: "+self.randomstr + '.'+self.ssrfpayload)
        #self.stdout.println("OLd:"+OldReq)
        #self.ssrfpayload = "zzz."+self.collaboratorContext.generatePayload(True)
        firstlineindex = OldReq.index("\r\n")


        NewReq = "".join((re.sub(urlpattern,self.dealmatch,OldReq[:firstlineindex]),OldReq[firstlineindex:]))

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
        checkRequestResponse = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), self._helpers.stringToBytes(NewReq))
        #collresult = self.collaboratorContext.fetchAllCollaboratorInteractions()
        collresult = self.collaboratorContext.fetchCollaboratorInteractionsFor(self.ssrfpayload)
        self.stdout.println(len(collresult))
        if(len(collresult) == 0):
            return None
        for coll in collresult:
            self.stdout.println(coll.getProperties())
            # type = coll.getProperty('type')
            # if type == 'DNS':
            #     self.stdout.println(base64.b64decode(coll.getProperty('raw_query'))[15:])
            
            #self._helpers.base64Encode

        # report the issue
        return [CustomScanIssue(
            baseRequestResponse.getHttpService(),
            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
            [self._callbacks.applyMarkers(baseRequestResponse, None, None)],
            "SSRF",
            "The response contains the string: " + self.ssrfpayload,
            "High")]

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
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

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
