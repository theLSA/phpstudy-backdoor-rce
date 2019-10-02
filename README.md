# phpstudy后门漏洞利用工具



## 0x00 概述

20190920 phpstudy爆出存在后门，该软件官网在2016年被入侵，软件安装包（php_xmlrpc.dll）被植入后门，利用http请求头的Accept-Encoding: gzip,deflate和'Accept-Charset'可造成远程代码执行。

本工具支持单url检测，cmdshell，get web shell（写入一句话木马），批量检测。



## 0x01 需求

python2.7

pip install requests



## 0x02 快速开始

使用帮助

![](https://github.com/theLSA/phpstudy-backdoor-rce/raw/master/demo/phpstudybd00.png)

单url漏洞检测

![](https://github.com/theLSA/phpstudy-backdoor-rce/raw/master/demo/phpstudybd01.png)

cmdshell

![](https://github.com/theLSA/phpstudy-backdoor-rce/raw/master/demo/phpstudybd02.png)

getshell

![](https://github.com/theLSA/phpstudy-backdoor-rce/raw/master/demo/phpstudybd03.png)

批量检测

![](https://github.com/theLSA/phpstudy-backdoor-rce/raw/master/demo/phpstudybd04.png)

## 0x03 反馈

[issus](https://github.com/theLSA/phpstudy-backdoor-rce/issues)
gmail：[lsasguge196@gmail.com](mailto:lsasguge196@gmail.com)
qq：[2894400469@qq.com](mailto:2894400469@qq.com)



