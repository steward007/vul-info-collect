# vul-info-collect

漏洞信息统计，用于获取特定软件版本漏洞的简要统计信息:CVE，漏洞总数、严重、高危、中危、低危漏洞个数，以及简单的文本和网页展示效果。



## Sample - v2

update:2020.1.3

获取某个软件版本的漏洞总览信息，包括：漏洞个数，严重、高危、中危、低危漏洞个数，及CVE的漏洞等级情况。

A script to get vulnerabilities of specific software version, which contains vul number, vul level and CVE no vul level.

```
PS E:\PycharmProjects\vul-info-collect> python3 .\script-v2.py
apache:http_server:2.4.38
https://nvd.nist.gov/vuln/search/results?form_type=Advanced&cves=on&cpe_version=cpe:/a:apache:http_server:2.4.38&startIndex=20
总计:38	严重:0	高危:13	中危:22	低危:3
CVE-2019-10081 - 高
CVE-2019-0197 - 中
CVE-2019-0196 - 中
CVE-2019-0220 - 中
CVE-2019-0211 - 高
CVE-2019-0217 - 高
CVE-2019-0215 - 高
CVE-2013-4365 - 中
CVE-2013-2765 - 中
CVE-2013-0942 - 中
CVE-2013-0941 - 低
CVE-2012-4360 - 中
CVE-2012-4001 - 中
CVE-2012-3526 - 中
CVE-2011-2688 - 高
CVE-2011-1783 - 中
CVE-2011-1752 - 中
CVE-2011-1176 - 中
CVE-2009-3095 - 高
CVE-2009-1890 - 高
CVE-2009-2299 - 中
CVE-2009-1955 - 高
CVE-2009-0796 - 低
CVE-2008-2579 - 中
CVE-2007-5156 - 中
CVE-2007-4723 - 高
CVE-2007-1349 - 中
CVE-2007-0086 - 高
CVE-2005-1268 - 中
CVE-2003-0020 - 中
CVE-2001-1556 - 中
CVE-2001-0131 - 低
CVE-1999-0289 - 中
CVE-1999-1237 - 高
CVE-1999-1412 - 高
CVE-1999-0678 - 中
CVE-1999-0236 - 高
CVE-1999-0070 - 中

apache:tomcat:7.0.92
https://nvd.nist.gov/vuln/search/results?form_type=Advanced&cves=on&cpe_version=cpe:/a:apache:tomcat:7.0.92&startIndex=0
总计:7	严重:0	高危:3	中危:2	低危:2
CVE-2019-0221 - 中
CVE-2019-0232 - 高
CVE-2016-5425 - 高
CVE-2011-1571 - 高
CVE-2011-1570 - 低
CVE-2011-1503 - 低
CVE-2011-1502 - 中
```



## Sample - v3

update:2020.1.3

获取某个软件版本的漏洞总览信息，包括：漏洞个数，严重、高危、中危、低危漏洞个数，漏洞描述等必要信息，及CVE的漏洞等级情况，并以html的形式展现。

A script to get vulnerabilities of specific software version, which contains vul number, vul level, vul description, and CVE no vul level, and present with html.

![image](https://raw.githubusercontent.com/starnightcyber/vul-info-collect/master/pic.png)

## Sample - v1

update: outdated

link: https://github.com/starnightcyber/scripts/tree/master/vul-info-collect
