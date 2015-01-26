# Pristine
This solution contains various snippets as a part of PRISTNE project.




Pristine.SecureChannel
======================
This project serves to develop Secure Channel as a part of RINA implementation.

The idea is to use libcrypto from OpenSSL Project to implement secure channel that works both on reliable and unrealiable data delivery service. 
This experimental implementation will use simplified underlaying DIF providing reliable delivery using TCP and unreliable delivery 
using UDP. The goal is to create a proof of concept implementation and analyze basic properties.

SecureChannel has following parameters:
* -p local port
* -P remote port
* -C configuration file

To test communication try the following (note that you should run nodes in separate terminals as the process ends if input is eof):
```
$ ./SecureChannel -p 22222 -P 11111 -C sc-des-sha1.cfg 1> out

$ ./SecureChannel -p 11111 -P 22222 -C sc-des-sha1.cfg < in

$ diff in out
```
Configuration file has the following format:
```
enc:<name of cipher for encoding including key size and mode>
mac:<name of cipher to generate message digest>
key:<key>
```
For example, example configuration file sc-aes-md5.cfg contains following:
```
enc:aes-256-ecb
mac:md5
key:01234567890123456789012345678901
```
