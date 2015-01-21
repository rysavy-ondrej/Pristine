# Pristine
This solution contains various snippets as a part of PRISTNE project.




Pristine.SecureChannel
======================
This project serves to develop Secure Channel as a part of RINA implementation.

The idea is to use libcrypto from OpenSSL Project to implement secure channel that works both on reliable and unrealiable data delivery service. 
This experimental implementation will use simplified underlaying DIF providing reliable delivery using TCP and unreliable delivery 
using UDP. The goal is to create a proof of concept implementation and analyze basic properties.


To test communication try the following:
> ./SecureChannel -p 22222 -P 11111 -C sc-des-sha1.cfg 1> out

> ./SecureChannel -p 11111 -P 22222 -C sc-des-sha1.cfg < in

> diff in out
