# Pristine
This solution contains various snippets as a part of PRISTNE project.




Pristine.SecureChannel
======================
This project serves to develop Secure Channel as a part of RINA implementation.

The idea is to use libcrypto from OpenSSL Project to implement secure channel that works both on reliable and unrealiable data delivery service.  This experimental implementation will use simplified underlaying DIF providing reliable delivery using TCP and unreliable delivery using UDP. The goal is to create a proof of concept implementation and analyze basic properties.


### Requirements
This project requires OpenSSL development package to be installed on a host system. 

```
$sudo apt-get install libssl-dev
```

### Compilation
To compile the project run make specifying which makefile to use. There are different makefiles depending target operating system:
* Makefile.Linux - for Linux operating systems
* Makefile.Apple - for Mac OS X platform, because OpenSSL though installed is marked as obsolete and cannot be used.

### Execution
Single executable file is generated calle SecureChannel. SecureChannel has following parameters:
* p port        : local UDP socket binds to given `port'
* P port        : UDP datagrams will be sent to the remote `port'
*  R address     : UDP datagrams will be sent to the remote host 
                  as specified by `address' (implicit value is 127.0.0.1)
* C config-file : a name of configuration file, if not specified
                  then default file name is `sechan.cfg'

To test the communication the following parameters can be used (note that you should run nodes in separate terminals as the process ends if input is eof):
```
$ ./SecureChannel -p 22222 -P 11111 -C sc-des-sha1.cfg 1> out

$ ./SecureChannel -p 11111 -P 22222 -C sc-des-sha1.cfg < in

$ diff in out
```
This runs two instances at the local machine. Use CTRL+D to end or CTR+C to terminate the program.

Configuration file has the following format:
```
enc:<name of cipher for encoding including key size and mode>
mac:<name of cipher to generate message digest>
key:<master key used to generate write keys>
```
For example, example configuration file sc-aes-md5.cfg contains following:
```
enc:aes-256-ecb
mac:md5
key:01234567890123456789012345678901
```
