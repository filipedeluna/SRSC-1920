# SRSC Project 19-20
repo para o proj SRSC 19-20

This handout was developed for the Computer Systems and Networks Security course at FCT-UNL. It's an implementation of a secure messaging repository system using  symmetric and asymmetric cryptography  for data encryption over secureSSL channels. The program allows users to share text and/or files.

The system was made to be almost fully parameterized for ease of testing and user freedom of choice. The system uses Diffie-Hellman public key cryptography to ensure the secrecy of all data exchanged between users. All the messages are fully encrypted, protected and authenticated. The user and message receipt data are signed to ensure non-repudiation. 

The system uses a simplified Public Key Infrastructure to distribute, validate, as well as revoke certificates. This PKI is the root of trust of all the principals involved in the system. Certificate chains are used between the involved principals, to  communicate over TLS secured channels, with the PKI certificate being the  root certificate. Both  the  PKI  and  mailbox  server  resort  to  an  SQLite local database to store all their data. The mailbox server and clients have a cache implementation to prevent unnecessary, redundant communications. Many other systems are in place to raise overall system security by preventing Denial of Service,  spoofing, replaying, sniffing, SQL injections and other types of attacks. A message exchange protocol was also created to allow for easy processing of message attachments (files), along with helper classes for all kinds of cryptographic operations.

------------------------------------------------------------------ 
General Info:
- You will need to chmod -R 755 the packagefolder to allow the applications to write their necessary files.

Initialization order:
        
1st - PKI: 
- Delete the DB and create a new keystore with a key pair. From this key pair, create certificates to place in the client and server trust stores.    
- Configure the pki.properties file

2nd - Server:  
- Delete the DB and logs, create a trustore and keystore to store the new keypair which will be create using the PKI.  
- Configure server.properties and, for the first time running, set "params_reset = true". This process may take a long time.
       
3rd - Client:
- Create the keystore and truststore.  
- Configure the client.properties file.   
- Start up the PKI and set "use_pki = true" before starting up the client, in order to generate the public key obtained by having the PKI sign the client's CSR.
