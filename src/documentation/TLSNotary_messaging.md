TLSNotary Messaging Protocol
============================

The auditor and auditee must communicate in real time in order to create the shared SSL session secrets. This messaging must occur over a channel which has the following features:

 * Reasonable performance
 * Good reliability
 * Privacy is highly desirable if not always strictly necessary
 * Anonymity is also desirable

It isn't completely easy to find an architecture which will give all these properties without some centralisation. For the time being, auditors will register channels on IRC and the messaging will be carried out there. There are a lot of reasonable alternatives which can be swapped in to replace IRC if that proves desirable.

## Message formatting ##

 1.  The "message content" (for all message types) is first RSA encrypted and then base64 encoded before being passed onto the message channel.
 2.  The first field for non-handshake messages is the userid of the counterparty, which has format `'user'+rand()` where rand is a 10 digit random number initialised at the start of the session.
 3.  The first field for handshake messages is one of `ae_hello:`,`ao_hello:` and `rs_pubkey:`.
 4. The second field will be either `seqno:N` or `ack:N` where N is the sequence number of the message.
 5. The third field will be the message content.
 6. The fourth field is either `CRLF` or `EOL`, the latter indicating the end of the message.

### Handshake message format ###

In order to support peer discovery on public channels, the auditee must initiate the messaging connection with a set of handshake messages. These TLSNotary peer handshake messages are not to be confused with TLS handshake messages.

 1. The auditee sends **ae_hello** and **rs_pubkey** messages.
 2. **ae_hello** has format: `ae_hello: X [CRLF/EOL]` where X, the message content, is: `auditor_pubkey[:10]||rsa_signature('ae_hello'||userid)` (where userid is the new user id for the auditee as defined above).
 3. **rs_pubkey** has format: `rs_pubkey: X [CRLF/EOL]` where X, the message content, is:  `reliable site pubkey modulus || reliable site pubkey exponent`.
 4. Upon receipt and correct parsing of the above two messages, the auditor sends **ao_hello** message.
 5. **ao_hello** has format: `ao_hello: X [CRLF/EOL]` where X, the message content, is: `rsa_signature('ao_hello'||userid)` where userid is the new user id for the auditor as defined above).

In this, 'reliable site' refers to a site pre-chosen at random from a list of highly stable internet sites, which will be used to prepare a PMS in the ensuing stages of the protocol. Any negotiated PMS is tried in a TLS handshake with this site to see if it fails due to padding errors.

The function of the handshake is to authenticate the connection between the temporary `userid` and the auditee's RSA public key (hence the use of RSA signatures). Using the temporary `userid` inside the data signed data avoids replay attacks.

## Message sequence in detail ##
The full sequence of messages for a typical session is illustrated below. Definitions for the non-handshake message types are given below the table.

| Auditee    |      | Auditor |
| :---------:|:----:|:-------:|
| ae_hello | >>>> | |
| rs_pubkey | >>>> | |
|  | <<<< | ao_hello |
| |*peer handshake over*            ||
|rcr_rsr | >>>> | |
| |<<<< | rrsapms_rhmac |
| | *prepare PMS over*  ||
|cr_sr_hmac_n_e | >>>> | |
| | <<<< | rsapms_hmacms_hmacek |
| verify_md5sha | >>>> | |
| | <<<< | verify_hmac |
| verify_md5sha2 | >>>> | |
| | <<<< | verify_hmac2 |
| | *main TLS handshake over*  ||
| commit_hash | >>>> | |
| | *main audit function over* ||
| | <<<< | sha1hmac_for_MS |
| link | >>>> | |

The sequence above is fixed; however, this doesn't mean that messages may not be repeated. For example, the peer handshake messages may be repeated. The prepare PMS phase often must be repeated until a successful PMS is found. The whole sequence from rcr_rsr can be repeated multiple times for multiple different pages within the same audit session, if that is required.

### Message Types ###

**rcr_rsr** : *Content*: reliable site client random and server random. *Notes*: sent to auditor as needed for the seed to the HMAC function.

**rrsapms_rhmac** : *Content*: reliable site RSA encrypted premaster secret half sent from auditor to auditee, concatenated with the HMAC for the master secret (see TLSNotary.pdf for details). *Notes*: Here the master secret is needed because, in order to receive a response to the 'Client Key Exchange' from the server, and thus to find out whether the encrypted PMS was correctly formatted, the client (in this case the auditee) must send the 'Client Finished' message encrypted with the correct client encryption key.

**cr_sr_hmac_n_e** : *Content*: client random, server random and md5 hmac for the master secret, as well as the public key modulus and exponent for the audited site. *Notes*: This is the first message sent by the auditee to the auditor for the real TLS handshake (for the site to be audited). 

**rsapms_hmacms_hmacek**: *Content*: the encrypted premaster secret half for the auditor, the sha1hmac for the master secret and the sha1 hmac for the expanded keys. *Notes*: the hmac for expanded keys is corrupted with garbage in the section required to produce the server mac key. Again, details are in TLSNotary.pdf.

**verify_md5sha** : *Content*: The md5 and sha1 hashes of all the handshake messages up to but not including the Client Finished handshake message. *Notes*: required in order to generate the verify data to be used in the Client Finished message.

**verify_hmac** : The md5 HMAC required by the auditee to construct the Verify Data correctly for Client Finished.

**verify_md5sha2** : The md5 and sha1 hashes of all the handshake messages up to but not including the Server Finished handshake message, which is required in order to generate the verify data to be used in the Server Finished message.

**verify_hmac2** : The md5 HMAC required by the auditee to construct the Verify Data correctly for Server Finished.

**commit_hash** : *Content*: The sha256 hashes of the entire server response as sent over the wire, and the md5 HMAC for the master secret. *Notes*: This is the crucial step to prevent the auditee faking the data by committing before he has access to the master secret.

**sha1hmac_for_MS** : *Content*: as the name implies. *Notes*: Allows the auditee to reconstruct the fully correct master secret (including server mac key) so as to decrypt the data safely.

**link** : *Content*: A URL where a zip file can be accessed containing the reveal of the earlier commitment. *Notes*: specifically the zip file will contain: 'response' file (full over-the-wire server response), 'md5hmac' file, 'IV' file (cipher state at the end of server finished message, allowing correct initialisation of decryption), 'domain' file (containg auditee's claim of the server accessed), 'cs' file (containing chosen cipher suite).

