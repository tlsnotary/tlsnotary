TLSNotary Messaging Protocol
============================

The auditor and auditee must communicate in real time in order to create the shared SSL session secrets. This messaging must occur over a channel which has the following features:

 - Reasonable performance
 - Good reliability
 - Privacy is highly desirable if not always strictly necessary
 - Anonymity is also desirable

 It isn't completely easy to find an architecture which will give all these properties without some centralisation. For the time being, auditors will register channels on IRC and the messaging will be carried out there. There are a lot of reasonable alternatives which can be swapped in to replace IRC if that proves desirable.

## Message formatting ##

 1.  The "message content" (for all message types) is first RSA encrypted and then base64 encoded before being passed onto the message channel.
 2.  Non-handshake messages must be prefixed with `userid` and suffixed with a 10 digit random number initialised at the start of the session.
 2. The second field will be either `seqno:N` or `ack:N` where N is the sequence number of the message.
 3. The third field will be the message content.
 4. The fourth field is either `CRLF` or `EOL`, the latter indicating the end of the message.

### Handshake message format ###

In order to support peer discovery on public channels, the auditee must initiate the messaging connection with a set of handshake messages. These TLSNotary peer handshake messages are not to be confused with TLS handshake messages.

 1. The auditee sends **ae_hello** and **rs_pubkey** messages.
 2. **ae_hello** has format: `ae_hello: X [CRLF/EOL]` where X, the message content, is: `auditor_pubkey[:10]||rsa_signature('ae_hello'||userid)` (where userid is the new user id for the auditee as defined above).
 3. **rs_pubkey** has format: `rs_pubkey: X [CRLF/EOL]` where X, the message content, is:  `reliable site pubkey modulus || reliable site pubkey exponent`.
 4. Upon receipt and correct parsing of the above two messages, the auditor sends **ao_hello** message.
 5. **ao_hello** has format: `ao_hello: X [CRLF/EOL]` where X, the message content, is: `rsa_signature('ao_hello'||userid)` where userid is the new user id for the auditor as defined above).

In this, 'reliable site' refers to a site pre-chosen by the auditee that will be used to prepare a PMS in the ensuing stages of the protocol. Any negotiated PMS is tried in a TLS handshake with this site to see if it fails due to padding errors.

Using the temporary user id in the signatures authenticates that user for this specific handshake, thus avoiding replay attacks.

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
| verify_md5 | >>>> | |
| | <<<< | verify_hmac |
| verify_md52 | >>>> | |
| | <<<< | verify_hmac2 |
| | *main TLS handshake over*  ||
| commit_hash | >>>> | |
| | *main audit function over* ||
| | <<<< | sha1hmac_for_MS |
| link | >>>> | |

### Message Types ###

**rcr_rsr** : reliable site client random and server random - sent to auditor as needed for the seed to the HMAC function.







