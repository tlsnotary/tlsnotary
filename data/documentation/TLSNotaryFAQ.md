TLSNotary FAQ
=============

##What does it do?(Or what's this all about?)##

Think of it as a cryptographically enhanced, on-steroids version of your generic, run-of-the-mill screen capture tool; it captures a webpage, attached with the proof that it comes from a particular website - as long as said website supports SSL connections - and sends it to an auditor who will then verify that the proof matches the content of the page provided.


##Why do I want to show this to a third-party? ##

There are many usage scenarios, e.g., people routinely provide screenshots or printouts as proofs that a transaction took place, or that certain words are said by certain people at certain places/times, to an authority to decide who is telling the truth. Such arbitrations/dispute settlements trhough a third-party are really common in our daily lives. An example might be proof of funds to support a visa application, or proof of residence using utility bills to set up an account.


##Why the need for all this crypto wizardry? My [screen-capture tool/printer/Skype session] works for me!##

Cryptography can provide protection against forgery (in other words, it can be used for checking *authentication* and *integrity* of messages - see [HMAC](https://en.wikipedia.org/wiki/Hash-based_message_authentication_code) for how this is achieved in TLS/SSL). Without such protection it's quite easy for the technically capable fraudster to produce an authentic looking fake proof even in high-stakes scenarios, e.g., it may be as simple as editing a number in the html source file of a bank statement to show a false value of total transfer amount. More advanced frauds may involve setting up fake websites. Proper use of cryptography can prevent this.

##That sounds scary, then how does your program protect me?##

Whenever a page is retrieved trhough a SSL connection, your browser sends a secret to the server on which the page is hosted, both the browser and the server then use the secret to create several keys, one of which is used to **encrypt** the communications between you and the server, while another is used to **authenticate** the page as being from the server. With TLSNotary, both the auditee and the auditor will be responsible for generating half of the secret, then the auditor will send the part of the secret needed by the auditee to generate the encryption key to the auditee, so that he alone knows the encryption/decryption key and nobody, includes the auditor, can spy on information he shouldn't know(e.g., his password). At the same time, the auditor will get the part required to generate the aunthentication key from the auditee, so that *he* alone knows the authentication key, and the auditee, without the key, **cannot produce a fake page** which can be verified by the key, to fool the auditor.

##But in that case how am I supposed to tell if the page from the server hasn't been tampered, without the authentication key?##

The auditee will in fact, get the authentication key to check the page, but the trick here is he can only do that after he commits the page cryptographically to a value, much like how the authentication scheme using the key works, the commitment is designed to be so strong that he cannot modify the content of the page to be audited after he makes the commitment.


##Great, then how should I use it?##

Thanks for the interest! We have made some [videos] showing you how. *Note: currently the installation process explained here is a little out of date; you no longer need the binary installation - you only need to download the zip of the code, and to have Python 2 installed on your system*. 


##But why should I trust you?##

You shouldn't, you should trust math and, to whatever extent possible, code that you can read and understand. We have tried extremely hard to make sure that the technical architecture requires trust nowhere; the code is in Python and Javascript, and there are no binaries to download. The algorithm, like the code, is 100% open source and everything is accessible here on the github repo. Most importantly, there is no modification needed to your Firefox browser; TLSNotary will simply be run as an add-on in your own copy of Firefox.

##How does my tlsnotary communicate with an auditor?##

The communication is done through an IRC channel and server of your choice, which can be specified in the "Advanced" settings, the deault channel is #tlsnotary on Freenode IRC, all the traffic between the auditee/auditor are encrypted using RSA-2048, so no one other than those who hold the private keys can view it. In order to facilitate such encrypted communications, the tlsnotary program will generate a public for you before the session starts, which you will exchange with the auditor for his public key.

##OK, enough high level overview. I need the details.##
Start [here](https://github.com/AdamISZ/tlsnotary/blob/no_patch/data/documentation/TLSNotary.pdf). This gives the theoretical underpinnings of the TLSNotary algorithm. A heavy dose of the [RFC](https://www.ietf.org/rfc/rfc2246.txt) is a prerequisite. After that, you may need to review code. The most important part is in [`tlsn_crypto.py`](https://github.com/AdamISZ/tlsnotary/blob/no_patch/data/shared/tlsn_crypto.py) and the `prepare_pms` and `audit_page` functions in the [auditee module](https://github.com/AdamISZ/tlsnotary/blob/no_patch/data/auditee/tlsnotary-auditee.py) and   `process_messages` in the [auditor module](https://github.com/AdamISZ/tlsnotary/blob/no_patch/data/auditor/tlsnotary-auditor.py). To understand how the auditor and auditee communicate in detail, please also read the [messaging protocol specification](https://github.com/AdamISZ/tlsnotary/blob/no_patch/data/documentation/TLSNotary_messaging.md).







