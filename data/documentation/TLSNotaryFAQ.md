TLSNotary FAQ

What does it do?(Or what's this all about?)

Think of it as a cryptographically enhanced, on-steroid version of your generic, run-of-the-mill screen capture tool, it captures a webpage, attached with the proof that it comes from a particular Website, as long as said website supports SSL connection, and send it to an auditor who will then verify if the proof matches the content of the page provided.


Why do I want to show this to a third-party? 

There are many use scenarios, e.g., people routinely provided screenshots as proofs that a transaction took place, or certain words are said by certain people at certain places/times, to an authority to decide who is telling the truth, such arbitrations/dispute settlements trhough a third-party are really common in our daily lives.


Why the need for all this cryptography dose? My screen-capture tool works for me!

Cryptography provides protection against forgery, without such protection it's very easy to produce an authentic looking fake proof even in high-stake scenarios, e.g., it's as simple as editing a number in the html source file of a bank statement to show a false value of total transfer amount.

That sounds scary, then how does your program protect me?


Whenever a page is retrieved trhough a SSL connection, your browser send a secret to the server on which the page is hosted, both the browser and the server then use the secret to create several keys, one of which is used to encrypt the communications between you and the server, another one is used to authenticate the page as being from the server. With TLSNotary, both the auditee and the auditor will be responsible for generating half of the secret,then the auditor will send the part of the secret needed by the auditee to generate the encryption key to the auditee, so that he alone knows the encryption/decryption key and nobody, includes the auditor, can spy on infromation he shouldn't know(e.g., his password). While the auditor will get the part required to generate the aunthentication key from the auditee, so that he alone knows the authentication key, and the auditee, without the key, cannot produce a fake page which can be verified by the key, to fool the auditor.

But in that case how am I supposed to tell if the page from the server hasn't been tampered, without the authentication key?

The auditee will in fact, get the authentication key to check the page, but the trick here is he can only does that after he commits the page cryptographically to a value, much like how the authenticaion scheme using the key works, the commitment is designed to be so strong that he cannot modify the content of the page to be audited after he makes the commitment.


Great, then how should I use it?

Thanks for the interest! We have made a video showing you how:(add link here) 


But why should I trust you?

You shouldn't, you should trust math and code that you can read and understand.










