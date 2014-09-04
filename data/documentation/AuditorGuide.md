Auditor Usage Instructions
==========================

Using TLSNotary as an auditor requires a more serious investment of time and effort, clearly.
The first steps would be to read the other documentation, starting with the [README](https://github.com/tlsnotary/tlsnotary/README.md),
and going on from there. Understanding the cryptography in detail is not a requirement, but you should at least
familiarise yourself with the basics of the algorithm as laid out in the [algorithm whitepaper](TLSNotary.pdf).
To be a little clearer on this point, you don't need to understand the details of TLS 1.0, the PRF modifications 
or the RSA homomorphism.

It's also very important that, before you start using TLSNotary in a real audit situation, you become very familiar
with its filesystem layout. In particular, you'll need to get used to where audit records are stored and how to read
them. This is covered in some detail below.

##Preparatory steps

###Setting up IRC.
In the file `tlsnotary.ini` in the `data/shared` directory, there are three settings for IRC. We default to freenode,
the most widely used IRC server, on the standard port 6667. However, you *should* change the IRC channel to one that
you have created and registered. You need to register to enable voicing of new users.

###Test out TLSNotary.
Once you have your IRC channel, and have recorded its name in `tlsnotary.ini`, you'll need to test it out. Run 
TLSNotary as an ordinary user and do self test for some random pages. Check that you see appropriate output in your
IRC channel; it should look like this:

except that the name of the channel is your chosen name. Notice that all traffic between users is encrypted.

###Key management.
Your TLSNotary public/private keypair is ...
