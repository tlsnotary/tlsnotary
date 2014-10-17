TLSNotary is a browser addon allowing the user (auditee) to submit non-forgeable web page captures. The third party (auditor) can verify the contents of the web page based on the HMAC signatures on HTTPS (TLS) encrypted traffic. The non-forgeable proof comes from the signature of the server SSL certificate and splitting up the encrypted connection secret between the auditee and the auditor.

Use cases 

- Proof of online banking payment
- Proof of identity on a third party site

## Contents

1. [How TLSNotary works](#how-tlsnotary-works)
1. [Installation](#installation)
1. [User guide for auditees](#user-guide)  
1. [User guide for auditees (video)](https://www.youtube.com/watch?v=kKdEhuiXYz4&list=PLnSCooZY6_w9j5tQ8jAeZtrl9l4NnL48G&index=3)- more educational
2. [User guide for auditors](/data/documentation/AuditorGuide.md)
1. [FAQ](/data/documentation/TLSNotaryFAQ.md)
1. [Algorithm white paper](/data/documentation/TLSNotary.pdf) 
2. [Discussion of algorithm (video)](https://www.youtube.com/watch?v=b4ukd4I8S9A&list=PLnSCooZY6_w9j5tQ8jAeZtrl9l4NnL48G&index=2)
5. [Peer messaging protocol spec](/data/documentation/TLSNotary_messaging.md) - technical details of auditor/auditee communication

## How TLSNotary works

1. The auditee does not need to give up any login details, cookies or other sensitive information - TLSNotary does not do any kind of man-in-the-middle inspection for secure traffic. 
1. The auditor wishes the auditee to show a web page capture from their browser and they give the auditee the key for this operation.
1. The auditee goes to the web page they wish to show and then choose to create TLSNotary capture of this page.
1. The auditee enters they key given by auditor. This key is used as the part of the secret token for TLS connection. 
1. The TLSNotary browser addon then creates a new secure connection to the server to fetch the page. 
1. The server signs the page for secure connection, as it is needed for HTTPS traffic. The signature is calculated from  auditee key, auditor key and server public SSL certificate.
2. The auditee logs out, invalidating any session data the captured web page may contain.
1. The auditee delivers the page and the signature to the auditor.
1. Because the signature is partially based on the public certificate of the server and the auditor key, the auditor can verify that the auditee did not tamper with the page and can trust its content.


##Installation##

TLSNotary can run on Linux, Mac and Windows and has only two dependencies:

1. [Firefox browser](https://www.mozilla.org/en-US/firefox/new/)
2. [Python 2.7+ for Windows](https://www.python.org/ftp/python/2.7.8/python-2.7.8.msi). Linux and MacOS should already have Python but be aware there is no current support for Python 3 in TLSNotary.

Once you have both of these (in particular, on Windows, make sure you can get a Python prompt by typing `python` at a command prompt), you are ready to try installing and running TLSNotary.

You can do `git clone` if you know what that is; if not, just click the "Download Zip" on the right hand side of this page.

Inside the `tlsnotary` folder created, you will see one directory, `data` (which contains all the code), and also startup scripts. If you are on Windows, double click the file `StartTLSNotary-windows.bat`. If you're on MacOS or Linux, start the appropriate shell script from the command line.

If you were successful you should see a new Firefox window (separate from any existing browser window) that looks like this:

![](/data/documentation/startwindow.png)

##User guide##

*This is a guide for a user who is to be audited. The guide for auditors is* [here](/data/documentation/AuditorGuide.md).

You still have a few things to do before you can use TLSNotary in a real life audit. Notice in the above screen there are three radio buttons 'Normal Mode', 'Selftest mode' and 'Advanced'. Leave the mode as 'Selftest' for now. 'Advanced' is currently only used for setting the communication channel (IRC) with the auditor, and you can leave it at the default settings for self test (when you do a real audit, your auditor will tell you which settings to put here).

###Performing the self test###
This is an essential first step - doing this enables you to find out if (a) your chosen audit website (e.g. bank) works correctly with TLSNotary and (b) the data gathered is as you need it to be.

* Click 'Start selftest' and wait for the 'ready' message to appear (the 'AUDIT THIS PAGE' button will also go blue).
* You can browse normally (you are using a copy of your own version of Firefox). Navigate to your intended website, log in as normal, and navigate to the page that you want to be audited (a message page, a bank statement page or similar).
* Click 'AUDIT THIS PAGE'. The audit will typically take 10-20 seconds. If the decryption is successful you'll see a screen something like this:

![](/data/documentation/decryptedOK.png)

Notice two things: "Page decryption successful" in the status bar, and that a new tab has opened. That tab will contain the exact html page that you're goind to send to the auditor. You'll also immediately notice that the page looks a bit different; it does not contain images. That's because you are being shown the "raw" version of the page, containing only the data your auditor will see. It's up to you to decide if the data in this page satisfies two criteria:

1. It doesn't contain information that you don't want the auditor to see (*note: you can also view the html file in text form by opening the file in `data/auditee/sessions/<session timestamp>/commit/html-1` - this will also contain the HTTP headers, including any cookies*).
2. It **does** contain data that proves what you want to prove (e.g. proves that you sent $100 on date:D from account X to recipient:Y - your auditor should tell you any details about what evidence you need).

Once you're satisfied on these two points, you can click 'FINISH'. Note: in self-test mode, you are only "auditing yourself", so **no one else will see the data at this stage**. After a few seconds, you should see a message saying "Congratulations, the audit has acknowledged..." etc. This means the audit is succcessfully completed. Go to `tlsnotary/data/auditor/sessions/[session timestamp]/decrypted` and in that folder, you should see a decrypted copy of your chosen audited html page. It should be identical to what you see in the Firefox browser, as well as what's stored in `tlsnotary/data/auditee/sessions/[session timestamp]/commit`.

###Logging out###
An important security step for a real audit; but, you **must** know in advance that it will work, so you **must** do it in self-test first. 

In case the server is providing cookies (or equivalent session preserving data) in the response which you're about to send to the auditor, you don't want to give the auditor (even though they ought to be trustworthy for obvious reasons) any information that might let them login to your account, even temporarily. There is a simple solution. Follow these steps (in self-test and real audits):

1. Press AUDIT THIS PAGE
2. Wait for the new tab to open as illustrated above.
3. Check that the data in the html page is as you want (as described above).
4. **LOG OUT** from your internet banking or other account that you're using.
5. Press FINISH

This way, any session cookies the auditor might see will no longer be valid. Also, don't forget that **because you are auditing an internal, logged in page, you are never going to send login credentials (passwords) to your auditor**. A nice sanity check is to open the html text file (as described above) and do a Ctrl-F find for any sensitive information such as passwords; if they're not there, you can be 100% sure you're not exposing them to your auditor, since that's the only data he/she will see.

###Running an audit for real###

In this case, an auditor will give you his public key. You should start up as before, but now switch to 'Normal mode'. Paste the auditor's key into the given field and send your public key to the auditor. You will then, after waiting for confirmation that the auditor is ready, press "Connect" on a screen like this:

![](/data/documentation/startreal.png)

The rest of the audit process is as for the 'self-test mode' described above.

Please note that, once you press "Finish" **the html of the audited page is sent irretrievably to the auditor**, so only press it once you're sure you're happy with that.

Finally, please note that the above instructions are only the technical instructions for how to run TLSNotary; they don't cover the other practical details of the audit, such as how any bitcoin payments/accounts are dealt with or timing restrictions. All of this will be covered in the trading software you're using (for example, [bitsquare](https://bitsquare.io)), and in any extra instructions given by your auditor.

###For historical reference###

The original idea started here: https://bitcointalk.org/index.php?topic=173220.0 . Please note that the earliest discussions are about something very different (in terms of software architecture, if not intent) than modern-day TLSNotary.

###Contact###

The authors (usernames dansmith_btc, waxwing and oakpacific) can be found on freenode.net IRC channel #tlsnotary-chat most of the time, and can also be contacted on reddit and bitcointalk.org. Alternatively, you can contact us at tlsnotarygroup~A~T~gmail.com.

