TLSNotary project
==================

1. [FAQ](/src/documentation/TLSNotaryFAQ.md)
2. [Installation](#how-to-install-and-run)
2. [User guide for auditee](#user-guide)
2. [User guide for auditor](/src/documentation/AuditorGuide.md)
3. [User guide (video)](https://www.youtube.com/watch?v=kKdEhuiXYz4&list=PLnSCooZY6_w9j5tQ8jAeZtrl9l4NnL48G&index=3)
5. [Algorithm white paper](/src/documentation/TLSNotary.pdf)
5. [Algorithm discussion (video)](https://www.youtube.com/watch?v=b4ukd4I8S9A&list=PLnSCooZY6_w9j5tQ8jAeZtrl9l4NnL48G&index=2)
5. [Peer messaging protocol specification](/src/documentation/TLSNotary_messaging.md) - technical details of auditor/auditee communication


###Introduction###

TLSNotary is a browser add-on which allows you (the auditee) to prove to the auditor that a certain HTTPS page is present in a web browser, without compromising your internet connection, passwords or credentials. TLSNotary can be used e.g. to prove to the auditor that you made an online bank transfer.

TLSNotary does not do man-in-the-middle snooping, but relies on SSL/TLS cryptography. TLSNotary page captures are non-forgeable.

![](/src/documentation/walkthrough_diagram_simplified.png)

##How to install and run##

TLSNotary can run on Linux, Mac and Windows and has only two dependencies:

1. [Firefox browser](https://www.mozilla.org/en-US/firefox/new/)
2. [Python 2.7+ for Windows](https://www.python.org/ftp/python/2.7.8/python-2.7.8.msi). Linux and MacOS should already have Python but be aware there is no current support for Python 3 in TLSNotary.

Once you have both of these (in particular, on Windows, make sure you can get a Python prompt by typing `python` at a command prompt), you are ready to try installing and running TLSNotary.

You can do `git clone` if you know what that is; if not, just click the "Download Zip" on the right hand side of this page.

Inside the `tlsnotary` folder created, you will see one directory, `src` (which contains all the code), and also startup scripts. If you are on Windows, double click the file `StartTLSNotary-windows.bat`. If you're on MacOS or Linux, start the appropriate shell script from the command line.

If you were successful you should see a new Firefox window (separate from any existing browser window) that looks like this:

![](/src/documentation/startwindow.png)

##User guide##

*This is a guide for a user who is to be audited. The guide for auditors is* [here](/src/documentation/AuditorGuide.md).

You still have a few things to do before you can use TLSNotary in a real life audit. Notice in the above screen there are three radio buttons 'Normal Mode', 'Selftest mode' and 'Advanced'. Leave the mode as 'Selftest' for now. 'Advanced' is currently only used for setting the communication channel (IRC) with the auditor, and you can leave it at the default settings for self test (when you do a real audit, your auditor will tell you which settings to put here).

###Performing the self test###
This is an essential first step - doing this enables you to find out if (a) your chosen audit website (e.g. bank) works correctly with TLSNotary and (b) the data gathered is as you need it to be.

* Click 'Start selftest' and wait for the 'ready' message to appear (the 'AUDIT THIS PAGE' button will also go blue).
* You can browse normally (you are using a copy of your own version of Firefox). Navigate to your intended website, log in as normal, and navigate to the page that you want to be audited (a message page, a bank statement page or similar).
* Click 'AUDIT THIS PAGE'. The audit will typically take 10-20 seconds. If the decryption is successful you'll see a screen something like this:

![](/src/documentation/decryptedOK.png)

Notice two things: "Page decryption successful" in the status bar, and that a new tab has opened. That tab will contain the exact html page that you're goind to send to the auditor. You'll also immediately notice that the page looks a bit different; it does not contain images. That's because you are being shown the "raw" version of the page, containing only the data your auditor will see. It's up to you to decide if the data in this page satisfies two criteria:

1. It doesn't contain information that you don't want the auditor to see (*note: you can also view the html file in text form by opening the file in `src/auditee/sessions/<session timestamp>/commit/html-1` - this will also contain the HTTP headers, including any cookies*).
2. It **does** contain data that proves what you want to prove (e.g. proves that you sent $100 on date:D from account X to recipient:Y - your auditor should tell you any details about what evidence you need).

Once you're satisfied on these two points, you can click 'FINISH'. Note: in self-test mode, you are only "auditing yourself", so **no one else will see the data at this stage**. After a few seconds, you should see a message saying "Congratulations, the audit has acknowledged..." etc. This means the audit is succcessfully completed. Go to `tlsnotary/src/auditor/sessions/[session timestamp]/decrypted` and in that folder, you should see a decrypted copy of your chosen audited html page. It should be identical to what you see in the Firefox browser, as well as what's stored in `tlsnotary/src/auditee/sessions/[session timestamp]/commit`.

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

![](/src/documentation/startreal.png)

The rest of the audit process is as for the 'self-test mode' described above.

Please note that, once you press "Finish" **the html of the audited page is sent irretrievably to the auditor**, so only press it once you're sure you're happy with that.

Finally, please note that the above instructions are only the technical instructions for how to run TLSNotary; they don't cover the other practical details of the audit, such as how any bitcoin payments/accounts are dealt with or timing restrictions. All of this will be covered in the trading software you're using (for example, [bitsquare](https://bitsquare.io)), and in any extra instructions given by your auditor.

###For historical reference###

The original idea started here: https://bitcointalk.org/index.php?topic=173220.0 . Please note that the earliest discussions are about something very different (in terms of software architecture, if not intent) than modern-day TLSNotary.

###Contact###

The authors (usernames dansmith_btc, waxwing and oakpacific) can be found on freenode.net IRC channel #tlsnotary-chat most of the time, and can also be contacted on reddit and bitcointalk.org. Alternatively, you can contact us at tlsnotarygroup~A~T~gmail.com.

