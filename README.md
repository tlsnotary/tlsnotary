TLSNotary Overview
==================

1. [For the generally curious - a FAQ](https://github.com/AdamISZ/tlsnotary/blob/no_patch/data/documentation/TLSNotaryFAQ.md)
2. [How to install and run](#how-to-install-and-run)
2. [User Guide](#user-guide)
3. [Video version of the above](https://www.youtube.com/playlist?list=PLnSCooZY6_w9j5tQ8jAeZtrl9l4NnL48G) for a more hands-on education style. This is a little out of date and will be updated soon.
5. [Algorithm white paper](https://github.com/AdamISZ/tlsnotary/blob/no_patch/data/documentation/TLSNotary.pdf)  (here be dragons).
5. [Peer messaging protocol spec](https://github.com/AdamISZ/tlsnotary/blob/no_patch/data/documentation/TLSNotary_messaging.md)


###Really, really short version: ###

tlsnotary allows the auditee to prove to the auditor that a certain https page is present in the auditee's browser.
This can be used e.g. when the auditee must prove to an arbitrator that a bank transfer has been made.

##How to install and run##

TLSNotary can run on Linux, Mac and Windows and has only two dependencies:
1. [Firefox browser](https://www.mozilla.org/en-US/firefox/new/)
2. [Python 2.7+ for Windows](https://www.python.org/ftp/python/2.7.8/python-2.7.8.msi). Linux and MacOS should already have Python but be aware there is no current support for Python 3 in TLSNotary.

Once you have both of these (in particular, on Windows, make sure you can get a Python prompt by typing `python` at a command prompt), you are ready to try installing and running TLSNotary.

You can do `git clone` if you know what that is; if not, just click the "Download Zip" on the right hand side of this page.

Inside the `tlsnotary` folder created, you will see one directory, `data` (which contains all the code), and also startup scripts. If you are on Windows, double click the file `StartTLSNotary-windows.bat`. If you're on MacOS or Linux, start the appropriate shell script from the command line.

If you were successful you should see a new Firefox window (separate from any existing browser window) that looks like this:

![](/data/documentation/startwindow.png)

##User guide.##

*This is a guide for a user who is to be audited. The guide for auditors will be produced separately.*

You still have a few things to do before you can use TLSNotary in a real life audit. Notice in the above screen there are two radio buttons 'Normal Mode', 'Selftest mode' and 'Advanced'. 

Perform self test:
* Click 'Start selftest' and wait for the 'ready' message to appear (the 'AUDIT THIS PAGE' button will also go blue).
* Navigate to your intended website, log in as normal, and navigate to the page that you want to be audited (a message page, a bank statement page or similar).
* Click 'AUDIT THIS PAGE'. The audit will typically take 10-20 seconds. If the decryption is successful you'll see a screen something like this:

![](/data/documentation/decryptedOK.png)

Notice two things: "Page decryption successful" in the status bar, and that a new tab has opened. That tab will contain the exact html page that you're goind to send to the auditor. It's recommended to set `prevent_render=1` in your `tlsnotary.ini` file. Then you will see the html in plaintext, as above. If you reset it to `prevent_render=0`, then this tab will show as an html page, although it won't look totally normal as you won't see images loaded. It's up to you to decide if the data in this page satisfies two criteria:

1. It doesn't contain information that you don't want the auditor to see.
2. It **does** contain data that proves what you want to prove (e.g. proves that you sent $100 on date:X to recipient:Y).




###For historical reference###

The original idea started here: https://bitcointalk.org/index.php?topic=173220.0 . Please note that the earliest discussions are about something very different (in terms of software architecture, if not intent) than modern-day TLSNotary.

###Contact###

The authors can be found on freenode.net IRC channel #bitsquare.io most of the time. Users dansmith_btc, waxwing and oakpacific can also be contacted on reddit and bitcointalk.org.

