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

Here's how to do it.

###For historical reference###

The original idea started here: https://bitcointalk.org/index.php?topic=173220.0 . Please note that the earliest discussions are about something very different (in terms of software architecture, if not intent) than modern-day TLSNotary.

###Contact###

The authors can be found on freenode.net IRC channel #bitsquare.io most of the time. Users dansmith_btc, waxwing and oakpacific can also be contacted on reddit and bitcointalk.org.

