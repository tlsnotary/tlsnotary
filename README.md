
Instructions on how to build Tor Browser Bundle deterministically with the NSS patch applied.
This will also build stcppipe deterministically.
NB: you must always be online during this process, because the VM pulls in dependencies 


You can select all and copy-paste the commands below into bash (including the #comments)


#--------------------------BASH BEGIN--------------------------------
git clone https://github.com/themighty1/tlsnotary.git
git clone https://git.torproject.org/builders/tor-browser-bundle.git
git clone -b tor-browser-builder-2 https://git.torproject.org/builders/gitian-builder.git
cd gitian-builder
#checkout commit from 2013-08-03 04:13:21
git checkout 133cb4320f414cfb1e484149d5bb38b62e6a42bb
cd ../tor-browser-bundle
#we checkout a specific commit (2014-02-21 02:16:02) against which these instructions are written
git checkout 662dd02278eb60686943730810166fe0b300cd91
cd gitian
#remove the word "torsocks " from line 59 - this will enable quicker downloads directly rather than via tor
sed -i '59s/torsocks //' Makefile
make prep
#about 1 GB of data will be downloaded (and git clone'd) (may take 2+ hours)
#apply patches to NSS libs
cd ../../gitian-builder/inputs/tor-browser
#checkout commit from 2014-02-13 23:20:16. May take a while cause the repo is huge
git checkout bd0a4271bc20d4c98ef310c42cdef7abf4ff82a4
patch security/nss/lib/softoken/pkcs11c.c < ../../../tlsnotary/data/gitian/pkcs11c.patch
patch security/nss/lib/ssl/ssl3con.c < ../../../tlsnotary/data/gitian/ssl3con.patch
#commit the changes to git, create a new tag. May take a couple of minutes cause the repo is huge
git commit -a -m "tlsnotary patch"
git tag -a tor-browser-24.3.0esr-3.5.2.1-build2_tlsnotary -m "tlsnotary tag"
cd ../../../tor-browser-bundle/gitian
#tell gitian to build our custom tag and not exit on failed tag signature verification
sed -i '6s/3.5.2.1-build2/3.5.2.1-build2_tlsnotary/' versions
sed -i '46s/exit 1/#exit 1/' verify-tags.sh
#comment out all references to 64bit in linux descriptors because
#gitian is known to act weirdly when building for both 32 and 64 bit platform at the same time
sed -i '7s/- "amd64"/#- "amd64"/' descriptors/linux/gitian-bundle.yml
sed -i '28s/- "tor-browser-linux64-gbuilt.zip"/#- "tor-browser-linux64-gbuilt.zip"/' descriptors/linux/gitian-bundle.yml
sed -i '30s/- "tor-linux64-gbuilt.zip"/#- "tor-linux64-gbuilt.zip"/' descriptors/linux/gitian-bundle.yml
sed -i '32s/- "pluggable-transports-linux64-gbuilt.zip"/#- "pluggable-transports-linux64-gbuilt.zip"/' descriptors/linux/gitian-bundle.yml
sed -i '7s/- "amd64"/#- "amd64"/' descriptors/linux/gitian-firefox.yml
sed -i '7s/- "amd64"/#- "amd64"/' descriptors/linux/gitian-pluggable-transports.yml
sed -i '7s/- "amd64"/#- "amd64"/' descriptors/linux/gitian-tor.yml
./mkbundle-linux.sh
#--------------------------BASH END--------------------------------


NB: you will be asked to enter the password 4 times(at the interval of approx 30 mins)
for each VM built : lucid-x86, lucid-amd64, precise-x86, precise-amd64

sometimes you may get an error which looks like
Checking if target is up..........
ssh: connect to host localhost port 2223: Connection refused
Another one I would get is:
Lucid amd64 VM build failed... Trying again
If after a while no activity happens on the console or the script keeps repeatedly failing, 
you will have to Ctrl+C and re-run ./mkbundle-linux.sh for this error to go away

After 5+ hours of VM setup and compilation, you should see 
*************Linux Bundle complete***************


Now build the bundle for Windows
#--------------------------BASH BEGIN--------------------------------
./mkbundle-windows.sh
#--------------------------BASH END--------------------------------


Check out the hash in gitian-builder/result/bundle-linux-res.yml on line 6.
The hash for tor-browser-linux32-3.5.2.1_en-US.tar.xz must be
3a9f262af9279cab550243c7c7a2cb02ba32c2880cbfa8d2a42c15dfd491798b

Check out the hash in gitian-builder/result/bundle-windows-res.yml look at line 6.
The hash for torbrowser-install-3.5.2.1_en-US.exe must be
4f3df70c3181f9f8bb199c7ca8a0f847b8f5dc6f716d14072ebb8a4a7fde65e3

Now build the bundle for Linux 64-bit.
Uncomment references to 64-bits and comment out all references to 32 bits:


#--------------------------BASH BEGIN--------------------------------
sed -i '6s/- "i386"/#- "i386"/' descriptors/linux/gitian-bundle.yml
sed -i '7s/#- "amd64"/- "amd64"/' descriptors/linux/gitian-bundle.yml
sed -i '27s/- "tor-browser-linux32-gbuilt.zip"/#- "tor-browser-linux32-gbuilt.zip"/' descriptors/linux/gitian-bundle.yml
sed -i '28s/#- "tor-browser-linux64-gbuilt.zip"/- "tor-browser-linux64-gbuilt.zip"/' descriptors/linux/gitian-bundle.yml
sed -i '29s/- "tor-linux32-gbuilt.zip"/#- "tor-linux32-gbuilt.zip"/' descriptors/linux/gitian-bundle.yml
sed -i '30s/#- "tor-linux64-gbuilt.zip"/- "tor-linux64-gbuilt.zip"/' descriptors/linux/gitian-bundle.yml
sed -i '31s/- "pluggable-transports-linux32-gbuilt.zip"/#- "pluggable-transports-linux32-gbuilt.zip"/' descriptors/linux/gitian-bundle.yml
sed -i '32s/#- "pluggable-transports-linux64-gbuilt.zip"/- "pluggable-transports-linux64-gbuilt.zip"/' descriptors/linux/gitian-bundle.yml
sed -i '6s/- "i386"/#- "i386"/' descriptors/linux/gitian-firefox.yml
sed -i '7s/#- "amd64"/- "amd64"/' descriptors/linux/gitian-firefox.yml
sed -i '6s/- "i386"/#- "i386"/' descriptors/linux/gitian-pluggable-transports.yml
sed -i '7s/#- "amd64"/- "amd64"/' descriptors/linux/gitian-pluggable-transports.yml
sed -i '6s/- "i386"/#- "i386"/' descriptors/linux/gitian-tor.yml
sed -i '7s/#- "amd64"/- "amd64"/' descriptors/linux/gitian-tor.yml
./mkbundle-linux.sh
#--------------------------BASH END--------------------------------


Check out the hash in gitian-builder/result/bundle-linux-res.yml on line 6.
The hash for tor-browser-linux64-3.5.2.1_en-US.tar.xz must be
2d3061f50ac6a6976aba7442dbad0f8e74391ab37a6d6d4600b479dd8cb5bb54



Next, build stcppipe for Win/Lin/Mac platforms.
We reuse Tor Browser Bundle's cross-compilers.
Unfortunately, due to a known bug a the cross-compiler for Mac is missing and must be
downloaded manually, see https://trac.torproject.org/projects/tor/ticket/10678

#--------------------------BASH BEGIN--------------------------------
cd ../../gitian-builder/inputs
wget https://mingw-and-ndk.googlecode.com/files/multiarch-darwin11-cctools127.2-gcc42-5666.3-llvmgcc42-2336.1-Linux-120724.tar.xz
cp tlsnotary/data/gitian/stcppipe.zip gitian-builder/inputs/
cd gitian-builder/
#--commit tor=HEAD is a dummy which does nothing. This is because gitian expects a git repo in order to work
./bin/gbuild --commit tor=HEAD -m 400 ../tlsnotary/data/gitian/stcppipe.yml
#--------------------------BASH END--------------------------------


#You should get the following results in gitian-builder/result/stcppipe-res.yml
2edea787026db4fde95ee58ed783218f406a80b956c81478620a474c9b7cfca6  stcppipe.exe
3266e831103992ff3c80ce411587fe10b98bdee59007279752a4436b31b6d6d1  stcppipe_linux
f804b49d07f858a8e9a9eb76f346e1a9b2ef90105caddead2789b252cfef809f  stcppipe_mac
