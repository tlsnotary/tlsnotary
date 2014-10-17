var auditeeBrowser;
var tlsnGetUrlsResponded = false;
var reqGetUrls;
var linkArray;
var tlsnCipherSuiteList;
var tlsnLinkIndex=0;
var tlsnCipherSuiteNames={"47":"security.ssl3.rsa_aes_128_sha","53":"security.ssl3.rsa_aes_256_sha",
	"4":"security.ssl3.rsa_rc4_128_md5","5":"security.ssl3.rsa_rc4_128_sha"};
var current_ciphersuite=''; //Testing only: used by script.js to tell backend which CS to use 
//we are using hardcoded port 37777 for now 
//var port_for_ciphertext = Cc["@mozilla.org/process/environment;1"].getService(Ci.nsIEnvironment).get("port_for_ciphertext");

//copied from https://developer.mozilla.org/en-US/docs/Code_snippets/Progress_Listeners
const STATE_STOP = Ci.nsIWebProgressListener.STATE_STOP;
const STATE_IS_WINDOW = Ci.nsIWebProgressListener.STATE_IS_WINDOW;

//wait for the page to become secure before we press AUDIT
var tlsnLoadListener = {
	QueryInterface: XPCOMUtils.generateQI(["nsIWebProgressListener",
										   "nsISupportsWeakReference"]),

	onStateChange: function(aWebProgress, aRequest, aFlag, aStatus) {},
	onLocationChange: function(aProgress, aRequest, aURI) {},
	onProgressChange: function(aWebProgress, aRequest, curSelf, maxSelf, curTot, maxTot) {},
	onStatusChange: function(aWebProgress, aRequest, aStatus, aMessage) {},
	onSecurityChange: function(aWebProgress, aRequest, aState)
	 {
        // check if the state is secure or not
        if(aState & Ci.nsIWebProgressListener.STATE_IS_SECURE)
        {
			gBrowser.removeProgressListener(this);
			//begin recording as soon as the page turns into https, but not immediately, because
			//send_certificate request must go out first
			setTimeout(tlsnRecord, 1000);
        }    
    }
}


if ("true" == Cc["@mozilla.org/process/environment;1"].getService(Ci.nsIEnvironment).get("TLSNOTARY_TEST")){
		setTimeout(tlsnInitTesting,3000); //allow some time for Connect button to activate
		testingMode = true;
}


function tlsnSimulateClick(what_to_click) {
  var event = new MouseEvent('click', {
    'view': window,
    'bubbles': true,
    'cancelable': true
  });
  //prevent popup blocker
  Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService).setBoolPref("dom.disable_open_during_load", false);
  what_to_click.dispatchEvent(event);
}


function tlsnSendErrorMsg(errmsg){
    var reqSendError = new XMLHttpRequest();
    reqSendError.open("HEAD", "http://127.0.0.1:27777"+"/log_error?errmsg="+errmsg, true);
    reqSendError.send();
    return;
}


function tlsnInitTesting(){
    //required to allow silent close of all other tabs
    Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService).setBoolPref("browser.tabs.warnOnCloseOtherTabs", false);	
    //ask the back end for a list of websites to visit
    reqGetUrls = new XMLHttpRequest();
    reqGetUrls.onload = responseGetUrls;
    reqGetUrls.open("HEAD", "http://127.0.0.1:27777"+"/get_websites", true);
    reqGetUrls.send();
    //wait for response
    responseGetUrls(0);
}


function responseGetUrls(iteration){
    if (typeof iteration == "number"){
        if (iteration > 5){
            //use an alert rather than messaging the backend, since that's exactly what's failing
            alert("responseGetUrls timed out - python backend not responding. please investigate.");
            return;
        }
        if (!tlsnGetUrlsResponded) setTimeout(responseGetUrls, 1000, ++iteration)
        return;
    }
    //else: not a timeout but a response from the server
    tlsnGetUrlsResponded = true;
    var query = reqGetUrls.getResponseHeader("response");
    if (query !== "get_websites"){
        //use an alert rather than messaging the backend, since that's exactly what's failing
        alert("Error - wrong response query header: "+query);
        return;
    }
    var tlsnUrlList = reqGetUrls.getResponseHeader("url_list");
    var cipherSuiteList = reqGetUrls.getResponseHeader("cs_list");
    linkArray = tlsnUrlList.split(',');
    tlsnCipherSuiteList = cipherSuiteList.split(',');
    //urls received, start the p2p connection
    var btn = content.document.getElementById("start_button");
    tlsnSimulateClick(btn);
    //wait for status bar to show readiness.
    waitForP2PConnection();
}


//The main addon will put ERROR message on timeout
function waitForP2PConnection(){
	var helpmsg = document.getElementById("help").value;
	if (helpmsg.startsWith("ERROR")){
		tlsnSendErrorMsg("Error received in browser: "+helpmsg +
						 "for site: "+linkArray[tlsnLinkIndex] +
						 " and cipher suite: "+tlsnCipherSuiteNames[tlsnCipherSuiteList[tlsnLinkIndex]]);
		return; //give up
	}
	if (!helpmsg.startsWith("Go to a page")){
		setTimeout(waitForP2PConnection, 1000);
		return;      
	}
	//else connected to peer
	startDecryptionProcess();
	//give auditor time to run checks and start the receiving thread
	setTimeout(openNextLink, 2000);
}


function openNextLink(){
	if (tlsnLinkIndex >= linkArray.length){
        tlsnStopRecord();
        return;
    }
    //set the cipher suite to be ONLY that in the given argument
    var prefs = Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService);
    var cs = tlsnCipherSuiteList[tlsnLinkIndex];
    //iterate over keys of associative array
    for (var key in tlsnCipherSuiteNames){
        if (key==cs){
            prefs.setBoolPref(tlsnCipherSuiteNames[key], true);
        }
        else {
            prefs.setBoolPref(tlsnCipherSuiteNames[key], false);
        }
    }
    
    current_ciphersuite = cs;
    auditeeBrowser = gBrowser.addTab(linkArray[tlsnLinkIndex]);
    gBrowser.addProgressListener(tlsnLoadListener);
    gBrowser.removeAllTabsBut(auditeeBrowser);
    document.getElementById("help").value = "Loading page..."
    //FIXME we should use auditeeBrowser here instead of gBrowser
    //but for some reason the listener never triggers then
	waitForRecordingToFinish(0);
}


function waitForRecordingToFinish(iteration){
   var helpmsg = document.getElementById("help").value;
    if (helpmsg.startsWith("ERROR")){
        tlsnSendErrorMsg("Error received in browser: "+helpmsg +
                         "for site: "+linkArray[tlsnLinkIndex] +
                         " and cipher suite: "+tlsnCipherSuiteNames[tlsnCipherSuiteList[tlsnLinkIndex]]);
        return; //give up
    }
    if (!(helpmsg.startsWith("Page decryption successful."))) {    
		if (iteration > 360){
			tlsnSendErrorMsg("Timed out waiting for page audit to finish"
							 +linkArray[tlsnLinkIndex]+" and cipher suite: "+
							 tlsnCipherSuiteNames[tlsnCipherSuiteList[tlsnLinkIndex]]);
			return;
		}
		setTimeout(waitForRecordingToFinish, 1000, ++iteration);
		return;
	}
	//the text is Page decryption successful. //give the addon some time to toggle off the offline mode
	tlsnLinkIndex++;
	setTimeout(openNextLink, 1000);
}


function tlsnRecord(){
    var btn = document.getElementById("button_record_enabled");
    tlsnSimulateClick(btn);
}


function tlsnStopRecord(){
    //reset prefs for file transfer
    /*var prefs = Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService);
    for (var i=0;i<4;i++){
            prefs.setBoolPref(tlsnCipherSuiteNames[i], true);
    }
    */
    var btnStop = document.getElementById("button_stop_enabled");
    tlsnSimulateClick(btnStop);
    waitForSessionEnd(0);
}


function waitForSessionEnd(iteration){
	var helpmsg = document.getElementById("help").value;
    if (!helpmsg.startsWith("Auditing session ended successfully")){
        if (iteration > 2000){
                tlsnSendErrorMsg("Timed out waiting for auditor to signal the verdict.");
                return;
         }
         setTimeout(waitForSessionEnd, 1000, ++iteration);
         return;
        }
	//the audit is fully completed. trigger the backend to do hash checks
    reqFinaliseTest = new XMLHttpRequest();
    //reqFinaliseTest.onload = responseGetKeyboardInput;
    reqFinaliseTest.open("HEAD", "http://127.0.0.1:27777"+"/end_test", true);
    reqFinaliseTest.send();
    //finished; there will be no response
}


var reqReadyToDecrypt;
var bStopReadyToDecrypt;
function startDecryptionProcess(){
	reqReadyToDecrypt = new XMLHttpRequest();
	reqReadyToDecrypt.onload = responseReadyToDecrypt;
	reqReadyToDecrypt.open("HEAD", "http://127.0.0.1:37777/ready_to_decrypt", true);
	reqReadyToDecrypt.send();
	responseReadyToDecrypt(0);
}

function responseReadyToDecrypt(iteration){
    if (typeof iteration == "number"){
        //if (iteration > 3000){
			//help.value = "ERROR responseReadyToDecrypt timed out";
			//we dont want to time out because this is an endless loop
            //return;
        
        if (!bStopReadyToDecrypt) setTimeout(responseReadyToDecrypt, 1000, ++iteration)
        return;
    }
    //else: not a timeout but a response from the server
	bStopReadyToDecrypt = true;
    var query = reqReadyToDecrypt.getResponseHeader("response");
    var b64ciphertext = reqReadyToDecrypt.getResponseHeader("ciphertext");
    var b64key = reqReadyToDecrypt.getResponseHeader("key");
    var b64iv = reqReadyToDecrypt.getResponseHeader("iv");
   	if (query != "ready_to_decrypt"){
		help.value = "ERROR Internal error. Wrong response header: " +query;
        return;
    }
    var b64cleartext = aes_decrypt(b64ciphertext, b64key, b64iv);
    bStopReadyToDecrypt = false;
    var req = new XMLHttpRequest();
    req.open("HEAD", "http://127.0.0.1:37777/cleartext="+b64cleartext, true);
	req.send();
	reqReadyToDecrypt.open("HEAD", "http://127.0.0.1:37777/ready_to_decrypt", true);
	reqReadyToDecrypt.timeout = 0; //no timeout
	reqReadyToDecrypt.send();
	responseReadyToDecrypt(0);
}

function aes_decrypt(b64ciphertext, b64key, b64IV){
	var cipherParams = CryptoJS.lib.CipherParams.create({
	ciphertext: CryptoJS.enc.Base64.parse(b64ciphertext)
	});
	var key = CryptoJS.enc.Base64.parse(b64key)
	var IV = CryptoJS.enc.Base64.parse(b64IV)
	var decrypted = CryptoJS.AES.decrypt(cipherParams, key, { iv: IV })
	var b64decrypted = decrypted.toString(CryptoJS.enc.Base64)
	return b64decrypted;
}
