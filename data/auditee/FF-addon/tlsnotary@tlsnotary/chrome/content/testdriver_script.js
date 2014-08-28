var auditeeBrowser;
var tlsnGetUrlsResponded = false;
var reqGetUrls;
var linkArray;
var tlsnCipherSuiteList;
var tlsnLinkIndex=0;
var tlsnCipherSuiteNames=["security.ssl3.rsa_aes_128_sha","security.ssl3.rsa_aes_256_sha","security.ssl3.rsa_rc4_128_md5","security.ssl3.rsa_rc4_128_sha"]
//copied from https://developer.mozilla.org/en-US/docs/Code_snippets/Progress_Listeners
//these const are already declared in script.js, if we declare them again, this script won't run
const STATE_STOP = Ci.nsIWebProgressListener.STATE_STOP;
const STATE_IS_WINDOW = Ci.nsIWebProgressListener.STATE_IS_WINDOW;
//wait for the page to fully load before we press RECORD
var tlsnLoadListener = {
	QueryInterface: XPCOMUtils.generateQI(["nsIWebProgressListener",
										   "nsISupportsWeakReference"]),

	onStateChange: function(aWebProgress, aRequest, aFlag, aStatus) {
		if ((aFlag & STATE_STOP) && (aFlag & STATE_IS_WINDOW) && (aWebProgress.DOMWindow == aWebProgress.DOMWindow.top)) {
			// This fires when the load finishes
			gBrowser.removeProgressListener(this);
			tlsnRecord();
		}
	},
	onLocationChange: function(aProgress, aRequest, aURI) {},
	onProgressChange: function(aWebProgress, aRequest, curSelf, maxSelf, curTot, maxTot) {},
	onStatusChange: function(aWebProgress, aRequest, aStatus, aMessage) {},
	onSecurityChange: function(aWebProgress, aRequest, aState) {}
}


if ("true" == Cc["@mozilla.org/process/environment;1"].getService(Ci.nsIEnvironment).get("TLSNOTARY_TEST")){
		setTimeout(tlsnInitTesting,3000); //allow some time for startIRC button to activate
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
    //urls received, start the connection over IRC
    var btn = content.document.getElementById("start_button");
    tlsnSimulateClick(btn);
    //wait for status bar to show readiness.
    waitForIRCStarted();
}


//The main addon will put ERROR message on timeout
function waitForIRCStarted(){
	var helpmsg = document.getElementById("help").value;
	if (helpmsg.startsWith("ERROR")){
		tlsnSendErrorMsg("Error received in browser: "+helpmsg +
						 "for site: "+linkArray[tlsnLinkIndex-1] +
						 " and cipher suite: "+tlsnCipherSuiteNames[tlsnCipherSuiteList[tlsnLinkIndex-1]]);
		return; //give up
	}
	if (!helpmsg.startsWith("Go to a page")){
		setTimeout(waitForIRCStarted, 1000);
		return;      
	}
	//else connected to IRC
	openNextLink();
}


function openNextLink(){
	if (tlsnLinkIndex > linkArray.length -1){
        tlsnStopRecord();
        return;
    }
    //set the cipher suite to be ONLY that in the given argument
    /*var prefs = Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService);
    var cs_int = parseInt(tlsnCipherSuiteList[tlsnLinkIndex]);
    for (var i=0;i<4;i++){
        if (i==cs_int){
            prefs.setBoolPref(tlsnCipherSuiteNames[i], true);
        }
        else {
            prefs.setBoolPref(tlsnCipherSuiteNames[i], false);
        }
    }
    */
    auditeeBrowser = gBrowser.addTab(linkArray[tlsnLinkIndex]);
    gBrowser.removeAllTabsBut(auditeeBrowser);
    document.getElementById("help").value = "Loading page..."
    //FIXME we should use auditeeBrowser here instead of gBrowser
    //but for some reason the listener never triggers then
    gBrowser.addProgressListener(tlsnLoadListener);
	tlsnLinkIndex++;
	waitForRecordingToFinish(0);
}


function waitForRecordingToFinish(iteration){
   var helpmsg = document.getElementById("help").value;
    if (helpmsg.startsWith("ERROR")){
        tlsnSendErrorMsg("Error received in browser: "+helpmsg +
                         "for site: "+linkArray[tlsnLinkIndex-1] +
                         " and cipher suite: "+tlsnCipherSuiteNames[tlsnCipherSuiteList[tlsnLinkIndex-1]]);
        return; //give up
    }
    if (!(helpmsg.startsWith("Page decryption successful."))) {    
		if (iteration > 360){
			tlsnSendErrorMsg("Timed out waiting for page to load and reload "
							 +linkArray[tlsnLinkIndex-1]+" and cipher suite: "+
							 tlsnCipherSuiteNames[tlsnCipherSuiteList[tlsnLinkIndex-1]]);
			return;
		}
		setTimeout(waitForRecordingToFinish, 1000, ++iteration);
		return;
	}
	//the text is Page decryption successful. //give the addon some time to toggle off the offline mode
	setTimeout(openNextLink, 3000);
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
        if (iteration > 200){
                tlsnSendErrorMsg("Timed out waiting to receive input from the keyboard to select the trace file.");
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
