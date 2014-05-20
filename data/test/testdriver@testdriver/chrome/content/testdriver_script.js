var mainWindow;
var auditeeBrowser;
var bHelpUpdate = false;
var tlsnGetUrlsResponded = false;
var reqGetUrls;
var tlsnLoadListener;
 var linkArray;
var tlsnCipherSuiteList;
var tlsnLinkIndex=0;

var tlsnCipherSuiteNames=["security.ssl3.rsa_aes_128_sha","security.ssl3.rsa_aes_256_sha","security.ssl3.rsa_rc4_128_md5","security.ssl3.rsa_rc4_128_sha"]


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

function tlsnInitTesting(){
    //get a global handle to the browser
    auditeeBrowser = gBrowser

    //required to allow silent close of all other tabs
    Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService).setBoolPref("browser.tabs.warnOnCloseOtherTabs", false);

    //need a progress listener to signal when initial page load completes:
    //copied from https://developer.mozilla.org/en-US/docs/Code_snippets/Progress_Listeners
    const STATE_STOP = Ci.nsIWebProgressListener.STATE_STOP;
    const STATE_IS_WINDOW = Ci.nsIWebProgressListener.STATE_IS_WINDOW;
    //wait for complete load of page before starting to record.
    tlsnLoadListener = {
        QueryInterface: XPCOMUtils.generateQI(["nsIWebProgressListener",
                                               "nsISupportsWeakReference"]),

        onStateChange: function(aWebProgress, aRequest, aFlag, aStatus) {
            if ((aFlag & STATE_STOP) && (aFlag & STATE_IS_WINDOW) && (aWebProgress.DOMWindow == aWebProgress.DOMWindow.top)) {
                // This fires when the load finishes
                auditeeBrowser.removeProgressListener(this);
                setTimeout(tlsnRecord, 2000);
            }
        },
        onLocationChange: function(aProgress, aRequest, aURI) {},
        onProgressChange: function(aWebProgress, aRequest, curSelf, maxSelf, curTot, maxTot) {},
        onStatusChange: function(aWebProgress, aRequest, aStatus, aMessage) {},
        onSecurityChange: function(aWebProgress, aRequest, aState) {}
    }

    //ask the back end for a list of websites to visit
    reqGetUrls = new XMLHttpRequest();
    reqGetUrls.onload = responseGetUrls;
    reqGetUrls.open("HEAD", "http://127.0.0.1:27777"+"/get_websites", true);
    reqGetUrls.send();
    //wait for response
    setTimeout(responseGetUrls, 1000,0);
    return;

}

function responseGetUrls(iteration){
    if (typeof iteration == "number"){
    //give 5 secs for backend to respond
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
    setTimeout(tlsnOpenLink,1000,0);
}

function tlsnSendErrorMsg(errmsg){
    var reqSendError = new XMLHttpRequest();
    reqSendError.open("HEAD", "http://127.0.0.1:27777"+"/log_error?errmsg="+errmsg, true);
    reqSendError.send();
    return;
}

function tlsnOpenLink(iteration){

    var helpmsg = document.getElementById("help").value;

    if (helpmsg.indexOf("ERR") == 0){
        tlsnSendErrorMsg("Error received in browser: "+helpmsg +
                         "for site: "+linkArray[tlsnLinkIndex-1] +
                         " and cipher suite: "+tlsnCipherSuiteNames[tlsnCipherSuiteList[tlsnLinkIndex-1]]);
        return; //give up
    }

    if (helpmsg.indexOf("Navigat",0) !== 0){
        if (typeof iteration == "number"){
        //give 200 secs for backend to respond (occasionally, servers are slow. better to just wait
        //than to needlessly corrupt an entire test).
            if (iteration > 200){
                tlsnSendErrorMsg("Timed out waiting for page load complete, for site: "
                                 +linkArray[tlsnLinkIndex-1]+" and cipher suite: "+
                                 tlsnCipherSuiteNames[tlsnCipherSuiteList[tlsnLinkIndex-1]]);
                return;
            }
            setTimeout(tlsnOpenLink, 1000, ++iteration);
            return;
        }
    }

    if (tlsnLinkIndex > linkArray.length -1){
        setTimeout(tlsnStopRecord,1000);
        return;
    }

    //set the cipher suite to be ONLY that in the given argument
    var prefs = Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService);
    var cs_int = parseInt(tlsnCipherSuiteList[tlsnLinkIndex]);
    for (var i=0;i<4;i++){
        if (i==cs_int){
            prefs.setBoolPref(tlsnCipherSuiteNames[i], true);
        }
        else {
            prefs.setBoolPref(tlsnCipherSuiteNames[i], false);
        }
    }

    auditeeBrowser.selectedTab = auditeeBrowser.addTab(linkArray[tlsnLinkIndex]);
    auditeeBrowser.removeAllTabsBut(auditeeBrowser.selectedTab);
    auditeeBrowser.addProgressListener(tlsnLoadListener);
    tlsnLinkIndex++;
    document.getElementById("help").value = "Loading page...";
    setTimeout(tlsnOpenLink,1000,0);

}

setTimeout(tlsnInitTesting,4000);

function tlsnRecord(){
    var btn = document.getElementById("button_record_enabled");
    tlsnSimulateClick(btn);
}

function tlsnStopRecord(){
    //reset prefs for file transfer
    var prefs = Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService);
    for (var i=0;i<4;i++){
            prefs.setBoolPref(tlsnCipherSuiteNames[i], true);
    }
    var btnStop = document.getElementById("button_stop_enabled");
    tlsnSimulateClick(btnStop);
    setTimeout(tlsnReceiveKeyboardInput,1000,0);

}

function tlsnReceiveKeyboardInput(iteration){
    var helpmsg = document.getElementById("help").value;
    if (!helpmsg.startsWith("Success")){
        //give 40 secs for backend to respond
        if (iteration > 20){
                tlsnSendErrorMsg("Timed out waiting to receive input from the keyboard to select the trace file.");
                return;
         }
         setTimeout(tlsnReceiveKeyboardInput, 1000, ++iteration);
         return;
        }

	//the audit is fully completed. trigger the backend to do hash checks
    reqFinaliseTest = new XMLHttpRequest();
    //reqFinaliseTest.onload = responseGetKeyboardInput;
    reqFinaliseTest.open("HEAD", "http://127.0.0.1:27777"+"/end_test", true);
    reqFinaliseTest.send();
    //finished; there will be no response
    return;
    
    //the code that has to do with FIle Upload dialog can be excised
    //-------------------------------------------------------------
    reqGetKeboardInput = new XMLHttpRequest();
    //reqGetKeboardInput.onload = responseGetKeyboardInput;
    reqGetKeboardInput.open("HEAD", "http://127.0.0.1:27777"+"/type_filepath", true);
    reqGetKeboardInput.send();
    //as of now, not bothering to wait for a response; should be fixed in case keyboard entry fails

    setTimeout(tlsnWaitForAuditCompletion, 1000,0);
    return;

}

function tlsnWaitForAuditCompletion(iteration){
    var helpmsg = document.getElementById("help").value;

    if (helpmsg.indexOf("Auditing",0) !== 0){
        if (typeof iteration == "number"){
        //give 60 secs for backend to respond
            if (iteration > 60){
                tlsnSendErrorMsg("Timed out waiting for tlsnotary to indicate successful completion of file transfer (and audit).");
                return;
            }
            setTimeout(tlsnWaitForAuditCompletion, 1000, ++iteration);
            return;
        }
    }

    //the audit is fully completed. trigger the backend to do hash checks
    reqFinaliseTest = new XMLHttpRequest();
    //reqFinaliseTest.onload = responseGetKeyboardInput;
    reqFinaliseTest.open("HEAD", "http://127.0.0.1:27777"+"/end_test", true);
    reqFinaliseTest.send();
    //finished; there will be no response

}

