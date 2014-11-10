var bStartRecordingResponded = false;
var bStopRecordingResponded = false;
var bStopStartAudit = false;
var bIsRecordingSoftwareStarted = false; //we start the software only once
var reqStartRecording;
var reqStopRecording;
var reqStartAudit;
var port;
var tab_url_full = "";//full URL at the time when AUDIT* is pressed
var tab_url = ""; //the URL at the time when AUDIT* is pressed (only the domain part up to the first /)
var session_path = "";
var audited_browser; //the FF's internal browser which contains the audited HTML
var testingMode = false;
var headers="";
var dict_of_certs = {};
var dict_of_status = {};
var dict_of_httpchannels = {};

port = Cc["@mozilla.org/process/environment;1"].getService(Ci.nsIEnvironment).get("FF_to_backend_port");
//setting homepage should be done from here rather than defaults.js in order to have the desired effect. FF's quirk.
Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService).getBranch("browser.startup.").setCharPref("homepage", "chrome://tlsnotary/content/auditee.html");
Components.utils.import("resource://gre/modules/PopupNotifications.jsm");


function popupShow(text) {
	PopupNotifications.show(gBrowser.selectedBrowser, "tlsnotary-popup", text,
	null, /* anchor ID */
	{
	  label: "Close this notification",
	  accessKey: "C",
	  callback: function() {},
	},
	null  /* secondary action */
	);
}

/*Show the notification with default buttons (usebutton undefined), 'AUDIT' and 'FINISH'
or with just the AUDIT button (usebutton true or truthy) or no buttons (usebutton false) */
function notBarShow(text,usebutton){
    var win = Services.wm.getMostRecentWindow('navigator:browser'); //this is the target window
    var _gNB = win.document.getElementById("global-notificationbox"); //global notification box area
    _gNB.removeAllNotifications();
    var buttons;
    if (typeof(usebutton)==='undefined'){
    //Default: show both buttons
	buttons = [{
	    label: 'AUDIT THIS PAGE',
	    popup: null,
	    callback: startRecording
	},
	{
	    label: 'FINISH',
	    accessKey: null,
	    popup: null,
	    callback: stopRecording
	    }];
    }
    else if (usebutton===false){
	buttons = null;
    }
    else{
	buttons = [{
	    label: 'AUDIT THIS PAGE',
	    accessKey: "U",
	    popup: null,
	    callback: startRecording
	}];
    }
	const priority = _gNB.PRIORITY_INFO_MEDIUM;
	_gNB.appendNotification(text, 'tlsnotary-box',
			     'chrome://tlsnotary/skin/security-icon.png',
			      priority, buttons);
}


//poll the env var to see if IRC started so that we can display a help message on the addon toolbar
//We do this from here rather than from auditee.html to make it easier to debug
var prevMsg = "";
setTimeout(startListening,500);
pollEnvvar();
function pollEnvvar(){
	var msg = Cc["@mozilla.org/process/environment;1"].getService(Ci.nsIEnvironment).get("TLSNOTARY_MSG");
	if (msg != prevMsg) {
		prevMsg = msg;
		notBarShow(msg,false);
	}
	var envvarvalue = Cc["@mozilla.org/process/environment;1"].getService(Ci.nsIEnvironment).get("TLSNOTARY_IRC_STARTED");
	if (!envvarvalue.startsWith("true")) {
		setTimeout(pollEnvvar, 1000);
		return;
	}
	//else if envvar was set, init all global vars
	
	
	var tmode = envvarvalue.charAt(envvarvalue.length -1)
	if (tmode=='0'){
	popupShow("The self testing audit connection is established. You may now open a new tab and go to a webpage. Please follow the instructions on the status bar below. ");
	}
	else {
	popupShow("The connection to the auditor has been established. You may now open a new tab and go to a webpage. Please follow the instructions on the status bar below.");
	}
	
	notBarShow("Go to a page and press AUDIT THIS PAGE. Then wait for the page to reload automatically.",true);
	
	if (Cc["@mozilla.org/process/environment;1"].getService(Ci.nsIEnvironment).
		get("TLSNOTARY_USING_BROWSER_AES_DECRYPTION") == 'true'){
		var decr_port = Cc["@mozilla.org/process/environment;1"].getService(Ci.nsIEnvironment).get("TLSNOTARY_AES_DECRYPTION_PORT");
		startDecryptionProcess(decr_port);
	}

}

function startListening(){
//from now on, we will check the security status of all loaded tabs
//and store the security status and certificate fingerprint in a lookup table
//indexed by the url. Doing this immediately allows the user to start
//loading tabs before the peer negotiation is finished.
    gBrowser.addProgressListener(myListener);
}

function startRecording(){
    audited_browser = gBrowser.selectedBrowser;
    tab_url_full = audited_browser.contentWindow.location.href;
    
    //remove hashes - they are not URLs but are used for internal page mark-up
    sanitized_url = tab_url_full.split("#")[0];
    
    if (!sanitized_url.startsWith("https://")){
	var btn = document.getElementsByAttribute("label","FINISH")[0]; //global notification box area
	errmsg="ERROR You can only audit pages which start with https://";
	if (typeof(btn)==='undefined'){
	    notBarShow(errmsg,true);
	}
	else{
	    notBarShow(errmsg);
	}
	return;
    }
    if (dict_of_status[sanitized_url] != "secure"){
	alert("Do not attempt to audit this page! It does not have a valid SSL certificate.");
	notBarShow("Go to a page and press AUDIT THIS PAGE. Then wait for the page to reload automatically.");
	return;
    }
    
    //passed tests, secure, grab headers, update status bar and start audit:
    var x = sanitized_url.split('/');
    x.splice(0,3);
    tab_url = x.join('/');
	
    var httpChannel = dict_of_httpchannels[sanitized_url]
	headers = "";
	headers += httpChannel.requestMethod + " /" + tab_url + " HTTP/1.1" + "\r\n";
	httpChannel.visitRequestHeaders(function(header,value){
                                  headers += header +": " + value + "\r\n";});
    notBarShow('Audit is underway, please wait...',false);
    startAudit(sanitized_url);
}


function buildBase64DER(chars){
    var result = "";
    for (i=0; i < chars.length; i++)
        result += String.fromCharCode(chars[i]);
    return btoa(result);
}


function startAudit(urldata){
    notBarShow("Audit is underway, please be patient.",false);
    reqStartAudit = new XMLHttpRequest();
    reqStartAudit.onload = responseStartAudit;
    var cert = dict_of_certs[urldata];
    var len = new Object();
    var rawDER = cert.getRawDER(len);
    var b64DERCert = buildBase64DER(rawDER);    
    var b64headers = btoa(headers); //headers is a global variable
    var ciphersuite = ''
    if (testingMode == true){
		ciphersuite = current_ciphersuite; //<-- global var from testdriver_script.js
	}
    reqStartAudit.open("HEAD", "http://127.0.0.1:"+port+"/start_audit?b64dercert="+b64DERCert+
		"&b64headers="+b64headers+"&ciphersuite="+ciphersuite, true);
	reqStartAudit.timeout = 0; //no timeout
    reqStartAudit.send();
    responseStartAudit(0);	
}


function responseStartAudit(iteration){
    if (typeof iteration == "number"){
        if (iteration > 100){
	    notBarShow("ERROR: responseStartAudit timed out",false);
            return;
        }
        if (!bStopStartAudit) setTimeout(responseStartAudit, 1000, ++iteration)
        return;
    }
    //else: not a timeout but a response from the server
	bStopStartAudit = true;
    var query = reqStartAudit.getResponseHeader("response");
    var status = reqStartAudit.getResponseHeader("status");
   	if (query != "start_audit"){
		notBarShow("ERROR Internal error. Wrong response header: " +query,false);
        return;
    }
    if (status != "success"){
        if (testingMode == true) {
	    notBarShow("ERROR Received an error message: " + status);
            return; //failure to find HTML is considered a fatal error during testing
        }
        notBarShow("ERROR Received an error message: " + status + ". Page decryption FAILED. Try pressing AUDIT THIS PAGE again",true);
        
        return;
    }

    //else successful response
    b64_html_paths = reqStartAudit.getResponseHeader("html_paths");
    html_paths_string = atob(b64_html_paths);

    html_paths = html_paths_string.split("&").filter(function(e){return e});

    //in new tlsnotary, perhaps there cannot be more than one html,
    //but kept in a loop just in case
    go_offline_for_a_moment(); //prevents loading images from cache
    for (var i=0; i<html_paths.length; i++){
        var browser = gBrowser.getBrowserForTab(gBrowser.addTab(html_paths[i]));
    }

    notBarShow("Page decryption successful. Press FINISH or go to another page and press AUDIT THIS PAGE");
    
}


function go_offline_for_a_moment(){
	BrowserOffline.toggleOfflineStatus();
	setTimeout(function(){
		BrowserOffline.toggleOfflineStatus();
		}, 1000)
}


function stopRecording(){
    notBarShow("Preparing the data to be sent to the auditor",false);
    

    reqStopRecording = new XMLHttpRequest();
    reqStopRecording.onload = responseStopRecording;
    reqStopRecording.open("HEAD", "http://127.0.0.1:"+port+"/stop_recording", true);
    reqStopRecording.send();
    responseStopRecording(0);
}

function responseStopRecording(iteration){
    if (typeof iteration == "number"){
		var timeout = 100;
		if (testingMode) timeout = 2000;
        if (iteration > timeout){
	    notBarShow("ERROR responseStopRecording timed out ",false);
            return;
        }
        if (!bStopRecordingResponded) setTimeout(responseStopRecording, 1000, ++iteration)
        return;
    }
    //else: not a timeout but a response from the server
	bStopRecordingResponded = true;
    var query = reqStopRecording.getResponseHeader("response");
    var status = reqStopRecording.getResponseHeader("status");
    session_path = reqStopRecording.getResponseHeader("session_path");
	
    if (query != "stop_recording"){
		notBarShow("ERROR Internal error. Wrong response header: "+query,false);
        return;
    }
	if (status != "success"){
		notBarShow("ERROR Received an error message: " + status,false);
		return;
	}

	popupShow("Congratulations. The auditor has acknowledged successful receipt of your audit data. You may now close the browser");
	notBarShow("Auditing session ended successfully",false);
	return;
}


function dumpSecurityInfo(channel,urldata) {
    const Cc = Components.classes;
    const Ci = Components.interfaces;
    // Do we have a valid channel argument?
    if (! channel instanceof  Ci.nsIChannel) {
        console.log("No channel available\n");
        return;
    }
    var secInfo = channel.securityInfo;
    // Print general connection security state
    if (secInfo instanceof Ci.nsITransportSecurityInfo) {
        secInfo.QueryInterface(Ci.nsITransportSecurityInfo);
        // Check security state flags
	latest_tab_sec_state = "uninitialised";
        if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_SECURE) == Ci.nsIWebProgressListener.STATE_IS_SECURE)
            latest_tab_sec_state = "secure";
        else if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_INSECURE) == Ci.nsIWebProgressListener.STATE_IS_INSECURE)
            latest_tab_sec_state = "insecure";
        else if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_BROKEN) == Ci.nsIWebProgressListener.STATE_IS_BROKEN)
            latest_tab_sec_state = "unknown";
	
	//remove hashes - they are not URLs but are used for internal page mark-up
	sanitized_url = urldata.split("#")[0];
	dict_of_status[sanitized_url] = latest_tab_sec_state;
	dict_of_httpchannels[sanitized_url]  = channel.QueryInterface(Ci.nsIHttpChannel);
	
    }
    else {
        console.log("\tNo security info available for this channel\n");
    }
    // Print SSL certificate details
    if (secInfo instanceof Ci.nsISSLStatusProvider) {
      var cert = secInfo.QueryInterface(Ci.nsISSLStatusProvider).SSLStatus.QueryInterface(Ci.nsISSLStatus).serverCert;
      dict_of_certs[sanitized_url] = cert;
      //send the cert immediately to backend to prepare encrypted PMS
	  send_cert_to_backend(cert);
    }
	
}


function send_cert_to_backend(cert){
    var len = new Object();
    var rawDER = cert.getRawDER(len);
    var b64DERCert = buildBase64DER(rawDER);    
	var reqSendCertificate = new XMLHttpRequest();
    reqSendCertificate.open("HEAD", "http://127.0.0.1:"+port+"/send_certificate?"+b64DERCert, true);
    reqSendCertificate.send();
    //we don't care about the response
}


var myListener =
{
    QueryInterface: function(aIID)
    {
        if (aIID.equals(Components.interfaces.nsIWebProgressListener) ||
           aIID.equals(Components.interfaces.nsISupportsWeakReference) ||
           aIID.equals(Components.interfaces.nsISupports))
            return this;
        throw Components.results.NS_NOINTERFACE;
    },

    onStateChange: function(aWebProgress, aRequest, aFlag, aStatus) { },

    onLocationChange: function(aProgress, aRequest, aURI) { },

    onProgressChange: function(aWebProgress, aRequest, curSelf, maxSelf, curTot, maxTot) { },
    onStatusChange: function(aWebProgress, aRequest, aStatus, aMessage) { },
    onSecurityChange: function(aWebProgress, aRequest, aState) 
    {
        // check if the state is secure or not
        if(aState & Ci.nsIWebProgressListener.STATE_IS_SECURE)
        {
            // this is a secure page, check if aRequest is a channel,
            // since only channels have security information
            if (aRequest instanceof Ci.nsIChannel)
            {
                dumpSecurityInfo(aRequest,gBrowser.selectedBrowser.contentWindow.location.href);
                
            }
        }    
    }
}


var reqReadyToDecrypt;
var bStopReadyToDecrypt = false;
var decryption_port;
function startDecryptionProcess(decr_port){
	decryption_port = decr_port; //increase the scope so other functions could access it
	reqReadyToDecrypt = new XMLHttpRequest();
	reqReadyToDecrypt.onload = responseReadyToDecrypt;
	reqReadyToDecrypt.open("HEAD", "http://127.0.0.1:"+decr_port+"/ready_to_decrypt", true);
	reqReadyToDecrypt.send();
	setTimeout(responseReadyToDecrypt, 0, 0);
}

function responseReadyToDecrypt(iteration){
    if (typeof iteration == "number" || iteration == undefined){
		//we dont want to time out because this is an endless loop        
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
		alert(iteration);
		notBarShow("ERROR Internal error. Wrong response header: " +query,false);
        return;
    }
    var b64cleartext = aes_decrypt(b64ciphertext, b64key, b64iv);
    bStopReadyToDecrypt = false;
    var req = new XMLHttpRequest();
    req.open("HEAD", "http://127.0.0.1:"+decryption_port+"/cleartext="+b64cleartext, true);
	req.send();
	reqReadyToDecrypt.open("HEAD", "http://127.0.0.1:"+decryption_port+"/ready_to_decrypt", true);
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





//The code below will have to be used again if sending file via
//sendspace using the pure python method becomes broken

////set a dir which will open up to in "choose file" dialog
//var ioSvc = Cc["@mozilla.org/network/io-service;1"].getService(Ci.nsIIOService);
//var prefService = Cc["@mozilla.org/content-pref/service;1"].getService(Ci.nsIContentPrefService);
//var uri = ioSvc.newURI("http://www.sendspace.com", null, null);
//prefService.setPref(uri, "browser.upload.lastDir", session_path, null);
//var uri2 = ioSvc.newURI("http://host03.pipebytes.com", null, null);
//prefService.setPref(uri2, "browser.upload.lastDir", session_path, null);
//var uri3 = ioSvc.newURI("http://www.jetbytes.com", null, null);
//prefService.setPref(uri3, "browser.upload.lastDir", session_path, null);

//ss_start(); //from sendspace.js
//setTimeout(ss_checkStarted, 20000)
//help.value = "Preparing the data to be sent to auditor using sendspace.com..."
	
//**********************Upload functions not in use for now
function ss_checkStarted(){
	if (ss_bSiteResponded == true) {
		return;
	}
	//else
	pb_start(); //from pipebytes.js
	setTimeout(pb_checkStarted, 20000)
	notBarShow("Preparing the data to be sent to auditor using pipebytes.com...",false);
}

function pb_checkStarted(){
	if (pb_bSiteResponded == true){
		return;
	}
	//else
	jb_start(); //from jetbytes.js
	setTimeout(jb_checkStarted, 20000)
	notBarShow("Preparing the data to be sent to auditor using jetbytes.com...",false);
}

function jb_checkStarted(){
	if (jb_bSiteResponded == true){
		 return;
	 }
	//else
	notBarShow("ERROR. Failed to transfer the file to auditor. You will have to do it manually",false);
}
