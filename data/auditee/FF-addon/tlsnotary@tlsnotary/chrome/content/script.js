var bStartRecordingResponded = false;
var bStopRecordingResponded = false;
var bStopPreparePMS = false;
var bGetHTMLPaths = false;
var bIsRecordingSoftwareStarted = false; //we start the software only once
var reqStartRecording;
var reqStopRecording;
var reqPreparePMS;
var reqGetHTMLPaths;
var port;
var tab_url_full = "";//full URL at the time when RECORD is pressed
var tab_url = ""; //the URL at the time when RECORD is pressed (only the domain part up to the first /)
var session_path = "";
var observer;
var audited_browser; //the FF's internal browser which contains the audited HTML
var help;
var button_record_enabled;
var button_record_disabled;
var button_spinner;
var button_stop_enabled;
var button_stop_disabled;
var testingMode = false;

port = Cc["@mozilla.org/process/environment;1"].getService(Ci.nsIEnvironment).get("FF_to_backend_port");
//setting homepage should be done from here rather than defaults.js in order to have the desired effect. FF's quirk.
Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService).getBranch("browser.startup.").setCharPref("homepage", "chrome://tlsnotary/content/auditee.html");
//TODO: the pref  below must be set from here rather than defaults.js because Firefox overrides them on startup
Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService).getBranch("network.proxy.").setIntPref("type", 0);
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

//poll the env var to see if IRC started so that we can display a help message on the addon toolbar
//We do this from here rather than from auditee.html to make it easier to debug
var prevMsg = "";
pollEnvvar();
function pollEnvvar(){
	var msg = Cc["@mozilla.org/process/environment;1"].getService(Ci.nsIEnvironment).get("TLSNOTARY_MSG");
	if (msg != prevMsg) {
		prevMsg = msg;
		document.getElementById("help").value = msg;
	}
	var envvarvalue = Cc["@mozilla.org/process/environment;1"].getService(Ci.nsIEnvironment).get("TLSNOTARY_IRC_STARTED");
	if (envvarvalue != "true") {
		setTimeout(pollEnvvar, 1000);
		return;
	}
	//else if envvar was set, init all global vars
	help = document.getElementById("help");
	button_record_enabled = document.getElementById("button_record_enabled");
	button_record_disabled = document.getElementById("button_record_disabled");
	button_spinner = document.getElementById("button_spinner");
	button_stop_enabled = document.getElementById("button_stop_enabled");
	button_stop_disabled = document.getElementById("button_stop_disabled");
	observer = new myObserver();
	help.value = "Navigate to a webpage and press RECORD. The page will reload automatically.";
	button_record_disabled.hidden = true;
	button_record_enabled.hidden = false;
	popupShow("The connection to the auditor has been established. You may now open a new tab and go to a webpage. Please follow the instructions on the status bar below.")
}


function startRecording(){
	audited_browser = gBrowser.selectedBrowser;
	tab_url_full = audited_browser.contentWindow.location.href;
	if (!tab_url_full.startsWith("https://")){
		help.value = "ERROR You can only record pages which start with https://";
		return;
	}
	tab_url = tab_url_full.split('/')[2]
	button_record_enabled.hidden = true;
	button_spinner.hidden = false;
	button_stop_disabled.hidden = false;
	button_stop_enabled.hidden = true;
	if (bIsRecordingSoftwareStarted){
		preparePMS();
		return;
	}	
	help.value = "Initializing the recording software"
	reqStartRecording = new XMLHttpRequest();
    reqStartRecording.onload = responseStartRecording;
    reqStartRecording.open("HEAD", "http://127.0.0.1:"+port+"/start_recording", true);
    reqStartRecording.send();
    responseStartRecording(0);
}


function responseStartRecording(iteration){
    if (typeof iteration == "number"){
        if (iteration > 5){
			help.value = "ERROR responseStartRecording timed out";
            return;
        }
        if (!bStartRecordingResponded) setTimeout(responseStartRecording, 1000, ++iteration)
        return;
    }
    //else: not a timeout but a response from the server
	bStartRecordingResponded = true;
    var query = reqStartRecording.getResponseHeader("response");
    var status = reqStartRecording.getResponseHeader("status");
    if (query != "start_recording"){
		help.value = "ERROR Internal error. Wrong response header: " + query;
        return;
    }
	if (status != "success"){
		help.value = "ERROR Received an error message: " + status;
		return;
	}
	//else successful response
	bIsRecordingSoftwareStarted = true;
	var proxy_port = reqStartRecording.getResponseHeader("proxy_port");
	var prefs = Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService);
	var port_int = parseInt(proxy_port);
	prefs.setIntPref("network.proxy.type", 1);
	prefs.setCharPref("network.proxy.ssl","127.0.0.1");
	prefs.setIntPref("network.proxy.ssl_port", port_int);
	preparePMS();
}


function preparePMS(){
	help.value = "Negotiating cryptographic parameters with the auditor"
	//tell backend to prepare a google-checked PMS
	reqPreparePMS = new XMLHttpRequest();
    reqPreparePMS.onload = responsePreparePMS;
    reqPreparePMS.open("HEAD", "http://127.0.0.1:"+port+"/prepare_pms", true);
    reqPreparePMS.send();
    responsePreparePMS(0);	
}


function responsePreparePMS(iteration){
    if (typeof iteration == "number"){
        if (iteration > 20){
			help.value = "ERROR responsePreparePMS timed out";
            return;
        }
        if (!bStopPreparePMS) setTimeout(responsePreparePMS, 1000, ++iteration)
        return;
    }
    //else: not a timeout but a response from the server
	bStopPreparePMS = true;
    var query = reqPreparePMS.getResponseHeader("response");
    var status = reqPreparePMS.getResponseHeader("status");
   	if (query != "prepare_pms"){
		help.value = "ERROR Internal error. Wrong response header: " +query;
        return;
    }
	if (status != "success"){
		help.value = "ERROR Received an error message: " + status;
		return;
	}
	//else success preparing PMS, resume page reload
	help.value = "Waiting for the page to reload fully"
	//don't reuse TLS sessions
	var sdr = Cc["@mozilla.org/security/sdr;1"].getService(Ci.nsISecretDecoderRing);
	sdr.logoutAndTeardown();
	observer.register();
	audited_browser.addProgressListener(loadListener);
	audited_browser.reloadWithFlags(Ci.nsIWebNavigation.LOAD_FLAGS_BYPASS_CACHE);
	makeSureReloadDoesntTakeForever(0);
}


function makeSureReloadDoesntTakeForever(iteration) {
	if (help.value == "Waiting for the page to reload fully") {
		if (iteration > 300){
			help.value = "ERROR page reloading is taking too long. You may Stop loading this page and try again"
            return;
        }
		setTimeout(makeSureReloadDoesntTakeForever, 1000, ++iteration);
		return;
	}
 }


function myObserver() {}
myObserver.prototype = {
  observe: function(aSubject, topic, data) {
	 var httpChannel = aSubject.QueryInterface(Ci.nsIHttpChannel);
	 var url = httpChannel.URI.spec; 
	 if (url == tab_url_full) {
		observer.unregister();
		Cc["@mozilla.org/process/environment;1"].getService(Ci.nsIEnvironment).set("NSS_PATCH_STAGE_ONE", "true");
		console.log("nss patch toggled");
	}
  },
  register: function() {
    var observerService = Cc["@mozilla.org/observer-service;1"].getService(Ci.nsIObserverService);
    observerService.addObserver(this, "http-on-modify-request", false);
  },
  unregister: function() {
    var observerService = Cc["@mozilla.org/observer-service;1"].getService(Ci.nsIObserverService);
    observerService.removeObserver(this, "http-on-modify-request");
  }
}


//copied from https://developer.mozilla.org/en-US/docs/Code_snippets/Progress_Listeners
const STATE_STOP = Ci.nsIWebProgressListener.STATE_STOP;
const STATE_IS_WINDOW = Ci.nsIWebProgressListener.STATE_IS_WINDOW;
//start decrypting the trace as soon as DOM is loaded
var loadListener = {
    QueryInterface: XPCOMUtils.generateQI(["nsIWebProgressListener",
                                           "nsISupportsWeakReference"]),

    onStateChange: function(aWebProgress, aRequest, aFlag, aStatus) {
        if ((aFlag & STATE_STOP) && (aFlag & STATE_IS_WINDOW) && (aWebProgress.DOMWindow == aWebProgress.DOMWindow.top)) {
            // This fires when the page load finishes
			audited_browser.removeProgressListener(this);
			help.value = "Decrypting HTML (will pop up in a new tab)"
			get_html_paths();
        }
    },
    onLocationChange: function(aProgress, aRequest, aURI) {},
    onProgressChange: function(aWebProgress, aRequest, curSelf, maxSelf, curTot, maxTot) {},
    onStatusChange: function(aWebProgress, aRequest, aStatus, aMessage) {},
    onSecurityChange: function(aWebProgress, aRequest, aState) {}
}


//get paths to decrypted html files on local filesystem and show the html
function get_html_paths(){
	reqGetHTMLPaths = new XMLHttpRequest();
    reqGetHTMLPaths.onload = responseGetHTMLPaths;
    b64domain = btoa(tab_url);
    reqGetHTMLPaths.open("HEAD", "http://127.0.0.1:"+port+"/get_html_paths?domain="+b64domain, true);
    reqGetHTMLPaths.send();
    responseGetHTMLPaths(0);	
}

//NB: FF ignores offline mode when proxy is set to manual
function toggleOffline(){
	var curvalue = Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService).getBranch("network.proxy.").getIntPref("type");
	var newvalue;
	if (curvalue == 0) newvalue = 1;
	if (curvalue == 1) newvalue = 0;
	Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService).getBranch("network.proxy.").setIntPref("type", newvalue);
	BrowserOffline.toggleOfflineStatus(); //analogous to toggling "Work Offline" in File menu
}


function responseGetHTMLPaths(iteration){
    if (typeof iteration == "number"){
        if (iteration > 10){
			help.value = "ERROR responseGetHTMLPaths timed out";
            return;
        }
        if (!bGetHTMLPaths) setTimeout(responseGetHTMLPaths, 1000, ++iteration)
        return;
    }
    //else: not a timeout but a response from my backend server
	bGetHTMLPaths = true;
    var query = reqGetHTMLPaths.getResponseHeader("response");
    var status = reqGetHTMLPaths.getResponseHeader("status");
    if (query != "get_html_paths"){
		help.value = "ERROR Internal error. Wrong response header: " + query;
        return;
    }
	if (status != "success"){
		if (testingMode == true) {
			help.value = "ERROR Received an error message: " + status;
			return; //failure to find HTML is considered a fatal error during testing
		}
		help.value = "ERROR Received an error message: " + status + ". Page decryption FAILED. Try pressing RECORD again";
		button_record_enabled.hidden = false;
		button_spinner.hidden = true;
		button_stop_disabled.hidden = true;
		button_stop_enabled.hidden = false;
		return;
	}
	//else successful response
	b64_html_paths = reqGetHTMLPaths.getResponseHeader("html_paths");
	html_paths_string = atob(b64_html_paths);
	html_paths = html_paths_string.split("&");
	toggleOffline();
	for (var i=0; i<html_paths.length; i++){
		if (html_paths[i] == "") continue;
		let browser = gBrowser.addTab(html_paths[i]);
	}
	//FIXME: we should install a pageload listener here rather than relying on timeout
	setTimeout(toggleOffline, 1000);
	help.value = "Page decryption successful. Navigate to another page and press RECORD or press STOP to end";
	button_record_enabled.hidden = false;
	button_spinner.hidden = true;
	button_stop_disabled.hidden = true;
	button_stop_enabled.hidden = false;
}


function stopRecording(){
	help.value = "Preparing the data to be sent to the auditor"
	//disable proxy so that we can reach our localhost backend
	Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService).getBranch("network.proxy.").setIntPref("type", 0);
	button_spinner.hidden = true;
	button_record_enabled.hidden = true;
	button_stop_enabled.hidden = true;
	button_record_disabled.hidden = false;

	reqStopRecording = new XMLHttpRequest();
    reqStopRecording.onload = responseStopRecording;
    reqStopRecording.open("HEAD", "http://127.0.0.1:"+port+"/stop_recording", true);
    reqStopRecording.send();
    responseStopRecording(0);
}


function responseStopRecording(iteration){
    if (typeof iteration == "number"){
        if (iteration > 30){
			help.value = "ERROR responseStopRecording timed out ";
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
	button_spinner.hidden = true;
	button_stop_disabled.hidden = false;
    if (query != "stop_recording"){
		help.value = "ERROR Internal error. Wrong response header: "+query;
        return;
    }
	if (status != "success"){
		help.value = "ERROR Received an error message: " + status;
		return;
	}
	//else successful response, disable proxying
	Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService).setIntPref("network.proxy.type", 0);
	popupShow("Congratulations. The auditor has acknowledged successful receipt of your audit data. You may now close the browser");
	help.value = "Auditing session ended successfully";
	return;
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
}




//**********************Upload functions not in use for now
function ss_checkStarted(){
	if (ss_bSiteResponded == true) {
		return;
	}
	//else
	pb_start(); //from pipebytes.js
	setTimeout(pb_checkStarted, 20000)
	help.value = "Preparing the data to be sent to auditor using pipebytes.com..."
}

function pb_checkStarted(){
	if (pb_bSiteResponded == true){
		return;
	}
	//else
	jb_start(); //from jetbytes.js
	setTimeout(jb_checkStarted, 20000)
	help.value = "Preparing the data to be sent to auditor using jetbytes.com..."
}

function jb_checkStarted(){
	if (jb_bSiteResponded == true){
		 return;
	 }
	//else
	help.value = "ERROR. Failed to transfer the file to auditor. You will have to do it manually"
}
