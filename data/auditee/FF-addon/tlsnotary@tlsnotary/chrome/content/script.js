var bStartRecordingResponded = false;
var bStopRecordingResponded = false;
var bStopPreparePMS = false;
var bGetHTMLPaths = false;
var bAuditeeMacCheckResponded = false;
var bIsRecordingSoftwareStarted = false; //we start the software only once
var reqStartRecording;
var reqStopRecording;
var reqPreparePMS;
var reqGetHTMLPaths;
var reqAuditeeMacCheck;
var port;
var tab_url_full = "";//full URL at the time when AUDIT* is pressed
var tab_url = ""; //the URL at the time when AUDIT* is pressed (only the domain part up to the first /)
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
var proxy_port_int;

port = Cc["@mozilla.org/process/environment;1"].getService(Ci.nsIEnvironment).get("FF_to_backend_port");
//setting homepage should be done from here rather than defaults.js in order to have the desired effect. FF's quirk.
Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService).getBranch("browser.startup.").setCharPref("homepage", "chrome://tlsnotary/content/auditee.html");
//TODO: the pref  below must be set from here rather than defaults.js because Firefox overrides them on startup
switchProxy(false);
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
	help.value = "Go to a page and press AUDIT THIS PAGE. Then wait for the page to reload automatically.";
	button_record_disabled.hidden = true;
	button_record_enabled.hidden = false;
	popupShow("The connection to the auditor has been established. You may now open a new tab and go to a webpage. Please follow the instructions on the status bar below.")
}


function startRecording(){
	audited_browser = gBrowser.selectedBrowser;
	tab_url_full = audited_browser.contentWindow.location.href;
	if (!tab_url_full.startsWith("https://")){
		help.value = "ERROR You can only audit pages which start with https://";
		return;
	}
	tab_url = tab_url_full.split('/')[2]
	button_record_enabled.hidden = true;
	button_spinner.hidden = false;
	button_stop_disabled.hidden = false;
	button_stop_enabled.hidden = true;

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
	proxy_port_int = parseInt(proxy_port);
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
    //else success preparing PMS, send request to wait
    //for backend to signal successful receipt of server traffic
    //before beginning the reload
    auditeeMacCheck();

    help.value = "Waiting for the page to reload fully (decrypted HTML will open in new tab)"
	//don't reuse TLS sessions
	var sdr = Cc["@mozilla.org/security/sdr;1"].getService(Ci.nsISecretDecoderRing);
	sdr.logoutAndTeardown();

    //observer lets us cut off any attempts to connect except
    //the main page resource
	observer.register();

    switchProxy(true);

    audited_browser.reloadWithFlags(Ci.nsIWebNavigation.LOAD_FLAGS_BYPASS_CACHE);
	makeSureReloadDoesntTakeForever(0);
}


function makeSureReloadDoesntTakeForever(iteration) {
    if (help.value == "Waiting for the page to reload fully (decrypted HTML will open in new tab)") {
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
	 if (url.startsWith("http://127.0.0.1:")) return;
	 else if (url != tab_url_full) {
		 //drop all random request which dont match the urlbar, however dont touch
		 //localhost requests to the backend
		console.log("cancelled url: " + url);
		aSubject.cancel(Components.results.NS_BINDING_ABORTED);
		return;
	 }
	 //else url matched
	 console.log("allowed url: " + url);
	 observer.unregister();
	 Cc["@mozilla.org/process/environment;1"].getService(Ci.nsIEnvironment).set("NSS_PATCH_STAGE_ONE", "true");
	 console.log("nss patch toggled");
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

function auditeeMacCheck(){
    reqAuditeeMacCheck = new XMLHttpRequest();
    reqAuditeeMacCheck.onload = responseAuditeeMacCheck;
    reqAuditeeMacCheck.open("HEAD", "http://127.0.0.1:"+port+"/auditee_mac_check", true);
    reqAuditeeMacCheck.send();
    responseAuditeeMacCheck(0);
}


function responseAuditeeMacCheck(iteration){
    if (typeof iteration == "number"){
        if (iteration > 60){
            help.value = "auditee mac check error";
           return;
        }
        if (!bAuditeeMacCheckResponded) setTimeout(responseAuditeeMacCheck, 1000, ++iteration)
        return;
    }
    //else: not a timeout but a response from my backend server
    bAuditeeMacCheckResponded = true;

    //stop reload (equivalent to pressing red X)
    audited_browser.stop();

    //go back to online (and disable the proxy)
    switchOffline(false);

    //open decrypted tab only after the new reload has finished
    //and the browser has been put into offline mode
    audited_browser.addProgressListener(loadListener);
    audited_browser.reloadWithFlags(Ci.nsIWebNavigation.LOAD_FLAGS_BYPASS_CACHE);
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

function responseGetHTMLPaths(iteration){
    if (typeof iteration == "number"){
        if (iteration > 20){
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
		help.value = "ERROR Received an error message: " + status + ". Page decryption FAILED. Try pressing AUDIT THIS PAGE again";
		button_record_enabled.hidden = false;
		button_spinner.hidden = true;
		button_stop_disabled.hidden = true;
		button_stop_enabled.hidden = false;
		return;
	}
	//else successful response
    b64_html_paths = reqGetHTMLPaths.getResponseHeader("html_paths");
    html_paths_string = atob(b64_html_paths);

    html_paths = html_paths_string.split("&").filter(function(e){return e});

    //in new tlsnotary, perhaps there cannot be more than one html,
    //but kept in a loop just in case
    for (var i=0; i<html_paths.length; i++){
        var browser = gBrowser.getBrowserForTab(gBrowser.addTab(html_paths[i]));
        if (i==html_paths.length-1){
            browser.addProgressListener(loadListener2);
        }
    }

	help.value = "Page decryption successful. Go to another page and press AUDIT THIS PAGE or press FINISH";
	button_record_enabled.hidden = false;
	button_spinner.hidden = true;
	button_stop_disabled.hidden = true;
	button_stop_enabled.hidden = false;
}

//copied from https://developer.mozilla.org/en-US/docs/Code_snippets/Progress_Listeners
const STATE_STOP = Ci.nsIWebProgressListener.STATE_STOP;
const STATE_IS_WINDOW = Ci.nsIWebProgressListener.STATE_IS_WINDOW;

var loadListener = {
    QueryInterface: XPCOMUtils.generateQI(["nsIWebProgressListener",
                                           "nsISupportsWeakReference"]),

    onStateChange: function(aWebProgress, aRequest, aFlag, aStatus) {
        if ((aFlag & STATE_STOP) && (aFlag & STATE_IS_WINDOW) && (aWebProgress.DOMWindow == aWebProgress.DOMWindow.top)) {
            // This fires when the page load finishes
            audited_browser.removeProgressListener(this);
            switchOffline(true);
            get_html_paths();
        }
    },
    onLocationChange: function(aProgress, aRequest, aURI) {},
    onProgressChange: function(aWebProgress, aRequest, curSelf, maxSelf, curTot, maxTot) {},
    onStatusChange: function(aWebProgress, aRequest, aStatus, aMessage) {},
    onSecurityChange: function(aWebProgress, aRequest, aState) {}
}

//TODO: It should be possible to reuse the loadListener code
//(e.g. something like loadListener2 = loadListener; loadListener2.onStateChange = ...)
//but have not managed it yet.
var loadListener2 = {
    QueryInterface: XPCOMUtils.generateQI(["nsIWebProgressListener",
                                           "nsISupportsWeakReference"]),

    onStateChange: function(aWebProgress, aRequest, aFlag, aStatus) {
        if ((aFlag & STATE_STOP) && (aFlag & STATE_IS_WINDOW) && (aWebProgress.DOMWindow == aWebProgress.DOMWindow.top)) {
            // This fires when the page load finishes
            switchOffline(false);
        }
    },
    onLocationChange: function(aProgress, aRequest, aURI) {},
    onProgressChange: function(aWebProgress, aRequest, curSelf, maxSelf, curTot, maxTot) {},
    onStatusChange: function(aWebProgress, aRequest, aStatus, aMessage) {},
    onSecurityChange: function(aWebProgress, aRequest, aState) {}
}


function switchProxy(s){
    if (s == true){
        var prefs = Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService);
        prefs.setIntPref("network.proxy.type", 1);
        prefs.setCharPref("network.proxy.ssl","127.0.0.1");
        //proxy_port_int is set in responseStartRecording
        prefs.setIntPref("network.proxy.ssl_port", proxy_port_int);
    }
    else{
        Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService).getBranch("network.proxy.").setIntPref("type", 0);
    }
}

//if switch set to true, go offline, else go online
function switchOffline(s){
    //NB: FF ignores offline mode when proxy is set to manual
    switchProxy(false);
    var ioService = Components.classes["@mozilla.org/network/io-service;1"].getService(Components.interfaces.nsIIOService2);
    if (!ioService.offline && s){
        BrowserOffline.toggleOfflineStatus();
    }
    else if (ioService.offline && !s){
        BrowserOffline.toggleOfflineStatus();
    }
    //other 2 conditions, do nothing
}

function stopRecording(){
	help.value = "Preparing the data to be sent to the auditor"
	//disable proxy so that we can reach our localhost backend
    switchProxy(false);
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
    switchProxy(false);
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
