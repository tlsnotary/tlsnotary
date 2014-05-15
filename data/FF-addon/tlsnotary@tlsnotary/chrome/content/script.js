var bStartRecordingResponded = false;
var bStopRecordingResponded = false;
var bStopPreparePMS = false;
var bGetHTMLPaths = false;
var bIsRecordingStarted = false;
var reqStartRecording;
var reqStopRecording;
var reqPreparePMS;
var reqGetHTMLPaths;
var port;
var url_for_recording_full = "";
var session_path = "";
var observer;
var audited_browser; //the FF's internal browser which contains the audited HTML
var help;

port = Cc["@mozilla.org/process/environment;1"].getService(Ci.nsIEnvironment).get("FF_to_backend_port");
//setting homepage should be done from here rather than defaults.js in order to have the desired effect. FF's quirk.
Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService).getBranch("browser.startup.").setCharPref("homepage", "chrome://tlsnotary/content/auditee.html");
//the 2 prefs below must be set from here rather than defaults.js because TBB overrides them on startup
Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService).getBranch("network.proxy.").setIntPref("type", 0);
Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService).getBranch("network.proxy.").setBoolPref("socks_remote_dns", false);

//poll the env var to see if IRC started
//so that we can display a help message on the addon toolbar
//TODO find out if auditee.html can access XUL ??? then we dont need this
pollEnvvar();
function pollEnvvar(){
	var envvarvalue = Cc["@mozilla.org/process/environment;1"].getService(Ci.nsIEnvironment).get("TLSNOTARY_IRC_STARTED");
	if (envvarvalue != "true"){
		setTimeout(pollEnvvar, 1000);
		return;
	}
	help = document.getElementById("help");
	//else if envvar was set
	help.value = "Navigate to a webpage and press RECORD. The page will reload automatically.";
	var button_record_enabled = document.getElementById("button_record_enabled");
	var button_record_disabled = document.getElementById("button_record_disabled");
	button_record_disabled.hidden = true;
	button_record_enabled.hidden = false;
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
            // This fires when the load finishes
			audited_browser.removeProgressListener(this);
			help.value = "Decrypting HTML (will pop up in a new tab)"
			//sleep at least 2 seconds so that the user could read the text above
			setTimeout(get_html_paths, 2000);
        }
    },
    onLocationChange: function(aProgress, aRequest, aURI) {},
    onProgressChange: function(aWebProgress, aRequest, curSelf, maxSelf, curTot, maxTot) {},
    onStatusChange: function(aWebProgress, aRequest, aStatus, aMessage) {},
    onSecurityChange: function(aWebProgress, aRequest, aState) {}
}


function myObserver() {}
myObserver.prototype = {
  observe: function(aSubject, topic, data) {
	 var httpChannel = aSubject.QueryInterface(Ci.nsIHttpChannel);
	 var accept = httpChannel.getRequestHeader("Accept");
	 var url_full = httpChannel.URI.spec;
	 var regex= /html/;
	 //remove the leading https:// and only keep the domain.com part
	 var urlparts1 = url_for_recording_full.slice(8).split("/")[0].split(".");
	 var url_for_recording_short = urlparts1[urlparts1.length-2] + "." + urlparts1[urlparts1.length-1];
	 
	 var urlparts2 = url_full.slice(8).split("/")[0].split(".");
	 var url_short = urlparts2[urlparts2.length-2] + "." + urlparts2[urlparts2.length-1];
	 
	 var url = url_full;
	 if ( (url_for_recording_short==url_short) && regex.test(accept) && url.startsWith("https://")
	  && !url.endsWith(".png") && !url.endsWith(".gif") && !url.endsWith(".svg") && !url.endsWith(".css") 
	  && !url.endsWith(".js") && !url.endsWith(".jpg") && !url.endsWith(".ico") && !url.endsWith(".woff") 
	  && !url.endsWith(".swf") && !url.contains("favicon.ico#") ) 	{
		observer.unregister();
		Cc["@mozilla.org/process/environment;1"].getService(Ci.nsIEnvironment).set("NSS_PATCH_STAGE_ONE", "true");
		console.log("patch toggled");
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
var observer = new myObserver();

//get paths to decrypted html files on local filesystem and show the html
function get_html_paths(){
	reqGetHTMLPaths = new XMLHttpRequest();
    reqGetHTMLPaths.onload = responseGetHTMLPaths;
    reqGetHTMLPaths.open("HEAD", "http://127.0.0.1:"+port+"/get_html_paths", true);
    reqGetHTMLPaths.send();
    //give 20 secs for escrow to respond
    setTimeout(responseGetHTMLPaths, 1000, 0);	
}

function responseGetHTMLPaths(iteration){
    if (typeof iteration == "number"){
    //give 5 secs for backend to respond
        if (iteration > 30){
            alert("responseGetHTMLPaths timed out");
            return;
        }
        if (!bGetHTMLPaths) setTimeout(responseGetHTMLPaths, 1000, ++iteration)
        return;
    }
    //else: not a timeout but a response from the server
	bGetHTMLPaths = true;
    var query = reqGetHTMLPaths.getResponseHeader("response");
    var status = reqGetHTMLPaths.getResponseHeader("status");

    if (query != "get_html_paths"){
        alert("Internal error. Wrong response header: " + query);
        return;
    }
	if (status != "success"){
		alert ("Received an error message: " + status);
		help.value = "Navigate to a webpage and press RECORD. The page will reload automatically.";
		var button_record_enabled = document.getElementById("button_record_enabled");
		var button_spinner = document.getElementById("button_spinner");
		var button_stop_enabled = document.getElementById("button_stop_enabled");
		var button_stop_disabled = document.getElementById("button_stop_disabled");
		
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
	for (var i=0; i<html_paths.length; i++){
		if (html_paths[i] == "") continue;
		gBrowser.addTab(html_paths[i]);
	}
	help.value = "Navigate to a webpage and press RECORD. The page will reload automatically.";
	var button_record_enabled = document.getElementById("button_record_enabled");
	var button_spinner = document.getElementById("button_spinner");
	var button_stop_enabled = document.getElementById("button_stop_enabled");
	var button_stop_disabled = document.getElementById("button_stop_disabled");
	
	button_record_enabled.hidden = false;
	button_spinner.hidden = true;
	button_stop_disabled.hidden = true;
	button_stop_enabled.hidden = false;
}


function startRecording(){
	audited_browser = gBrowser.selectedBrowser;
	url_for_recording_full = audited_browser.contentWindow.location.href;
	if (!url_for_recording_full.startsWith("https://")){
		alert("You can only record pages which start with https://");
		return;
	}
	var button_record_enabled = document.getElementById("button_record_enabled");
	var button_spinner = document.getElementById("button_spinner");
	var button_stop_enabled = document.getElementById("button_stop_enabled");
	var button_stop_disabled = document.getElementById("button_stop_disabled");
	
	button_record_enabled.hidden = true;
	button_spinner.hidden = false;
	button_stop_disabled.hidden = false;
	button_stop_enabled.hidden = true;

	if (bIsRecordingStarted){
		preparePMS();
		return;
	}
	
	help.value = "Initializing the recording software"
	reqStartRecording = new XMLHttpRequest();
    reqStartRecording.onload = responseStartRecording;
    reqStartRecording.open("HEAD", "http://127.0.0.1:"+port+"/start_recording", true);
    reqStartRecording.send();
    //give 20 secs for escrow to respond
    setTimeout(responseStartRecording, 1000, 0);
}

function preparePMS(){
	help.value = "Negotiating cryptographic parameters with auditor"
	//tell backend to prepare a google-checked PMS
	reqPreparePMS = new XMLHttpRequest();
    reqPreparePMS.onload = responsePreparePMS;
    reqPreparePMS.open("HEAD", "http://127.0.0.1:"+port+"/prepare_pms", true);
    reqPreparePMS.send();
    //give 20 secs for escrow to respond
    setTimeout(responsePreparePMS, 1000, 0);	
}

function responseStartRecording(iteration){
    if (typeof iteration == "number"){
    //give 5 secs for backend to respond
        if (iteration > 5){
            alert("responseStartRecording timed out");
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
        alert("Internal error. Wrong response header: " + query);
        return;
    }
	if (status != "success"){
		alert ("Received an error message: " + status);
		return;
	}
	//else successful response
	bIsRecordingStarted = true;
	var proxy_port = reqStartRecording.getResponseHeader("proxy_port");
	var prefs = Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService);
	var port_int = parseInt(proxy_port);
	prefs.setIntPref("network.proxy.type", 1);
	prefs.setCharPref("network.proxy.ssl","127.0.0.1");
	prefs.setIntPref("network.proxy.ssl_port", port_int);
	preparePMS();
}

function responsePreparePMS(iteration){
    if (typeof iteration == "number"){
    //give 5 secs for backend to respond
        if (iteration > 20){
            alert("responsePreparePMS timed out");
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
        alert("Internal error. Wrong response header: "+query);
        return;
    }
	if (status != "success"){
		alert ("Received an error message: " + status);
		return;
	}
	//else success preparing PMS, resume page reload
	help.value = "Waiting for the page to reload fully"
	var sdr = Cc["@mozilla.org/security/sdr;1"].getService(Ci.nsISecretDecoderRing);
	sdr.logoutAndTeardown();
	observer.register();
	audited_browser.addProgressListener(loadListener);
	audited_browser.reloadWithFlags(Ci.nsIWebNavigation.LOAD_FLAGS_BYPASS_CACHE);
}


function stopRecording(){
	help.value = "Preparing the data to be sent to auditor"
	//disable proxy so that we can reach our localhost backend
	Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService).getBranch("network.proxy.").setIntPref("type", 0);
	var button_record_disabled = document.getElementById("button_record_disabled");
	var button_record_enabled = document.getElementById("button_record_enabled");
	var button_spinner = document.getElementById("button_spinner");
	var button_stop_enabled = document.getElementById("button_stop_enabled");
	var button_stop_disabled = document.getElementById("button_stop_disabled");

	button_spinner.hidden = true;
	button_record_enabled.hidden = true;
	button_stop_enabled.hidden = true;
	button_record_disabled.hidden = false;

	reqStopRecording = new XMLHttpRequest();
    reqStopRecording.onload = responseStopRecording;
    reqStopRecording.open("HEAD", "http://127.0.0.1:"+port+"/stop_recording", true);
    reqStopRecording.send();
    //give 20 secs for escrow to respond
    setTimeout(responseStopRecording, 1000, 0);
}


function responseStopRecording(iteration){
    if (typeof iteration == "number"){
    //give 5 secs for backend to respond
        if (iteration > 20){
            alert("responseStopRecording timed out");
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
	
	var button_spinner = document.getElementById("button_spinner");
	var button_stop_disabled = document.getElementById("button_stop_disabled");
	button_spinner.hidden = true;
	button_stop_disabled.hidden = false;

    if (query != "stop_recording"){
        alert("Internal error. Wrong response header: "+query);
        return;
    }
	if (status != "success"){
		alert ("Received an error message: " + status);
		return;
	}
	//else successful response, disable proxying
	Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService).setIntPref("network.proxy.type", 0);
	//set a dir which will open up to in "choose file" dialog
	var ioSvc = Cc["@mozilla.org/network/io-service;1"].getService(Ci.nsIIOService);
	var prefService = Cc["@mozilla.org/content-pref/service;1"].getService(Ci.nsIContentPrefService);
	var uri = ioSvc.newURI("http://www.sendspace.com", null, null);
	prefService.setPref(uri, "browser.upload.lastDir", session_path, null);
	var uri2 = ioSvc.newURI("http://host03.pipebytes.com", null, null);
	prefService.setPref(uri2, "browser.upload.lastDir", session_path, null);
	var uri3 = ioSvc.newURI("http://www.jetbytes.com", null, null);
	prefService.setPref(uri3, "browser.upload.lastDir", session_path, null);
	console.log("was here");
	
	ss_start(); //from sendspace.js
	setTimeout(ss_checkStarted, 20000)
	help.value = "Preparing the data to be sent to auditor using sendspace.com..."
}


function ss_checkStarted(){
	if (ss_bSiteResponded == true) {
		help.value = "Beginning the data transfer using sendspace.com...";
		return;
	}
	//else
	pb_start(); //from pipebytes.js
	setTimeout(pb_checkStarted, 20000)
	help.value = "Preparing the data to be sent to auditor using pipebytes.com..."
}

function pb_checkStarted(){
	if (pb_bSiteResponded == true){
		help.value = "Beginning the data transfer using pipebytes.com...";
		return;
	}
	//else
	jb_start(); //from jetbytes.js
	setTimeout(jb_checkStarted, 20000)
	help.value = "Preparing the data to be sent to auditor using jetbytes.com..."
}

function jb_checkStarted(){
	if (jb_bSiteResponded == true){
		 help.value = "Beginning the data transfer using jetbytes.com...";
		 return;
	 }
	//else
	help.value = "Failed to transfer the file to auditor. You will have to do it manually"
}
