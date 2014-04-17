var bStartRecordingResponded = false;
var bStopRecordingResponded = false;
var bStopPreparePMS = false;
var bIsRecordngStarted = false;
var reqStartRecording;
var reqStopRecording;
var reqPreparePMS;
var port;
var url_for_recording_full = "";
var session_path = "";

port = Components.classes["@mozilla.org/process/environment;1"].getService(Components.interfaces.nsIEnvironment).get("FF_to_backend_port");
//setting homepage should be done from here rather than defaults.js in order to have the desired effect. FF's quirk.
Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService).getBranch("browser.startup.").setCharPref("homepage", "chrome://tlsnotary/content/auditee.html");
//the 2 prefs below must be set from here rather than defaults.js because TBB overrides them on startup
Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService).getBranch("network.proxy.").setIntPref("type", 0);
Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService).getBranch("network.proxy.").setBoolPref("socks_remote_dns", false);

//poll the env var to see if IRC started
//so that we can display a help message on the addon toolbar
pollEnvvar();
function pollEnvvar(){
	var envvarvalue = Components.classes["@mozilla.org/process/environment;1"].getService(Components.interfaces.nsIEnvironment).get("TLSNOTARY_IRC_STARTED");
	if (envvarvalue != "true"){
		setTimeout(pollEnvvar, 1000);
		return;
	}
	//else if envvar was set
	var help = document.getElementById("help");
	help.value = "Navigate to a webpage and press RECORD. The page will reload automatically.";
	var button_record_enabled = document.getElementById("button_record_enabled");
	var button_record_disabled = document.getElementById("button_record_disabled");
	button_record_disabled.hidden = true;
	button_record_enabled.hidden = false;
}


function startRecording(){
	url_for_recording_full = gBrowser.contentWindow.location.href;
	if (!url_for_recording_full.startsWith("https://")){
		alert("You can only record pages which start with https://");
		return;
	}
	var button_record_enabled = document.getElementById("button_record_enabled");
	var button_spinner = document.getElementById("button_spinner");
	var button_stop_enabled = document.getElementById("button_stop_enabled");
	var button_stop_disabled = document.getElementById("button_stop_disabled");

	if (bIsRecordngStarted){
		preparePMS();
		return;
	}
	button_record_enabled.hidden = false;
	button_spinner.hidden = false;
	button_stop_disabled.hidden = true;
	button_stop_enabled.hidden = false;

	reqStartRecording = new XMLHttpRequest();
    reqStartRecording.onload = responseStartRecording;
    reqStartRecording.open("HEAD", "http://127.0.0.1:"+port+"/start_recording", true);
    reqStartRecording.send();
    //give 20 secs for escrow to respond
    setTimeout(responseStartRecording, 1000, 0);
}

function preparePMS(){
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
	bIsRecordngStarted = true;
	var proxy_port = reqStartRecording.getResponseHeader("proxy_port");
	var prefs = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService);
	var port_int = parseInt(proxy_port);
	prefs.setIntPref("network.proxy.type", 1);
	prefs.setCharPref("network.proxy.ssl","127.0.0.1");
	prefs.setIntPref("network.proxy.ssl_port", port_int);
	var sdr = Components.classes["@mozilla.org/security/sdr;1"].getService(Components.interfaces.nsISecretDecoderRing);
	sdr.logoutAndTeardown();
	var help = document.getElementById("help");
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
	var help = document.getElementById("help");
	help.value = "You can navigate to more than one page. When finished, press STOP"
	//alert("Reloading may take up to one minute, depending on the number of resources on the page.")
	observer = new myObserver();
	BrowserReloadSkipCache();
}




function stopRecording(){
	//disable proxy so that we can reach our localhost backend
	Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService).getBranch("network.proxy.").setIntPref("type", 0);
	var button_record_disabled = document.getElementById("button_record_disabled");
	var button_spinner = document.getElementById("button_spinner");
	var button_stop_enabled = document.getElementById("button_stop_enabled");
	var button_stop_disabled = document.getElementById("button_stop_disabled");

	button_spinner.hidden = true;
	button_record_disabled. hidden = false;
	button_stop_enabled.hidden = true;
	button_spinner.hidden = false;

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
	var prefs = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService);
	prefs.setIntPref("network.proxy.type", 0);
	start_jetbytes(); //from jetbytes.js
}


function myObserver() {  this.register();}
myObserver.prototype = {
  observe: function(aSubject, topic, data) {
	 var httpChannel = aSubject.QueryInterface(Components.interfaces.nsIHttpChannel);
	 var accept = httpChannel.getRequestHeader("Accept");
	 var url_full = httpChannel.URI.spec;
	 var regex= /html/;
	 //remove the leading https:// and only keep the domain.com part
	 var urlparts1 = url_for_recording_full.slice(8).split("/")[0].split(".");
	 var url_for_recording_short = urlparts1[urlparts1.length-2] + "." + urlparts1[urlparts1.length-1];
	 
	 var urlparts2 = url_full.slice(8).split("/")[0].split(".");
	 var url_short = urlparts2[urlparts2.length-2] + "." + urlparts2[urlparts2.length-1];
	 
	 var url = url_full;
	 if ( (url_for_recording_short==url_short) && regex.test(accept) && url.startsWith("https://") && !url.endsWith(".png") && !url.endsWith(".gif") && !url.endsWith(".svg") && !url.endsWith(".css") && !url.endsWith(".js") && !url.endsWith(".jpg") && !url.endsWith(".ico") && !url.endsWith(".woff") && !url.endsWith(".swf") && !url.contains("favicon.ico#") ) 	{
		Components.classes["@mozilla.org/process/environment;1"].getService(Components.interfaces.nsIEnvironment).set("NSS_PATCH_STAGE_ONE", "true");
		console.log("patch toggled");
		observer.unregister();
	}
  },
  register: function() {
    var observerService = Components.classes["@mozilla.org/observer-service;1"]
                          .getService(Components.interfaces.nsIObserverService);
    observerService.addObserver(this, "http-on-modify-request", false);
  },
  unregister: function() {
    var observerService = Components.classes["@mozilla.org/observer-service;1"]
                            .getService(Components.interfaces.nsIObserverService);
    observerService.removeObserver(this, "http-on-modify-request");
  }
}
var observer = new myObserver();
