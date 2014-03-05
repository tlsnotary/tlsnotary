var bStartRecordingResponded = false;
var bStopRecordingResponded = false;
var reqStartRecording;
var reqStopRecording;
var port;

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
	var button_record_enabled = document.getElementById("button_record_enabled");
	var button_spinner = document.getElementById("button_spinner");
	var button_stop_enabled = document.getElementById("button_stop_enabled");
	var button_stop_disabled = document.getElementById("button_stop_disabled");


	button_record_enabled.hidden = true;
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
	var proxy_port = reqStartRecording.getResponseHeader("proxy_port");
	var prefs = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService);
	var port_int = parseInt(proxy_port);
	var proxy_prefs = prefs.getBranch("network.proxy.");
	proxy_prefs.setIntPref("type", 1);
	proxy_prefs.setCharPref("ssl","127.0.0.1");
	proxy_prefs.setIntPref("ssl_port", port_int);
	var sdr = Components.classes["@mozilla.org/security/sdr;1"].getService(Components.interfaces.nsISecretDecoderRing);
	sdr.logoutAndTeardown();
	var help = document.getElementById("help");
	help.value = "You can navigate to more than one page. When finished, press STOP"
	alert("Reloading may take up to one minute, depending on the number of resources on the page.")
	BrowserReloadSkipCache();
}


function stopRecording(){
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
    var session_path = reqStopRecording.getResponseHeader("session_path");
	
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
	var proxy_prefs = prefs.getBranch("network.proxy.");
	proxy_prefs.setIntPref("type", 0);
	alert("Auditing session finished successfully. All files pertaining to this session are located in "+ session_path)
	var help = document.getElementById("help");
	help.value = "Your auditing session finished successfully. You may now close the browser."
}

