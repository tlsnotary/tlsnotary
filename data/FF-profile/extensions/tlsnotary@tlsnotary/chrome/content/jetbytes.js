//Use server jetbytes.com for p2p exchange of tracefile
//Open a hidden tab, present the user with file select dialog
//and get server response with file download link
var jettab;
var observer;
var reqInformBackend;
var bInformBackendResponded;
var reqSendLink;
var bSendLinkResponded;

function start_jetbytes(){
	jettab = gBrowser.addTab("jetbytes.com")
	gBrowser.hideTab(jettab)
	gBrowser.getBrowserForTab(jettab).addEventListener("load", eventHandler_htmlLoad, true)
}


function informBackend(){
	reqInformBackend = new XMLHttpRequest();
    reqInformBackend.onload = responseInformBackend;
    //port is a global var from script.js
    reqInformBackend.open("HEAD", "http://127.0.0.1:"+port+"/inform_backend", true);
    reqInformBackend.send();
    //give 20 secs for escrow to respond
    setTimeout(responseInformBackend, 1000, 0);
}

function responseInformBackend(iteration){
    if (typeof iteration == "number"){
    //give 5 secs for backend to respond
        if (iteration > 5){
            alert("responseInformBackend timed out");
            return;
        }
        if (!bInformBackendResponded) setTimeout(responseInformBackend, 1000, ++iteration)
        return;
    }
    //else: not a timeout but a response from the server
	bInformBackendResponded = true;
    var query = reqInformBackend.getResponseHeader("response");
    var status = reqInformBackend.getResponseHeader("status");

    if (query != "inform_backend"){
        alert("Internal error. Wrong response header: " + query);
        return;
    }
	if (status != "success"){
		alert ("Received an error message: " + status);
		return;
	}
	//else successful response
	simulateClick();
}


function simulateClick() {
  var event = new MouseEvent('click', {
    'view': window,
    'bubbles': true,
    'cancelable': true
  });
  var iframe = gBrowser.getBrowserForTab(jettab).contentWindow.document.getElementsByClassName("frame")[0]
  var input = iframe.contentDocument.childNodes[2].childNodes[2].childNodes[1].childNodes[3]
  var prefs = Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService);
  prefs.setBoolPref("dom.disable_open_during_load", false)   //prevent popup blocker
  input.dispatchEvent(event);
  observer = new myObserver(); //waits for the get response
}

//wait for the page to be loaded
function eventHandler_htmlLoad(event){
	if (event.originalTarget instanceof HTMLDocument){	
		var win = event.originalTarget.defaultView;
		if (!win.frameElement) {
			gBrowser.getBrowserForTab(jettab).removeEventListener("load", eventHandler_htmlLoad, true);
			alert("In the next dialog window, please, choose the file mytrace.zip and press Open.\n\
The file will be immediately forwarded to the auditor.");
			informBackend();
		}
	}
}

function myObserver() {  this.register();}
myObserver.prototype = {
  observe: function(aSubject, topic, data) {
	 var httpChannel = aSubject.QueryInterface(Ci.nsIHttpChannel);
	 var url = httpChannel.URI.spec;
	 if (url.startsWith("http://jetbytes.com/ctl/get_url")){
		observer.unregister();
		//we need to wait for the page to fully load
		setTimeout(getLink, 3000, 0);
		//TODO find a better way to determine when iframe loaded rather than relying on a 3 sec timeout
		help.value = "Sending data to auditor and waiting for confirmation"
	}
  },
  register: function() {
    var observerService = Cc["@mozilla.org/observer-service;1"].getService(Ci.nsIObserverService);
    observerService.addObserver(this, "http-on-examine-response", false);
  },
  unregister: function() {
    var observerService = Cc["@mozilla.org/observer-service;1"].getService(Ci.nsIObserverService);
    observerService.removeObserver(this, "http-on-examine-response");
  }
}

function getLink(){
	var html = gBrowser.getBrowserForTab(jettab).contentWindow.document.body.innerHTML
	var regexp = /http:\/\/.*jetbytes\.com\/[0-9,a-f]*/
	var res_array = html.match(regexp)
	if (res_array == null){
		return; //falure
	}
	var filelink = res_array[0];
	sendLinkToBackend(filelink);
}

function sendLinkToBackend(filelink){
	reqSendLink = new XMLHttpRequest();
    reqSendLink.onload = responseSendLink;
    //port is a global var from script.js
    reqSendLink.open("HEAD", "http://127.0.0.1:"+port+"/send_link?" + filelink , true);
    reqSendLink.send();
    //give 20 secs for escrow to respond
    setTimeout(responseSendLink, 1000, 0);
}

function responseSendLink(iteration){
    if (typeof iteration == "number"){
    //give 5 secs for backend to respond
        if (iteration > 20){
            alert("responseSendLink timed out");
            return;
        }
        if (!bSendLinkResponded) setTimeout(responseSendLink, 1000, ++iteration)
        return;
    }
    //else: not a timeout but a response from the server
	bSendLinkResponded = true;
    var query = reqSendLink.getResponseHeader("response");
    var status = reqSendLink.getResponseHeader("status");

    if (query != "send_link"){
        alert("Internal error. Wrong response header: " + query);
        return;
    }
	if (status != "success"){
		alert ("Received an error message: " + status);
		return;
	}
	//else successful response
	help.value = "Auditing session has finished"

	alert ("Congratulations. Auditor acknowledged successful receipt of the audit data. \n\
All data pertaining to this audit session are located in " + session_path + "\n\
You may now close the browser.");
}
