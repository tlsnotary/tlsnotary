//Use server jetbytes.com for p2p exchange of tracefile
//Open a hidden tab, present the user with file select dialog
//and get server response with file download link
var jb_tab;
var jb_observer;
var jb_reqInformBackend;
var jb_bInformBackendResponded;
var jb_reqSendLink;
var jb_bSendLinkResponded;
var jb_bSiteResponded = false;

function jb_start(){
	jb_tab = gBrowser.addTab("jetbytes.com");
	gBrowser.hideTab(jb_tab);
	gBrowser.getBrowserForTab(jb_tab).addEventListener("load", jb_eventHandler_htmlLoad, true);
}


function jb_simulateClick() {
  var event = new MouseEvent('click', {
    'view': window,
    'bubbles': true,
    'cancelable': true
  });
  var iframe = gBrowser.getBrowserForTab(jb_tab).contentWindow.document.getElementsByClassName("frame")[0];
  var input = iframe.contentDocument.childNodes[2].childNodes[2].childNodes[1].childNodes[3];
  //prevent popup blocker
  Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService).setBoolPref("dom.disable_open_during_load", false);
  input.dispatchEvent(event);
  jb_observer = new jb_myObserver(); //waits for the get response
}

//wait for the page to be loaded
function jb_eventHandler_htmlLoad(event){
	jb_bSiteResponded = true;
	if (event.originalTarget instanceof HTMLDocument){	
		var win = event.originalTarget.defaultView;
		if (!win.frameElement) {
			gBrowser.getBrowserForTab(jb_tab).removeEventListener("load", jb_eventHandler_htmlLoad, true);
			//alert("In the next dialog window, please, choose the file mytrace.zip and press Open.\n\
The file will be immediately forwarded to the auditor.");
			jb_simulateClick();
		}
	}
}

function jb_myObserver() {  this.register();}
jb_myObserver.prototype = {
  observe: function(aSubject, topic, data) {
	 var httpChannel = aSubject.QueryInterface(Ci.nsIHttpChannel);
	 var url = httpChannel.URI.spec;
	 if (url.startsWith("http://jetbytes.com/ctl/get_url")){
		jb_observer.unregister();
		//we need to wait for the page to fully load
		setTimeout(jb_getLink, 3000, 0);
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

function jb_getLink(){
	var html = gBrowser.getBrowserForTab(jb_tab).contentWindow.document.body.innerHTML
	var regexp = /http:\/\/.*jetbytes\.com\/[0-9,a-f]*/
	var res_array = html.match(regexp)
	if (res_array == null){
		return; //falure
	}
	var filelink = res_array[0];
	jb_sendLinkToBackend(filelink);
}

function jb_sendLinkToBackend(filelink){
	jb_reqSendLink = new XMLHttpRequest();
    jb_reqSendLink.onload = jb_responseSendLink;
    //port is a global var from script.js
    jb_reqSendLink.open("HEAD", "http://127.0.0.1:"+port+"/send_link?" + filelink , true);
    jb_reqSendLink.send();
    //give 20 secs for escrow to respond
    setTimeout(jb_responseSendLink, 1000, 0);
}

function jb_responseSendLink(iteration){
    if (typeof iteration == "number"){
    //give 5 secs for backend to respond
        if (iteration > 20){
			help.value == "ERROR";
            alert("responseSendLink timed out");
            return;
        }
        if (!jb_bSendLinkResponded) setTimeout(jb_responseSendLink, 1000, ++iteration)
        return;
    }
    //else: not a timeout but a response from the server
	jb_bSendLinkResponded = true;
    var query = jb_reqSendLink.getResponseHeader("response");
    var status = jb_reqSendLink.getResponseHeader("status");

    if (query != "send_link"){
		help.value == "ERROR";
        alert("Internal error. Wrong response header: " + query);
        return;
    }
	if (status != "success"){
		help.value == "ERROR";
		alert ("Received an error message: " + status);
		return;
	}
	//else successful response
	help.value = "Auditing session has finished"

	alert ("Congratulations. Auditor acknowledged successful receipt of the audit data. \n\
All data pertaining to this audit session are located in " + session_path + "\n\
You may now close the browser.");
}
