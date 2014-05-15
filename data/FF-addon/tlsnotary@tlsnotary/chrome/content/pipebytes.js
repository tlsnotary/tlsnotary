//Use server pipebytes.com for p2p exchange of tracefile
//Open a hidden tab, present the user with file select dialog
//and get server response with file download link
var pb_tab;
var pb_observer;
var pb_reqInformBackend;
var pb_bInformBackendResponded;
var pb_reqSendLink;
var pb_bSendLinkResponded;
var pb_bSiteResponded = false;

function pb_start(){
	pb_tab = gBrowser.addTab("pipebytes.com");
	gBrowser.hideTab(pb_tab);
	gBrowser.getBrowserForTab(pb_tab).addEventListener("load", pb_eventHandler_htmlLoad, true);
}


function pb_simulateClick(what_to_click) {
  var event = new MouseEvent('click', {
    'view': window,
    'bubbles': true,
    'cancelable': true
  });
  //prevent popup blocker
  Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService).setBoolPref("dom.disable_open_during_load", false);
  what_to_click.dispatchEvent(event);
}


function pb_checkUploadButton(){
	var upload_button = gBrowser.getBrowserForTab(pb_tab).contentWindow.document.getElementsByName("upload")[0];
	//className changes to "button" when the button becomes active
	if (upload_button.className != 'button'){
		setTimeout(pb_checkUploadButton, 1000);
		return;
	}
	var input_URL = gBrowser.getBrowserForTab(pb_tab).contentWindow.document.getElementsByName("url")[0];
	var url = input_URL.value;
	pb_simulateClick(upload_button);
	//change the url to bypass the html page and fetch the file directly
	var newurl = url.replace("php", "py");
	pb_sendLinkToBackend(newurl);
}


//wait for the page to be loaded
function pb_eventHandler_htmlLoad(event){
	pb_bSiteResponded = true;
	if (event.originalTarget instanceof HTMLDocument){	
		var win = event.originalTarget.defaultView;
		if (!win.frameElement) {
			gBrowser.getBrowserForTab(pb_tab).removeEventListener("load", pb_eventHandler_htmlLoad, true);
			//alert("In the next dialog window, please, choose the file mytrace.zip and press Open.\n\
The file will be immediately forwarded to the auditor.");
			var fileinput = gBrowser.getBrowserForTab(pb_tab).contentWindow.document.getElementsByName("file")[0];
			pb_simulateClick(fileinput);
			pb_checkUploadButton();
		}
	}
}


function pb_sendLinkToBackend(filelink){
	pb_reqSendLink = new XMLHttpRequest();
    pb_reqSendLink.onload = pb_responseSendLink;
    //port is a global var from script.js
    pb_reqSendLink.open("HEAD", "http://127.0.0.1:"+port+"/send_link?" + filelink , true);
    pb_reqSendLink.send();
    //give 20 secs for escrow to respond
    setTimeout(pb_responseSendLink, 1000, 0);
}


function pb_responseSendLink(iteration){
    if (typeof iteration == "number"){
    //give 5 secs for backend to respond
        if (iteration > 20){
            alert("responseSendLink timed out");
            return;
        }
        if (!pb_bSendLinkResponded) setTimeout(pb_responseSendLink, 1000, ++iteration);
        return;
    }
    //else: not a timeout but a response from the server
	pb_bSendLinkResponded = true;
    var query = pb_reqSendLink.getResponseHeader("response");
    var status = pb_reqSendLink.getResponseHeader("status");

    if (query != "send_link"){
        alert("Internal error. Wrong response header: " + query);
        return;
    }
	if (status != "success"){
		alert ("Received an error message: " + status);
		return;
	}
	//else successful response
	help.value = "Auditing session has finished";

	alert ("Congratulations. Auditor acknowledged successful receipt of the audit data. \n\
All data pertaining to this audit session are located in " + session_path + "\n\
You may now close the browser.");
}
