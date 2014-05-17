var ss_link_tab;
var ss_reqInformBackend;
var ss_bInformBackendResponded;
var ss_reqSendLink;
var ss_bSendLinkResponded;
var ss_bSiteResponded = false;
var ss_tab;

function ss_start(){
	ss_tab = gBrowser.addTab("https://www.sendspace.com");
	gBrowser.hideTab(ss_tab);
	gBrowser.getBrowserForTab(ss_tab).addEventListener("load", ss_eventHandler_htmlLoad, true);
}

//wait for the page to be loaded
function ss_eventHandler_htmlLoad(event){
	ss_bSiteResponded = true;
	if (event.originalTarget instanceof HTMLDocument){	
		var win = event.originalTarget.defaultView;
		if (!win.frameElement) {
			gBrowser.getBrowserForTab(ss_tab).removeEventListener("load", ss_eventHandler_htmlLoad, true);
			//alert("In the next dialog window, please, choose the file mytrace.zip and press Open.\n\
			//The file will be immediately forwarded to the auditor.");
			var fileinput = gBrowser.getBrowserForTab(ss_tab).contentWindow.document.getElementById("upload_file");
			ss_simulateClick(fileinput);
			help.value = "Beginning the data transfer using sendspace.com...";
			ss_checkUploadButton();
		}
	}
}

function ss_checkUploadButton(){
	var span_element = gBrowser.getBrowserForTab(ss_tab).contentWindow.document.getElementsByClassName("filename")[0];
	//this span's title changes after the file was selected
	if (span_element.title == "") {
		setTimeout(ss_checkUploadButton, 1000);
		return;
	}
	var upload_button = gBrowser.getBrowserForTab(ss_tab).contentWindow.document.getElementsByClassName("submit button")[1];
	ss_simulateClick(upload_button);
	ss_checkLink();
}


function ss_checkLink(){
	var share_link_class_array = gBrowser.getBrowserForTab(ss_tab).contentWindow.document.getElementsByClassName("share link");
	if (share_link_class_array.length < 1){
		setTimeout(ss_checkLink, 1000);
		return;	
	}
	var filelink = share_link_class_array[0].href
	ss_link_tab = gBrowser.addTab(filelink);
	gBrowser.hideTab(ss_link_tab);
	gBrowser.getBrowserForTab(ss_link_tab).addEventListener("load", ss_filelink_eventHandler_htmlLoad, true);
}


//wait for the page to be loaded
function ss_filelink_eventHandler_htmlLoad(event){
	ss_bSiteResponded = true;
	if (event.originalTarget instanceof HTMLDocument){	
		var win = event.originalTarget.defaultView;
		if (!win.frameElement) {
			gBrowser.getBrowserForTab(ss_link_tab).removeEventListener("load", ss_filelink_eventHandler_htmlLoad, true);
			var down_button = gBrowser.getBrowserForTab(ss_link_tab).contentWindow.document.getElementById("download_button");
			var final_url = down_button.href;
			ss_sendLinkToBackend(final_url);
		}
	}
}


function ss_sendLinkToBackend(filelink){
	ss_reqSendLink = new XMLHttpRequest();
    ss_reqSendLink.onload = ss_responseSendLink;
    //port is a global var from script.js
    ss_reqSendLink.open("HEAD", "http://127.0.0.1:"+port+"/send_link?" + filelink , true);
    ss_reqSendLink.send();
    //give 20 secs for escrow to respond
    setTimeout(ss_responseSendLink, 1000, 0);
}


function ss_responseSendLink(iteration){
    if (typeof iteration == "number"){
    //give 5 secs for backend to respond
        if (iteration > 20){
			help.value = "ERROR";
            alert("responseSendLink timed out");
            return;
        }
        if (!ss_bSendLinkResponded) setTimeout(ss_responseSendLink, 1000, ++iteration);
        return;
    }
    //else: not a timeout but a response from the server
	ss_bSendLinkResponded = true;
    var query = ss_reqSendLink.getResponseHeader("response");
    var status = ss_reqSendLink.getResponseHeader("status");

    if (query != "send_link"){
		help.value = "ERROR";
        alert("Internal error. Wrong response header: " + query);
        return;
    }
	if (status != "success"){
		help.value = "ERROR";
		alert ("Received an error message: " + status);
		return;
	}
	//else successful response
	help.value = "Auditing session has finished";

	alert ("Congratulations. Auditor acknowledged successful receipt of the audit data. \n\
All data pertaining to this audit session are located in " + session_path + "\n\
You may now close the browser.");
}

function ss_simulateClick(what_to_click) {
  var event = new MouseEvent('click', {
    'view': window,
    'bubbles': true,
    'cancelable': true
  });
  //prevent popup blocker
  Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService).setBoolPref("dom.disable_open_during_load", false);
  what_to_click.dispatchEvent(event);
}
