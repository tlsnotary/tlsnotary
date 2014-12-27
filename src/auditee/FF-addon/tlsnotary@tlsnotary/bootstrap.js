Components.utils.import('resource://gre/modules/Services.jsm');

function startup(data,reason) {
	Services.scriptloader.loadSubScript("chrome://tlsnotary/content/script.js", null, "UTF-8" /* The script's encoding */);
	Services.scriptloader.loadSubScript("chrome://tlsnotary/content/testdriver_script.js", null, "UTF-8" /* The script's encoding */);
	Services.scriptloader.loadSubScript("chrome://tlsnotary/content/core.js", null, "UTF-8" /* The script's encoding */);
	Services.scriptloader.loadSubScript("chrome://tlsnotary/content/enc-base64.js", null, "UTF-8" /* The script's encoding */);
	Services.scriptloader.loadSubScript("chrome://tlsnotary/content/cipher-core.js", null, "UTF-8" /* The script's encoding */);
	Services.scriptloader.loadSubScript("chrome://tlsnotary/content/aes.js", null, "UTF-8" /* The script's encoding */);
}
function shutdown(data,reason) {}
function install(data,reason) {}
function uninstall(data,reason) {}
