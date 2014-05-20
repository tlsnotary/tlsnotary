//We only need RSA-AES128&256
pref("security.ssl3.dhe_dss_aes_128_sha", false);
pref("security.ssl3.dhe_dss_aes_256_sha",false);
pref("security.ssl3.dhe_dss_camellia_128_sha",false);
pref("security.ssl3.dhe_dss_camellia_256_sha",false);
pref("security.ssl3.dhe_dss_des_ede3_sha",false);
pref("security.ssl3.dhe_rsa_aes_128_sha",false);
pref("security.ssl3.dhe_rsa_aes_256_sha",false);
pref("security.ssl3.dhe_rsa_camellia_128_sha",false);
pref("security.ssl3.dhe_rsa_camellia_256_sha",false);
pref("security.ssl3.dhe_rsa_des_ede3_sha",false);
pref("security.ssl3.ecdh_ecdsa_aes_128_sha",false);
pref("security.ssl3.ecdh_ecdsa_aes_256_sha",false);
pref("security.ssl3.ecdh_ecdsa_des_ede3_sha",false);
pref("security.ssl3.ecdh_ecdsa_rc4_128_sha",false);
pref("security.ssl3.ecdh_rsa_aes_128_sha",false);
pref("security.ssl3.ecdh_rsa_aes_256_sha",false);
pref("security.ssl3.ecdh_rsa_des_ede3_sha",false);
pref("security.ssl3.ecdh_rsa_rc4_128_sha",false);
pref("security.ssl3.ecdhe_ecdsa_aes_128_sha",false);
pref("security.ssl3.ecdhe_ecdsa_aes_256_sha",false);
pref("security.ssl3.ecdhe_ecdsa_des_ede3_sha",false);
pref("security.ssl3.ecdhe_ecdsa_rc4_128_sha",false);
pref("security.ssl3.ecdhe_rsa_aes_128_sha",false);
pref("security.ssl3.ecdhe_rsa_aes_256_sha",false);
pref("security.ssl3.ecdhe_rsa_des_ede3_sha",false);
pref("security.ssl3.ecdhe_rsa_rc4_128_sha",false);
pref("security.ssl3.rsa_aes_128_sha",true);
pref("security.ssl3.rsa_aes_256_sha",true);
pref("security.ssl3.rsa_camellia_128_sha",false);
pref("security.ssl3.rsa_camellia_256_sha",false);
pref("security.ssl3.rsa_des_ede3_sha",false);
pref("security.ssl3.rsa_fips_des_ede3_sha",false);
pref("security.ssl3.rsa_rc4_128_md5",true);
pref("security.ssl3.rsa_rc4_128_sha",true);
pref("security.ssl3.rsa_seed_sha",false);
pref("security.tls.version.max",1); // use only TLS 1.0

pref("security.enable_tls_session_tickets",false);

//tshark can't dissect spdy. websockets may cause unexpected issues
pref("network.http.spdy.enabled",false);
pref("network.http.spdy.enabled.v2",false);
pref("network.http.spdy.enabled.v3",false);
pref("network.websocket.enabled",false);
//no cache should be used
pref("browser.cache.disk.enable", false);
pref("browser.cache.memory.enable", false);
pref("browser.cache.disk_cache_ssl", false);
pref("network.http.use-cache", false);

pref("browser.shell.checkDefaultBrowser", false);
pref("startup.homepage_welcome_url", "");
pref("browser.rights.3.shown", true)
pref("extensions.checkCompatibility", false);
pref("browser.link.open_newwindow", 3); //open new window in a new tab
pref("browser.link.open_newwindow.restriction", 0); // enforce the above rule without exceptions
// The last version of the browser to successfully load extensions. 
//Used to determine whether or not to disable extensions due to possible incompatibilities. 
pref("extensions.lastAppVersion", "100.0.0"); //gets overriden by tbb
pref("extensions.update.autoUpdate", false);  //doesnt exist in tbb
pref("extensions.update.enabled", false);
pref("datareporting.policy.dataSubmissionEnabled", false)

//Override Tor Browser Bundle's 
//NB network.proxy.* prefs do not override from here, we call them from within addon's JS
pref("network.proxy.type", 0);
//if socks_remote_dns is true even with proxy.type == 0, TBB still tries to use proxy
//That's a TBB/Firefox24ESR bug (not present if FF27, though)
pref("network.proxy.socks_remote_dns", false);
pref("extensions.enabledAddons", "tlsnotary%40tlsnotary:0.1,testdriver%40testdriver:0.1")
