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
