Java.perform(function()
{
    console.log("[*] Starting SSL pinning bypass...");

// Bypass
cho
OkHttp
try {
var CertificatePinner = Java.use('okhttp3.CertificatePinner');
CertificatePinner.check$okhttp.implementation = function(p0, p1) {
console.log("[*] Bypassing OkHttp certificate pinning");
return;
};
} catch(e)
{}

// Bypass
cho
TrustManager
try {
var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');

TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
console.log("[*] Bypassing TrustManager verification");
return untrustedChain;
};
} catch(e)
{}

console.log("[+] SSL pinning bypass ready");
});Java.perform(function() {
    console.log("[*] Starting SSL pinning bypass...");

    // Bypass cho OkHttp
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check$okhttp.implementation = function(p0, p1) {
            console.log("[*] Bypassing OkHttp certificate pinning");
            return;
        };
    } catch(e) {}

    // Bypass cho TrustManager
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');

        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log("[*] Bypassing TrustManager verification");
            return untrustedChain;
        };
    } catch(e) {}

    console.log("[+] SSL pinning bypass ready");
});