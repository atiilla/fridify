// Description: Universal SSL pinning bypass script for Android applications

Java.perform(function() {
    console.log("[+] SSL Pinning Bypass Script Loaded");
    
    // Method 1: OkHttp3 CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, list) {
            console.log('[+] OkHttp3 CertificatePinner.check() bypassed for ' + hostname);
            return;
        };
        
        CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(hostname, certs) {
            console.log('[+] OkHttp3 CertificatePinner.check() bypassed for ' + hostname);
            return;
        };
        
        console.log('[+] OkHttp3 CertificatePinner pinning disabled');
    } catch(err) {
        console.log('[-] OkHttp3 CertificatePinner not found');
    }
    
    // Method 2: TrustManagerImpl
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log('[+] TrustManagerImpl verifyChain() bypassed for ' + host);
            return untrustedChain;
        };
        console.log('[+] TrustManagerImpl pinning disabled');
    } catch (err) {
        console.log('[-] TrustManagerImpl not found');
    }
    
    // Method 3: SSLContext
    try {
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        SSLContext.init.implementation = function(keyManagers, trustManagers, secureRandom) {
            console.log('[+] SSLContext.init() bypassed');
            this.init(keyManagers, null, secureRandom);
        };
        console.log('[+] SSLContext pinning disabled');
    } catch (err) {
        console.log('[-] SSLContext not found');
    }
    
    // Method 4: X509TrustManager
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var TrustManager = Java.registerClass({
            name: 'com.android.org.conscrypt.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {
                    console.log('[+] X509TrustManager.checkClientTrusted() bypassed');
                },
                checkServerTrusted: function(chain, authType) {
                    console.log('[+] X509TrustManager.checkServerTrusted() bypassed');
                },
                getAcceptedIssuers: function() {
                    console.log('[+] X509TrustManager.getAcceptedIssuers() bypassed');
                    return [];
                }
            }
        });
        console.log('[+] X509TrustManager pinning disabled');
    } catch (err) {
        console.log('[-] X509TrustManager not found');
    }
    
    // Method 5: Webview SSL Error handler
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(webView, sslErrorHandler, sslError) {
            console.log('[+] WebViewClient.onReceivedSslError() bypassed');
            sslErrorHandler.proceed();
        };
        console.log('[+] WebViewClient pinning disabled');
    } catch (err) {
        console.log('[-] WebViewClient not found');
    }
    
    console.log("[+] SSL Pinning Bypass Complete!");
});