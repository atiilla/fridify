/*
 * Universal Android SSL Pinning Bypass Script
 * This script attempts to bypass various SSL pinning implementations
 */

setTimeout(function() {
    Java.perform(function() {
        console.log("[+] Android SSL Pinning Bypass Script Loaded");
        
        // Bypass TrustManagerImpl (Android < 7)
        try {
            var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            var checkServerTrustedMethod = TrustManagerImpl.checkServerTrusted;
            
            checkServerTrustedMethod.implementation = function(chain, authType) {
                console.log('[+] Bypassed TrustManagerImpl checkServerTrusted');
                return;
            };
            
            console.log('[+] TrustManagerImpl bypass successful');
        } catch (err) {
            console.log('[-] TrustManagerImpl bypass failed: ' + err);
        }
        
        // Bypass OkHTTP 3 CertificatePinner
        try {
            var CertificatePinner = Java.use('okhttp3.CertificatePinner');
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, certificates) {
                console.log('[+] Bypassed OkHTTP 3 CertificatePinner.check()');
                return;
            };
            
            CertificatePinner.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function(hostname, certificate) {
                console.log('[+] Bypassed OkHTTP 3 CertificatePinner.check()');
                return;
            };
            
            console.log('[+] OkHTTP 3 CertificatePinner bypass successful');
        } catch (err) {
            console.log('[-] OkHTTP 3 CertificatePinner bypass failed: ' + err);
        }
        
        // Bypass TrustManager (Android Universal)
        try {
            var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            var SSLContext = Java.use('javax.net.ssl.SSLContext');
            
            // TrustManager bypass
            var TrustManager = Java.registerClass({
                name: 'com.securitybypass.TrustManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() { return []; }
                }
            });
            
            // Create a new instance of our custom TrustManager
            var TrustManagers = [TrustManager.$new()];
            
            // Get SSLContext
            var SSLContext_init = SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;', 
                '[Ljavax.net.ssl.TrustManager;', 
                'java.security.SecureRandom'
            );
            
            // Override SSLContext.init method
            SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
                console.log('[+] Bypassing SSLContext.init by using custom TrustManager');
                SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
            };
            
            console.log('[+] SSLContext TrustManager bypass successful');
        } catch (err) {
            console.log('[-] SSLContext TrustManager bypass failed: ' + err);
        }
        
        // Bypass WebView SSL validation
        try {
            var WebViewClient = Java.use('android.webkit.WebViewClient');
            var WebViewClient_onReceivedSslError = WebViewClient.onReceivedSslError;
            
            WebViewClient_onReceivedSslError.implementation = function(webView, sslErrorHandler, sslError) {
                console.log('[+] Bypassing WebViewClient.onReceivedSslError');
                sslErrorHandler.proceed();
            };
            
            console.log('[+] WebViewClient SSL validation bypass successful');
        } catch (err) {
            console.log('[-] WebViewClient SSL validation bypass failed: ' + err);
        }
        
        console.log('[+] SSL Pinning Bypass Completed');
    });
}, 0); 