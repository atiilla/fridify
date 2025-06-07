Java.perform(function() {
    var TrustManager = Java.registerClass({
        name: 'com.custom.TrustManager',
        implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.implementation = function(keyManager, trustManager, secureRandom) {
        console.log('[+] Bypassing SSL Pinning');
        var trustManagers = [TrustManager.$new()];
        this.init(keyManager, trustManagers, secureRandom);
    };
});