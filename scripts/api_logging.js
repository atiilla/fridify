Java.perform(function() {
    // Common Android API hooks
    var HttpURLConnection = Java.use('java.net.HttpURLConnection');
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    var Retrofit = Java.use('retrofit2.Retrofit');
    
    // HTTP URL Connection
    HttpURLConnection.connect.implementation = function() {
        console.log('[+] HttpURLConnection.connect() called');
        console.log('URL: ' + this.getURL().toString());
        console.log('Method: ' + this.getRequestMethod());
        this.connect();
    };
    
    // OkHttp
    OkHttpClient.newCall.implementation = function(request) {
        console.log('[+] OkHttpClient.newCall() intercepted');
        console.log('URL: ' + request.url().toString());
        console.log('Method: ' + request.method());
        console.log('Headers: ' + request.headers().toString());
        return this.newCall(request);
    };
    
    // Retrofit
    Retrofit.create.implementation = function(service) {
        console.log('[+] Retrofit API Service created');
        console.log('Service: ' + service.toString());
        return this.create(service);
    };
});