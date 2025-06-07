/*
 * Network API Monitor Script
 * This script monitors various networking APIs to intercept requests and responses
 */

setTimeout(function() {
    Java.perform(function() {
        console.log("[+] Network API Monitoring Script Loaded");

        // Monitor OkHttp3 (common HTTP client)
        try {
            // Monitor OkHttp3 Request
            var Request = Java.use('okhttp3.Request');
            Request.method.implementation = function() {
                var method = this.method();
                var url = this.url().toString();
                console.log('[+] OkHttp3 Request: ' + method + ' ' + url);
                return method;
            };

            // Monitor OkHttp3 Response
            var Response = Java.use('okhttp3.Response');
            Response.body.implementation = function() {
                var body = this.body();
                var request = this.request();
                var url = request.url().toString();
                var method = request.method();
                var responseCode = this.code();
                
                console.log('[+] OkHttp3 Response: ' + method + ' ' + url + ' -> ' + responseCode);
                
                // Try to get response body (can only be consumed once)
                if (body) {
                    try {
                        var bodyString = body.string();
                        console.log('[+] Response Body: ' + bodyString);
                        
                        // Recreate body since we consumed it
                        var ResponseBody = Java.use('okhttp3.ResponseBody');
                        var MediaType = Java.use('okhttp3.MediaType');
                        var Buffer = Java.use('okio.Buffer');
                        var buffer = Buffer.$new();
                        buffer.writeUtf8(bodyString);
                        body = ResponseBody.create(body.contentType(), bodyString.length, buffer);
                    } catch (e) {
                        console.log('[-] Could not read response body: ' + e);
                    }
                }
                
                return body;
            };
            
            console.log('[+] OkHttp3 hooks installed successfully');
        } catch (err) {
            console.log('[-] OkHttp3 hook failed: ' + err);
        }
        
        // Monitor URLConnection (Java's built-in HTTP client)
        try {
            var URL = Java.use('java.net.URL');
            URL.openConnection.overload().implementation = function() {
                var url = this.toString();
                console.log('[+] URLConnection Request: ' + url);
                return this.openConnection.call(this);
            };
            
            var HttpURLConnection = Java.use('java.net.HttpURLConnection');
            HttpURLConnection.getResponseCode.implementation = function() {
                var responseCode = this.getResponseCode.call(this);
                var url = this.getURL().toString();
                var method = this.getRequestMethod();
                console.log('[+] HttpURLConnection Response: ' + method + ' ' + url + ' -> ' + responseCode);
                return responseCode;
            };
            
            console.log('[+] URLConnection hooks installed successfully');
        } catch (err) {
            console.log('[-] URLConnection hook failed: ' + err);
        }
        
        // Monitor Volley (another common HTTP library)
        try {
            var StringRequest = Java.use('com.android.volley.toolbox.StringRequest');
            StringRequest.deliverResponse.implementation = function(response) {
                console.log('[+] Volley String Response: ' + response);
                return this.deliverResponse.call(this, response);
            };
            
            var JsonRequest = Java.use('com.android.volley.toolbox.JsonRequest');
            JsonRequest.deliverResponse.implementation = function(response) {
                console.log('[+] Volley JSON Response: ' + response);
                return this.deliverResponse.call(this, response);
            };
            
            var Request = Java.use('com.android.volley.Request');
            Request.deliverError.implementation = function(error) {
                console.log('[+] Volley Error: ' + error);
                return this.deliverError.call(this, error);
            };
            
            console.log('[+] Volley hooks installed successfully');
        } catch (err) {
            console.log('[-] Volley hook failed: ' + err);
        }
        
        // Monitor Retrofit (popular API client)
        try {
            var OkHttpCall = Java.use('retrofit2.OkHttpCall');
            OkHttpCall.execute.implementation = function() {
                var request = this.rawCall.request();
                var url = request.url().toString();
                var method = request.method();
                console.log('[+] Retrofit Request: ' + method + ' ' + url);
                
                var response = this.execute.call(this);
                console.log('[+] Retrofit Response: ' + response);
                
                return response;
            };
            
            console.log('[+] Retrofit hooks installed successfully');
        } catch (err) {
            console.log('[-] Retrofit hook failed: ' + err);
        }

        console.log("[+] Network API Monitoring Setup Completed");
    });
}, 0); 