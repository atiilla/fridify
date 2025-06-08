// Diagnostics for Android SSL Pinning and Proxy Issues

// This is a standalone script to diagnose why traffic isn't showing up in MITM proxy
// Run this separately after attaching to your target application

// Customize these settings:
const PROXY_IP = "192.168.0.196";  // Your MITM proxy IP
const PROXY_PORT = 8080;           // Your MITM proxy port

(function() {
  // Get basic process information
  const processInfo = {
    id: Process.id,
    arch: Process.arch,
    platform: Process.platform,
    pageSize: Process.pageSize
  };
  
  send({type: 'message', text: '=== NETWORK DIAGNOSTICS STARTING ===', important: true});
  send({type: 'message', text: `Process: PID ${processInfo.id}, ${processInfo.arch}, ${processInfo.platform}`});
  
  // Track all network activity
  const networkActivity = {
    dnsLookups: [],
    connections: [],
    httpRequests: [],
    sslOperations: [],
    lastError: null
  };
  
  // 1. Find loaded network libraries
  const loadedLibraries = Process.enumerateModules();
  const networkLibs = loadedLibraries.filter(lib => 
    lib.name.includes('ssl') || 
    lib.name.includes('crypto') || 
    lib.name.includes('socket') ||
    lib.name.includes('okhttp') ||
    lib.name.includes('network')
  );
  
  send({type: 'message', text: `Found ${networkLibs.length} potential network libraries:`});
  networkLibs.forEach(lib => {
    send({type: 'message', text: `- ${lib.name} @ ${lib.base}`});
  });
  
  // 2. Check if Java is available and monitor HTTP calls
  let javaAvailable = false;
  try {
    Java.perform(function() {
      javaAvailable = true;
      send({type: 'message', text: 'Java runtime is available', important: true});
      
      // Check proxy settings
      try {
        const SystemProperties = Java.use('android.os.SystemProperties');
        const proxyHost = SystemProperties.get('http.proxyHost', '');
        const proxyPort = SystemProperties.get('http.proxyPort', '');
        
        if (proxyHost.length > 0) {
          send({type: 'message', text: `Current proxy settings: ${proxyHost}:${proxyPort}`, important: true});
        } else {
          send({type: 'message', text: 'No proxy currently configured', important: true});
          
          // Try to set proxy
          try {
            SystemProperties.set('http.proxyHost', PROXY_IP);
            SystemProperties.set('http.proxyPort', PROXY_PORT.toString());
            
            // Verify if it worked
            const newProxyHost = SystemProperties.get('http.proxyHost', '');
            if (newProxyHost === PROXY_IP) {
              send({type: 'message', text: `Successfully set proxy to ${PROXY_IP}:${PROXY_PORT}`, important: true});
            } else {
              send({type: 'message', text: 'Failed to set proxy (may need root access)', important: true});
            }
          } catch (e) {
            send({type: 'message', text: `Error setting proxy: ${e.message}`});
          }
        }
      } catch (e) {
        send({type: 'message', text: `Error checking proxy settings: ${e.message}`});
      }
      
      // Monitor URL connections
      try {
        const URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function() {
          const url = this.toString();
          send({type: 'message', text: `URL opened: ${url}`, important: true});
          networkActivity.httpRequests.push({ time: new Date(), url: url });
          return this.openConnection();
        };
        send({type: 'message', text: 'Monitoring URL connections'});
      } catch (e) {
        send({type: 'message', text: `Failed to hook URL.openConnection: ${e.message}`});
      }
      
      // Monitor HttpURLConnection
      try {
        const HttpURLConnection = Java.use('java.net.HttpURLConnection');
        HttpURLConnection.connect.implementation = function() {
          try {
            const url = this.getURL().toString();
            const method = this.getRequestMethod();
            send({type: 'message', text: `HTTP ${method} request to ${url}`, important: true});
            networkActivity.httpRequests.push({ time: new Date(), url: url, method: method });
          } catch (e) {
            send({type: 'message', text: `Error logging HTTP connection: ${e.message}`});
          }
          this.connect();
        };
        send({type: 'message', text: 'Monitoring HttpURLConnection'});
      } catch (e) {
        send({type: 'message', text: `Failed to hook HttpURLConnection: ${e.message}`});
      }
      
      // Look for OkHttp
      try {
        const OkHttpClient = Java.use('okhttp3.OkHttpClient');
        send({type: 'message', text: 'OkHttp detected!', important: true});
        
        // Try to hook OkHttp calls
        try {
          OkHttpClient.newCall.overload('okhttp3.Request').implementation = function(request) {
            try {
              const url = request.url().toString();
              const method = request.method();
              send({type: 'message', text: `OkHttp ${method} request to ${url}`, important: true});
              networkActivity.httpRequests.push({ 
                time: new Date(), 
                url: url, 
                method: method,
                client: 'OkHttp'
              });
            } catch (e) {
              send({type: 'message', text: `Error logging OkHttp call: ${e.message}`});
            }
            return this.newCall(request);
          };
          send({type: 'message', text: 'Monitoring OkHttp calls'});
        } catch (e) {
          send({type: 'message', text: `Failed to hook OkHttp.newCall: ${e.message}`});
        }
      } catch (e) {
        send({type: 'message', text: 'OkHttp not detected'});
      }
    });
  } catch (e) {
    send({type: 'message', text: `Java is not available: ${e.message}`, important: true});
  }
  
  // 3. Monitor native network functions
  try {
    // DNS lookups
    const getaddrinfo = Module.findExportByName(null, 'getaddrinfo');
    if (getaddrinfo) {
      Interceptor.attach(getaddrinfo, {
        onEnter: function(args) {
          const hostname = Memory.readUtf8String(args[0]);
          if (hostname) {
            send({type: 'message', text: `DNS lookup for: ${hostname}`, important: true});
            networkActivity.dnsLookups.push({ time: new Date(), hostname: hostname });
          }
        }
      });
      send({type: 'message', text: 'Monitoring DNS lookups'});
    }
    
    // TCP connections
    const connect = Module.findExportByName(null, 'connect');
    if (connect) {
      Interceptor.attach(connect, {
        onEnter: function(args) {
          try {
            this.sockfd = args[0].toInt32();
            const sockAddr = args[1];
            
            if (sockAddr) {
              const sa_family = Memory.readU16(sockAddr.add(0));
              
              if (sa_family === 2) { // AF_INET
                let port = Memory.readU16(sockAddr.add(2));
                port = ((port & 0xff) << 8) | ((port & 0xff00) >> 8);
                
                let ip = '';
                for (let i = 0; i < 4; i++) {
                  ip += Memory.readU8(sockAddr.add(4 + i));
                  if (i < 3) ip += '.';
                }
                
                this.connectionInfo = { sockfd: this.sockfd, ip: ip, port: port };
                networkActivity.connections.push({
                  time: new Date(),
                  ip: ip,
                  port: port
                });
                
                send({type: 'message', text: `TCP connection to ${ip}:${port}`, important: true});
              }
            }
          } catch (e) {
            send({type: 'message', text: `Error parsing connection: ${e.message}`});
          }
        },
        onLeave: function(retval) {
          if (this.connectionInfo) {
            const result = retval.toInt32();
            const status = result === 0 ? 'Success' : 'Failed';
            
            send({type: 'message', text: `Connection to ${this.connectionInfo.ip}:${this.connectionInfo.port} ${status}`});
            
            // Check if connecting to our proxy
            if (this.connectionInfo.ip === PROXY_IP && this.connectionInfo.port === PROXY_PORT) {
              send({type: 'message', text: `Proxy connection ${status}!`, important: true});
            }
            
            // If connecting to HTTPS port
            if (this.connectionInfo.port === 443) {
              send({type: 'message', text: `HTTPS connection to ${this.connectionInfo.ip} ${status}`, important: true});
            }
          }
        }
      });
      send({type: 'message', text: 'Monitoring TCP connections'});
    }
    
    // SSL/TLS operations
    const sslFunctions = [
      'SSL_connect', 'SSL_read', 'SSL_write', 'SSL_get_fd', 'SSL_CTX_new'
    ];
    
    sslFunctions.forEach(funcName => {
      const address = Module.findExportByName(null, funcName);
      if (address) {
        Interceptor.attach(address, {
          onEnter: function(args) {
            send({type: 'message', text: `${funcName} called`, important: true});
            networkActivity.sslOperations.push({
              time: new Date(),
              function: funcName
            });
          },
          onLeave: function(retval) {
            if (funcName === 'SSL_connect') {
              const result = retval.toInt32();
              send({type: 'message', text: `SSL handshake result: ${result}`, important: true});
            }
          }
        });
        send({type: 'message', text: `Hooked ${funcName}`});
      }
    });
  } catch (e) {
    send({type: 'message', text: `Error setting up native hooks: ${e.message}`});
    networkActivity.lastError = e.message;
  }
  
  // 4. Periodically report network activity
  setTimeout(function reportStatus() {
    send({type: 'message', text: '--- NETWORK ACTIVITY REPORT ---', important: true});
    send({type: 'message', text: `DNS Lookups: ${networkActivity.dnsLookups.length}`});
    send({type: 'message', text: `TCP Connections: ${networkActivity.connections.length}`});
    send({type: 'message', text: `HTTP Requests: ${networkActivity.httpRequests.length}`});
    send({type: 'message', text: `SSL/TLS Operations: ${networkActivity.sslOperations.length}`});
    
    // Provide detailed diagnostics if no connections are seen
    if (networkActivity.connections.length === 0 && networkActivity.httpRequests.length === 0) {
      send({type: 'message', text: 'NO NETWORK ACTIVITY DETECTED', important: true});
      send({type: 'message', text: 'Possible reasons:', important: true});
      send({type: 'message', text: '1. App is not making network requests'});
      send({type: 'message', text: '2. App is using custom network stack not captured by hooks'});
      send({type: 'message', text: '3. App has anti-tampering protection preventing Frida'});
      
      if (networkActivity.dnsLookups.length > 0) {
        send({type: 'message', text: 'DNS lookups detected but no connections - network may be blocked', important: true});
      }
    }
    
    // Check for proxy connection
    const proxyConnections = networkActivity.connections.filter(
      conn => conn.ip === PROXY_IP && conn.port === PROXY_PORT
    );
    
    if (proxyConnections.length > 0) {
      send({type: 'message', text: `${proxyConnections.length} connection(s) to proxy detected`, important: true});
    } else {
      send({type: 'message', text: 'No connections to proxy detected - traffic not being routed', important: true});
    }
    
    // Schedule next report
    setTimeout(reportStatus, 10000);
  }, 5000);
  
  send({type: 'message', text: 'Network diagnostics running - waiting for activity...', important: true});
})(); 