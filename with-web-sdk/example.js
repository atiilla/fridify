const FridaBridge = require('./index');

// Sample Frida script that will be injected into the target process
const fridaScript = `
  (function() {
    console.log("Frida script loaded!");
    
    // Send a message back to Node.js
    send({type: "message", text: "Hello from Frida!"});
    
    // Handle messages from Node.js
    recv("ping", function() {
      send({type: "pong", timestamp: new Date().toISOString()});
    });
    
    // Example of hooking a function
    Interceptor.attach(Module.findExportByName(null, "open"), {
      onEnter: function(args) {
        var path = Memory.readUtf8String(args[0]);
        send({
          type: "function-called",
          function: "open",
          path: path
        });
      }
    });
  })();
`;

async function main() {
  try {
    // Create a new Frida bridge instance
    const frida = new FridaBridge();
    
    // Connect to Frida
    console.log('Connecting to Frida...');
    await frida.connect();
    
    // Get available devices
    const devices = await frida.getDevices();
    console.log('Available devices:', devices.map(d => `${d.id} (${d.name})`));
    
    if (devices.length === 0) {
      console.error('No devices found');
      await frida.disconnect();
      return;
    }
    
    // Use the first device (usually local)
    await frida.getDevice(devices[0].id);
    console.log(`Using device: ${frida.device.name}`);
    
    // Get processes
    const processes = await frida.getProcesses();
    console.log(`Found ${processes.length} processes`);
    
    // Find a process to attach to (for demonstration, we'll choose a browser if available)
    let targetProcess = null;
    const browserNames = ['chrome', 'firefox', 'msedge', 'safari'];
    
    for (const browser of browserNames) {
      targetProcess = processes.find(p => p.name.toLowerCase().includes(browser));
      if (targetProcess) break;
    }
    
    // If no browser found, use the first process that's not our own Node.js process
    if (!targetProcess) {
      targetProcess = processes.find(p => !p.name.toLowerCase().includes('node'));
    }
    
    if (!targetProcess) {
      console.error('No suitable target process found');
      await frida.disconnect();
      return;
    }
    
    console.log(`Attaching to process: ${targetProcess.name} (${targetProcess.pid})`);
    
    // Attach to the target process
    await frida.attachToProcess(targetProcess.pid);
    
    // Create and load a script
    const script = await frida.createScript(fridaScript);
    
    // Set up message handler
    frida.onMessage(message => {
      if (message.type === 'send') {
        const payload = message.payload;
        
        if (payload.type === 'message') {
          console.log('Script message:', payload.text);
        } else if (payload.type === 'pong') {
          console.log('Received pong - Timestamp:', payload.timestamp);
        } else if (payload.type === 'function-called') {
          console.log(`Function ${payload.function} called with path: ${payload.path}`);
        } else {
          console.log('Script message:', payload);
        }
      } else if (message.type === 'error') {
        console.error('Script error:', message.stack);
      }
    });
    
    // Load the script
    await frida.loadScript();
    
    console.log('Script loaded successfully');
    
    // Send a ping after a short delay
    setTimeout(async () => {
      console.log('Sending ping to script...');
      await frida.post('ping', null);
      
      console.log('Press Ctrl+C to exit');
    }, 1000);
    
    // Handle graceful shutdown
    process.on('SIGINT', async () => {
      console.log('Disconnecting from Frida...');
      await frida.disconnect();
      console.log('Disconnected from Frida');
      process.exit(0);
    });
    
  } catch (error) {
    console.error('Error:', error);
  }
}

main(); 