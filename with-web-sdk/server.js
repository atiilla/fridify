const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const path = require('path');
const FridaBridge = require('./index');

// Create Express app
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Create HTTP server
const server = http.createServer(app);

// Create Socket.IO server
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Store active Frida bridges
const bridges = new Map();

// Socket.IO connection handler
io.on('connection', (socket) => {
  console.log(`Client connected: ${socket.id}`);
  
  // Create a new Frida bridge instance for this client
  const frida = new FridaBridge();
  bridges.set(socket.id, frida);
  
  // Handle connection to Frida
  socket.on('connect-frida', async (options = {}, callback) => {
    try {
      console.log('Client requesting Frida connection');
      const result = await frida.connect(options);
      console.log('Frida connection result:', result);
      callback({ success: result });
    } catch (error) {
      console.error('Error connecting to Frida:', error);
      callback({ success: false, error: error.message });
    }
  });
  
  // Handle getting devices
  socket.on('get-devices', async (callback) => {
    try {
      console.log('Client requesting devices');
      const devices = await frida.getDevices();
      console.log(`Found ${devices.length} devices`);
      callback({ success: true, devices });
    } catch (error) {
      console.error('Error getting devices:', error);
      callback({ success: false, error: error.message });
    }
  });
  
  // Handle selecting a device
  socket.on('select-device', async (deviceId, callback) => {
    try {
      console.log(`Client selecting device: ${deviceId}`);
      const device = await frida.getDevice(deviceId);
      console.log('Device selected:', device);
      callback({ success: true, device });
    } catch (error) {
      console.error('Error selecting device:', error);
      callback({ success: false, error: error.message });
    }
  });
  
  // Handle getting processes
  socket.on('get-processes', async (callback) => {
    try {
      console.log('Client requesting processes');
      const processes = await frida.getProcesses();
      console.log(`Found ${processes.length} processes`);
      callback({ success: true, processes });
    } catch (error) {
      console.error('Error getting processes:', error);
      callback({ success: false, error: error.message });
    }
  });
  
  // Handle attaching to a process
  socket.on('attach-process', async (pid, callback) => {
    try {
      console.log(`Client attaching to process: ${pid}`);
      const session = await frida.attachToProcess(pid);
      console.log('Session created:', session.id);
      callback({ success: true, sessionId: session.id });
    } catch (error) {
      console.error('Error attaching to process:', error);
      callback({ success: false, error: error.message });
    }
  });
  
  // Handle spawning a process
  socket.on('spawn-process', async (data, callback) => {
    try {
      console.log(`Client spawning process: ${data.packageName}`);
      
      // Validate that we have a proper package name
      if (!data.packageName || typeof data.packageName !== 'string') {
        throw new Error('Invalid package name provided');
      }
      
      // For Android package names, check if it contains at least two dots (com.example.app)
      if (!data.packageName.match(/^[a-zA-Z0-9_.]+\.[a-zA-Z0-9_.]+(?:\.[a-zA-Z0-9_.]+)+$/)) {
        console.warn(`Warning: '${data.packageName}' might not be a valid Android package name`);
      }
      
      // Try to spawn the process
      const pid = await frida.spawnProcess(data.packageName);
      console.log(`Process spawned with PID: ${pid}`);
      
      // Automatically attach to the spawned process
      const session = await frida.attachToProcess(pid);
      console.log('Session created:', session.id);
      
      // Resume the spawned process
      await frida.resumeProcess(pid);
      console.log('Process resumed');
      
      callback({ success: true, pid, sessionId: session.id });
    } catch (error) {
      console.error('Error spawning process:', error);
      
      // Provide more helpful error messages
      let errorMessage = error.message;
      if (error.message.includes('Unable to find application')) {
        errorMessage = `Unable to find application with identifier '${data.packageName}'. Please ensure you're using the correct package name (e.g., com.example.app).`;
      }
      
      callback({ success: false, error: errorMessage });
    }
  });
  
  // Handle creating and loading a script
  socket.on('create-script', async (scriptSource, callback) => {
    try {
      console.log('Client creating script of length:', scriptSource.length);
      console.log('Script content:', scriptSource);
      
      // Create the script
      const script = await frida.createScript(scriptSource);
      console.log('Script created');
      
      // Set up message handler to forward messages to the client
      frida.onMessage(message => {
        console.log('Script message received:', message);
        socket.emit('script-message', message);
      });
      
      // Load the script
      console.log('Loading script...');
      await frida.loadScript();
      console.log('Script loaded successfully');
      
      callback({ success: true });
    } catch (error) {
      console.error('Error creating/loading script:', error);
      callback({ success: false, error: error.message });
    }
  });
  
  // Handle posting messages to the script
  socket.on('post-message', async (message, data, callback) => {
    try {
      console.log(`Client posting message: ${message}`, data);
      await frida.post(message, data);
      console.log('Message posted successfully');
      callback({ success: true });
    } catch (error) {
      console.error('Error posting message:', error);
      callback({ success: false, error: error.message });
    }
  });
  
  // Handle disconnection from Frida
  socket.on('disconnect-frida', async (callback) => {
    try {
      console.log('Client disconnecting from Frida');
      await frida.disconnect();
      console.log('Disconnected from Frida');
      callback({ success: true });
    } catch (error) {
      console.error('Error disconnecting from Frida:', error);
      callback({ success: false, error: error.message });
    }
  });
  
  // Handle client disconnection
  socket.on('disconnect', async () => {
    console.log(`Client disconnected: ${socket.id}`);
    
    // Clean up Frida bridge
    const frida = bridges.get(socket.id);
    if (frida) {
      try {
        await frida.disconnect();
        console.log(`Cleaned up Frida bridge for ${socket.id}`);
      } catch (error) {
        console.error(`Error cleaning up Frida bridge: ${error.message}`);
      }
      bridges.delete(socket.id);
    }
  });
});

// Define API routes
app.get('/api/status', (req, res) => {
  res.json({ status: 'Frida bridge server is running' });
});

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Frida bridge server listening on port ${PORT}`);
}); 