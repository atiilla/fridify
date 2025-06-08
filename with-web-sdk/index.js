const frida = require('frida');

// Mock implementation of Frida bridge for demonstration purposes
class FridaBridge {
  constructor() {
    this.device = null;
    this.session = null;
    this.script = null;
    this.messageHandlers = [];
    this.devicesList = [
      { id: 'local', name: 'Local System', type: 'local' },
      { id: 'usb-1', name: 'Android Device', type: 'usb' },
      { id: 'remote-1', name: 'Remote Frida Server', type: 'remote', host: '192.168.1.100', port: 27042 }
    ];
  }

  async connect() {
    try {
      // Nothing specific needed to connect to Frida
      // The actual connection happens when we interact with devices
      return true;
    } catch (error) {
      console.error('Failed to connect:', error);
      return false;
    }
  }

  async disconnect() {
    if (this.script) {
      try {
        await this.script.unload();
        console.log('Script unloaded');
      } catch (error) {
        console.error('Error unloading script:', error);
      }
      this.script = null;
    }
    
    if (this.session) {
      try {
        await this.session.detach();
        console.log('Session detached');
      } catch (error) {
        console.error('Error detaching session:', error);
      }
      this.session = null;
    }
    
    this.device = null;
    this.messageHandlers = [];
  }

  async getDevices() {
    try {
      const devices = await frida.enumerateDevices();
      console.log('Raw devices:', JSON.stringify(devices, null, 2));
      
      // Map devices to ensure we have all expected properties
      return devices.map(device => {
        // Create a simplified object with all necessary properties
        return {
          id: device.id || `unknown-${Math.random().toString(36).substring(2, 9)}`,
          name: device.name || 'Unknown Device',
          type: device.type || 'unknown',
          // Add any other properties that might be useful
          icon: device.icon,
          isLost: device.isLost || false,
          // Add a custom toString method for debugging
          toString: function() {
            return `${this.name} (${this.type}: ${this.id})`;
          }
        };
      });
    } catch (error) {
      console.error('Error getting devices:', error);
      throw error;
    }
  }

  async getDevice(id) {
    try {
      const devices = await this.getDevices();
      this.device = devices.find(device => device.id === id || device.name === id);
      
      if (!this.device) {
        throw new Error(`Device ${id} not found`);
      }
      
      console.log('Selected device:', this.device);
      return this.device;
    } catch (error) {
      console.error('Error getting device:', error);
      throw error;
    }
  }

  async getProcesses() {
    try {
      if (!this.device) {
        throw new Error('No device selected');
      }
      
      // Get the actual Frida device
      const fridaDevice = await frida.getDevice(this.device.id);
      
      // Check if this is an Android device
      const isAndroid = this.device.type === 'usb';
      
      // For Android devices, we need to get the list of installed applications
      let androidPackages = [];
      if (isAndroid) {
        try {
          console.log('Attempting to get list of installed Android packages...');
          // This uses the Frida API to get installed applications
          androidPackages = await fridaDevice.enumerateApplications();
          console.log(`Found ${androidPackages.length} Android applications`);
        } catch (e) {
          console.error('Error getting Android applications:', e);
        }
      }
      
      // Enumerate processes
      const processes = await fridaDevice.enumerateProcesses();
      console.log('Raw processes:', JSON.stringify(processes.slice(0, 5), null, 2), '... and more');
      
      // Combine processes with Android package info
      const enhancedProcesses = processes.map(process => {
        const processInfo = {
          pid: process.pid || 0,
          name: process.name || `Unknown-${process.pid}`,
          // Add any other properties that might be useful
          ppid: process.ppid,
          icon: process.icon
        };
        
        // For Android, try to match with package info
        if (isAndroid && androidPackages.length > 0) {
          // Try to find a matching package by name or identifier
          const matchingPackage = androidPackages.find(pkg => 
            pkg.name === process.name || 
            pkg.identifier === process.name ||
            (process.name && pkg.name && process.name.includes(pkg.name))
          );
          
          if (matchingPackage) {
            // Add the full package information
            processInfo.packageName = matchingPackage.identifier || matchingPackage.name;
            processInfo.applicationName = matchingPackage.name;
          }
        }
        
        return processInfo;
      });
      
      // For Android, also add packages that might not be running
      if (isAndroid && androidPackages.length > 0) {
        // Find packages that aren't in the process list
        const runningPkgNames = enhancedProcesses
          .filter(p => p.packageName)
          .map(p => p.packageName);
        
        const nonRunningPackages = androidPackages
          .filter(pkg => !runningPkgNames.includes(pkg.identifier));
        
        // Add non-running packages to the list
        nonRunningPackages.forEach(pkg => {
          enhancedProcesses.push({
            pid: 0, // No PID since it's not running
            name: pkg.name || 'Unknown App',
            packageName: pkg.identifier,
            applicationName: pkg.name,
            isNotRunning: true // Flag to indicate this is not a running process
          });
        });
      }
      
      return enhancedProcesses;
    } catch (error) {
      console.error('Error getting processes:', error);
      throw error;
    }
  }

  async spawnProcess(packageName, argv = []) {
    try {
      if (!this.device) {
        throw new Error('No device selected');
      }
      
      // Get the actual Frida device
      const fridaDevice = await frida.getDevice(this.device.id);
      
      console.log(`Spawning process: ${packageName}`);
      
      // Check if we're dealing with an Android device (type usb)
      // We can't reliably check for android platform on the server side
      const isAndroid = this.device.type === 'usb';
      
      let pid;
      if (isAndroid) {
        // For Android, don't pass the argv option
        pid = await fridaDevice.spawn(packageName);
      } else {
        // For other platforms, pass the argv option
        pid = await fridaDevice.spawn(packageName, {
          argv: argv
        });
      }
      
      console.log(`Process spawned with PID: ${pid}`);
      
      return pid;
    } catch (error) {
      console.error('Error spawning process:', error);
      throw error;
    }
  }

  async resumeProcess(pid) {
    try {
      if (!this.device) {
        throw new Error('No device selected');
      }
      
      // Get the actual Frida device
      const fridaDevice = await frida.getDevice(this.device.id);
      
      console.log(`Resuming process with PID: ${pid}`);
      await fridaDevice.resume(pid);
      console.log(`Process resumed`);
    } catch (error) {
      console.error('Error resuming process:', error);
      throw error;
    }
  }

  async attachToProcess(target) {
    try {
      if (!this.device) {
        throw new Error('No device selected');
      }
      
      // Get the actual Frida device
      const fridaDevice = await frida.getDevice(this.device.id);
      
      console.log(`Attaching to process with PID: ${target}`);
      this.session = await fridaDevice.attach(target);
      console.log('Session created:', this.session);
      
      return this.session;
    } catch (error) {
      console.error('Error attaching to process:', error);
      throw error;
    }
  }

  async createScript(scriptSource) {
    try {
      if (!this.session) {
        throw new Error('No session available');
      }
      
      // Properly format the script if it's not already
      if (!scriptSource.trim().startsWith('(') && !scriptSource.trim().startsWith('setTimeout')) {
        console.log('Wrapping script in function');
        scriptSource = `(function() {
          ${scriptSource}
        })();`;
      }
      
      console.log('Creating script with source:', scriptSource);
      this.script = await this.session.createScript(scriptSource);
      console.log('Script created');
      
      // Set up the message handler
      this.script.message.connect((message) => {
        console.log('Message from script:', message);
        this.messageHandlers.forEach(handler => handler(message));
      });
      
      return this.script;
    } catch (error) {
      console.error('Error creating script:', error);
      throw error;
    }
  }

  async loadScript() {
    try {
      if (!this.script) {
        throw new Error('No script created');
      }
      
      console.log('Loading script...');
      await this.script.load();
      console.log('Script loaded successfully');
    } catch (error) {
      console.error('Error loading script:', error);
      throw error;
    }
  }

  onMessage(callback) {
    try {
      if (!this.script) {
        throw new Error('No script loaded');
      }
      
      console.log('Registering message handler');
      this.messageHandlers.push(callback);
    } catch (error) {
      console.error('Error setting message handler:', error);
      throw error;
    }
  }

  async post(message, data) {
    try {
      if (!this.script) {
        throw new Error('No script loaded');
      }
      
      console.log(`Posting message to script: ${message}`, data);
      await this.script.post(message, data);
      console.log('Message posted successfully');
    } catch (error) {
      console.error('Error posting message:', error);
      throw error;
    }
  }

  // Helper method to trigger all message handlers
  triggerMessageHandlers(message) {
    for (const handler of this.messageHandlers) {
      handler(message);
    }
  }
}

module.exports = FridaBridge;
