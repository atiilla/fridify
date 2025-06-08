document.addEventListener('DOMContentLoaded', function() {
    // DOM elements
    const connectBtn = document.getElementById('connect-btn');
    const disconnectBtn = document.getElementById('disconnect-btn');
    const refreshDevicesBtn = document.getElementById('refresh-devices-btn');
    const devicesSelect = document.getElementById('devices-select');
    const refreshProcessesBtn = document.getElementById('refresh-processes-btn');
    const processesSelect = document.getElementById('processes-select');
    const attachBtn = document.getElementById('attach-btn');
    const spawnBtn = document.getElementById('spawn-btn');
    const scriptEditor = document.getElementById('script-editor');
    const loadScriptBtn = document.getElementById('load-script-btn');
    const pingBtn = document.getElementById('ping-btn');
    const consoleOutput = document.getElementById('console');
    const clearConsoleBtn = document.getElementById('clear-console-btn');
    
    // Connection status
    let isConnected = false;
    let isAttached = false;
    let isScriptLoaded = false;
    
    // Connect to Socket.IO server
    const socket = io();
    
    // Log to console
    function log(message, type = 'info') {
        const line = document.createElement('p');
        line.className = `console-line console-${type}`;
        line.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
        consoleOutput.appendChild(line);
        consoleOutput.scrollTop = consoleOutput.scrollHeight;
        
        // Also log to browser console for debugging
        console.log(`[${type}] ${message}`);
    }
    
    // Clear console
    clearConsoleBtn.addEventListener('click', function() {
        consoleOutput.innerHTML = '';
    });
    
    // Connect to Frida
    connectBtn.addEventListener('click', function() {
        log('Connecting to Frida...');
        
        socket.emit('connect-frida', {}, function(response) {
            if (response.success) {
                log('Connected to Frida successfully', 'success');
                isConnected = true;
                
                // Update UI
                connectBtn.disabled = true;
                disconnectBtn.disabled = false;
                refreshDevicesBtn.disabled = false;
                
                // Automatically refresh devices
                refreshDevices();
            } else {
                log(`Failed to connect to Frida: ${response.error}`, 'error');
            }
        });
    });
    
    // Disconnect from Frida
    disconnectBtn.addEventListener('click', function() {
        log('Disconnecting from Frida...');
        
        socket.emit('disconnect-frida', function(response) {
            if (response.success) {
                log('Disconnected from Frida successfully', 'success');
                isConnected = false;
                isAttached = false;
                isScriptLoaded = false;
                
                // Update UI
                connectBtn.disabled = false;
                disconnectBtn.disabled = true;
                refreshDevicesBtn.disabled = true;
                devicesSelect.disabled = true;
                refreshProcessesBtn.disabled = true;
                processesSelect.disabled = true;
                attachBtn.disabled = true;
                loadScriptBtn.disabled = true;
                pingBtn.disabled = true;
                spawnBtn.disabled = true;
                
                // Clear selects
                devicesSelect.innerHTML = '';
                processesSelect.innerHTML = '';
            } else {
                log(`Failed to disconnect from Frida: ${response.error}`, 'error');
            }
        });
    });
    
    // Refresh devices
    function refreshDevices() {
        log('Getting available devices...');
        
        socket.emit('get-devices', function(response) {
            if (response.success) {
                const devices = response.devices;
                log(`Found ${devices.length} device(s)`, 'success');
                
                // Debug: Log the device structure
                console.log('Device data:', devices);
                
                // Update UI
                devicesSelect.innerHTML = '';
                
                if (devices.length === 0) {
                    log('No devices found. Make sure Frida server is running on your target device.', 'error');
                    return;
                }
                
                devices.forEach(device => {
                    // Extract device information with fallbacks
                    const deviceId = device.id || 'unknown-id';
                    const deviceName = device.name || 'Unknown Device';
                    const deviceType = device.type || 'unknown';
                    
                    const option = document.createElement('option');
                    option.value = deviceId;
                    option.textContent = `${deviceName} (${deviceType}: ${deviceId})`;
                    devicesSelect.appendChild(option);
                    
                    // Log each device for debugging
                    log(`Device: ${deviceName}, Type: ${deviceType}, ID: ${deviceId}`, 'info');
                });
                
                devicesSelect.disabled = false;
                refreshProcessesBtn.disabled = false;
            } else {
                log(`Failed to get devices: ${response.error}`, 'error');
            }
        });
    }
    
    refreshDevicesBtn.addEventListener('click', refreshDevices);
    
    // Refresh processes
    refreshProcessesBtn.addEventListener('click', function() {
        const deviceId = devicesSelect.value;
        if (!deviceId) {
            log('No device selected', 'error');
            return;
        }
        
        log(`Selecting device: ${deviceId}`);
        socket.emit('select-device', deviceId, function(response) {
            if (response.success) {
                const deviceName = response.device.name || 'Unknown Device';
                log(`Selected device: ${deviceName}`, 'success');
                
                log('Getting processes...');
                socket.emit('get-processes', function(response) {
                    if (response.success) {
                        const processes = response.processes;
                        log(`Found ${processes.length} process(es)`, 'success');
                        
                        // Debug: Log the process structure
                        console.log('Process data:', processes);
                        
                        // Update UI
                        processesSelect.innerHTML = '';
                        
                        if (processes.length === 0) {
                            log('No processes found on the device.', 'error');
                            return;
                        }
                        
                        // Group processes by type (running and not running)
                        const runningProcesses = processes.filter(p => !p.isNotRunning);
                        const notRunningPackages = processes.filter(p => p.isNotRunning);
                        
                        // Add optgroups for better organization
                        if (runningProcesses.length > 0) {
                            const runningGroup = document.createElement('optgroup');
                            runningGroup.label = 'Running Processes';
                            processesSelect.appendChild(runningGroup);
                            
                            runningProcesses.forEach(process => addProcessOption(process, runningGroup));
                        }
                        
                        if (notRunningPackages.length > 0) {
                            const appsGroup = document.createElement('optgroup');
                            appsGroup.label = 'Installed Applications';
                            processesSelect.appendChild(appsGroup);
                            
                            notRunningPackages.forEach(process => addProcessOption(process, appsGroup));
                        }
                        
                        // Enable the controls
                        processesSelect.disabled = false;
                        attachBtn.disabled = false;
                        spawnBtn.disabled = false;
                    } else {
                        log(`Failed to get processes: ${response.error}`, 'error');
                    }
                });
            } else {
                log(`Failed to select device: ${response.error}`, 'error');
            }
        });
        
        // Helper function to add a process option to a group
        function addProcessOption(process, group) {
            const pid = process.pid || 0;
            const name = process.name || 'Unknown Process';
            const packageName = process.packageName;
            const applicationName = process.applicationName;
            
            const option = document.createElement('option');
            
            // If we have the package name, that's what we want to use for spawning
            if (packageName) {
                option.value = packageName; // Store the full package name
                option.setAttribute('data-package', packageName); // Also store as attribute
                
                // Format the display text based on available info
                if (applicationName && applicationName !== packageName) {
                    option.textContent = `${applicationName} (${packageName})`;
                } else {
                    option.textContent = packageName;
                }
                
                // If it's a running process, add the PID
                if (pid > 0) {
                    option.textContent += ` [PID: ${pid}]`;
                    option.setAttribute('data-pid', pid);
                }
            } else {
                // No package name, just use process name and PID
                option.value = name; 
                option.textContent = `${name} [PID: ${pid}]`;
                option.setAttribute('data-pid', pid);
            }
            
            // Flag for non-running apps
            if (process.isNotRunning) {
                option.classList.add('not-running');
                option.style.fontStyle = 'italic';
            }
            
            group.appendChild(option);
        }
    });
    
    // Spawn process and automatically load the bypass script
    spawnBtn.addEventListener('click', function() {
        const selectedOption = processesSelect.options[processesSelect.selectedIndex];
        if (!selectedOption) {
            log('No process selected', 'error');
            return;
        }
        
        // First check if we have a data-package attribute (most reliable)
        let packageName = selectedOption.getAttribute('data-package');
        
        // If not, try to extract it from the text content
        if (!packageName) {
            const optionText = selectedOption.textContent;
            const packageNameMatch = optionText.match(/([a-zA-Z0-9_.]+\.[a-zA-Z0-9_.]+(?:\.[a-zA-Z0-9_.]+)+)/);
            
            if (packageNameMatch && packageNameMatch[1]) {
                // If we found a pattern that looks like a package name (com.example.app)
                packageName = packageNameMatch[1];
            } else {
                // Fallback to the value (which might not be correct for Android)
                packageName = selectedOption.value;
            }
        }
        
        if (!packageName) {
            log('Invalid package name', 'error');
            return;
        }
        
        log(`Spawning application with package name: ${packageName}`);
        socket.emit('spawn-process', { packageName }, function(response) {
            if (response.success) {
                log(`Spawned application with PID: ${response.pid}`, 'success');
                log(`Automatically attached to process (Session ID: ${response.sessionId})`, 'success');
                isAttached = true;
                
                // Automatically load the script
                const scriptSource = scriptEditor.value.trim();
                if (!scriptSource) {
                    log('Script is empty', 'error');
                    return;
                }
                
                log('Automatically loading SSL pinning bypass script...');
                socket.emit('create-script', scriptSource, function(scriptResponse) {
                    if (scriptResponse.success) {
                        log('SSL pinning bypass script loaded successfully', 'success');
                        isScriptLoaded = true;
                        
                        // Update UI
                        loadScriptBtn.disabled = false;
                        pingBtn.disabled = false;
                    } else {
                        log(`Failed to load bypass script: ${scriptResponse.error}`, 'error');
                    }
                });
            } else {
                log(`Failed to spawn application: ${response.error}`, 'error');
            }
        });
    });
    
    // Attach to process
    attachBtn.addEventListener('click', function() {
        const selectedOption = processesSelect.options[processesSelect.selectedIndex];
        if (!selectedOption) {
            log('No process selected', 'error');
            return;
        }
        
        const pid = selectedOption.getAttribute('data-pid');
        if (!pid) {
            log('Invalid process ID', 'error');
            return;
        }
        
        log(`Attaching to process: ${pid}`);
        socket.emit('attach-process', parseInt(pid), function(response) {
            if (response.success) {
                log(`Attached to process (Session ID: ${response.sessionId})`, 'success');
                isAttached = true;
                
                // Update UI
                loadScriptBtn.disabled = false;
            } else {
                log(`Failed to attach to process: ${response.error}`, 'error');
            }
        });
    });
    
    // Load script
    loadScriptBtn.addEventListener('click', function() {
        const scriptSource = scriptEditor.value.trim();
        if (!scriptSource) {
            log('Script is empty', 'error');
            return;
        }
        
        log('Creating and loading script...');
        socket.emit('create-script', scriptSource, function(response) {
            if (response.success) {
                log('Script created and loaded successfully', 'success');
                isScriptLoaded = true;
                
                // Update UI
                pingBtn.disabled = false;
            } else {
                log(`Failed to create/load script: ${response.error}`, 'error');
            }
        });
    });
    
    // Send ping
    pingBtn.addEventListener('click', function() {
        log('Sending ping to script...');
        socket.emit('post-message', 'ping', null, function(response) {
            if (response.success) {
                log('Ping sent successfully', 'success');
            } else {
                log(`Failed to send ping: ${response.error}`, 'error');
            }
        });
    });
    
    // Handle script messages
    socket.on('script-message', function(message) {
        console.log('Received script message:', message);
        
        try {
            if (message.type === 'send') {
                const payload = message.payload;
                
                if (payload.type === 'message') {
                    const importance = payload.important ? 'success' : 'info';
                    log(`Script message: ${payload.text}`, importance);
                } else if (payload.type === 'error') {
                    log(`Script error: ${payload.message}`, 'error');
                } else if (payload.type === 'pong') {
                    log(`Received pong - Timestamp: ${payload.timestamp}`, 'success');
                } else if (payload.type === 'function-called') {
                    log(`Function ${payload.function} called with path: ${payload.path}`, 'info');
                } else {
                    // Generic handler for other message types
                    log(`Script message: ${JSON.stringify(payload)}`, 'info');
                }
            } else if (message.type === 'error') {
                log(`Script error: ${message.description || message.stack || 'Unknown error'}`, 'error');
            } else {
                log(`Unknown message type: ${JSON.stringify(message)}`, 'error');
            }
        } catch (error) {
            log(`Error processing script message: ${error.message}`, 'error');
            console.error('Error processing message:', error, message);
        }
    });
    
    // Handle socket connection events
    socket.on('connect', function() {
        log('Connected to server', 'success');
    });
    
    socket.on('disconnect', function() {
        log('Disconnected from server', 'error');
        
        // Reset connection status
        isConnected = false;
        isAttached = false;
        isScriptLoaded = false;
        
        // Update UI
        connectBtn.disabled = false;
        disconnectBtn.disabled = true;
        refreshDevicesBtn.disabled = true;
        devicesSelect.disabled = true;
        refreshProcessesBtn.disabled = true;
        processesSelect.disabled = true;
        attachBtn.disabled = true;
        loadScriptBtn.disabled = true;
        pingBtn.disabled = true;
        spawnBtn.disabled = true;
    });
    
    // Initial log
    log('Frida Web Client loaded', 'info');
}); 