<pre style="font-family: 'Courier New', monospace; font-size: 14px; color: #58A6FF; background: #0D1117; padding: 20px; border-radius: 12px; margin: 20px 0; text-align: center; line-height: 1; white-space: pre;">    
                                                                ##                                  ##
#####    ##  ##    ####    ######           ####    ##  ##    #####    ####    ##  ##    ####     #####    ####    ######
##  ##   #######      ##    ##  ##             ##   ##  ##     ##     ##  ##   #######      ##     ##     ##  ##    ##  ##
##  ##   ## # ##   #####    ##  ##          #####   ##  ##     ##     ##  ##   ## # ##   #####     ##     ##  ##    ##
##  ##   ##   ##  ##  ##    #####          ##  ##   ##  ##     ## ##  ##  ##   ##   ##  ##  ##     ## ##  ##  ##    ##
##  ##   ##   ##   #####    ##              #####    ######     ###    ####    ##   ##   #####      ###    ####    ####
                           ####
</pre>
  <p><strong>Nmap Automator</strong> is an advanced Python framework for automating network scanning with <code>nmap</code>. Designed for ethical hackers, system administrators, and cybersecurity professionals, it provides asynchronous and scheduled scanning, remote control via REST API, encrypted result storage, and Telegram notifications.</p>

  <h2 style="color: #58A6FF; margin-top: 30px;">Key Features</h2>
  <ul style="text-align: left; padding-left: 20px;">
    <li>Asynchronous and scheduled scanning (SYN, TCP, UDP, OS detection, Aggressive, Ping).</li>
    <li>RESTful API for remote scan execution (built with Quart — async Flask).</li>
    <li>Automatic encryption of results using Fernet (symmetric AES).</li>
    <li>Telegram alerts on scan completion or errors.</li>
    <li>Configuration via environment variables (<code>.env</code>) and API.</li>
    <li>Comprehensive logging with rotation.</li>
    <li>Strict input validation for IPs, CIDR ranges, and domains.</li>
  </ul>

  <h2 style="color: #58A6FF; margin-top: 30px;">Installation</h2>
  <ol style="text-align: left; padding-left: 20px;">
    <li>Clone the repository:
      <pre style="background: #161B22; color: #C9D1D9; padding: 12px; border-radius: 6px; overflow-x: auto; margin: 10px 0;"><code>git clone https://github.com/nazariihafych/nmap-automator.git
cd nmap-automator</code></pre>
    </li>
    <li>Install dependencies:
      <pre style="background: #161B22; color: #C9D1D9; padding: 12px; border-radius: 6px; overflow-x: auto; margin: 10px 0;"><code>pip install -r requirements.txt</code></pre>
    </li>
    <li>Create a <code>.env</code> file in the project root:
      <pre style="background: #161B22; color: #C9D1D9; padding: 12px; border-radius: 6px; overflow-x: auto; margin: 10px 0;"><code>TELEGRAM_BOT_TOKEN=your_telegram_bot_token
TELEGRAM_CHAT_ID=your_chat_id
FERNET_KEY=your_44_char_fernet_key_here
INITIAL_TASKS=[{"target":"192.168.1.1","scan_type":"TCP","interval":30}]

# Nmap settings
NMAP_HOST_TIMEOUT_SEC=300
NMAP_MAX_RETRIES=2</code></pre>
    </li>
  </ol>

  <h2 style="color: #58A6FF; margin-top: 30px;">Quick Start</h2>
  <pre style="background: #161B22; color: #C9D1D9; padding: 12px; border-radius: 6px; overflow-x: auto;"><code>python autonmap.py</code></pre>
  <p>The application will start an API server at <code>http://0.0.0.0:5000</code> and execute any tasks defined in <code>INITIAL_TASKS</code>.</p>

  <h2 style="color: #58A6FF; margin-top: 30px;">Remote API Control</h2>
  <h3>Run an Immediate Scan</h3>
  <pre style="background: #161B22; color: #C9D1D9; padding: 12px; border-radius: 6px; overflow-x: auto;"><code>curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1", "scan_type": "TCP"}'</code></pre>

  <h3>Schedule a Periodic Scan</h3>
  <pre style="background: #161B22; color: #C9D1D9; padding: 12px; border-radius: 6px; overflow-x: auto;"><code>curl -X POST http://localhost:5000/schedule \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1", "scan_type": "SYN", "interval": 30}'</code></pre>

  <h2 style="color: #58A6FF; margin-top: 30px;">Encryption & Decryption</h2>
  <p>All scan results are automatically saved in encrypted form (Fernet) in the <code>encrypted_results/</code> directory.</p>

  <p>To decrypt a file, use the included <code>decrypt.py</code> script:</p>

  <h3>1. Ensure your <code>FERNET_KEY</code> is in <code>.env</code></h3>
  <pre style="background: #161B22; color: #C9D1D9; padding: 12px; border-radius: 6px; overflow-x: auto; margin: 10px 0;"><code>FERNET_KEY=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEfGhIjKlMnOpQrStUvWxYz1234=</code></pre>

  <h3>2. Run decryption</h3>
  <pre style="background: #161B22; color: #C9D1D9; padding: 12px; border-radius: 6px; overflow-x: auto; margin: 10px 0;"><code># Print to terminal
python decrypt.py encrypted_results/192.168.1.1_TCP_20240510_120000.json

# Save to file
python decrypt.py encrypted_results/192.168.1.1_TCP_20240510_120000.json -o result.json</code></pre>

  <p>💡 <strong>Warning:</strong> Never lose your <code>FERNET_KEY</code> — encrypted data is unrecoverable without it.</p>

  <h2 style="color: #58A6FF; margin-top: 30px;">Requirements</h2>
  <ul style="text-align: left; padding-left: 20px;">
    <li>Python 3.7+</li>
    <li><code>nmap</code> installed and in <code>PATH</code></li>
  </ul>
  <pre style="background: #161B22; color: #C9D1D9; padding: 12px; border-radius: 6px; overflow-x: auto; margin: 10px 0;"><code>sudo apt-get install nmap  # Ubuntu/Debian
brew install nmap          # macOS</code></pre>

  <h2 style="color: #58A6FF; margin-top: 30px;">Project Structure</h2>
  <ul style="text-align: left; padding-left: 20px; font-family: monospace;">
    <li><code>autonmap.py</code> — main application (API server + task scheduler)</li>
    <li><code>decrypt.py</code> — utility to decrypt scan results</li>
    <li><code>encrypted_results/</code> — encrypted scan outputs</li>
    <li><code>scan_log.txt</code> — rotating log file</li>
    <li><code>requirements.txt</code> — dependencies</li>
    <li><code>.env</code> — secrets and configuration</li>
  </ul>

  <h2 style="color: #FF7B72; margin-top: 30px;">⚠️ Ethical Use Only</h2>
  <p>This tool is for <strong>authorized security testing only</strong>. Do not scan networks you do not own or lack explicit written permission to test. Unauthorized scanning may be illegal.</p>
  <p style="font-style: italic; color: #8B949E;">
    Provided "AS IS" WITHOUT WARRANTY.<br>
    The author is not liable for any misuse or damages.
  </p>
</div>
