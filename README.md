
# wspiper
**wspiper** is a linux command line utility. It establishes websocket connection to a remote server, create two local-named pipes - for reading messages and for writing messages. wspiper constantly awaits for messages from websocket connection(both text and binary) and from in-pipe. Messages received from the websocket are being relayed to the out-pipe, messages from the in-pipe relayed to the websocket connection. wspiper is a foreground proccess, writes messages to the stdout and to the syslog.
Websocket connection support ws and wss via OpenSSL.
``````
                                                         In-pipe               
                                                        /tmp/wsinpipe◄───────  
                                                          │                    
                                                          │                    
                              ┌──────────────────┐        │                    
                              │                  │◄───────┘                    
◄──────────websocket ◄────────┤      WSPIPER     │                             
──────────►connection────────►│                  ├───────────┐                 
                              └──────────────────┘           │                 
                                                             │                 
                                                             ▼                 
                                                           Out-pipe            
                                                           /tmp/wsoutpipe ────►
``````


One can do:

`echo "{ 'message':'Hello, World'}\n" > /tmp/wsinpipe`

JSON message will be read from in-pipe and delivered to a remote server via websocket-connection. Please, note `\n` at the end - `newline` is a default message delimiter by which **wspiper** detects messages in the in-pipe.

Then server could respond with `"{ 'response': 'Weclcome fellow Piper!'}"` and one can issue:

`cat /tmp/wsoutpipe` to receive it.


# Command Line Options

- `-c`, `--connect`  
  URI list to connect to. List format: `uri1,uri2,uri3,...`  
  Each URI: `scheme://host[:port][path]`  
  - `scheme`: `ws` (WebSocket over HTTP) or `wss` (WebSocket over HTTPS)  
  - `host`: FQDN (resolved), IPv4, or `[IPv6]` (IPv6 must be in square brackets per RFC)  
  - `port`: TCP port. If omitted: `wss` → 443, `ws` → 80  
  - `path`: URL path  

 **Example:**
`ws://brain4net.com:888/ui,ws://ya.ru/path1/long/,wss://8.8.8.8/very/long/path,ws://mail.ru:44555/,wss://ya.ru,https://d3.ru/,wss://[2022:BBB:88:2::1]:8866/v6/path`

*Note:* `https://d3.ru/` will be silently skipped (unknown protocol). Only `ws://` or `wss://` allowed.


- `-t`, `--timeout`  
Timeout for WebSocket session setup, in milliseconds.  
Default: `1000` (1 sec)  
Applies to: session setup and socket read timeout.

- `-r`, `--reconnect`  
Reconnection period for WebSocket session, in milliseconds.  
Default: `1000` (1 sec)

- `-o`, `--out-pipe-name`  
Named pipe to write messages received from WebSocket.  
Default: `/tmp/wsoutpipe`

- `-i`, `--in-pipe-name`  
Named pipe to read messages and forward them to WebSocket.  
Default: `/tmp/wsinpipe`

- `-n`, `--no-check-cert`  
Disable CA certificate verification (for `wss`).

- `-p`, `--ping-period`  
Interval for sending WebSocket pings, in milliseconds.  
Default: `1000` (1 sec)

- `-g`, `--pong-timeout`  
Timeout for receiving pong response, in milliseconds.  
Default: `3000` (3 sec)

- `-d`, `--delimiter`  
Message delimiter.  
Default: `\n`  
Supported: `\n`, `\n\n...`, `\t`, `\r`, `\r\n`, ` ` (space), `\0` (null)

---

### TODO (Planned)

- `-g`, `--origin` — set WebSocket origin header  
- `-v`, `--verbose` — enable verbose logging  
- `-m`, `--max-msg-size` — max message size in bytes, default: `65536` (64 KB)  
- `-s`, `--pipes-buffer-size` — named pipe buffer size in bytes, default: `4096` (4 KB)