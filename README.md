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

command line options:
-c <URI-list>, --connect <URI-list> - URI list to connect to URI list is: <URL1>,<URL2>,<URL3>,...
 each URL on format <proto>:<host>[:<port>][path]
 where:
 <proto> - ws(for websocket over http) or wss(for websocket over https)
 <host> - FQDN (will be resolved) or IPv4 address or [IPv6] (rfc requires ipv6 in square brackets)
 <port> (not required) - tcp port num. if ommitted wss uses - 443  and ws - 80
 <path> - URL path
 
example:
 ws://brain4net.com:888/ui,ws://ya.ru/path1/long/,wss://8.8.8.8/very/long/path,ws://mail.ru:44555/,wss://ya.ru,https://d3.ru/,wss://[2022:BBB:88:2::1]:8866/v6/path
https://d3.ru/ in above will be silently skipped due to unknown proto. Have to be ws|wss

-t, --timeout - timeout for WS-session setup, ms, default - 1000(1sec) - session setup timeout, socket read timeout
-r, --reconnect - reconnect WS-session period, ms, default - 1000(1sec)
-o, --out-pipe-name - name of a pipe where wspiper will push received via ws messages, def - /tmp/wsoutpipe
-i, --in-pipe-name - name of a pipe where wspiper will listen and receive messages and relay these messages to ws, def - /tmp/wsinpipe
-n, --no-check-cert - do not check CA certs

-p, --ping-period - period of sending WS pings, ms, default - 1000(1sec)
-g, --pong-timeout - Pong recv timeout, ms, default 3000(3s)

-d, --delimiter - set message delimiter. Default - \n. Possible values - \n, \n\n.., \t, \r, \r\n, <symbol>, \0 - null.

TODO:
-g, --origin - web-socket origin
-v, --verbose - verbose logging
-m, --max-msg-size - maximum message size in bytes, default - 65536 (64KB)
-s, --pipes-buffer-size - size of named pipes buffer in bytes, default - 4096 (4KB)
