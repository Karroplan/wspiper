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