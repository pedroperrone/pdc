simple_switch_CLI --thrift-port 9090 < commands-s1.txt && echo loaded s1 commands
simple_switch_CLI --thrift-port 9091 < commands-s2.txt && echo loaded s2 commands
simple_switch_CLI --thrift-port 9092 < commands-s3.txt && echo loaded s3 commands
