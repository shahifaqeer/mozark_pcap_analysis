# mozark_pcap_analysis

### Data and Files Required
- tshark_extract_fields.sh
- News App Data folder containing tcpdump files
- testing_results_pcap_id.csv

## News App Analysis

- Input: Pcap from news apps (India Today and ToI) in different network conditions
- Output: KPI Analysis group

### Data:
- India Today Poor: tcpdump_9.49.14
- India Today Good: tcpdump_22.59.47
- ToI Good: tcpdump_23.40.32

### Steps:
- convert pcap to json for all tcp_dump files [tshark_convert.sh]
- load json to pandas dataframe and combine
- add meta info csv on files - network conditions, app, date and time
- calculate basic KPIs for each tcpdump file per stream, (src-dst) pair, overall file
- comparison/correlation between KPIs and network conditions

## KPIs

#### Meta data
- Trace name, Date, Start time, End time, Duration
- Total number of packets
- Packets/sec timeseries [Burst rate]
- Burst time
- Bytes/sec Throughput (up) timeseries
- Bytes/sec Throughput (dw) timeseries

#### IP
- Number of IPv4 vs IPv6 packets: Data vs others
- Bytes of IPv4 vs IPv6 packets: Data vs others

#### UDP
- Number of UDP packets
- Number of DNS vs Others

#### DNS
- Number of DNS packets
- Number queries and responses - on IPv4 and IPv6
- Number of error responses
- dns.time for responses as a list => max, 90perc, 50perc, avg [describe]
- dns.time | dns server | dns url => best and worst performers
- number of DNS servers
- number of queries vs number of unique queries
- time between same repeated query in a trace
- DNS over TCP and DNSSEC over TCP
- (max, avg, perc) DNS LOOKUP TIME

#### TCP
- Number of TCP packets - on IPv4 and IPv6
- Number of Data packets vs Number of overhead
- Number of tcp.analysis.flags and individual flags (retrans, dup_ack, zero_window, etc)
- Zombie: TCP connections with no data vs time
- Concurrent TCP connections vs time (no FIN)
- Concurrent TCP connections to same server (IP) vs time -- shouldn't be more that 6 for browsers in HTTP/1.1
- (max, avg, total) TCP window size vs time
- (max, avg, perc) TCP HANDSHAKE TIME


#### TLS/HTTPS
- ESNI all vs ESNI unique
- 3rd party vs 1st party vs CDNs connections
- Zombie TLS: encrypted handshake keep alive
- HTTPS in TLS vs unknown data in TLS
- TLS reused
- Security: cipher text DHE or old (server choice)
- (max, avg, perc) TLS HANDSHAKE TIME

## WATERFALL PLOT

#### Extract timings
#### Merge DNS and TCP timings based on server name

#### HTTP
- 200, 300, 400+ response counts
- data download HTTP vs time
- concurrent HTTP connects vs time
- max concurrent HTTP connects to same server -- should be 6 or lower
- 3rd party, 1st party, CDN resource counts
- (max, avg, perc) TTFB
- (max, avg, perc) DATA DOWNLOAD

#### TIMING
- TODO
