#!/bin/bash
# sh tshark_extract_fields.sh  [-h] | [ -i /input_path/trace.pcap -o output_path/tshark_trace.log -k ]

usage="sh $(basename "$0") [-h | -i | -o | -a] -- program to extract packet fields as log file from a pcap for KPI calculations using tshark 

where:
    -h  show this help text
    -i  path to input pcap input.pcap
    -o  path to output csv log file output.log
    -a  output all related fields (only KPI fields by default)"

while getopts hkfi:o: option
do
	case "${option}"
	in
	h|help) echo "$usage"
			exit 0
			;;
	i) INPUTPCAPPATH=${OPTARG};;
	o) OUTPUTLOGPATH=${OPTARG};;
	a) ALLFIELDS=1;;
	esac
done

if [[ $ALLFIELDS -eq 1 ]]; then

	tshark -r $INPUTPCAPPATH -T fields -E header=y -E separator=, \
	-e frame.number -e frame.time_delta -e frame.len -e vlan.id -e eth.trailer -e eth.src -e eth.dst -e frame.protocols -e _ws.col.Protocol -e _ws.col.Info -e icmp.type \
	-e ip.proto -e ip.src -e ip.dst -e ip.dsfield -e ip.dsfield.dscp -e ip.flags -e ip.frag_offset -e ip.ttl -e ip.len \
	-e tcp.stream -e tcp.srcport -e tcp.dstport -e tcp.seq -e tcp.hdr_len -e tcp.len -e tcp.ack -e tcp.ack.nonzero -e tcp.window_size -e tcp.nxtseq -e tcp.time_delta -e tcp.time_relative \
	-e tcp.options -e tcp.options.mss -e tcp.options.mss_val -e tcp.options.qs -e tcp.options.sack -e tcp.options.snack -e tcp.options.tfo -e tcp.options.wscale.multiplier \
	-e tcp.connection.syn -e tcp.connection.sack -e tcp.connection.rst -e tcp.connection.fin -e tcp.flags -e tcp.segment -e tcp.segment.count -e tcp.segment.error -e tcp.segment.multipletails -e tcp.segment.overlap \
	-e tcp.analysis.ack_lost_segment -e tcp.analysis.ack_rtt -e tcp.analysis.acks_frame -e tcp.analysis.bytes_in_flight -e tcp.analysis.duplicate_ack -e tcp.analysis.duplicate_ack_frame -e tcp.analysis.duplicate_ack_num \
	-e tcp.analysis.fast_retransmission -e tcp.analysis.flags -e tcp.analysis.initial_rtt -e tcp.analysis.keep_alive -e tcp.analysis.keep_alive_ack -e tcp.analysis.lost_segment -e tcp.analysis.out_of_order \
	-e tcp.analysis.retransmission -e tcp.analysis.reused_ports -e tcp.analysis.rto -e tcp.analysis.rto_frame -e tcp.analysis.spurious_retransmission -e tcp.analysis.tfo_syn \
	-e tcp.analysis.window_full -e tcp.analysis.window_update -e tcp.analysis.zero_window -e tcp.analysis.zero_window_probe -e tcp.analysis.zero_window_probe_ack \
	-e ssl.handshake.type -e ssl.alert_message -e ssl.record -e ssl.record.content_type -e ssl.handshake -e ssl.handshake.cert_type.type -e ssl.handshake.extensions_alpn_str -e ssl.handshake.extensions_server_name \
	-e x509ce.dNSName \
	-e http.request.method -e http.request.uri -e http.location -e http.request.full_uri -e http.request.version -e http.user_agent -e http.host -e http.connection -e http.accept_encoding -e http.request_number -e http.response_in -e http.next_request_in -e http.response.code -e http.content_type -e http.content_length -e http.referer \
	-e _ws.expert.severity \
	-e udp.stream -e udp.dstport -e udp.srcport -e udp.length.bad -e udp.length.bad_zero -e udp.possible_traceroute \
	-e dns.time -e dns.flags -e dns.flags.rcode -e dns.count.queries -e dns.qry.name -e dns.count.labels -e dns.qry.type -e dns.qry.class -e dns.count.answers -e dns.count.add_rr -e dns.count.auth_rr -e dns.count.prerequisites -e dns.count.updates -e dns.count.zones -e dns.resp.name -e dns.resp.type -e dns.resp.class -e dns.resp.ttl -e dns.a -e dns.aaaa -e dns.cname -e dns.dname \
	> $OUTPUTLOGPATH

else

	tshark -r $INPUTPCAPPATH -Y "not(ip.addr == 127.0.0.1) && (ipv6 || ip)" -T fields -E header=y -E separator=\| \
	-e frame.number -e frame.time -e frame.time_relative -e frame.len -e ip.version -e ip.proto -e ip.src -e ip.dst -e ip.flags -e ip.frag_offset -e ip.ttl -e ip.len -e ip.fragment.error \
	-e tcp.stream -e tcp.time_relative -e tcp.time_delta -e tcp.srcport -e tcp.dstport -e tcp.len -e tcp.hdr_len -e tcp.pdu.size -e tcp.window_size -e tcp.flags -e tcp.flags.fin -e tcp.flags.ack -e tcp.flags.syn \
	-e tcp.analysis.retransmission -e tcp.analysis.rto  -e tcp.analysis.ack_rtt -e tcp.analysis.initial_rtt -e tcp.analysis.bytes_in_flight -e tcp.analysis.duplicate_ack -e tcp.analysis.fast_retransmission -e tcp.analysis.flags -e tcp.analysis.keep_alive -e tcp.analysis.keep_alive_ack -e tcp.analysis.lost_segment -e tcp.analysis.out_of_order \
	-e tcp.analysis.reused_ports -e tcp.analysis.rto_frame -e tcp.analysis.spurious_retransmission -e tcp.analysis.tfo_syn \
	-e tcp.analysis.window_full -e tcp.analysis.window_update -e tcp.analysis.zero_window -e tcp.analysis.zero_window_probe -e tcp.analysis.zero_window_probe_ack \
	-e tcp.options.wscale.multiplier -e tcp.segment.error \
	-e tls.record.content_type -e tls.handshake.type -e tls.alert_message -e tls.handshake.cert_type.type -e tls.handshake.extensions_server_name -e tls.handshake.extensions_alpn_str -e tls.resumed -e tls.handshake.ciphersuite -e tls.segment.error -e tls.alert_message -e tls.alert_message.desc -e tls.alert_message.level \
	-e x509ce.dNSName \
	-e http.response.code -e http.location -e http.request.full_uri -e http.request.method -e http.request.uri -e http.time -e http.content_length -e http.referer \
	-e _ws.expert.severity \
	-e udp.stream -e udp.dstport -e udp.srcport -e udp.length.bad -e udp.length.bad_zero -e udp.possible_traceroute -e udp.checksum.bad \
	-e dns.flags -e dns.flags.rcode -e dns.flags.response -e dns.time -e dns.count.queries -e dns.qry.name -e dns.resp.ttl \
	> $OUTPUTLOGPATH

	# -e tcp.options.wscale -e tcp.options.wscale_val \

fi

# -Y http.request -T fields -e http.host -e http.user_agent -e ip.dst -e http.request.full_uri

# simple
#-e frame.number -e frame.time_delta -e frame.len -e eth.src -e eth.dst -e frame.protocols \
#-e ip.proto -e ip.src -e ip.dst -e ip.flags -e ip.len \
#-e tcp.stream -e tcp.srcport -e tcp.dstport -e tcp.seq -e tcp.hdr_len -e tcp.ack -e tcp.window_size -e -e tcp.flags
#-e tcp.analysis.<STUFF HERE>

# TCP Flags
# tcp.flags.cwr
# tcp.flags.ecn
# tcp.flags.fin
# tcp.flags.ns
# tcp.flags.push
# tcp.flags.res
# tcp.flags.reset
# tcp.flags.syn
# tcp.flags.urg
# -- tcp.urgent_pointer

# TCP Options
# MSS, QS, SACK, SNACK, TFO, TimeStamp, WindowScaling

# TCP Checksum seems to be disabled

# Use ssl instead of tls
#-e tls.handshake -e tls.handshake.ciphersuite -e tls.alert_message -e tls.alert_message.level -e tls. \

# SSL
# extensions_alpn_str = next protocol usually HTTP1.1
# extensions_server_name = only server name not the full resource URL

# x509ce.dNSName = server name from certificate

# HTTP
# _ws.expert.severity = chat level
# media.type = image/webp but prints all data

# INVALID FIELDS
# -e udp.time_delta -e udp.time_relative
# -e tcp.analysis.push_bytes_sent -e tcp.options.qs.rate
# -e tcp.options.time_stamp -e tcp.options.wscale 