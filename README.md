#!/bin/bash


# Define the input pcap file and output directory

INPUT_PCAP="input.pcap"

OUTPUT_DIR="output_json"


# Create output directory if it doesn't exist

mkdir -p $OUTPUT_DIR


# Run Tshark filters and generate JSON files

echo "Starting Tshark analysis..."


tshark -r $INPUT_PCAP -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" -T json > $OUTPUT_DIR/syn_scan.json

tshark -r $INPUT_PCAP -Y 'ftp.request.command == "STOR" || smb || http.content_length > 100000' -T json > $OUTPUT_DIR/suspicious_transfer.json

tshark -r $INPUT_PCAP -Y 'dns.qry.name matches "[0-9a-z]{10}\.com"' -T json > $OUTPUT_DIR/suspicious_dns.json

tshark -r $INPUT_PCAP -Y 'tcp.len > 1000' -T json > $OUTPUT_DIR/large_transfer.json

tshark -r $INPUT_PCAP -Y 'http contains "password=" || ftp || telnet' -T json > $OUTPUT_DIR/unencrypted_creds.json

tshark -r $INPUT_PCAP -Y 'ip.dst != 192.168.1.0/24' -T json > $OUTPUT_DIR/external_traffic.json

tshark -r $INPUT_PCAP -Y 'icmp' -T json > $OUTPUT_DIR/icmp_traffic.json

tshark -r $INPUT_PCAP -Y 'tls' -T json > $OUTPUT_DIR/encrypted_traffic.json


# JSON analysis

echo "Analyzing JSON files..."


# Check for SYN scan (potential port scan)

SYN_SCAN_IPS=$(jq '.[] | .layers.ip.src' $OUTPUT_DIR/syn_scan.json)

if [[ ! -z "$SYN_SCAN_IPS" ]]; then

    echo "Possible SYN Scan detected from IPs: $SYN_SCAN_IPS" >> $OUTPUT_DIR/alert_log.txt

    echo "Possible SYN Scan detected from IPs: $SYN_SCAN_IPS" | mail -s "SYN Scan Alert" your_email@example.com

fi


# Check for suspicious file transfers (large content length)

LARGE_TRANSFERS=$(jq '.[] | .layers.ip.src, .layers.http.content_length' $OUTPUT_DIR/suspicious_transfer.json)

if [[ ! -z "$LARGE_TRANSFERS" ]]; then

    echo "Suspicious file transfers detected: $LARGE_TRANSFERS" >> $OUTPUT_DIR/alert_log.txt

    echo "Suspicious file transfers detected: $LARGE_TRANSFERS" | mail -s "Suspicious File Transfer Alert" your_email@example.com

fi


# Check for suspicious DNS queries

SUSPICIOUS_DNS=$(jq '.[] | .layers.dns.qry.name' $OUTPUT_DIR/suspicious_dns.json)

if [[ ! -z "$SUSPICIOUS_DNS" ]]; then

    echo "Suspicious DNS queries detected: $SUSPICIOUS_DNS" >> $OUTPUT_DIR/alert_log.txt

    echo "Suspicious DNS queries detected: $SUSPICIOUS_DNS" | mail -s "Suspicious DNS Query Alert" your_email@example.com

fi


# Check for unencrypted credentials

UNENCRYPTED_CREDS=$(jq '.[] | .layers.http' $OUTPUT_DIR/unencrypted_creds.json)

if [[ ! -z "$UNENCRYPTED_CREDS" ]]; then

    echo "Unencrypted credentials detected: $UNENCRYPTED_CREDS" >> $OUTPUT_DIR/alert_log.txt

    echo "Unencrypted credentials detected: $UNENCRYPTED_CREDS" | mail -s "Unencrypted Credentials Alert" your_email@example.com

fi


# Log analysis completion

echo "Analysis complete. Alerts saved in $OUTPUT_DIR/alert_log.txt"


# Optional: Clean up by archiving the files

tar -czf $OUTPUT_DIR/archive_$(date +%F).tar.gz $OUTPUT_DIR/*

