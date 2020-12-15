#!/usr/bin/env bash
#
# Requirement : install tool : ipset
#
# 1) Downloads country ip-nets, blocks the entire country. Why should I ever communicate with China or Russia?
# 
# 2) Download known malcious ip-addresses, adds to a block list
#

countries="
ru
cn
"

firewall-cmd --permanent --direct --remove-rules ipv4 filter INPUT
firewall-cmd --permanent --direct --remove-rules ipv4 filter OUTPUT
firewall-cmd --reload

for country in $countries; do
	echo "Starting block IP segment any traffic from : $country"

	ipset destroy $country
	rm -rf $country.zone

	ipset -N $country hash:net

	wget http://www.ipdeny.com/ipblocks/data/countries/$country.zone
	echo "Number of network segments to block: "$(wc -l $country.zone | awk '{ print $1 }')

	for i in $(cat $country.zone) ; do
		ipset -A $country $i
	done
	rm -rf $country.zone

	firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 -m set --match-set $country src -j DROP 
	firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 1 -m set --match-set $country dst -j DROP 

	firewall-cmd --reload &>/dev/null
done

rm -rf ipsum.txt
wget https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt
ipset -q destroy ipsum
ipset -q create ipsum hash:ip hashsize 262144 maxelem 262144

echo "Starting block known malcious ip-addresses"
echo "Number of malicious ip-addresses : "$(sed '/^#/d' ipsum.txt | wc -l | awk '{ print $1 }')

for malicious_ip in $(sed '/^#/d' ipsum.txt |awk '{ print $1 }'); do
	ipset add ipsum $malicious_ip
done
rm -rf ipsum.txt

firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 -m set --match-set ipsum src -j DROP 
firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 1 -m set --match-set ipsum dst -j DROP
firewall-cmd --reload
