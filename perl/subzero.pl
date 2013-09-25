#!/usr/bin/perl
############################################
##                                        ##
## Sniffer derived from Zero packet genny ##
##                                        ##
############################################
## Fait par TUW
## WC 2013
##
## Win only for now, using pcap
## Do away with Net::Pcap and Net::RawIP

use Net::Pcap;
use Getopt::Long qw(:config bundling);
our $doansi = 0;
my $halp = 0;
our $suppress0800 = 0;
our $suppressetype = 0;
our $timestamp = 0;
our $datatoo = 0;
my $useadapter = 0;
our $regex = "";
our $filter = "";
our $dumphex = 0;
our $filteretype = "";

$nocolour = "1;30";

GetOptions(
	"a" => \$doansi,
	"d" => \$datatoo,
	"h" => \$halp,
	"s" => \$suppress0800,
	"e" => \$suppressetype,
	"t" => \$timestamp,
	"i=i" => \$useadapter,
	"r=s"   => \$regex,
	"f=s"   => \$filter,
	"x"   => \$dumphex,
	"p=s" => \$filteretype
	);
# add option for payload highlighting without payload filtering
if ($halp > 0) {
	print "-a\tANSI color output\n";
	print "-d\tShow payloads\n";
	print "-e\tSupresses common ethertypes:\n\tInternet Protocol Version 4 (0800)\n\tPer-VLAN Spanning Tree Plus (0032 usually)\n\tInternet Protocol Version 6 (86DD)\n\tEthernet Configuration Testing Protocol (9000)\n\tAddress Resolution Protocl (0806)\n\tLink Layer Discovery Protocol (88CC)\n\tCisco Discovery Protocol (006F usually)\n\tEAP over LAN (888E)\n";
	print "-f [s]\tFilter by IPv4 address\n";
	print "-h\tThis cruft\n";
	print "-i [n]\tAdapter number\n";
	print "-p [s]\tFilter by ethertype\n";
	print "-r [s]\tRegex filter and payload highlighting\n";
	print "-s\tSupresses Internet Protocol Version 4 (0800)\n";
	print "-t\tTimestamp\n";
	print "-x\tDump hex payload (requires -d)\n";
	print "\n";
	#for ($g=16;$g<255;$g++) {  ## 256 color xterm test
	#	printf(apx($g) . "[%03d]",$g);
	#	print "\n" unless ($g-15) % 6;
	#}
	#print ap(0);
	exit;
}

print "Running as UID $> at PID $$\n";

my @adpts = Net::Pcap::findalldevs(\$err);
@adpts > 0 or die "No adapters found!\n";
$numadpt = @adpts;

if ($useadapter > 0) {
	$ichooseyou = $useadapter;
}
else {
	for ($inc=0;$inc<$numadpt;$inc++) {
		$dnic = $adpts[$inc];
		Net::Pcap::lookupnet($dnic, \$nip, \$nmask, \$err);
		$thisone = sprintf "%d.%d.%d.%d\/%d.%d.%d.%d",(($nip & 0xFF000000)>>24),(($nip & 0x00FF0000)>>16),(($nip & 0x0000FF00)>>8),($nip & 0x000000FF),(($nmask & 0xFF000000)>>24),(($nmask & 0x00FF0000)>>16),(($nmask & 0x0000FF00)>>8),($nmask & 0x000000FF);
		print "$inc) $thisone\n";
	}
	print "\nSelect Adapter: ";
	$ichooseyou = <>;
	chomp($ichooseyou);
}
useThisNIC($ichooseyou);

$|++;


$stathash = { ## isn't resetting for each call
	"Total" => "0",
	"Proto" => {},
	"Ver" => {}
};

$nic = Net::Pcap::open_live($dnic, 9228, 1, 0, \$err) or die;

printf "-\nListening on $dnic\nIP: %d.%d.%d.%d Mask: %d.%d.%d.%d\n",(($nip & 0xFF000000)>>24),(($nip & 0x00FF0000)>>16),(($nip & 0x0000FF00)>>8),($nip & 0x000000FF),(($nmask & 0xFF000000)>>24),(($nmask & 0x00FF0000)>>16),(($nmask & 0x0000FF00)>>8),($nmask & 0x000000FF);

Net::Pcap::loop($nic, -1, \&printPackets, '');

printf "-\n%d packets received\n", $stathash{"Total"};
foreach my $statproto (keys(%{$stathash{"Proto"}})) {
	printf "%-14s%d\n", $statproto, $stathash{"Proto"}{$statproto};
}
foreach my $statver (keys(%{$stathash{"Ver"}})) {
	printf "%-14s%d\n", "IPv$statver", $stathash{"Ver"}{$statver};
}

sub ap {
	# 0	Reset / Normal	all attributes off
	# 5	Blink: Slow	less than 150 per minute
	# 30–37	Set text color	30 + x, where x is from the color table below
	# 0	1	2	3	4	5	6	7
	# Black	Red	Green	Yellow	Blue	Magenta	Cyan	White
	return $doansi>0?"\033[".shift."m":"";
}

sub apx {
	#return $doansi>0?"\033[38;5;".shift."m":"";
	return "\033[48;5;".shift."m";
	# background would be [48;5;shiftm
}

sub thetime {
	if ($timestamp > 0) {
		return "-----------------[" . ap("1;37") . scalar localtime() . ap($nocolour) . "]-----------------\n";
	}
	else {
		return "-" x 60 . "\n";
	}
}

sub printPackets { ## Parses packets into human readable, crafts response based on pack received, really only cares about TCP right now
	#unless (!ReadKey(-1)) {
	#	Net::Pcap::close($nic);
	#}
	$stathash{"Total"}++;
	my ($zed,$zedhash,$data) = @_; ## zed passed as null from &sniff
	$caplen = $zedhash->{"caplen"};
	my $i = 0;
	#printf "\nCaptured %ld of %ld bytes in packet\n", $caplen, $datalen;
	## NB: 4 byte MAC CRC appended to end of payload, or at least it ought to be
	my($macaddydest,$macaddysrc) = unpack 'H12H12', substr $data, $i;
	#print "MAC SRC $macaddysrc MAC DEST $macaddydest\n";
	$macaddysrc = uc($macaddysrc);
	$macaddydest = uc($macaddydest);
	$checkforbadoui = substr($macaddysrc,1,1);
	if ($checkforbadoui eq "2" || $checkforbadoui eq "6" || $checkforbadoui eq "A" || $checkforbadoui eq "E") {
		print "---------------------------------------------\n";
		print "BAD OUI BAD OUI BAD OUI BAD OUI BAD OUI\n";
		print "MAC SRC $macaddysrc MAC DEST $macaddydest\n";
		print "---------------------------------------------\n";
	}
	$i += 12; ## Jump past MAC addys
	($etherall) = unpack 'H4', substr $data, $i;
	$i += 2; ## skip over ethertype for payload printing
	$etherall = uc($etherall);
	#print "Network Layer Protocol: $etherall";
	$vlan = "";
	while ($etherall eq "8100" || $etherall eq "88A8") { ## found VLAN stuffs, iterate for QinQinQin....
		$vlan .= "Network Layer Protocol: " . ethertype($etherall) . " ";
		($tci,$etherall) = unpack 'B16H4', substr $data, $i;
		($pcp,$dei,$vid) = unpack 'a3a1a12', substr $tci, 0;
		$i += 4; ## skip over ethertype for payload printing
		$vlan .= "Priority Code Point: " . parsehdra($pcp) . " Drop Eligible Indicator: " . parsehdra($dei) . " VLAN Identifier: " . parsehdra($vid) . "\n";
	}
	unless ($etherall eq "0800") {
		return if $filter ne "";
	}
	if ($etherall eq "0800") {
		return if $suppress0800 > 0;
	}
	if ($etherall eq "0800" || $etherall eq "0032" || $etherall eq "86DD" || $etherall eq "9000" || $etherall eq "0806" || $etherall eq "88CC" || $etherall eq "006F" || $etherall eq "888E") { 
		return if $suppressetype > 0;
	}
	if ($filteretype ne "") {
		return unless $filteretype eq $etherall;
	}
	unless ($data =~ /$regex/i) {
		return;
	}
	$macinfo = "";
	$macinfo .= thetime() . ap($nocolour) . "MAC SRC:" . ap("1;32") . $macaddysrc . ap($nocolour) . " MAC DEST:" . ap("1;31") . $macaddydest . ap(0) . "\n";
	print $vlan;
	if (hex($etherall) < 0x05dc) { ## I'm still not 100% certain this is working as intended, but it seems to work
		$macinfo .= ap($nocolour) . "Network Layer Protocol: " . ap("1;35") . $etherall . " IEEE802.3 LLC SAP Frame" . ap(0) . "\n";
	}
	else {
		$macinfo .= ap($nocolour) . "Network Layer Protocol: " . ap("1;35") . ethertype($etherall) . ap(0) . "\n";
	}
	if ($filter eq "") {
		print $macinfo;
	}
	## add recursive vlan checks here, with goto to circle back to the underlying protocols
	if($etherall eq "0800") { ## DIX Ethernet II frame
		$xdrstr = unpack 'B328', substr $data, $i;
		my ($hdripv) = unpack 'a4', substr $xdrstr, 0;
		$stathash{"Ver"}{parsehdra($hdripv)}++;
		if (parsehdra($hdripv) == 4) {
			my ($hdrihl,$hdrtosprec,$hdrtosdel,$hdrtostru,$hdrtosrel,$hdrtosmon,$hdrtosres,$hdrtlen,$hdrid,$hdrresf,$hdrdf,$hdrmf,$hdrfrg,$hdrttl,$hdrpro,$hdrchk,$sclassa,$sclassb,$sclassc,$sclassd,$dclassa,$dclassb,$dclassc,$dclassd) = unpack 'a4a3aaaaaa16a16aaaa13a8a8a16a8a8a8a8a8a8a8a8', substr $xdrstr, 4;
			$srcaddress = (parsehdra($sclassa) . "." . parsehdra($sclassb) . "." .  parsehdra($sclassc) . "." . parsehdra($sclassd));
			$dstaddress = (parsehdra($dclassa) . "." . parsehdra($dclassb) . "." . parsehdra($dclassc) . "." . parsehdra($dclassd));
			if ($filter ne "") {
				unless ($filter eq $srcaddress || $filter eq $dstaddress) {
					return;
				}
				else {
					print $macinfo;
				}
			}
			$stathash{"Proto"}{datapro(parsehdra($hdrpro))}++;
			print ap($nocolour), "IPV: ", ap("1;37"), parsehdra($hdripv), " ", dataipv(parsehdra($hdripv)), ap($nocolour), " IHL: ", ap("1;37"), parsehdra($hdrihl), ap($nocolour), " ID: ", ap("1;37"), parsehdra($hdrid), ap($nocolour), " DF: ", ap("1;37"), $hdrdf, ap($nocolour), " MF: ", ap("1;37"), $hdrmf, ap($nocolour), " TTL: " , ap("1;37"), parsehdra($hdrttl), ap($nocolour), " Protocol: " , ap("1;37"), parsehdra($hdrpro), " ", datapro(parsehdra($hdrpro)), ap(0), "\n";
			printf ap($nocolour) . "%-13s" . ap("0;32") . "%-15s" . ap($nocolour) . "%-16s" . ap("0;31") . "%-15s" . ap(0) . "\n", "Src Address: ", $srcaddress , "  Dest Address: ", $dstaddress;
			$xdroffset = parsehdra($hdrihl);
			$xdroffset *= 32;
			if ($hdrihl eq "0101") {
				#$hdroptions = "none";
			}
			#else {
			#	$hdroptionbits = parsehdra($hdrihl);
			#	$hdroptionbits -= 5;
			#	$hdroptionbits *= 32;
			#	my ($hdroptions) = unpack "a$hdroptionbits", substr $xdrstr, $xdroffset;
			#	$xdroffset += $hdroptionbits;
			#}
			$i += 20; ## we found an ip header and ipv4 which we printed, but we didnt find tcp, so increase beyond the ip header and print the rest as payload
			if (parsehdra($hdrpro) == 6) { # TCP
				my ($tdrsrc,$tdrdst,$tdrseq,$tdrack,$tdroff,$tdrsixres,$tdrflagurg,$tdrflagack,$tdrflagpsh,$tdrflagrst,$tdrflagsyn,$tdrflagfin,$tdrwin,$tdrchk,$tdrurg) = unpack 'a16a16a32a32a4a6aaaaaaa16a16a16', substr $xdrstr, $xdroffset;
				printf ap($nocolour) . "%-13s" . ap("0;32") . "%-15s" . ap($nocolour) . "%-16s" . ap("0;31") . "%-15s" . ap(0) . "\n", "Src Port: ", parsehdra($tdrsrc), "  Dest Port: ", parsehdra($tdrdst);
				printf ap($nocolour) . "%-13s" . ap("1;37") . "%-15s" . ap($nocolour) . "%-16s" . ap("1;37") . "%-15s" . ap(0) . "\n", "Seq: ", parsehdra($tdrseq), "  Ack: ", parsehdra($tdrack);
				printf ap($nocolour) . "%-13s" . ap("1;37") . "%-15s" . ap($nocolour) . "%-16s", "Window: ", parsehdra($tdrwin), "  Flags: ";
				$tdrflagurg ? print ap("1;37") . "URG " : eval(1);
				$tdrflagack ? print ap("0;32") . "ACK " : eval(1);
				$tdrflagpsh ? print ap("1;33") . "PSH " : eval(1);
				$tdrflagrst ? print ap("1;31") . "RST " : eval(1);
				$tdrflagsyn ? print ap("1;32") . "SYN " : eval(1);
				$tdrflagfin ? print ap("1;31") . "FIN " : eval(1);
				print ap(0) . "\n";
				$ldest = (parsehdra($dclassa) . "." . parsehdra($dclassb) . "." . parsehdra($dclassc) . "." . parsehdra($dclassd));
				$listenport = parsehdra($tdrdst);
				$i += 20;  ## we found a tcp header, so skip past 20 bytes for the purpose of payload printing
				if ($ldest eq "127.0.0.1" && $listenport == "2345" && $tdrflagsyn == "1") { ####### Test for crafting responses ####### Test for crafting responses #######
					print "\n\nPACKET\n";
					@listensrc = (chr(parsehdra($sclassa)),chr(parsehdra($sclassb)),chr(parsehdra($sclassc)),chr(parsehdra($sclassd)));
					@listendest = (chr(parsehdra($dclassa)),chr(parsehdra($dclassb)),chr(parsehdra($dclassc)),chr(parsehdra($dclassd)));
					$finalsrc = join('',@listendest); ## SOURCE IP
					$finaldest = join('',@listensrc); ## DEST IP
					my($macbindest,$macbinsrc) = unpack 'B48B48', substr $data, $i; ## should be old var $offset instead of $i, but getting rid of offset, so fix this later
					@newmacdest = unpack 'a8a8a8a8a8a8', $macbindest; ## DEST MAC ####
					$finalmacdest = "";                                              #
					foreach my $mdbyte (@newmacdest) {                               #
						$finalmacdest .= chr(parsehdra($mdbyte));                    ############## MAC ADDYS STILL UNTESTED #################
					}                                                                #
					@newmacsrc = unpack 'a8a8a8a8a8a8', $macbinsrc; ## SOURCE MAC ####
					$finalmacsrc = "";
					foreach my $msbyte (@newmacsrc) {
						$finalmacsrc .= chr(parsehdra($msbyte));
					}
					@mdports = unpack('a8a8', $tdrsrc); ## DEST PORT
					$finaldport = "";
					foreach my $msdport (@mdports) {
						$finaldport .= chr(parsehdra($msdport));
					}
					@msports = unpack('a8a8', $tdrdst); ## SOURCE PORT
					$finalsport = "";
					foreach my $mssport (@msports) {
						$finalsport .= chr(parsehdra($mssport));
					}
					@ackall = unpack('a8a8a8a8', $tdrseq); ## ACKNOWLEDGEMENT
					$finalack = "";
					foreach my $mfack (@ackall) {
						$finalack .= chr(parsehdra($mfack));
					}
					@fuckwindow = unpack('a8a8', $tdrwin); ## WINDOW
					$finalwin = "";
					foreach my $fuckwin (@fuckwindow) {
						$finalwin .= chr(parsehdra($fuckwin));
					}
					$finalttl = chr(parsehdra($hdrttl)); ## TTL
					#################### NEED TO CALC IP AND TCP CHECKSUMS ##########################
					$initamk = "\x45\x00\x00\x28\x69\x69\x40\x00" . $finalttl . "\x06\x00\x00" . $finalsrc . $finaldest;
					@amkcheck = pack('H8H8H8H8H8', $initamk); ## IP CHECKSUM		    $amkcheck[0] = $amkcheck[0] & 0xFFFF0000000000000000>>16;		    $amkcheck[1] = $amkcheck[1] & 0x0000FFFF000000000000>>12;
					print "\nMy values are ";
					foreach my $zenzed (@amkcheck) {
						print "-" . unpack('H8',$zenzed) . "-\n"
					}
					$amkcummulator = "";
					foreach my $SweetJesusLordNo (@amkcheck) {
						$amkcummulator += $SweetJesusLordNo;
						print "Cummulator at $amkcummulator\n";
					}
					$amkcummulatormod = $amkcummulator>>20;
					print "Mod is $amkcummulatormod\n";
					$amkcummulator += $amkcummulatormod;
					print "Resulting cummulator is $amkcummulator\n";
					$amkcummulator &= 0xFFFF;
					print "Resulting checksum is $amkcummulator\n";
					#       /----\MAC Header/--------------\                                                IP Header                               /-\                                         TCP Header                                                     /---\      Data       /------\
					$msoyeah   =   "\x08\x00" .              "\x45\x00\x00\x28\x69\x69\x40\x00" . $finalttl . "\x06\xF7\x3F" . $finalsrc . $finaldest . $finalsport . $finaldport . "\xB1\xAE\xCA\x5A" . $finalack . "\x50\x12" . $finalwin . "\x25\x28\x00\x00"  .  scalar localtime();#    |
					#       |      |------/                    ||  |----/  |/  |----/  |----/    |-------/      |/  |----/    |-------/|-----------/   |---------/   |---------/      |------------/    |-------/      ||  |/    |-------/      |----/  |----/                              |
					#       |      \Ethertype: TCP/IP          ||  |       |   |       |         |              |   |         |        \Dest IP        |             |                |                 |              ||  |     |              |       \Urgent Pointer: 0                  |
					#       |                                  ||  |       |   |       |         |              |   |         \Source IP               |             |                |                 |              ||  |     |              \TCP Checksum: 2528                         |
					#       |                                  ||  |       |   |       |         |              |   \IP Checksum: F73F                 |             |                |                 |              ||  |     \Window Size                                               |
					#       |                                  ||  |       |   |       |         |              \Protocol: TCP                         |             |                |                 |              ||  \Flags: Syn(2) Ack(16)                                           |
					#       |                                  ||  |       |   |       |         \TTL: 64                                              |             |                |                 |              |\Reserved                                                           |
					#       |                                  ||  |       |   |       \Frag Bits and Offset: Dont Frag                                |             |                |                 |              \Header Length: 5 words (20 bytes)                                   |
					#       |                                  ||  |       |   \ID: 26985                                                              |             |                |                 \Ack Number: 0                                                                      |
					#       |                                  ||  |       \Datagram Length: 40 bytes                                                  |             |                \Seq Number: 2981022298                                                                               |
					#       |                                  ||  \TOS Bits: None                                                                     |             \Dest Port                                                                                                             |
					#       |                                  |\Header Length: 5 words (20 bytes)                                                     \Source Port                                                                                                                         |
					#       |                                  \IP Version: 4                                                                                                                                                                                                               |
					#       \---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------/
					# x02\x04\x40\x0c\x04\x02\x08\x0a". "\x00\x99\x21\x73\x00\x00\x00\x00\x01\x03\x03\x00 OPTIONS
					print "MAC SRC " . unpack('B*', $finalmacsrc) . "\n";
					print "MAC DEST " . unpack('B*', $finalmacdest) . "\n";
					print "IP SRC " . unpack('B*', $finalsrc) . "\n";
					print "IP DEST " . unpack('B*', $finaldest) . "\n";
					print "PORT SRC " . unpack('B*', $finalsport) . "\n";
					print "PORT DEST " . unpack('B*', $finaldport) . "\n";
					print "ACK " . unpack('B*', $finalack) . " and ORIG SEQ " . $tdrseq . "\n";
					$msoy = new Net::RawIP({generic =>{}});
					$msoy->ethnew($dnic, source => $finalmacsrc, dest => $finalmacdest);
					$msuccess = $msoy->send_eth_frame($msoyeah,0);
					print "Reply Sent\n\n" if $msuccess;
					print "Reply Failed\n\n" unless $msuccess;
				}
			}
			elsif (parsehdra($hdrpro) == 112) { #VRRP
				my ($tdrver,$tdrtype,$tdrvid,$tdrpri,$tdrcount,$tdratype,$tdrint,$tdrchk) = unpack 'a4a4a8a8a8a8a8a16', substr $xdrstr, $xdroffset;
				print ap($nocolour), "Version: ", ap("1;37"), parsehdra($tdrver), ap($nocolour), " Type: ", ap("1;37"), parsehdra($tdrtype), ap($nocolour), " VirtRtrID: ", ap("1;37"), parsehdra($tdrvid), ap($nocolour), " Pri: ", ap("1;37"), parsehdra($tdrpri), ap($nocolour), " IPCount: ", ap("1;37"), parsehdra($tdrcount), ap($nocolour), "\nAuth Type: ", ap("1;37"), parsehdra($tdratype), ap($nocolour), " Interval: ", ap("1;37"), parsehdra($tdrint), ap($nocolour), " Checksum: ", ap("1;37"), parsehdra($tdrchk), ap(0), "\n";
				$i += 8; ## we found a vrrp header, so skip past 8 bytes for the purpose of payload printing
			}
			elsif (parsehdra($hdrpro) == 17) { #UDP
				my ($udpsport,$udpdport,$udplen,$udpchecksum) = unpack 'a16a16a16a16', substr $xdrstr, $xdroffset;
				print ap($nocolour), "Src Port: ", ap("0;32"), parsehdra($udpsport), ap($nocolour), " Dest Port: ", ap("0;31"), parsehdra($udpdport), ap($nocolour), " Length: ", ap("1;37"), parsehdra($udplen), ap($nocolour), " Chksum: ", ap("1;37"), parsehdra($udpchecksum), ap(0), "\n";
				$i += 8; ## we found a udp header, so skip past 8 bytes for the purpose of payload printing
			}
		}
	}
	elsif (hex($etherall) < 0x05dc) { ## 802.3 LLC SAP Header  http://tools.ietf.org/html/rfc5342
		#$llclen = parsehdra($etherall);
		$llclen = $etherall;
		$xdrstr = unpack 'H*', substr $data, $i;
		my ($llcdsap,$llcssap,$llcctrl) = unpack 'a2a2a2', substr $xdrstr, 0;
		$llcdsap = uc($llcdsap);
		$llcssap = uc($llcssap);
		$llcctrl = uc($llcctrl);
		print ap($nocolour) . "Length: " . ap("1;37") . $llclen . ap($nocolour) . " DSAP: " . ap("1;37") . $llcdsap . ap($nocolour) . " SSAP: " . ap("1;37") . $llcssap . ap($nocolour) . " CTRL: " . ap("1;37") . $llcctrl . ap(0) . "\n";
		$i += 3;
		if (($llcdsap eq "AA" || $llcdsap eq "AB")&&($llcssap eq "AA" || $llcssap eq "AB")&&($llcctrl eq "03")) { ## then SNAP extension
			print ap($nocolour) . "Subnetwork Access Protocol (SNAP)" , ap(0) . "\n";
			$snaploop = 1;
			while ($snaploop) { ## OUI Extended Ethertype to zeros OUI loop
				my ($llcsnapoui,$llcsnaptype) = unpack 'a6a4', substr $xdrstr, (1 + ($snaploop * 5));
				$llcsnapoui = uc($llcsnapoui);
				$llcsnaptype = uc($llcsnaptype);
				if ($llcsnapoui eq "000000") {
					if ($llcsnaptype eq "88B7") {
						$snaploop++;
					}
					else {
						$snaploop = 0;
					}
					print ap($nocolour) . ($snaploop?"Extended ":"") . "OUI: " . ap("1;37") . $llcsnapoui . ap($nocolour) . ($snaploop?"Extended":"") . " Ethertype: " . ap("1;37") . ethertype($llcsnaptype) . ap(0) . "\n";
				}
				else {
					$snaploop = 0;
					print ap($nocolour) . "OUI: " . ap("1;37") . $llcsnapoui . ap($nocolour) . " PID: " . ap("1;37") . snappid($llcsnaptype) . ap(0) . "\n";
				}
				$i += 5;
			}
		}
		else {
			## print some shit here having to do with whatever SAP stuff does
		}
	}

	## Payload
	if ($datatoo > 0) {
		my %highlightpayload;
		$ndata = substr $data, $i;
		while ($ndata =~ /$regex/ig) {
			$highlightpayload[1]{$-[0]}++;
			$highlightpayload[0]{$+[0]}++;
		}
		$thischar = 0;
		$hexchar = 0;
		$hexhighlight = "1;36";
		$currenthighlight = "1;33";
		$payloadOutputLength = ($dumphex > 0?12:60);
		until ($i>=$caplen) {
			#local $,=' ';
			my $lg = substr $data, $i, $payloadOutputLength;
			$i+=$payloadOutputLength;
			if ($dumphex > 0) {
				printf ap("1;34") . "%.8X  ", $i;
				foreach my $hexuchar (split('',$lg)) {
					if (exists $highlightpayload[1]{$hexchar}) {
						$hexhighlight = "1;37";
						print ap($hexhighlight);
					}
					elsif (exists $highlightpayload[0]{$hexchar}) {
						$hexhighlight = "1;36";
						print ap($hexhighlight);
					}
					elsif (($hexchar % $payloadOutputLength) == 0) {
						print ap($hexhighlight);
					}
					print unpack ('H2', $hexuchar) . " ";
					$hexchar++;
				}
				print ap($nocolour) . ('   'x($payloadOutputLength-(length $lg)));
			}
			#print unpack ('H2'x$payloadOutputLength, $lg), '  'x($payloadOutputLength-length $lg) if $dumphex > 0;
			$lg =~ s/[\x00-\x1F\xFF]/./g;
			foreach my $uchar (split('',$lg)) {
				if (exists $highlightpayload[1]{$thischar}) {
					$currenthighlight = "1;34";
					print ap($currenthighlight);
				}
				elsif (exists $highlightpayload[0]{$thischar}) {
					$currenthighlight = "1;33";
					print ap($currenthighlight);
				}
				elsif (($thischar % $payloadOutputLength) == 0) {
					print ap($currenthighlight);
				}
				print $uchar;
				$thischar++;
			}
			print ap(0) . "\n";
		}
		undef $highlightpayload[0]; ## it seems to be necessary that you undefine these anonymous arrays or else they dont go away when this hash gets un-my'd
		undef $highlightpayload[1];
	}
}

sub useThisNIC {
	my ($useNIC) = @_;
	$dnic = $adpts[$useNIC];
	Net::Pcap::lookupnet($dnic, \$nip, \$nmask, \$err);
}

sub parsehdra { ## bin2dec 32 bit max subroutine
	return unpack("N", pack("B32", substr("0" x 32 . shift, -32)));
}

sub dataipv { ## Returns version names from numbers
	my ($ipvcomp) = @_;
	@suparIPv = ("Reserved", "Unassigned", "Unassigned", "Unassigned", "IP", "ST", "SIP, SIPP, IPv6", "TP/IX", "PIP", "TUBA", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Reserved");
	if ($ipvcomp >= 0 && $ipvcomp <= 15) {
		return $suparIPv[$ipvcomp];
	}
	else { return "Error in sub(dataipv) [$ipvcomp]"; }
}

sub datatosprec { ## Returns precedence names from numbers
	my ($tospreccomp) = @_;
	@suparTosPrec = ("Routine", "Priority", "Immediate", "Flash", "Flash Override", "CRITIC/ECP", "Internetwork Control", "Network Control");
	if ($tospreccomp >= 0 && $tospreccomp <= 7) {
		return $suparTosPrec[$tospreccomp];
	}
	else { return "Error in sub(datatosprec) [$tospreccomp]"; }
}

sub datapro { ## Returns protocol names from numbers
	my ($procomp) = @_;
	@suparProto = ("IPv6 Hop-by-Hop Option", "ICMP", "IGMP, RGMP", "GGP", "IP in IP Encapsulation", "ST", "TCP", "UCL, CBT", "EGP", "IGRP", "BBN RCC Monitoring", "NVP", "PUP", "ARGUS", "EMCON", "XNET", "Chaos", "UDP", "TMux", "DCN Measurement Subsystems", "HMP", "Packet Radio Measurement", "XEROX NS IDP", "Trunk-1", "Trunk-2", "Leaf-1", "Leaf-2", "RDP", "IRTP", "ISO Transport Protocol Class 4", "NETBLT", "MFE Network Services Protocol", "MERIT Internodal Protocol", "Sequential Exchange Protocol", "Third Party Connect Protocol", "IDPR", "XTP", "Datagram Delivery Protocol", "IDPR", "TP++ Transport Protocol", "IL Transport Protocol", "IPv6 over IPv4", "SDRP", "IPv6 Routing Header", "IPv6 Fragment Header", "IDRP", "RSVP", "GRE", "MHRP", "BNA", "ESP", "AH", "Integrated Net Layer Security TUBA", "IP with Encryption", "NARP", "Minimal Encapsulation Protocol", "TLSP", "SKIP", "ICMPv6, MLD", "IPv6 No Next Header", "Destination Options for IPv6", "Any host internal protocol", "CFTP", "Any local network", "SATNET, Backroom EXPAK", "Kryptolan", "MIT Remote Virtual Disk Protocol", "Internet Pluribus Packet Core", "Any distributed file system", "SATNET Monitoring", "VISA Protocol", "Internet Packet Core Utility", "Computer Protocol Network Executive", "Computer Protocol Heart Beat", "Wang Span Network", "Packet Video Protocol", "Backroom SATNET Monitoring", "SUN ND PROTOCOL-Temporary", "WIDEBAND Monitoring", "WIDEBAND EXPAK", "ISO Internet Protocol", "VMTP", "SECURE-VMTP", "VINES", "TTP", "NSFNET-IGP", "Dissimilar Gateway Protocol", "TCF", "EIGRP", "OSPF, MOSPF", "Sprite RPC Protocol", "Locus Address Resolution Protocol", "MTP", "AX.25 Frames", "IP-within-IP Encapsulation Protocol", "Mobile internetworking Control Protocol", "Semaphore Communications Sec. Pro", "Ethernet-within-IP Encapsulation", "Encapsulation Header", "Any private encryption scheme", "GMTP", "IFMP", "PNNI over IP", "PIM", "ARIS", "SCPS", "QNX", "Active Networks", "IPPCP", "SNP", "Compaq Peer Protocol", "IPX in IP", "VRRP", "PGM", "Any 0-hop protocol", "L2TP", "DDX", "IATP", "ST", "SRP", "UTI", "SMP", "SM", "PTP", "ISIS over IPv4", "FIRE", "CRTP", "CRUDP", "SSCOPMCE", "IPLT", "SPS", "PIPE", "SCTP", "Fibre Channel", "RSVP-E2E-IGNORE");
	if ($procomp >= 0 && $procomp <= 133) {
		return $suparProto[$procomp];
	}
	if ($procomp > 134 && $procomp < 255) { return "Unassigned"; }
	if ($procomp == 255) { return "Reserved"; }
	else { return "Error in sub(datapro) [$procomp]"; }
}

sub ethertype { ## Returns ethertypes from numbers IPV4, PVSTP+, IPV6, ECTP, ARP, LLDP, 006F
	my ($ethercomp) = shift;
	%suparEther = (
		'0600', 'Xerox NS IDP',
		'0601', 'XNS Address Translation',
		'0800', 'Internet Protocol Version 4 (IPv4)',
		'0801', 'X.75 Internet',
		'0802', 'Cisco Discovery Protocol, VLAN Trunking Protocol, NBS Internet, or Spanning Tree Protocol',
		'0803', 'ECMA Internet',
		'0804', 'CHAOSnet',
		'0805', 'X.25 Level 3',
		'0806', 'Address Resolution Protocol (ARP)',
		'0807', 'XNS Compatibility',
		'0808', 'RFC1701 (GRE)',
		'081C', 'Symbolics Private',
		'0842', 'Wake-on-LAN',
		'0888', 'Xyplex',
		'0889', 'Xyplex',
		'088A', 'Xyplex',
		'0900', 'Ungermann-Bass Network Debugger',
		'0A00', 'Xerox IEEE802.3 PUP',
		'0A01', 'Xerox IEEE802.3 PUP Address Translation',
		'0BAD', 'Banyan Systems',
		'0BAF', 'Banyon VINES Echo',
		'1000', 'Berkeley Trailer Negotiation',
		'1001', 'Berkeley Trailer Encapsulation for IP',
		'1002', 'Berkeley Trailer Encapsulation for IP',
		'1003', 'Berkeley Trailer Encapsulation for IP',
		'1004', 'Berkeley Trailer Encapsulation for IP',
		'1005', 'Berkeley Trailer Encapsulation for IP',
		'1006', 'Berkeley Trailer Encapsulation for IP',
		'1007', 'Berkeley Trailer Encapsulation for IP',
		'1008', 'Berkeley Trailer Encapsulation for IP',
		'1009', 'Berkeley Trailer Encapsulation for IP',
		'100A', 'Berkeley Trailer Encapsulation for IP',
		'100B', 'Berkeley Trailer Encapsulation for IP',
		'100C', 'Berkeley Trailer Encapsulation for IP',
		'100D', 'Berkeley Trailer Encapsulation for IP',
		'100E', 'Berkeley Trailer Encapsulation for IP',
		'100F', 'Berkeley Trailer Encapsulation for IP',
		'1234', 'DCA - Multicast',
		'1600', 'VALID System Protocol',
		'1989', 'Artificial Horizons ("Aviator" Dogfight Simulator)',
		'1995', 'Datapoint Corporation (RCL LAN Protocol)',
		'22F3', 'IETF TRILL Protocol',
		'3C00', '3Com NBP Virtual Circuit Datagram (Like XNS SPP)',
		'3C01', '3Com NBP System Control Datagram',
		'3C02', '3Com NBP Connect Request (Virtual CCT)',
		'3C03', '3Com NBP Connect Repsonse',
		'3C04', '3Com NBP Connect Complete',
		'3C05', '3Com NBP Close Request (Virtual CCT)',
		'3C06', '3Com NBP Close Response',
		'3C07', '3Com NBP Datagram (Like XNS IDP)',
		'3C08', '3Com NBP Datagram Broadcast',
		'3C09', '3Com NBP Claim NetBIOS Name',
		'3C0A', '3Com NBP Delete Netbios Name',
		'3C0B', '3Com NBP Remote Adaptor Status Request',
		'3C0C', '3Com NBP Remote Adaptor Response',
		'3C0D', '3Com NBP Reset',
		'4242', 'PCS Basic Block Protocol',
		'424C', 'Information Modes Little Big LAN Diagnostic',
		'4321', 'THD - Diddle',
		'4C42', 'Information Modes Little Big LAN',
		'5208', 'BBN Simnet Private',
		'6000', 'DEC unassigned, Experimental',
		'6001', 'DEC Maintenance Operation Protocol (MOP) Dump/Load Assistance',
		'6002', 'DEC Maintenance Operation Protocol (MOP) Remote Console',
		'6003', 'DECNET Phase IV, DNA Routing',
		'6004', 'DEC Local Area Transport (LAT)',
		'6005', 'DEC Diagnostic Protocol',
		'6006', 'DEC Customer Protocol',
		'6007', 'DEC Local Area VAX Cluster (LAVC), System Communication Architecture (SCA)',
		'6008', 'DEC AMBER',
		'6009', 'DEC MUMPS',
		'6010', '3Com Corporation',
		'6011', '3Com Corporation',
		'6012', '3Com Corporation',
		'6013', '3Com Corporation',
		'6014', '3Com Corporation',
		'7000', 'Ungermann-Bass Download',
		'7001', 'Ungermann-Bass NIUs',
		'7002', 'Ungermann-Bass Diagnostic/Loopback',
		'7003', 'Ungermann-Bass (NMC To/From UB Bridge)',
		'7005', 'Ungermann-Bass Bridge Spanning Tree',
		'7007', 'OS/9 Microware',
		'7009', 'OS/9 Net',
		'7020', 'LRT (England) (Now Sintrom)',
		'7021', 'LRT (England) (Now Sintrom)',
		'7022', 'LRT (England) (Now Sintrom)',
		'7023', 'LRT (England) (Now Sintrom)',
		'7024', 'LRT (England) (Now Sintrom)',
		'7025', 'LRT (England) (Now Sintrom)',
		'7026', 'LRT (England) (Now Sintrom)',
		'7027', 'LRT (England) (Now Sintrom)',
		'7028', 'LRT (England) (Now Sintrom)',
		'7029', 'LRT (England) (Now Sintrom)',
		'7030', 'Racal-Interlan',
		'7031', 'Prime NTS (Network Terminal Service)',
		'7034', 'Cabletron',
		'8003', 'Cronus VLN',
		'8004', 'Cronus Direct',
		'8005', 'HP Probe protocol',
		'8006', 'Nestar',
		'8008', 'AT&T/Stanford Univ. Local Use',
		'8010', 'Excelan',
		'8013', 'Silicon Graphics Diagnostic',
		'8014', 'Silicon Graphics Network Games',
		'8015', 'Silicon Graphics Reserved',
		'8016', 'Silicon Graphics XNS NameServer, Bounce Server',
		'8019', 'Apollo DOMAIN',
		'802E', 'Tymshare',
		'802F', 'Tigan, Inc.',
		'8035', 'Reverse Address Resolution Protocol (RARP)',
		'8036', 'Aeonic Systems',
		'8037', 'IPX (Novell Netware)',
		'8038', 'DEC LanBridge Management',
		'8039', 'DEC DSM/DDP',
		'803A', 'DEC Argonaut Console',
		'803B', 'DEC VAXELN',
		'803C', 'DEC DNS Naming Service',
		'803D', 'DEC Ethernet CSMA/CD Encryption Protocol',
		'803E', 'DEC Distributed Time Service',
		'803F', 'DEC LAN Traffic Monitor Protocol',
		'8040', 'DEC PATHWORKS DECnet NETBIOS Emulation',
		'8041', 'DEC Local Area System Transport',
		'8042', 'DEC Unassigned',
		'8044', 'Planning Research Corp.',
		'8046', 'AT&T',
		'8047', 'AT&T',
		'8048', 'DEC Availability Manager for Distributed Systems DECamds',
		'8049', 'ExperData',
		'805B', 'VMTP (Versatile Message Transaction Protocol, RFC-1045) (Stanford) (Was Stanford V Kernel, Experimental)',
		'805C', 'Stanford V Kernel, Version 6.0',
		'805D', 'Evans & Sutherland',
		'8060', 'Little Machines',
		'8062', 'Counterpoint Computers',
		'8065', 'University of Mass. at Amherst',
		'8066', 'University of Mass. at Amherst',
		'8067', 'Veeco Integrated Automation',
		'8068', 'General Dynamics',
		'8069', 'AT&T',
		'806A', 'Autophon',
		'806C', 'ComDesign',
		'806D', 'Compugraphic Corporation',
		'806E', 'Landmark Graphics Corporation',
		'806F', 'Landmark Graphics Corporation',
		'8070', 'Landmark Graphics Corporation',
		'8071', 'Landmark Graphics Corporation',
		'8072', 'Landmark Graphics Corporation',
		'8073', 'Landmark Graphics Corporation',
		'8074', 'Landmark Graphics Corporation',
		'8075', 'Landmark Graphics Corporation',
		'8076', 'Landmark Graphics Corporation',
		'8077', 'Landmark Graphics Corporation',
		'807A', 'Matra',
		'807B', 'Dansk Data Elektronik',
		'807C', 'Merit Internodal (or University of Michigan)',
		'807D', 'Vitalink Communications',
		'807E', 'Vitalink Communications',
		'807F', 'Vitalink Communications',
		'8080', 'Vitalink TransLAN III Management',
		'8081', 'Counterpoint Computers',
		'8082', 'Counterpoint Computers',
		'8083', 'Counterpoint Computers',
		'8088', 'Xyplex',
		'8089', 'Xyplex',
		'808A', 'Xyplex',
		'809B', 'EtherTalk (AppleTalk over Ethernet)',
		'809C', 'Datability',
		'809D', 'Datability',
		'809E', 'Datability',
		'809F', 'Spider Systems Ltd.',
		'80A3', 'Nixdorf Computers',
		'80A4', 'Siemens Gammasonics Inc.',
		'80A5', 'Siemens Gammasonics Inc.',
		'80A6', 'Siemens Gammasonics Inc.',
		'80A7', 'Siemens Gammasonics Inc.',
		'80A8', 'Siemens Gammasonics Inc.',
		'80A9', 'Siemens Gammasonics Inc.',
		'80AA', 'Siemens Gammasonics Inc.',
		'80AB', 'Siemens Gammasonics Inc.',
		'80AC', 'Siemens Gammasonics Inc.',
		'80AD', 'Siemens Gammasonics Inc.',
		'80AE', 'Siemens Gammasonics Inc.',
		'80AF', 'Siemens Gammasonics Inc.',
		'80B0', 'Siemens Gammasonics Inc.',
		'80B1', 'Siemens Gammasonics Inc.',
		'80B2', 'Siemens Gammasonics Inc.',
		'80B3', 'Siemens Gammasonics Inc.',
		'80C0', 'DCA (Digital Comm. Assoc.) Data Exchange Cluster',
		'80C1', 'DCA (Digital Comm. Assoc.) Data Exchange Cluster',
		'80C2', 'DCA (Digital Comm. Assoc.) Data Exchange Cluster',
		'80C3', 'DCA (Digital Comm. Assoc.) Data Exchange Cluster',
		'80C6', 'Pacer Software',
		'80C7', 'Applitek Corporation',
		'80C8', 'Intergraph Corporation',
		'80C9', 'Intergraph Corporation',
		'80CA', 'Intergraph Corporation',
		'80CB', 'Intergraph Corporation',
		'80CC', 'Intergraph Corporation',
		'80CD', 'Harris Corporation',
		'80CE', 'Harris Corporation',
		'80CF', 'Taylor Instrument',
		'80D0', 'Taylor Instrument',
		'80D1', 'Taylor Instrument',
		'80D2', 'Taylor Instrument',
		'80D3', 'Rosemount Corporation',
		'80D4', 'Rosemount Corporation',
		'80D5', 'IBM SNA Services Over Ethernet',
		'80DD', 'Varian Associates',
		'80DE', 'TRFS (Integrated Solutions Transparent Remote File System)',
		'80DF', 'TRFS (Integrated Solutions Transparent Remote File System)',
		'80E0', 'Allen-Bradley',
		'80E1', 'Allen-Bradley',
		'80E2', 'Allen-Bradley',
		'80E3', 'Allen-Bradley',
		'80E4', 'Datability',
		'80E5', 'Datability',
		'80E6', 'Datability',
		'80E7', 'Datability',
		'80E8', 'Datability',
		'80E9', 'Datability',
		'80EA', 'Datability',
		'80EB', 'Datability',
		'80EC', 'Datability',
		'80ED', 'Datability',
		'80EE', 'Datability',
		'80EF', 'Datability',
		'80F0', 'Datability',
		'80F2', 'Retix',
		'80F3', 'AppleTalk Address Resolution Protocol (AARP)',
		'80F4', 'Kinetics',
		'80F5', 'Kinetics',
		'80F7', 'Apollo Computer',
		'80FF', 'Wellfleet Communications',
		'8100', 'Wellfleet Communications',
		'8101', 'Wellfleet Communications',
		'8100', 'VLAN-tagged frame (IEEE 802.1Q) & Shortest Path Bridging IEEE 802.1aq',
		'8102', 'Wellfleet; BOFL (Breath Of Life) Packets',
		'8103', 'Wellfleet Communications',
		'8107', 'Symbolics Private',
		'8108', 'Symbolics Private',
		'8109', 'Symbolics Private',
		'812B', 'Talaris',
		'8130', 'Waterloo Microsystems Inc.',
		'8131', 'VG Laboratory Systems',
		'8137', 'Novell (Old) NetWare IPX (ECONFIG E option)',
		'8138', 'Novell, Inc. IPX',
		'8139', 'KTI',
		'813A', 'KTI',
		'813B', 'KTI',
		'813C', 'KTI',
		'813D', 'KTI',
		'813F', 'M/MUMPS Data Sharing',
		'8145', 'Vrije Universiteit (NL) Amoeba 4 RPC (Obsolete)',
		'8146', 'Vrije Universiteit (NL) FLIP (Fast Local Internet Protocol)',
		'8147', 'Vrije Universiteit (NL) (Reserved)',
		'814C', 'SNMP over Ethernet (RFC1089)',
		'814F', 'Technically Elite Concepts Network Professor',
		'8191', 'PowerLAN NetBIOS/NetBEUI (PC)',
		'817D', 'XTP',
		'81D6', 'Artisoft Lantastic',
		'81D7', 'Artisoft Lantastic',
		'8203', 'QNX Software Systems Ltd. Qnet',
		'8204', 'QNX Software Systems Ltd. Qnet',
		'8205', 'QNX Software Systems Ltd. Qnet',
		'8390', 'Accton Technologies',
		'852B', 'Talaris Multicast',
		'8582', 'Kalpana',
		'86DD', 'Internet Protocol Version 6 (IPv6)',
		'8739', 'Control Technology Inc. RDP Without IP',
		'873A', 'Control Technology Inc. Mcast Industrial Ctrl Protocol',
		'873B', 'Control Technology Inc. Proprietary',
		'873C', 'Control Technology Inc. Proprietary',
		'8808', 'Ethernet Flow Control',
		'8809', 'Ethernet OAM Protocol IEEE 802.3ah (Slow Protocols)',
		'8819', 'CobraNet',
		'8820', 'Hitachi Cable (Optoelectronic Systems Laboratory)',
		'8847', 'MPLS Unicast',
		'8848', 'MPLS Multicast',
		'8856', 'Axis Communications AB Proprietary Bootstrap/Config',
		'8863', 'PPPoE Discovery Stage',
		'8864', 'PPPoE Session Stage',
		'8870', 'Jumbo Frames',
		'887B', 'HomePlug 1.0 MME',
		'8888', 'HP LanProbe test',
		'888E', 'EAP over LAN (IEEE 802.1X)',
		'8892', 'PROFINET Protocol',
		'889A', 'HyperSCSI (SCSI over Ethernet)',
		'88A2', 'ATA over Ethernet',
		'88A4', 'EtherCAT Protocol',
		'88A8', 'Provider Bridging (IEEE 802.1ad) & Shortest Path Bridging IEEE 802.1aq',
		'88AB', 'Ethernet Powerlink',
		'88B7', 'OUI Extended Ethertype',
		'88CC', 'Link Layer Discovery Protocol (LLDP)',
		'88CD', 'SERCOS III',
		'88E1', 'HomePlug AV MME',
		'88E3', 'Media Redundancy Protocol (IEC62439-2)',
		'88E5', 'MAC security (IEEE 802.1AE)',
		'88F7', 'Precision Time Protocol (IEEE 1588)',
		'8902', 'IEEE 802.1ag Connectivity Fault Management (CFM) Protocol/ITU-T Recommendation Y.1731 (OAM)',
		'8906', 'Fibre Channel Over Ethernet (FCoE)',
		'8914', 'FCoE Initialization Protocol',
		'8915', 'RDMA Over Converged Ethernet (RoCE)',
		'9000', 'Ethernet Configuration Testing Protocol',
		'9001', '3Com (Formerly Bridge Communications), XNS Systems Management',
		'9002', '3Com (Formerly Bridge Communications), TCP/IP Systems Management',
		'9003', '3Com (Formerly Bridge Communications), Loopback Detection',
		'9100', 'Q-in-Q',
		'AAAA', 'DECNET (Used by VAX 6220 DEBNI)',
		'CAFE', 'Veritas Low Latency Transport (LLT) for Veritas Cluster Server',
		'FAF5', 'Sonix Arpeggio',
		'FF00', 'BBN VITAL-LanBridge Cache Wakeups'
	);
	if (exists $suparEther{$ethercomp}) {
		return "$ethercomp " . $suparEther{$ethercomp};
	}
	else { return "$ethercomp Unassigned"; }
}

sub snappid { ## Returns SNAP PID from numbers
	my ($pidcomp) = shift;
	%suparPID = (
		'0104', 'Port Aggregation Protocol (PAgP)',
		'0108', 'Root Link Query Request (RLQ-REQ)',
		'0109', 'Root Link Query Acknowledge (RLQ-ACK)',
		'010B', 'Per-VLAN Spanning Tree Plus (PVST+)',
		'0111', 'Unidirection Link Detection (UDLD)',
		'2000', 'Cisco Discovery Protocol (CDP)',
		'2003', 'VLAN Trunking Protocol (VTP)',
		'2004', 'Dynamic Trunking Protocol (DTP)'
	);
	if (exists $suparPID{$pidcomp}) {
		return "$pidcomp " . $suparPID{$pidcomp};
	}
	else { return "$pidcomp Unassigned"; }
}

sub sentrydc2hx { ## Packs decimal value into selected field, updates some future packet info window
	$pkval = chr($sentry->get);
	print "PKV $pkval\n";
	$pkval = unpack("B*",$pkval);
	print "PKV $pkval\n";
	$pkval = pack("c*",$pkval);
	print "PKV $pkval\n";
	$sentryval = $sentry->get;
	#    $sentryval =~ s/[\x0-\xF]/chr($1)/ge;
	$sentryval =~ s/(.)/ord($1)/ge;
	$sentry->delete("0.0","end");
	$sentry->insert("0.0",$sentryval);
}

__END__

=head1 NAME

SubZero

=head1 SYNOPSIS

MAC SRC:20370616005C MAC DEST:01000CCCCCCC
Network Layer Protocol: 0153 IEEE802.3 LLC SAP Frame
Length: 0153 DSAP: AA SSAP: AA CTRL: 03
Subnetwork Access Protocol (SNAP)
OUI: 00000C PID: 0128 Unassigned
00000016 : 02 b4 ff 1c 00 02 00 08 00 00 00 01  .¦..........
00000022 : 00 03 00 08 00 00 00 00 00 04 00 08  ............
0000002E : 00 00 00 01 00 05 00 08 00 00 00 00  ............
0000003A : 00 06 00 08 00 00 00 02 00 31 00 0a  .........1..
00000046 : 20 37 06 16 00 5c 00 3f 00 13 53 45   7...\.?..SE
00000052 : 50 32 30 33 37 30 36 31 36 30 30 35  P20370616005
0000005E : 43 00 32 00 11 53 43 43 50 34 32 2e  C.2..SCCP42.
0000006A : 39 2d 32 2d 31 53 00 33 00 0c 43 50  9-2-1S.3..CP
00000076 : 2d 37 39 34 32 47 00 34 00 0f 46 43  -7942G.4..FC
00000082 : 48 31 35 32 33 39 39 53 4a 00 37 00  H152399SJ.7.
0000008E : 08 0a 24 51 c9 00 38 00 08 ff ff ff  ..$Q+.8.....
0000009A : 00 00 39 00 08 0a 24 51 01 00 3a 00  ..9...$Q..:.
000000A6 : 08 0a 05 a7 0b 00 3b 00 08 0a 06 a7  ...º..;....º
000000B2 : 0b 00 3c 00 08 00 00 00 00 00 3d 00  ..<.......=.
000000BE : 08 0a 12 01 32 00 3e 00 08 0a 24 01  ....2.>...$.
000000CA : 32 00 40 00 0f 6d 61 6e 74 65 63 68  2.@..mantech
000000D6 : 2e 63 6f 6d 00 36 00 08 00 00 00 04  .com.6......
000000E2 : 00 41 00 08 00 00 00 51 00 43 00 08  .A.....Q.C..
000000EE : 00 00 00 01 00 44 00 08 00 00 00 0f  .....D......
000000FA : 00 45 00 08 00 00 00 0f 00 48 00 15  .E.......H..
00000106 : 00 00 00 00 00 00 00 00 00 00 00 00  ............
00000112 : 00 00 00 00 00 00 49 00 06 00 06 00  ......I.....
0000011E : 4a 00 44 00 00 00 00 00 00 00 00 00  J.D.........
0000012A : 00 00 00 00 00 00 00 00 00 00 00 00  ............
00000136 : 00 00 00 00 00 00 00 00 00 00 00 00  ............
00000142 : 00 00 00 00 00 00 00 00 00 00 00 00  ............
0000014E : 00 00 00 00 00 00 00 00 00 00 00 00  ............
0000015A : 00 00 00 00 00 00 00                 .......


MAC SRC:001E139E9200 MAC DEST:AB0000020000
Network Layer Protocol: 6002 DEC Maintenance Operation Protocol (MOP) Remote Console
3d 00 07 00 00 00 01 00 03 03 00 00 <- 3d means length 61, 07 is the SID (system ID, i think) (The MOP server supports the request ID message, periodic system ID messages, and the remote console carrier functions.)
02 00 02 21 00 03 00 06 00 00 00 00
00 00 04 00 02 3c 00 05 00 02 d8 05
06 00 02 00 01 07 00 06"00 1e 13 9e <-- this is the clients MAC of course
92 00"64 00 01 79 90 01 01 01 91 01 <-- more of MAC, 79 might be 121, which is the mop communication device code assigned to cisco by dec
02 ee 05

MAC SRC:001E13A01600 MAC DEST:AB0000020000
Network Layer Protocol: 6002 DEC Maintenance Operation Protocol (MOP) Remote Console
3d 00 07 00 00 00 01 00 03 03 00 00
02 00 02 21 00 03 00 06 00 00 00 00
00 00 04 00 02 3c 00 05 00 02 d8 05
06 00 02 00 01 07 00 06"00 1e 13 a0
16 00"64 00 01 79 90 01 01 01 91 01
02 ee 05

typed ``b/100 esa0'', then at the Bootfile: prompt
typed ``mopboot'' whereby on the x86 machine
<ethernet address>.SYS... Which address is that? It should be the VAXen address, and with lowercase letters. 
At the chevron prompt I'm typing "b esa0" and in the /tftpboot/mop directory is the file 08002b1d0ac8.SYS 
watching the request with tcpdump and moptrace
-rw-r--r-- 1 hbent users 71168 2005-02-09 12:43 08002b1c9782.SYS

MOP RC 802.3 8:0:2b:1d:a:c8 > ab:0:0:2:0:0 len 46 code 07 SID
MOP RC 8:0:2b:1d:a:c8 > ab:0:0:2:0:0 len 37 code 07 SID
MOP DL 802.3 8:0:2b:1d:a:c8 > ab:0:0:1:0:0 len 47 code 08 RPR
MOP DL 8:0:2b:1d:a:c8 > ab:0:0:1:0:0 len 39 code 08 RPR

MOP DL 802.3 8:0:2b:1d:a:c8 > ab:0:0:1:0:0 len 47 code 08 RPR
MOP DL 802.3 0:c:29:a9:4:72 > 8:0:2b:1d:a:c8 len 9 code 03 ASV
MOP DL 8:0:2b:1d:a:c8 > ab:0:0:1:0:0 len 39 code 08 RPR
MOP DL 0:c:29:a9:4:72 > 8:0:2b:1d:a:c8 len 1 code 03 ASV

MOP RC 802.3 8:0:2b:3c:1c:db   > ab:0:0:2:0:0      len   45 code 07 SID 
MOP RC 802.3 8:0:2b:3c:1c:db   > ab:0:0:2:0:0      len   45 code 07 SID 
MOP RC 8:0:2b:3c:1c:db   > ab:0:0:2:0:0      len   37 code 07 SID 
MOP RC 802.3 8:0:2b:3c:1c:db   > ab:0:0:2:0:0      len   45 code 07 SID 
MOP RC 8:0:2b:3c:1c:db   > ab:0:0:2:0:0      len   37 code 07 SID 
MOP RC 8:0:2b:3c:1c:db   > ab:0:0:2:0:0      len   37 code 07 SID 
MOP DL 802.3 8:0:2b:3c:1c:db   > ab:0:0:1:0:0      len   47 code 08 RPR 
MOP DL 802.3 0:0:92:90:9:8d    > 8:0:2b:3c:1c:db   len    9 code 03 ASV 
MOP DL 802.3 8:0:2b:3c:1c:db   > ab:0:0:1:0:0      len   47 code 08 RPR 
MOP DL 802.3 0:d:61:c3:c4:5a  > 8:0:2b:3c:1c:db   len    9 code 03 ASV 
MOP DL 802.3 0:0:92:90:9:8d    > 8:0:2b:3c:1c:db   len    9 code 03 ASV 
MOP DL 802.3 8:0:2b:3c:1c:db   > 0:0:92:90:9:8d    len   47 code 08 RPR 
MOP DL 802.3 8:0:2b:3c:1c:db   > ab:0:0:1:0:0      len   47 code 08 RPR 
MOP DL 802.3 0:0:92:90:9:8d    > 8:0:2b:3c:1c:db   len    9 code 03 ASV 
MOP DL 802.3 8:0:2b:3c:1c:db   > 0:0:92:90:9:8d    len   47 code 08 RPR 
MOP DL 802.3 0:0:92:90:9:8d    > 8:0:2b:3c:1c:db   len 1006 code 02 MLD 
MOP DL 802.3 8:0:2b:3c:1c:db   > 0:0:92:90:9:8d    len   11 code 0a RML 
MOP DL 802.3 0:0:92:90:9:8d    > 8:0:2b:3c:1c:db   len 1006 code 02 MLD 
MOP DL 802.3 8:0:2b:3c:1c:db   > 0:0:92:90:9:8d    len   11 code 0a RML 
MOP DL 802.3 8:0:2b:3c:1c:db   > 0:0:92:90:9:8d    len   11 code 0a RML 
MOP DL 802.3 0:0:92:90:9:8d    > 8:0:2b:3c:1c:db   len    9 code 03 ASV 
MOP DL 802.3 8:0:2b:3c:1c:db   > 0:0:92:90:9:8d    len   11 code 0a RML 
MOP DL 802.3 0:0:92:90:9:8d    > 8:0:2b:3c:1c:db   len 1006 code 02 MLD 
MOP DL 802.3 0:0:92:90:9:8d    > 8:0:2b:3c:1c:db   len 1006 code 02 MLD 
MOP DL 802.3 8:0:2b:3c:1c:db   > 0:0:92:90:9:8d    len   11 code 0a RML 
MOP DL 802.3 8:0:2b:3c:1c:db   > 0:0:92:90:9:8d    len   11 code 0a RML 

 In normal state, a DECnet Phase IV node must set its physical  address
     to a function of its DECnet address.  Referring to transmission order,
     the first three bytes of the address consist of  one  of  the  address
     groups  assigned to Digital by Xerox.  The fourth byte is a zero.  The
     fifth byte is the low order byte of the 16 bit DECnet address, and the
     sixth byte is the high order byte of the 16 bit DECnet address.

     So, for example, DECnet node number 14 would have the Ethernet address
     AA-00-04-00-0E-00   (this   format  for  address  display  is  further
     discussed in a later section).
