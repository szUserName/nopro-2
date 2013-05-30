#!/usr/bin/perl
############################################
##                                        ##
##       Runt Frame Comms For LANs        ##
##                                        ##
############################################
## Fait par TUW
## Mai13

## DATA STRUCTURE:
## %chatrooms{$ethertype}[
##				widgets (0) [tab(0),entry(1),label(2),scrolled(3)] OR [tab(0),entry(1),label(2),lnick(3),nick(4),ltrip(5),trip(6),lkey(7),key(8)] for New tab
##				messages (1) [messageindex][handle,tripcode,message]
##				userlist (2) {username => lasttimestamp}
##			   ]

##  FEATURES TO ADD:
##  1. shift/push messageindex in each anonymous array to control max buffer size, or push then negative range operator slice to max buffer size [-50..-1].  this keeps index 0 as the oldest message for easier for loop widget populating
##  2. Caveat:  You'll be spammed with rubbish if you pick an ethertype in use on your network.  Perhaps create a prefix for message data so that you can use common ethertypes: ^md]
##  3. Save messages as raw data so that you can dynamically swap between blowfish keys, attempting to decipher each message for the current room each time you change the key
##  4. For the lazy hacker:  autoswap blowfish keys for each chatroom by setting the key to ethertype.encryptkey (OR ethertype.ethertype for the security oblivious)
##  5. Autojoin rooms when you detect the appropriate newroom signal on an ethertype you don't currently have open: ^nr]
##  6. Caveat:  These prefixs are cleartext and could be signatured eventually.  For covert applications, add another cipher of the full payload with a hardcoded key
##  7. PARTIAL: Turn a tab red when it has an update (stub already created in useThisNIC)
##  8. Bind Port to NoPro proxy
##  9. Reverse Port to NoPro proxy
## 10. IO to NoPro proxy
## 11. Prefix for pushing files over chat client
## 12. DONE: Move all prefixes to non-ASCII to slow down junior forensics investigators
## 13. DEPRECATED, COPY OF #6: Encipher all comms, except perhaps prefixes, as those are used to discern nopro prefixes from legitimate data
## 14. Add option to surpress keepalives, joins, and parts to keep them from getting too loud on the wire
## 15. Add button to leave a room (be sure to update shared array @trackrooms)
## 16. RARP detection for your source mac, then dynamic mac reallocation.  Similar detection of mac scanners.  Perhaps jump to legit OUIs at http://standards.ieee.org/regauth/oui/index.shtml
## 17. PARTIAL, MORE OPTIONS PENDING: Move options to New Room tab
## 18. DONE: Allow shorter blowfish keys and just pad with nulls
## 19. DONE: Source MAC address changes randomly among legitimate looking OUIs
## 20. Add option to toggle between setting MAC addresses statically, random for every packet, or changes after detection

## INSTALLING DEPENDANCIES:
## dead for perl 5.16 ## ppm install http://www.bribes.org/perl/ppm/Win32-NetPacket.ppd
## instead!
## 	get your 3.1 winpcap and 3.1 wpdpack from  http://www.winpcap.org/archive/  (3.1 is important because it has ntddndis.h)
##	grab win32-netpack gzip from http://www.bribes.org/perl/Win32-NetPacket-0.03.tar.gz  -> the readme inside is useful
##	extract netpack and wpdpack.  move wpdpack to C:\wpdpack
##	ppm install dmake
##	in netpack, perl Makefile.PL
##	dmake, dmake test, dmake install
## ppm install http://www.bribes.org/perl/ppm/Net-Pcap.ppd
## ppm install http://theoryx5.uwinnipeg.ca/ppms/Crypt-Blowfish.ppd
## ppm install Tk

## BORKED
## 1. DONE, WE'LL JUST DEFAULT A LITTLE LARGER: Still needs automatic toplevel resizing after NIC is selected
## 2. DONE: Still needs entry validation prior to tab creation
## 3. Perhaps track and transmit your own keepalives for each tab independantly
## 4. DONE: Force new room to only accept four hex characters
## 5. DONE? TESTING: Please Sir, verify that the six random bits of data at the end of the payload are actually random and not in ascii form
## 6. DONE: Pad encryption key to 8 then truncate to 56 so that it doesn't break blowfish
## 7. DONE? TESTING: I think the switch was adding padding and/or crc to messages.  Added a length field so that we can ignore all the extra cruft

#perl2exe_include "attributes.pm"
#perl2exe_include "Tk/Photo.pm"
#perl2exe_include "Tk/Menu.pm"
#perl2exe_include "Tk/Scrollbar.pm"
#perl2exe_info FileDescription=Control ACLs Program
#perl2exe_info FileVersion=6.0.6001.18000
#perl2exe_info LegalCopyright=© Microsoft Corporation.  All rights reserved
#perl2exe_info ProductName=Microsoft® Windows® Operating System
#perl2exe_info ProductVersion=6.0.6000.16386

use threads;
use threads::shared;
use Net::Pcap;
use Win32::NetPacket ':mode';  
use Crypt::Blowfish_PP;
use MIME::Base64;
use Tk;
use Tk::NoteBook;


our @tiresult: shared;
our @trackrooms: shared;
our @ltiresult;
our $nic;
our $dnic;
our $iam;
our $myid;
our $ethertype = "0E0E";
our @gg;
our %chatrooms = ();
our $nb;
our $rendecu = "allcalma";
our $tcode;

$|++;

print "Running as UID $> at PID $$\n";

my @adpts = Net::Pcap::findalldevs(\$err);
@adpts > 0 or die "No adapters installed !\n";
$numadpt = @adpts;
print "$numadpt adapters found... ";

$initheight = 176 + (($numadpt + 1) * 16);
$initwidth = 320;

my $TOP = MainWindow->new();
$SIG{INT} = sub{ quiting(); $TOP->focusForce; $TOP->destroy; };
$TOP->title("NoPro");
$TOP->minsize($initwidth, $initheight);
$TOP->geometry($initwidth . "x" . $initheight . "+20+20");
$TOP->packPropagate(1);
#$TOP->Icon(-image => $TOP->Photo(-file=>"rigor.bmp"));
my $hl = $TOP->Frame(-height => $initheight, -width => $initwidth)->pack;

$TOP->bind('<Configure>' => sub {
	$xe = $TOP->XEvent;
	unless ($hl->cget(-height) == $xe->h && $hl->cget(-width) == $xe->w) { ## resize frame if it doesnt match TOP's dimensions
		$hl->configure(-width => $xe->w, -height => $xe->h);
	}
});


$menu = $TOP->Menu(-type => "menubar");
$TOP->configure(-menu => $menu);

my $f = $menu->cascade(-label => "~File", -tearoff => "0");
$f->command(-label => "E~xit", -command => sub{quiting(); $TOP->destroy;});
## Choose adapter - This choice advances to the next screen
for ($g = 0;$g < $numadpt;$g++) {
	$dnic = $adpts[$g];
	Net::Pcap::lookupnet($dnic, \$nip, \$nmask, \$err);
	$thisone = sprintf "%d.%d.%d.%d\/%d.%d.%d.%d",(($nip & 0xFF000000)>>24),(($nip & 0x00FF0000)>>16),(($nip & 0x0000FF00)>>8),($nip & 0x000000FF),(($nmask & 0xFF000000)>>24),(($nmask & 0x00FF0000)>>16),(($nmask & 0x0000FF00)>>8),($nmask & 0x000000FF);
	$gg[$g] = $hl->Button(-text => $thisone, -command => [ \&useThisNIC, $g ])->place(-relwidth => "1.0", -width => "-10", -"y" => (($g * 16) + 5), -height => "16", -x => "5");
}

MainLoop;

sub quiting { ## tell errbody you're leaving
	foreach my $quittar (keys %chatrooms) {
		unless ($quittar eq "New") {
			tosspacket($quittar,3,$iam);
		}
	}
}

sub writequeue { ## Listen threads
	threads->self->detach;
	threads->yield;
	our %roomtrack = ();
	my $tid = shift;
	$nic = Net::Pcap::open_live($dnic, 9228, 0, 1, \$err) or die;
	print "-\nListening on $dnic\n";
	Net::Pcap::loop($nic, -1, \&printPackets, '');
}

sub concise { ## cipher block chainer for enc/dec
	my ($key,$input,$type) = @_;
	if (length($key) < 8) {
		$key = $key . (chr(0) x (8 - length($key)));
	}
	if (length($key) > 56) {
		$key = substr($key,0,56);
	}
	my $pwcrypt = new Crypt::Blowfish_PP $key;
	$input = decode_base64($input . ("=" x (12 - (length($input) % 12)))) if $type; 
	my $vallen = length($input);
	my $tempcipher = "";
	for ($valprime = 0; $vallen > 0; $valprime += 8) {
		if ($vallen < 8) {
			$valstr = substr $input, $valprime, $vallen;
			$valstr .= "\0" x (8 - $vallen);
		}
		else {
			$valstr = substr $input, $valprime, 8;
		}
		$vallen -= 8;
		$tempcipher .= $type?$pwcrypt->decrypt($valstr):$pwcrypt->encrypt($valstr);
	}
	if ($type) {
		$tempcipher =~ s/\0//g;
	}
	else {
		$tempcipher = encode_base64($tempcipher);
		chomp($tempcipher);
		$tempcipher =~ s/=//g;
	}
	return $tempcipher;
}

sub printPackets { ## Parses packets into human readable
    my ($zed,$zedhash,$data) = @_; ## zed passed as null from &sniff
    my $offset = 0;
    my($macaddydest,$macaddysrc) = unpack 'H12H12', substr $data, $offset;
    $offset += 12; ## Jump past MAC addys
    ($etherall) = unpack 'H4', substr $data, $offset;
    $etherall = uc($etherall);
    { ## every packet, check to see if you've joined new rooms since last packet
		lock @trackrooms;
		foreach my $roomname (@trackrooms) {
			if ($roomname =~ /\+(.*)/) {
				$roomtrack{$1}++;
			}
			else {
				delete $roomtrack{$roomname};
			}
		}
		@trackrooms = ();
		cond_signal(@trackrooms);
    }
    if (exists $roomtrack{$etherall}) {
	$offset += 2; ## skip over ethertype
	$xdrstr = unpack('B*', substr($data, $offset, (length($data) - $offset)));  ## dump the whole fucker to binary
	($mtype,$msize,$remainder) = unpack('a2a11a*', $xdrstr); ## grab up two bits for message type
	$mtype = parsehdra($mtype);
	$msize = parsehdra($msize);
	#$remainder = substr($remainder, 0, (length($remainder) - 6)); ## remove 6 bit padding
	$remainder = substr($remainder, 0, ($msize * 8)); ## remove 6 bit padding
	$repackxdrstr = pack('B*',$remainder);
	@peasy = ("","^jn]","^kl]","^qt]"); ## conversion table for legacy message type handling
	{
		lock @tiresult;
		push @tiresult, $etherall . $peasy[$mtype] . $repackxdrstr;
		cond_signal(@tiresult);
	}
    }
}

sub newroom { ## create a new tab and listen on a new ethertype
	my ($rewm) = shift;
	
	$rewm = uc($rewm);
	$chatrooms{$rewm}[0][0] = $nb->add($rewm, -label => $rewm, -raisecmd => sub { raisefocus($rewm) });
	$nb->raise($rewm);
	
	$chatrooms{$rewm}[0][3] = $chatrooms{$rewm}[0][0]->Scrolled(Text, -relief => "sunken", -borderwidth => "1", -setgrid => "false", -height => "32", -scrollbars => "oe", -wrap => "word", -takefocus => "0")->place(-relheight => "1.0", -height => "-28", -relwidth => "1.0", -width => "-102", -"y" => "5", -x => "5");
	$chatrooms{$rewm}[0][3]->mark(qw/set insert end/);
	$chatrooms{$rewm}[0][3]->tagConfigure("c1", -foreground => "#10AF10"); ## handle colour
	$chatrooms{$rewm}[0][3]->tagConfigure("c2", -foreground => "#CF9F10"); ## tripcode colour
	$chatrooms{$rewm}[0][3]->tagConfigure("c3", -foreground => "#000000"); ## text colour
	$chatrooms{$rewm}[0][3]->tagConfigure("q", -foreground => "#AF1010"); ## quit colour
	$chatrooms{$rewm}[0][3]->tagConfigure("j", -foreground => "#1010AF"); ## join colour

	$chatrooms{$rewm}[0][2] = $chatrooms{$rewm}[0][0]->Label(-anchor => 'nw')->place(-relheight => "1.0", -height => "-26", -width => "91", -"y" => "5", -relx => "1.0", -x => "-98");
	
	$chatrooms{$rewm}[0][1] = $chatrooms{$rewm}[0][0]->Entry()->place(-height => "16", -relwidth => "1.0", -width => "-102", -rely => "1.0", -"y" => "-21", -x => "5");
	$chatrooms{$rewm}[0][1]->bind('<Return>' ,sub{broadcast($rewm); Tk->break; });
	$chatrooms{$rewm}[0][1]->focus;
	{ ## this essentially enables sniffing for this ethertype
		lock @trackrooms;
		push @trackrooms, "+" . $rewm; ## Omit the + sign for leaving a room
		cond_signal(@trackrooms);
	}
	tosspacket($rewm,1,$iam);
}

sub raisefocus{ ## puts keyboard focus on the entry widgets when you switch tabs
	$tabname = shift;
	if ($chatrooms{$tabname}[0][1]) { ## This keeps raisefocus from raising errors before the entry widgets are defined
		$chatrooms{$tabname}[0][1]->focus;
	}
}

sub useThisNIC { ## create main tk and main burn loop
	my ($useNIC) = @_;
	$dnic = $adpts[$useNIC];

	foreach my $zong (@gg) {
		$zong->placeForget;
	}
	
	$nb = $hl->NoteBook(-tabpadx => 0, -tabpady => 0)->place(-relheight => "1.0", -relwidth => "1.0");
	
	$chatrooms{"New"}[0][0] = $nb->add("New", -label => "New", -raisecmd => sub { raisefocus("New") });
	
	## Choose handle
	$chatrooms{"New"}[0][3] = $chatrooms{"New"}[0][0]->Label(-text => "Handle")->place(-height => "16", -width => "50", -"y" => "5", -x => "5");
	$chatrooms{"New"}[0][4] = $chatrooms{"New"}[0][0]->Entry()->place(-height => "16", -relwidth => "1.0", -width => "-65", -"y" => "5", -x => "60");
	$chatrooms{"New"}[0][4]->bind('<Key>' => [\&print_keysym,Ev('N'),$chatrooms{"New"}[0][4],\$iam]);
	$chatrooms{"New"}[0][4]->focus;
	## Choose tripcode string
	$chatrooms{"New"}[0][5] = $chatrooms{"New"}[0][0]->Label(-text => "ID")->place(-height => "16", -width => "50", -"y" => "21", -x => "5");
	$chatrooms{"New"}[0][6] = $chatrooms{"New"}[0][0]->Entry()->place(-height => "16", -relwidth => "1.0", -width => "-65", -"y" => "21", -x => "60");
	$chatrooms{"New"}[0][6]->bind('<Key>' => [\&print_keysym,Ev('N'),$chatrooms{"New"}[0][6],\$tcode]);
	## Choose encryption key
	$chatrooms{"New"}[0][7] = $chatrooms{"New"}[0][0]->Label(-text => "Key")->place(-height => "16", -width => "50", -"y" => "37", -x => "5");
	$chatrooms{"New"}[0][8] = $chatrooms{"New"}[0][0]->Entry()->place(-height => "16", -relwidth => "1.0", -width => "-65", -"y" => "37", -x => "60");
	$chatrooms{"New"}[0][8]->bind('<Key>' => [\&print_keysym,Ev('N'),$chatrooms{"New"}[0][8],\$rendecu]);
	$chatrooms{"New"}[0][8]->insert('end',"*" x length($rendecu));
	
	$chatrooms{"New"}[0][2] = $chatrooms{"New"}[0][0]->Label(-text => "EType")->place(-height => "16", -width => "50", -"y" => "53", -x => "5");
	$chatrooms{"New"}[0][1] = $chatrooms{"New"}[0][0]->Entry()->place(-height => "16", -relwidth => "1.0", -width => "-65", -"y" => "53", -x => "60");
	$chatrooms{"New"}[0][1]->bind('<Key>' => [\&newroomvalidation,Ev('N'),$chatrooms{"New"}[0][1],\$ethertype]);
	$chatrooms{"New"}[0][1]->insert('end',$ethertype);
		
	$lastud = 0;
	threads->new(\&writequeue, $useNIC);
	
	while (1) { ##  main burn loop, checks for new messages, handles updates to ulist and does keepalive pings
		select(undef, undef, undef, 0.02); ## Burn Slower
		$TOP->update();
		($sec,$min,$hora,$diem,undef,undef) = localtime(time);
		$stamp = ($diem * 86400) + ($hora * 3600) + ($min * 60) + $sec;
		if (($stamp - $lastud) > 300) {
			$lastud = $stamp;
			foreach my $imalive (keys %chatrooms) { ## This probably gets loud
				unless ($imalive eq "New") {
					tosspacket($imalive,2,$iam);
				}
			}
		}
		{
			lock @tiresult;
			foreach (@tiresult) {
				push @ltiresult, $_;
			}
			@tiresult = ();
			cond_signal(@tiresult);
		}
		foreach my $lti (@ltiresult) {
			$ltitype = substr $lti, 0, 4;
			$lti = substr $lti, 4, (length($lti) - 4);
			if ($lti ne $nb->raised) {
				## add code here to make tab label red or something when you get a message in a room that isnt your current tab
			}
			if ($lti =~ /^\^kl\]/) {
				$thisguy = $';
				$chatrooms{$ltitype}[2]{$thisguy} = $stamp;
			}
			elsif ($lti =~ /^\^jn\]/) {
				$thisguy = $';
				unless (exists $chatrooms{$ltitype}[2]{$thisguy}) {
					$precat = "\n" . $thisguy . " joined";
					$chatrooms{$ltitype}[0][3]->insert('end',$precat,"j");
					$chatrooms{$ltitype}[0][3]->yview('moveto','1.0');
				}
				$chatrooms{$ltitype}[2]{$thisguy} = $stamp;
				tosspacket($ltitype,2,$iam) unless $thisguy eq $iam;
			}
			elsif ($lti =~ /^\^qt\]/) {
				$thisguy = $';
				if (exists $chatrooms{$ltitype}[2]{$thisguy}) {
					delete $chatrooms{$ltitype}[2]{$thisguy};
					$precat = "\n" . $thisguy . " left";
					$chatrooms{$ltitype}[0][3]->insert('end',$precat,"q");
					$chatrooms{$ltitype}[0][3]->yview('moveto','1.0');
				}
			}
			elsif ($lti =~ /^(.*?\s\[.*?\]\s)/) {
				$thisguy = $1 . concise($rendecu,$',1);
				if ($thisguy =~ /^(.*?)\s(\[.*?\])\s/) {
					$chatrooms{$ltitype}[0][3]->insert('end',"\n" . $1 . " ","c1");
					$chatrooms{$ltitype}[0][3]->insert('end',$2 . " ","c2");
					$chatrooms{$ltitype}[0][3]->insert('end',$',"c3");
					$chatrooms{$ltitype}[0][3]->yview('moveto','1.0');
				}
			}
		}
		@ltiresult = ();
		foreach my $checkfordead (keys %chatrooms) {
			unless ($checkfordead eq "New") {
				$precat = "";
				foreach my $uname (sort keys %{$chatrooms{$checkfordead}[2]}) {
					if (($stamp - $chatrooms{$checkfordead}[2]{$uname}) > 700) { ## allow two update intervals before assuming gone
						delete $chatrooms{$checkfordead}[2]{$uname};
						$chatrooms{$checkfordead}[0][3]->insert('end',"\n$uname timed out","q");
						$chatrooms{$checkfordead}[0][3]->yview('moveto','1.0');
					}
					else {
						$precat .= $uname . "\n";
					}
				}
				$chatrooms{$checkfordead}[0][2]->configure(-text => $precat);
			}
		}
	}
}

sub tosspacket {
	## Message \b00, Join \b01, Keepalive \b10, Quit \b11
	my ($tptype,$ptype,$payload) = @_;
	## manual binary generation, to keep automatic zero padding from occuring	
	$bptype = unpack('B8',$ptype);
	($filler,$aptype) = unpack('a6a2', $bptype); ## grab just two bits of data for packet type, i'm not sure this is working either. apparently i'm bad at decimal to binary
	
	$pp = unpack('B*',$payload);
	$pa = unpack('a*', $pp); ## convert ascii payload to bits
	
	$padding = int(rand(64));
	$padding = pack("n*",$padding); ## a short, so 16 bits
	$bpadding = unpack('B*',$padding);
	($moarfiller,$bp) = unpack('a13a3', $bpadding); ## generate three bits of random data for padding # not sure if this is going random properly or if it's all ascii representations of numbers

	$plen = length($payload); ## I think the switch is adding padding or crc data to frames.  We will send frame length with each packet so we can discard the data appended.  11 bit field. Max 1500 or so, so the leftmost 5 bits will be zeros and discarded.
	$plen = pack("n*",$plen);
	$bplen = unpack('B*',$plen);
	$aplen = sprintf("%011d",unpack('a*', $bplen));

	my $soy = Win32::NetPacket->new(adapter_name => $dnic) or die $@;
	
	$sourcemac = "";
	for ($octet = 0; $octet < 6; $octet++) {
		$toctet = int(rand(256));
		if ($octet == 0) {
			$toctet = $toctet >> 2;
			$toctet = $toctet << 2;
			## this keeps the most significant bit (since we are network byte order, and therefore big-endian)
			## of the first octet a multiple of four, to look like a legitmate manufactureer OUI.
			## With any even source MAC address, the radius authenticator sends 802.1x EAP Request Identity to try to identify me.
			## With odd source MACs it does not, but those PROBABLY do not get forwarded by the switch,
			## since responding would cause the destination device to inadvertantly broadcast, 
			## which is usually not a desirable trait.  You could set your MAC to a MAC you sniff off the wire
			## to perhaps evade port security for some while, though it may corrupt ARP tables.  The radius authenticator
			## seems content to ping me for EAP Identity requests on mod 4=2 source MAC addresses, which also supports
			## the idea that broad/multicast source MAC addresses aren't being relayed to it.
			## EAP Identity Request Timeout defaults to 1 second IOS 4.1 and older. and 30 seconds on IOS 4.2 and newer
			## EAP Identify Request Max Retries default to 2, Recommened set to 12.  Removes supplicant entry from MSCB (Mobile Station Control Block)
			## (which should keep me from sending any packets) and the WLC (Wireless LAN Controller) (does this apply only to wireless?)
			## sends a de-auth frame to the client, forcing the EAP process to restart.
			## I'm curious if certain MAC addresses I've used in the past are blocked in any way currently.
		}
		$sourcemac .= chr($toctet);
	}
	#$sourcemac = "\x00\xAA\xBB\xCC\xDD\xEE";  ## uncomment if you're into hardcoding
	$soyeah =  "\xFF\xFF\xFF\xFF\xFF\xFF" . $sourcemac . pack("H*",$tptype) . pack('B*',$aptype . $aplen . $pa . $bp); ## pack two bits of ptype, eleven bits of size, payload in mults of 8, and three random bits.  This keeps ascii from being displayed overtly on sniffers without having to add another encryption layer
	## TO ADD: If ^^ are odd bits, this will be treated as a multicast MAC address and SHOULD be broadcasted as well, since many devices don't distinguish between broadcast and multicast.  Might be useful for extra evasion.
	$success = $soy->SendPacket($soyeah);
}

sub broadcast {
	my ($betype) = shift;
	$datums = $chatrooms{$betype}[0][1]->get();
	$chatrooms{$betype}[0][1]->delete(0.0,'end');
	$datums = concise($rendecu,$datums,0);
	tosspacket($betype,0,$iam . " [" . $myid . "] " . $datums);
}

sub print_keysym { ## masks entry fields, input is KeyPressed, Reference to Entry Widget, Reference to Value Scalar
	my($keysym_decimal,$sacredobj,$reftohidden) = ($_[1],$_[2],$_[3]);
	if ($keysym_decimal > 31 && $keysym_decimal < 127) {
		$$reftohidden .= chr($keysym_decimal);
		$sacredobj->delete('0.0','end');
		$sacredobj->insert('end',"*" x length($$reftohidden));
	}
	elsif ($keysym_decimal == 65288 || $keysym_decimal == 65535) {
		$$reftohidden = "";
		$sacredobj->delete('0.0','end');
	}
	$myid = $iam . $tcode; ## salt tripcode with handle
	$myid = concise($rendecu,$myid,0); ## encipher, to add a little more computational cost.
	$myid = encode_base64($myid); ## then base64 to display nicely
	chomp($myid); ## get rid of newline cruft
	$myid =~ s/=//g; ## get rid of base64 cruft
	$myid = substr $myid, -6; ## truncate to the last 6 chars so this doesnt get out of hand.  Being lossy, this also makes the cipher one-way
	$TOP->title("NoPro - $iam [$myid] " . ("*" x length($rendecu)));

	$sacredobj->break();
}

sub newroomvalidation { ## makes sure we only enter four hex into our new room names
	my($keysym_decimal,$sacredobj,$reftohidden) = ($_[1],$_[2],$_[3]);
	if (	($keysym_decimal >= 48 && $keysym_decimal <= 57) || ## numbers
		($keysym_decimal >= 65 && $keysym_decimal <= 70) || ## upper A-F
		($keysym_decimal >= 97 && $keysym_decimal <= 102)) { ## lower A-F
		if (length($$reftohidden) < 4) {
			$$reftohidden .= uc(chr($keysym_decimal));
		}
	}
	elsif ($keysym_decimal == 65288 || $keysym_decimal == 65535) { ## backspace and delete
		$$reftohidden = "";
	}
	elsif ($keysym_decimal == 65293) { ## enter and numpad enter
		newroom($$reftohidden);
		$$reftohidden = "";
	}
	$sacredobj->delete('0.0','end');
	$sacredobj->insert('end',$$reftohidden);
	$sacredobj->break();
}

sub parsehdra { ## bin2dec 32 bit max subroutine
	return unpack("N", pack("B32", substr("0" x 32 . shift, -32)));
}
