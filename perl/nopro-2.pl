#!/usr/bin/perl
############################################
##                                        ##
##       Runt Frame Comms For LANs        ##
##                                        ##
############################################
## Fait par TUW
## Mai13

## dead for perl 5.16 ## ppm install http://www.bribes.org/perl/ppm/Win32-NetPacket.ppd
## instead!
## 	get your 3.1 winpcap and 3.1 wpdpack from  http://www.winpcap.org/archive/  (3.1 is important because it has ntddndis.h)
##	grab win32-netpack gzip from http://www.bribes.org/perl/Win32-NetPacket-0.03.tar.gz  -> the readme inside is useful
##	extract netpack and wpdpack.  make wpdpack to C:\wpdpack
##	ppm install dmake
##	in netpack, perl Makefile.PL
##	dmake, dmake test, dmake install
## ppm install http://www.bribes.org/perl/ppm/Net-Pcap.ppd
## ppm install http://theoryx5.uwinnipeg.ca/ppms/Crypt-Blowfish.ppd
## ppm install Tk
## ppm install Tk-ROText

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


our @tiresult: shared;
our @trackrooms: shared;
our @ltiresult;
use Tk;
use Tk::NoteBook;

print "Running as UID $> at PID $$\n";

our $nic; ## init variable globally
our $dnic;
our $iam;
our $myid;
our @gg;
our $ethertype;
our %chatrooms = ();
our $nb;

$|++;

my @adpts = Net::Pcap::findalldevs(\$err);
@adpts > 0 or die "No adapters installed !\n";
$numadpt = @adpts;
print "$numadpt adapters found... ";

$initheight = 76 + (($numadpt + 1) * 16);
$initwidth = 220;

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
$whatever = (($numadpt + 1) * 16) + 5;
## Choose handle
$nicktext = $hl->Label(-text => "Handle")->place(-height => "16", -width => "50", -"y" => $whatever, -x => "5");
$nick = $hl->Entry()->place(-height => "16", -relwidth => "1.0", -width => "-65", -"y" => $whatever, -x => "60");
$nick->focus;
## Choose tripcode string
$whatever += 16;
$nidtext = $hl->Label(-text => "ID")->place(-height => "16", -width => "50", -"y" => $whatever, -x => "5");
$myid = "";
$nid = $hl->Entry()->place(-height => "16", -relwidth => "1.0", -width => "-65", -"y" => $whatever, -x => "60");
$nid->bind('<Key>' => [\&print_keysym,Ev('N'),$nid,\$myid]);
## Choose encryption key - add checks later to pad this to 8 then truncate down to 56
$whatever += 16;
$nkeytext = $hl->Label(-text => "Key")->place(-height => "16", -width => "50", -"y" => $whatever, -x => "5");
$rendecu = "allcalma";
$nkey = $hl->Entry()->place(-height => "16", -relwidth => "1.0", -width => "-65", -"y" => $whatever, -x => "60");
$nkey->bind('<Key>' => [\&print_keysym,Ev('N'),$nkey,\$rendecu]);
$nkey->insert('end',"*" x length($rendecu));
## Variable ethertype - Must be 4 hex or roof flies off, add checks later
$whatever += 16;
$netypetext = $hl->Label(-text => "EType")->place(-height => "16", -width => "50", -"y" => $whatever, -x => "5");
$ethertype = "0E0E";
$netype = $hl->Entry()->place(-height => "16", -relwidth => "1.0", -width => "-65", -"y" => $whatever, -x => "60");
$netype->insert('end',$ethertype);

## data structure is %chatrooms{$ethertype}[
##						widgets (0) [tab(0),entry(1),label(2),scrolled(3: not present in New tab)]
##						messages (1) [messageindex][handle,tripcode,message]
##						userlist (2) {username => lasttimestamp}
##					   ]

## FEATURES TO ADD:
## 1. shift/push messageindex in each anonymous array to control max buffer size, or push then negative range operator slice to max buffer size [-50..-1].  this keeps index 0 as the oldest message for easier for loop widget populating
## 2. Caveat:  You'll be spammed with rubbish if you pick an ethertype in use on your network.  Perhaps create a prefix for message data so that you can use common ethertypes: ^md]
## 3. Save messages as raw data so that you can dynamically swap between blowfish keys, attempting to decipher each message for the current room each time you change the key
## 4. For the lazy hacker:  autoswap blowfish keys for each chatroom by setting the key to ethertype . defaultkey
## 5. Autojoin rooms when you detect the appropriate newroom signal on an ethertype you don't currently have open: ^nr]
## 6. Caveat:  these prefixs are cleartext and could be signatured eventually.  for covert applications, add another cipher of the full payload with a hardcoded key

MainLoop;

sub quiting {
	foreach my $quittar (keys %chatrooms) {
		unless ($quittar eq "New") {
			tosspacket($quittar,"^qt]" . $iam);
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
	$offset += 2;
	$xdrstr = substr $data, $offset, (length($data) - $offset);
	{
		lock @tiresult;
		push @tiresult, $etherall . $xdrstr;
		cond_signal(@tiresult);
	}
    }
}

sub newroom {
	my ($rewm) = shift;
	
	$rewm = uc($rewm);
	#$chatrooms{$rewm} = $nb->add($rewm, -label => $rewm, -raisecmd=>$sentry->focus); ## create a sub that populates messsages, users, and tracks default focus for each tab
	$chatrooms{$rewm}[0][0] = $nb->add($rewm, -label => $rewm);

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
	tosspacket($rewm, "^jn]" . $iam); ## send this for each room creation instead
}

sub useThisNIC { ## create main tk and main burn loop
	$TOP->configure(-height => ($initheight + 50), -width => ($initwidth + 100));
	$hl->configure(-height => ($initheight + 50), -width => ($initwidth + 100));
	my ($useNIC) = @_;
	$iam = $nick->get;
	$ethertype = uc($netype->get);
	$myid = $iam . $myid; ## salt tripcode with handle
	$myid = concise($rendecu,$myid,0); ## encipher, to add a little more computational cost.
	$myid = encode_base64($myid); ## then base64 to display nicely
	chomp($myid); ## get rid of newline cruft
	$myid =~ s/=//g; ## get rid of base64 cruft
	$myid = substr $myid, -6; ## truncate to the last 6 chars so this doesnt get out of hand.  Being lossy, this also makes the cipher one-way
	$TOP->title("NoPro - $iam [$myid] " . ("*" x length($rendecu)));
	foreach my $zong (@gg) {
		$zong->placeForget;
	}
	$nicktext->placeForget;
	$nick->placeForget;
	$nidtext->placeForget;
	$nid->placeForget;
	$dnic = $adpts[$useNIC];
	
	$nb = $hl->NoteBook(-tabpadx => 0, -tabpady => 0)->place(-relheight => "1.0", -relwidth => "1.0");
	
	#$chatrooms{"New"}[0][0] = $nb->add("New", -label => "New", -raisecmd=>$chatrooms{"New"}[0][1]->focus); ## create a sub that populates messsages, users, and tracks default focus for each tab
	$chatrooms{"New"}[0][0] = $nb->add("New", -label => "New");

	$chatrooms{"New"}[0][2] = $chatrooms{"New"}[0][0]->Label(-text => "EType")->place(-height => "16", -width => "50", -"y" => "76", -x => "5");
	$chatrooms{"New"}[0][1] = $chatrooms{"New"}[0][0]->Entry()->place(-height => "16", -relwidth => "1.0", -width => "-65", -"y" => "76", -x => "60"); ## enter key here should spawn a new room tab
	#$chatrooms{"New"}[0][1]->bind('<Return>' => [\&newroom,$chatrooms{"New"}[0][1]->get]);
	$chatrooms{"New"}[0][1]->bind('<Return>' => sub{ newroom($chatrooms{"New"}[0][1]->get); });
	$chatrooms{"New"}[0][1]->focus;
	
	newroom("0E0E");

	$lastud = 0;
	threads->new(\&writequeue, $useNIC);
	
	while (1) { ##  main burn loop, checks for new messages, handles updates to ulist and does keepalive pings
		select(undef, undef, undef, 0.02); ## Burn Slower
		$TOP->update();
		($sec,$min,$hora,$diem,undef,undef) = localtime(time);
		$stamp = ($diem * 86400) + ($hora * 3600) + ($min * 60) + $sec;
		if (($stamp - $lastud) > 300) {
			$lastud = $stamp;
			foreach my $imalive (keys %chatrooms) { ## This probably gets loud, set option to surpress
				unless ($imalive eq "New") {
					tosspacket($imalive,"^kl]" . $iam);
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
				tosspacket($ltitype,"^kl]" . $iam) unless $thisguy eq $iam;
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
	my ($tptype,$payload) = @_;
	my $soy = Win32::NetPacket->new(adapter_name => $dnic) or die $@;
	$soyeah =  "\xFF\xFF\xFF\xFF\xFF\xFF" . "\x00\xAA\xBB\xCC\xDD\xEE" . pack("H*",$tptype) . $payload;
	## TO ADD: If ^^ are odd bits, this will be treated as a multicast MAC address and SHOULD be broadcasted as well, since many devices don't distinguish between broadcast and multicast.  Might be useful for extra evasion.
	$success = $soy->SendPacket($soyeah);
}

sub broadcast {
	my ($betype) = shift;
	$datums = $chatrooms{$betype}[0][1]->get();
	$chatrooms{$betype}[0][1]->delete(0.0,'end');
	$datums = concise($rendecu,$datums,0);
	tosspacket($betype,$iam . " [" . $myid . "] " . $datums);
}

sub print_keysym { ## masks entry fields, input is KeyPressed, Reference to Entry Widget, Reference to Value Scalar
	my($keysym_decimal,$sacredobj,$reftohidden) = ($_[1],$_[2],$_[3]);
	if ($keysym_decimal > 31 && $keysym_decimal < 127) {
		$$reftohidden .= chr($keysym_decimal);
		$sacredobj->delete('0.0','end');
		$sacredobj->insert('end',"*" x length($$reftohidden));
		$sacredobj->break();
	}
	elsif ($keysym_decimal == 65288 || $keysym_decimal == 65535) {
		$$reftohidden = "";
		$sacredobj->delete('0.0','end');
		$sacredobj->break();
	}
	else {
		return;
	}
}

sub parsehdra { ## bin2dec 32 bit max subroutine
	return unpack("N", pack("B32", substr("0" x 32 . shift, -32)));
}
