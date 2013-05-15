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
our @ltiresult;
use Tk;
require Tk::ROText;

print "Running as UID $> at PID $$\n";

our $nic; ## init variable globally
our $dnic;
our $iam;
our $myid;
our @gg;
our %ul;
our $ethertype;

$|++;

my @adpts = Net::Pcap::findalldevs(\$err);
@adpts > 0 or die "No adapters installed !\n";
$numadpt = @adpts;
print "$numadpt adapters found... ";

$initheight = 64 + (($numadpt + 1) * 16);
$initwidth = 500;

my $TOP = MainWindow->new();
$SIG{INT} = sub{ tosspacket("^qt]" . $iam); $TOP->focusForce; $TOP->destroy; };
$TOP->title("NoPro");
$TOP->minsize($initwidth, eval($initheight - 19));
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
$f->command(-label => "E~xit", -command => sub{tosspacket("^qt]" . $iam); $TOP->destroy;});
## Choose adapter - This choice advances to the next screen
for ($g = 0;$g < $numadpt;$g++) {
	$dnic = $adpts[$g];
	Net::Pcap::lookupnet($dnic, \$nip, \$nmask, \$err);
	$thisone = sprintf "%d.%d.%d.%d\/%d.%d.%d.%d",(($nip & 0xFF000000)>>24),(($nip & 0x00FF0000)>>16),(($nip & 0x0000FF00)>>8),($nip & 0x000000FF),(($nmask & 0xFF000000)>>24),(($nmask & 0x00FF0000)>>16),(($nmask & 0x0000FF00)>>8),($nmask & 0x000000FF);
	$gg[$g] = $hl->Button(-text => $thisone, -command => [ \&useThisNIC, $g ])->place(-relwidth => "1.0", -width => "-10", -"y" => (($g * 16) + 5), -height => "16", -x => "5");
}
$whatever = (($numadpt + 1) * 16) + 5;
## Choose handle
$nicktext = $hl->ROText(-borderwidth => "0", -wrap => "none", -takefocus => "0")->place(-height => "16", -width => "50", -"y" => $whatever, -x => "5");
$nicktext->insert("end", "Handle");
$nick = $hl->Entry()->place(-height => "16", -relwidth => "1.0", -width => "-65", -"y" => $whatever, -x => "60");
$nick->focus;
## Choose tripcode string
$whatever += 16;
$nidtext = $hl->ROText(-borderwidth => "0", -wrap => "none", -takefocus => "0")->place(-height => "16", -width => "50", -"y" => $whatever, -x => "5");
$nidtext->insert("end", "ID");
$myid = "";
$nid = $hl->Entry()->place(-height => "16", -relwidth => "1.0", -width => "-65", -"y" => $whatever, -x => "60");
$nid->bind('<Key>' => [\&print_keysym,Ev('N'),$nid,\$myid]);
## Choose encryption key - add checks later to make sure this fails modulus 8 before proceeding - perhaps pad/truncate to 8 to make it friendly
$whatever += 16;
$nkeytext = $hl->ROText(-borderwidth => "0", -wrap => "none", -takefocus => "0")->place(-height => "16", -width => "50", -"y" => $whatever, -x => "5");
$nkeytext->insert("end", "Key");
$rendecu = "allcalma";
$nkey = $hl->Entry()->place(-height => "16", -relwidth => "1.0", -width => "-65", -"y" => $whatever, -x => "60");
$nkey->bind('<Key>' => [\&print_keysym,Ev('N'),$nkey,\$rendecu]);
$nkey->insert('end',"*" x length($rendecu));
## Variable ethertype - Must be 4 hex or roof flies off
$whatever += 16;
$netypetext = $hl->ROText(-borderwidth => "0", -wrap => "none", -takefocus => "0")->place(-height => "16", -width => "50", -"y" => $whatever, -x => "5");
$netypetext->insert("end", "Ethertype");
$ethertype = "0E0E";
$netype = $hl->Entry()->place(-height => "16", -relwidth => "1.0", -width => "-65", -"y" => $whatever, -x => "60");
$netype->insert('end',$ethertype);
## TO ADD: ok, so here is the idea:
## since we listen for all traffic anyways, set up tabs such that each tab is a chatroom, where the chatroom name is the ethertype.
## whenever you get a message that matches a chatroom you have open, push the data to the appropriate array that tracks messages for that ethertype/room
## then just populate that data to your $t widget when you switch to that tab
## data structure will be %chatrooms{$ethertype}[messageindex]
## shift/push messages in each anonymous array to control max buffer size, or push then negative range operator slice to max buffer size [-50..-1].  this keeps index 0 as the oldest message for easier for loop widget populating
## Make 0E0E the default chatroom I guess
## Caveat:  You'll be spammed with rubbish if you pick an ethertype in use on your network

MainLoop;

sub writequeue { ## Listen threads
	threads->self->detach;
	threads->yield;
	my $tid = shift;
	$nic = Net::Pcap::open_live($dnic, 9228, 0, 1, \$err) or die;
	print "-\nListening on $dnic\n";
	tosspacket("^jn]" . $iam);
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
    if($etherall eq $ethertype) {
	$offset += 2;
	$xdrstr = substr $data, $offset, (length($data) - $offset);
	unless ($xdrstr =~ /^\^(kl|qt|jn)\]/) {
		if ($xdrstr =~ /^(.*?\s\[.*?\]\s)/) {
			$xdrstr = $1 . concise($rendecu,$',1);
		}
	}
	{
		lock @tiresult;
		push @tiresult, $xdrstr;
		cond_signal(@tiresult);
	}
    }
}

sub useThisNIC { ## create main tk and main burn loop
	my ($useNIC) = @_;
	$iam = $nick->get;
	$ethertype = uc($netype->get);
	$myid = $iam . $myid; ## salt tripcode with handle
	$myid = concise($rendecu,$myid,0); ## encipher, to add a little more computational cost.
	$myid = encode_base64($myid); ## then base64 to display nicely
	chomp($myid); ## get rid of newline cruft
	$myid =~ s/=//g; ## get rid of base64 cruft
	$myid = substr $myid, -6; ## truncate to the last 6 chars so this doesnt get out of hand.  Being lossy, this also makes the cipher one-way
	$TOP->title("NoPro - $iam [$myid] $ethertype " . ("*" x length($rendecu)));
	foreach my $zong (@gg) {
		$zong->placeForget;
	}
	$nicktext->placeForget;
	$nick->placeForget;
	$nidtext->placeForget;
	$nid->placeForget;
	$dnic = $adpts[$useNIC];
	$t = $hl->Scrolled(Text, -relief => "sunken", -borderwidth => "1", -setgrid => "false", -height => "32", -scrollbars => "oe", -wrap => "word", -takefocus => "0")->place(-relheight => "1.0", -height => "-28", -relwidth => "1.0", -width => "-102", -"y" => "5", -x => "5");
	$t->mark(qw/set insert end/);
	$t->tagConfigure("c1", -foreground => "#10AF10"); ## handle colour
	$t->tagConfigure("c2", -foreground => "#CF9F10"); ## tripcode colour
	$t->tagConfigure("c3", -foreground => "#000000"); ## text colour
	$t->tagConfigure("q", -foreground => "#AF1010"); ## quit colour
	$t->tagConfigure("j", -foreground => "#1010AF"); ## join colour

	$stext = $hl->ROText(-borderwidth => "0", -wrap => "none", -takefocus => "0")->place(-relheight => "1.0", -height => "-26", -width => "91", -"y" => "5", -relx => "1.0", -x => "-98");
	
	$sentry = $hl->Entry()->place(-height => "16", -relwidth => "1.0", -width => "-102", -rely => "1.0", -"y" => "-21", -x => "5");
	$sentry->bind('<Return>' ,sub{broadcast(); Tk->break; });
	$sentry->focus;
	$lastud = 0;
	threads->new(\&writequeue, $useNIC);
	
	while (1) { ##  main burn loop, checks for new messages, handles updates to ulist and does keepalive pings
		select(undef, undef, undef, 0.01); ## Burn Slower
		$TOP->update();
		($sec,$min,$hora,$diem,undef,undef) = localtime(time);
		$stamp = ($diem * 86400) + ($hora * 3600) + ($min * 60) + $sec;
		if (($stamp - $lastud) > 300) {
			$lastud = $stamp;
			tosspacket("^kl]" . $iam);
		}
		{
			lock @tiresult;
			foreach (@tiresult) {
				push @ltiresult, $_;
			}
			@tiresult = ();
			cond_signal(@tiresult);
		}
		foreach (@ltiresult) {
			if (/^\^kl\]/) {
				$thisguy = $';
				$ul{$thisguy} = $stamp;
			}
			elsif (/^\^jn\]/) {
				$thisguy = $';
				unless (exists $ul{$thisguy}) {
					$precat = "\n" . $thisguy . " joined";
					$t->insert('end',$precat,"j");
					$t->yview('moveto','1.0');
				}
				$ul{$thisguy} = $stamp;
				tosspacket("^kl]" . $iam) unless $thisguy eq $iam;
			}
			elsif (/^\^qt\]/) {
				$thisguy = $';
				if (exists $ul{$thisguy}) {
					delete $ul{$thisguy};
					$precat = "\n" . $thisguy . " left";
					$t->insert('end',$precat,"q");
					$t->yview('moveto','1.0');
				}
			}
			else {
				$thisguy = $_ ;
				if ($thisguy =~ /^(.*?)\s(\[.*?\])\s/) {
					$t->insert('end',"\n" . $1 . " ","c1");
					$t->insert('end',$2 . " ","c2");
					$t->insert('end',$',"c3");
					$t->yview('moveto','1.0');
				}
			}
		}
		@ltiresult = ();
		$stext->delete('0.0','end');
		foreach my $uname (sort keys %ul) {
			if (($stamp - $ul{$uname}) > 500) {
				delete $ul{$uname};
				$t->insert('end',"\n$uname timed out","q");
				$t->yview('moveto','1.0');
			}
			else {
				$precat = $uname . "\n";
				$stext->insert("end", $precat);
			}
		}
	}
}

sub tosspacket {
	my ($payload) = shift;
	my $soy = Win32::NetPacket->new(adapter_name => $dnic) or die $@;
	$soyeah =  "\xFF\xFF\xFF\xFF\xFF\xFF" . "\x00\xAA\xBB\xCC\xDD\xEE" . pack("H*",$ethertype) . $payload;
	## TO ADD: If ^^ are odd bits, this will be treated as a multicast MAC address and SHOULD be broadcasted as well, since many devices don't distinguish between broadcast and multicast.  Might be useful for extra evasion.
	$success = $soy->SendPacket($soyeah);
}

sub broadcast {
	$datums = $sentry->get();
	$sentry->delete(0.0,'end');
	$datums = concise($rendecu,$datums,0);
	tosspacket($iam . " [" . $myid . "] " . $datums);
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
