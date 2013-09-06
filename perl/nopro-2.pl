#!/usr/bin/perl
############################################
##                                        ##
##       Runt Frame Comms For LANs        ##
##                                        ##
############################################
## Fait par TUW
## Mai13

## Compile with: pp -o nopro.exe nopro-2.pl

## DATA STRUCTURE:
## %chatrooms{$ethertype}[
##				widgets (0) Room Tabs: [tab(0),entry(1),label(2),scrolled(3),close(4),resize(5),heartbeat(6,7,8),chatoptions(9,10)]
##					    New Tab:   [tab(0),etype(1),letype(2),lnick(3),nick(4),ltrip(5),trip(6),lkey(7),key(8),exit(9),resize(10),joinbutton(11),heartbeat(12,13,14,15),chatoptions(16,17,18)]
##				messages (1) [messageindex][handle,tripcode,message]
##				userlist (2) {username => [lastactiveheartbeattimestamp,lastpackettimestamp]}
##				updatepending (3)
##				options(4) [heartbeat(0), timestamp(1), tripcode(2)]
##			   ]

## FEATURES TO ADD:
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
## 11. PARTIAL: Prefix for pushing files over chat client (stub created, opcode created)
	#create a filebuffer data object
	#send segment/total for each segment
	#then receiver requests segments that didnt arrive or werent the full max seg size
	#then cat buffer together and dump to file
	#field for file name
	#progress bar? progress blocks?
## 16. RARP detection for your source mac, then dynamic mac reallocation.  Similar detection of mac scanners.  Perhaps jump to legit OUIs at http://standards.ieee.org/regauth/oui/index.shtml
## 17. PARTIAL, MORE OPTIONS PENDING: Move options to New Room tab
## 20. Add option to toggle between setting MAC addresses statically, random for every packet, or changes after detection
## 22. On quit, signal child threads so that they might close cleanly.
## 26. User define the heartbeat timings in the UI i guess, if users like that sort of thing and don't want colours changing so often.
## 27. DONE: Move all heartbeat and chat options to be per room, defaulting to whatever the New tab settings are when you join each room, always overridden by local settings

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
## 3. DONE, could use a test or two - Perhaps track and transmit your own keepalives for each tab independantly
## 10. FIXED: Make it more obvious that enter is bound to create tab in New tab etype widget
## 11. Choosing an interface using tabtabtabenter doesnt work like clicking it does, the new widgets exist and accept input, but the frame doesnt refresh
## 13. There is no taskbar icon in overrideredirect mode, and therefore it does not flash
## 14. PARTIAL, test with other people - Keepalive isnt, you know, keeping alive.
## 15. PARTIAL - FIX TURNS OFF WINDOW FLASHING, WHICH WAS BROKEN ANYWAYS.  FIX ALL THAT THEN THIS IS FIXED: Entry widgets aren't regaining focus after a message is submitted
## 17. Find mouseover background colours for buttons and customize them.
## 18. Change individual tab colours for when a channel had an update
## 19. Change nicklist to a scrolled (osoe)
## 20. DONE: Fixed a minor race condition where you could delete a room while the burn loop was still processing its values in the data structure
## 21. Make sure we limit data sent for shell responses if we get more than 5000 or so bytes of data
## 22. When someone freezes out, it freezefloods the channel.  This was after i went from active to disabled, if that matters.

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
use Getopt::Long qw(:config bundling);
our $doansi = 0;
my $halp = 0;

GetOptions(
	"a" => \$doansi,
	"h" => \$halp
	);

if ($halp > 0) {
	print "-h\tThis cruft\n";
	print "-a\tANSI color output\n";
	exit;
}
our @tiresult: shared;
our @trackrooms: shared;
our @ltiresult;
our @leavelist;
our $nic;
our $dnic;
our $iam;
our $myid;
our $ethertype = "0E0E";
our @gg;
our %chatrooms = ();
our $nb;
our $rendecu = "allcalma";
our $tcode = "";
our $active = "New";
our $heartbeat = 2;
our $showtimestamp = 0;
our $showtripcode = 1;

$|++;

print "Running as UID ".ap(31)."$>".ap(0)." at PID ".ap(31)."$$".ap(0)."\n";
my @adpts = Net::Pcap::findalldevs(\$err);
@adpts > 0 or die "No adapters installed !\n";
$numadpt = @adpts;
print ap(36)."$numadpt".ap(0)." adapters found... ";

my $winH = 176 + (($numadpt + 1) * 16);
my $winW = 320;
my $winX = 20;
my $winY = 20;
my $TOP = MainWindow->new();
$SIG{INT} = sub{ quiting(); $TOP->focusForce; $TOP->destroy; };
$TOP->title("NoPro");
$TOP->minsize($winW, $winH);
$TOP->geometry($winW . "x" . $winH . "+" . $winX . "+" . $winX);
$TOP->packPropagate(1);
$TOP->overrideredirect(1);
#$TOP->Icon(-image => $TOP->Photo(-file=>"rigor.bmp"));
my $hl = $TOP->Frame(-height => $winH, -width => $winW)->pack;

my $dragFromX = 0;
my $dragFromY = 0;
my $isDragging = 0;
setdragbindings($hl,0);

$TOP->bind('<Configure>' => sub {
	$xe = $TOP->XEvent;
	unless ($hl->cget(-height) == $xe->h && $hl->cget(-width) == $xe->w) { ## resize frame if it doesnt match TOP's dimensions
		$hl->configure(-width => $xe->w, -height => $xe->h);
	}
});

## Choose adapter - This choice advances to the next screen
for ($g = 0;$g < $numadpt;$g++) {
	$dnic = $adpts[$g];
	Net::Pcap::lookupnet($dnic, \$nip, \$nmask, \$err);
	$thisone = sprintf "%d.%d.%d.%d\/%d.%d.%d.%d",(($nip & 0xFF000000)>>24),(($nip & 0x00FF0000)>>16),(($nip & 0x0000FF00)>>8),($nip & 0x000000FF),(($nmask & 0xFF000000)>>24),(($nmask & 0x00FF0000)>>16),(($nmask & 0x0000FF00)>>8),($nmask & 0x000000FF);
	$gg[$g] = $hl->Button(-text => $thisone, -command => [ \&useThisNIC, $g ])->place(-relwidth => "1.0", -width => "-10", -"y" => (($g * 16) + 5), -height => "16", -x => "5");
}
$gg[$g] = $hl->Button(-text => "Exit", -background => "#FF0000", -command => sub{quiting(); $TOP->destroy;})->place(-height => "16", -width => "45", -rely => "1.0", -"y" => "-21", -relx => "1.0", -x => "-96");
$g++;
$gg[$g] = $hl->Button(-text => "Resize", -background => "#FF6600")->place(-height => "16", -width => "45", -rely => "1.0", -"y" => "-21", -relx => "1.0", -x => "-50");
setdragbindings($gg[$g],1);
MainLoop;

sub ap {
	# 0	Reset / Normal	all attributes off
	# 5	Blink: Slow	less than 150 per minute
	# 30–37	Set text color	30 + x, where x is from the color table below
	# 0	1	2	3	4	5	6	7
	# Black	Red	Green	Yellow	Blue	Magenta	Cyan	White
	return $doansi>0?"\033[".shift."m":"";
}

sub setdragbindings { ## controls screen movement and resizing
	($dobject,$dtype) = @_;
	if ($dtype) { ## type 1 is resize
		$dobject->bind('<ButtonPress-1>', sub {
			$isDragging++;
			$dragFromX = $winW - (($Tk::event->X) - $winX); ## find click offset compared to dimensions of window
			$dragFromY = $winH - (($Tk::event->Y) - $winY);
		});
		$dobject->bind ('<ButtonRelease-1>', sub {
			$isDragging = 0;
		});
		$dobject->bind ('<Motion>', sub {
			return unless $isDragging;
			my $curX = ($Tk::event->X);
			my $curY = ($Tk::event->Y);
			$curX -= ($winX - $dragFromX); ## find new window dimension, minus window position offset, minus resize button offset
			$curY -= ($winY - $dragFromY);
			$winW = $curX;
			$winH = $curY;
			$TOP->geometry($winW.'x'.$winH); ## alot smoother than MoveResizeWindow because you avoid to withdraw/deiconify flicker
		});
	}
	else { ## type 0 is move
		$dobject->bind('<ButtonPress-1>', sub {
			$isDragging++;
			$dragFromX = ($Tk::event->X) - $winX; ## find click offset compared to position of window
			$dragFromY = ($Tk::event->Y) - $winY;
		});
		$dobject->bind ('<ButtonRelease-1>', sub {
			$isDragging = 0;
		});
		$dobject->bind ('<Motion>', sub {
			return unless $isDragging;
			my $curX = ($Tk::event->X);
			my $curY = ($Tk::event->Y);
			$curX -= $dragFromX; ## find new window position compared to where it was when you first clicked to drag
			$curY -= $dragFromY;
			$winX = $curX;
			$winY = $curY;
			$TOP->MoveToplevelWindow($winX,$winY);
		});
	}
}

sub quiting { ## tell errbody you're leaving
	foreach my $quittar (keys %chatrooms) {
		unless ($quittar eq "New") {
			tosspacket($quittar,3,$iam);
		}
	}
}

sub writequeue { ## listen threads
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
		$tempcipher = encode_base64($tempcipher, ""); ## default is \n line separator between each 76 bytes, specify empty string to fix this
		chomp($tempcipher);
		$tempcipher =~ s/=//g;
	}
	return $tempcipher;
}

sub printPackets { ## parses packets
    my (undef,undef,$data) = @_;
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
	($mtype,$remainder) = unpack('a3a*', $xdrstr); ## grab up two bits for message type
	$mtype = parsehdra($mtype); ## convert type to decimal
	($remainder) = $remainder =~ /^(.*?)0*$/; ## remove trailing nulls
	$remainder = substr($remainder, 0, (length($remainder) - 5)); ## remove the 5 padding bits
	$repackxdrstr = pack('B*',$remainder); ## convert payload to ascii
	@peasy = ("","^jn]","^kl]","^qt]","^fl]","^rq]","^ss]","^sr]"); ## conversion table for opcodes: 0 message, 1 join, 2 keepalive, 3 quit, 4 filesend, 5 filerequest, 6 sendtoshell, 7 shellresponse(necessary?)
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
	$chatrooms{$rewm}[3] = "0";
	$chatrooms{$rewm}[0][0] = $nb->add($rewm, -label => $rewm, -raisecmd => sub { raisefocus($rewm) }, -createcmd => [\&raisefocus, "New"]);
	$nb->raise($rewm);
	## Text field
	$chatrooms{$rewm}[0][3] = $chatrooms{$rewm}[0][0]->Scrolled(Text, -relief => "sunken", -borderwidth => "1", -setgrid => "false", -height => "32", -scrollbars => "oe", -wrap => "word", -takefocus => "0")->place(-relheight => "1.0", -height => "-28", -relwidth => "1.0", -width => "-102", -"y" => "5", -x => "5");
	$chatrooms{$rewm}[0][3]->mark(qw/set insert end/);
	$chatrooms{$rewm}[0][3]->tagConfigure("c1", -foreground => "#10AF10"); ## handle colour
	$chatrooms{$rewm}[0][3]->tagConfigure("c2", -foreground => "#CF9F10"); ## tripcode colour
	$chatrooms{$rewm}[0][3]->tagConfigure("c3", -foreground => "#000000"); ## text colour
	$chatrooms{$rewm}[0][3]->tagConfigure("q", -foreground => "#AF1010"); ## quit colour
	$chatrooms{$rewm}[0][3]->tagConfigure("j", -foreground => "#1010AF"); ## join colour
	$chatrooms{$rewm}[0][3]->tagConfigure("s", -foreground => "#303030"); ## shell colour
	## Check if the room is a known protocol
	if (chkethertype($rewm) ne "Unassigned") {
		$chatrooms{$rewm}[0][3]->insert('end',chkethertype($rewm),"q");
		$chatrooms{$rewm}[0][3]->yview('moveto','1.0');
	}
	## Room options
	$chatrooms{$rewm}[4][0] = $heartbeat;
	$chatrooms{$rewm}[4][1] = $showtimestamp;
	$chatrooms{$rewm}[4][2] = $showtripcode;
	$chatrooms{$rewm}[0][6] = $chatrooms{$rewm}[0][0]->Radiobutton(-text => "Act", -indicatoron => "0", -selectcolor => "#00FF00", -activebackground => "#00FF00", -value => "2", -variable => \$chatrooms{$rewm}[4][0])->place(-height => "16", -width => "30", -rely => "1.0", -"y" => "-53", -relx => "1.0", -x => "-96");
	$chatrooms{$rewm}[0][7] = $chatrooms{$rewm}[0][0]->Radiobutton(-text => "Adp", -indicatoron => "0", -selectcolor => "#7F00FF", -activebackground => "#7F00FF", -value => "1", -variable => \$chatrooms{$rewm}[4][0])->place(-height => "16", -width => "30", -rely => "1.0", -"y" => "-53", -relx => "1.0", -x => "-66");
	$chatrooms{$rewm}[0][8] = $chatrooms{$rewm}[0][0]->Radiobutton(-text => "Dis", -indicatoron => "0", -selectcolor => "#00FFFF", -activebackground => "#00FFFF", -value => "0", -variable => \$chatrooms{$rewm}[4][0])->place(-height => "16", -width => "30", -rely => "1.0", -"y" => "-53", -relx => "1.0", -x => "-36");
	$chatrooms{$rewm}[0][9] = $chatrooms{$rewm}[0][0]->Checkbutton(-text => "Time", -indicatoron => "0", -selectcolor => "#1010AF", -activebackground => "#1010AF", -variable => \$chatrooms{$rewm}[4][1])->place(-height => "16", -width => "45", -rely => "1.0", -"y" => "-37", -relx => "1.0", -x => "-96");
	$chatrooms{$rewm}[0][10] = $chatrooms{$rewm}[0][0]->Checkbutton(-text => "Trip", -indicatoron => "0", -selectcolor => "#CF9F10", -activebackground => "#CF9F10", -variable => \$chatrooms{$rewm}[4][2])->place(-height => "16", -width => "45", -rely => "1.0", -"y" => "-37", -relx => "1.0", -x => "-50");
	## Leave button
	$chatrooms{$rewm}[0][4] = $chatrooms{$rewm}[0][0]->Button(-text => "Close", -background => "#FF0000", -command => sub{leaveroom($rewm)})->place(-height => "16", -width => "45", -rely => "1.0", -"y" => "-21", -relx => "1.0", -x => "-96");
	## Resize button
	$chatrooms{$rewm}[0][5] = $chatrooms{$rewm}[0][0]->Button(-text => "Resize", -background => "#FF6600")->place(-height => "16", -width => "45", -rely => "1.0", -"y" => "-21", -relx => "1.0", -x => "-50");
	setdragbindings($chatrooms{$rewm}[0][5],1);
	## Namelist
	$chatrooms{$rewm}[0][2] = $chatrooms{$rewm}[0][0]->Text()->place(-relheight => "1.0", -height => "-60", -width => "91", -"y" => "5", -relx => "1.0", -x => "-96"); ## Change this to a scrolled later
	$chatrooms{$rewm}[0][2]->tagConfigure("hb", -background => "#00FF00"); ## heartbeat good colour, for active heartbeat while idle, lasts 700 seconds
	$chatrooms{$rewm}[0][2]->tagConfigure("hc1", -background => "#FF0000"); ## heatmap warm colour, these are all for passive heartbeats based on message traffic, degrades one per minute
	$chatrooms{$rewm}[0][2]->tagConfigure("hc2", -background => "#FF33CC"); ## heatmap luke colour
	$chatrooms{$rewm}[0][2]->tagConfigure("hc3", -background => "#7F00FF"); ## heatmap room colour
	$chatrooms{$rewm}[0][2]->tagConfigure("hc4", -background => "#3366FF"); ## heatmap cool colour
	$chatrooms{$rewm}[0][2]->tagConfigure("hc5", -background => "#00FFFF"); ## heatmap ice cold! colour
	## Input widget
	$chatrooms{$rewm}[0][1] = $chatrooms{$rewm}[0][0]->Entry()->place(-height => "16", -relwidth => "1.0", -width => "-102", -rely => "1.0", -"y" => "-21", -x => "5");
	$chatrooms{$rewm}[0][1]->bind('<Return>' ,sub{broadcast($rewm); });
	$chatrooms{$rewm}[0][1]->focus;
	{ ## this essentially enables sniffing for this ethertype
		lock @trackrooms;
		push @trackrooms, "+" . $rewm; ## Omit the + sign for leaving a room
		cond_signal(@trackrooms);
	}
	tosspacket($rewm,1,$iam); # initial join message
}

sub leaveroom { ## close a tab and stop listening for events on its ethertype
	$ltabname = shift;
	tosspacket($ltabname,3,$iam);
	{
		lock @trackrooms;
		push @trackrooms, $ltabname; ## Omit the + sign for leaving a room
		cond_signal(@trackrooms);
	}
	push @leavelist, $ltabname; ## schedule removal of this room, so that we don't get race errors in our burn loop
}

sub raisefocus{ ## puts keyboard focus on the entry widgets when you switch tabs
	$active = shift;
	$chatrooms{$active}[3] = 0; ## Reset pending updates counter for this room
	if ($chatrooms{$active}[0][1]) { ## This keeps raisefocus from raising errors before the entry widgets are defined
		$chatrooms{$active}[0][1]->focus;
	}
}

sub useThisNIC { ## create main tk and main burn loop
	my ($useNIC) = @_;
	$dnic = $adpts[$useNIC];
	foreach my $zong (@gg) {
		$zong->placeForget;
	}
	$nb = $hl->NoteBook(-tabpadx => 0, -tabpady => 0)->place(-relheight => "1.0", -relwidth => "1.0");
	setdragbindings($nb,0);
	$chatrooms{"New"}[3] = "0";
	$chatrooms{"New"}[0][0] = $nb->add("New", -label => "New", -raisecmd => sub { raisefocus("New") }, -createcmd => [\&raisefocus, "New"]);
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
	## Join a channel
	$chatrooms{"New"}[0][2] = $chatrooms{"New"}[0][0]->Label(-text => "EType")->place(-height => "16", -width => "50", -"y" => "53", -x => "5");
	$chatrooms{"New"}[0][1] = $chatrooms{"New"}[0][0]->Entry()->place(-height => "16", -relwidth => "1.0", -width => "-100", -"y" => "53", -x => "60");
	$chatrooms{"New"}[0][1]->bind('<Key>' => [\&newroomvalidation,Ev('N'),$chatrooms{"New"}[0][1],\$ethertype]);
	$chatrooms{"New"}[0][1]->insert('end',$ethertype);
	$chatrooms{"New"}[0][11] = $chatrooms{"New"}[0][0]->Button(-text => "Join", -command => [\&newroomvalidation,'65293','65293',$chatrooms{"New"}[0][1],\$ethertype])->place(-height => "16", -relx => "1.0", -width => "35", -"y" => "53", -x => "-40"); ## hardcoded 65293 makes this work like an enter key, we pass it twice because command callbacks are different than keybind callbacks, apparently
	## Heartbeat checkbutton
	$chatrooms{"New"}[0][12] = $chatrooms{"New"}[0][0]->Label(-anchor => 'w', -text => "Heartbeat")->place(-height => "16", -width => "95", -"y" => "76", -x => "5");
	$chatrooms{"New"}[0][13] = $chatrooms{"New"}[0][0]->Radiobutton(-anchor => 'w', -value => "2", -variable => \$heartbeat, -text => "Active")->place(-height => "16", -width => "95", -"y" => "92", -x => "5");
	$chatrooms{"New"}[0][14] = $chatrooms{"New"}[0][0]->Radiobutton(-anchor => 'w', -value => "1", -variable => \$heartbeat, -text => "Adaptive")->place(-height => "16", -width => "95", -"y" => "108", -x => "5");
	$chatrooms{"New"}[0][15] = $chatrooms{"New"}[0][0]->Radiobutton(-anchor => 'w', -value => "0", -variable => \$heartbeat, -text => "Disabled")->place(-height => "16", -width => "95", -"y" => "124", -x => "5");
	## Chat options
	$chatrooms{"New"}[0][16] = $chatrooms{"New"}[0][0]->Label(-anchor => 'w', -text => "Chat Options")->place(-height => "16", -width => "115", -"y" => "76", -x => "100");
	$chatrooms{"New"}[0][17] = $chatrooms{"New"}[0][0]->Checkbutton(-anchor => 'w', -variable => \$showtimestamp, -text => "Show Timestamps")->place(-height => "16", -width => "115", -"y" => "92", -x => "100");
	$chatrooms{"New"}[0][18] = $chatrooms{"New"}[0][0]->Checkbutton(-anchor => 'w', -variable => \$showtripcode, -text => "Show Tripcodes")->place(-height => "16", -width => "115", -"y" => "108", -x => "100");
	## Exit button
	$chatrooms{"New"}[0][9] = $chatrooms{"New"}[0][0]->Button(-text => "Exit", -background => "#FF0000", -command => sub{quiting(); $TOP->destroy;})->place(-height => "16", -width => "45", -rely => "1.0", -"y" => "-21", -relx => "1.0", -x => "-96");
	## Resize button
	$chatrooms{"New"}[0][10] = $chatrooms{"New"}[0][0]->Button(-text => "Resize", -background => "#FF6600")->place(-height => "16", -width => "45", -rely => "1.0", -"y" => "-21", -relx => "1.0", -x => "-50");
	setdragbindings($chatrooms{"New"}[0][10],1);

	$nb->configure(-bd => 1, -background => "#303090", -foreground => "#FF00FF", -inactivebackground => "#E0E0E0");
		
	threads->new(\&writequeue, $useNIC);

	while (1) { ##  main burn loop, checks for new messages, handles updates to ulist and does keepalive pings
		select(undef, undef, undef, 0.02); ## Burn Slower
		foreach my $leavings (@leavelist) {
			delete $chatrooms{$leavings};
			$nb->delete($leavings);
		}
		@leavelist = ();
		$TOP->update();
		($sec,$min,$hora,$diem,undef,undef) = localtime(time);
		$stamp = ($diem * 86400) + ($hora * 3600) + ($min * 60) + $sec;
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
			if ($lti =~ /^\^kl\]/) { ## keepalive
				$thisguy = $';
				$chatrooms{$ltitype}[2]{$thisguy}[0] = $stamp;
				$chatrooms{$ltitype}[2]{$thisguy}[1] = $stamp;
			}
			elsif ($lti =~ /^\^jn\]/) { ## join
				$thisguy = $';
				$chatrooms{$ltitype}[2]{$thisguy}[1] = $stamp;
				unless (exists $chatrooms{$ltitype}[2]{$thisguy}) {
					$precat = "\n" . $thisguy . " joined";
					$chatrooms{$ltitype}[0][3]->insert('end',$precat,"j");
					$chatrooms{$ltitype}[0][3]->yview('moveto','1.0');
					if ($chatrooms{$ltitype}[4][0] == "2") { ## active heartbeat, so we send heartbeat so this guy knows we're here
						tosspacket($ltitype,2,$iam) unless $thisguy eq $iam;
					}
					elsif ($chatrooms{$ltitype}[4][0] == "1") { ## adaptive heartbeat, so we send a join instead. this _shouldnt_ spam because it checks for exists
						tosspacket($ltitype,1,$iam) unless $thisguy eq $iam;
					}
				}
			}
			elsif ($lti =~ /^\^qt\]/) { ## quit
				$thisguy = $';
				if (exists $chatrooms{$ltitype}[2]{$thisguy}) {
					delete $chatrooms{$ltitype}[2]{$thisguy};
					$precat = "\n" . $thisguy . " left";
					$chatrooms{$ltitype}[0][3]->insert('end',$precat,"q");
					$chatrooms{$ltitype}[0][3]->yview('moveto','1.0');
				}
			}
			elsif ($lti =~ /^\^fl\]/) { ## filesend - getting this here means we are receiving a file, populate filereceive for filename
				$thisguy = concise($rendecu,$',1);
				$chatrooms{$ltitype}[2]{$thisguy}[1] = $stamp;
				($fielname,$segnum,$maxseg,$segment) = $thisguy =~ /^(.*?)\s(.*?)\s(.*?)\s(.*)$/;
				
				$recvbuffer{$fielname}[$segnum] = $segment;
				$incomplete = 0;
				for ($segi = 0;$segi < $maxseg;$segi++) {
					$incomplete = 1 if $recvbuffer{$fielname}[$segi] eq "";
				}
				unless ($incomplete) { ## when you have all file segments
					open(FH,">>$fielname"); ## append writes
						foreach my $part (@{$recvbuffer{$fielname}}) { # is this array dereference right?
							print FH $part; ## is this right too?
						}
						delete $recvbuffer{$fielname}; ## clear recvbuffer for this file
					close(FH);
				}
			}
			elsif ($lti =~ /^\^rq\]/) { ## filerequest
				# add this once you have $thisguy resolution: $chatrooms{$ltitype}[2]{$thisguy}[1] = $stamp;
				## this will be for requesting file segments to start with, and then when we get agents working this will be for retrieving remote files from the agent
			}
			elsif ($lti =~ /^\^ss\]/) { ## shellsend
				## dont open a shell here, since we arent an agent, just parrot back the command so that we know what it was
				$thisguy = concise($rendecu,$',1);
				$chatrooms{$ltitype}[2]{$thisguy}[1] = $stamp;
				$chatrooms{$ltitype}[0][3]->insert('end',$thisguy,"s");
				$chatrooms{$ltitype}[0][3]->yview('moveto','1.0');
				##$TOP->focus(-force);
			}
			elsif ($lti =~ /^\^sr\]/) { ## shellresponse
				$thisguy = $1 . concise($rendecu,$',1);
				if ($thisguy =~ /^(.*?)\s(\[.*?\])\s/) {
					$chatrooms{$ltitype}[2]{$1}[1] = $stamp;
					$chatrooms{$ltitype}[0][3]->insert('end',"\n");
					$chatrooms{$ltitype}[0][3]->insert('end',$hora . ":" . sprintf("%02d",$min) . ":" . sprintf("%02d",$sec) . " ","j") if $chatrooms{$ltitype}[4][1]; # timestamp
					$chatrooms{$ltitype}[0][3]->insert('end',$1 . " ","c1"); # name
					$chatrooms{$ltitype}[0][3]->insert('end',$2 . " ","c2") if $chatrooms{$ltitype}[4][2]; # tripcode
					$chatrooms{$ltitype}[0][3]->insert('end',$',"s"); # text
					$chatrooms{$ltitype}[0][3]->yview('moveto','1.0');
					##$TOP->focus(-force); # this fucks with entry widgets regaining focus after you type a message, move this outside just message events anyways
					unless ($ltitype eq $active) {
						$chatrooms{$ltitype}[3]++; ## flash message updates, move this to all updates later
					}
				}
			}
			elsif ($lti =~ /^(.*?\s\[.*?\]\s)/) { # messages
				$thisguy = $1 . concise($rendecu,$',1);
				if ($thisguy =~ /^(.*?)\s(\[.*?\])\s/) {
					$chatrooms{$ltitype}[2]{$1}[1] = $stamp;
					$chatrooms{$ltitype}[0][3]->insert('end',"\n");
					$chatrooms{$ltitype}[0][3]->insert('end',$hora . ":" . sprintf("%02d",$min) . ":" . sprintf("%02d",$sec) . " ","j") if $chatrooms{$ltitype}[4][1]; # timestamp
					$chatrooms{$ltitype}[0][3]->insert('end',$1 . " ","c1"); # name
					$chatrooms{$ltitype}[0][3]->insert('end',$2 . " ","c2") if $chatrooms{$ltitype}[4][2]; # tripcode
					$chatrooms{$ltitype}[0][3]->insert('end',$',"c3"); # text
					$chatrooms{$ltitype}[0][3]->yview('moveto','1.0');
					##$TOP->focus(-force); # this fucks with entry widgets regaining focus after you type a message, move this outside just message events anyways
					unless ($ltitype eq $active) {
						$chatrooms{$ltitype}[3]++; ## flash message updates, move this to all updates later
					}
				}
			}
		}
		@ltiresult = ();
		foreach my $checkfordead (keys %chatrooms) {
			if ($chatrooms{$checkfordead}[3] > 0) { ## i guess this is where i would put tab flashing on updates, if it worked
				#$chatrooms{$checkfordead}[0][0]->configure(-label => "");
				#$TOP->update;
				#$chatrooms{$checkfordead}[0][0]->configure(-label => $checkfordead);
				#$TOP->update;
			}
			unless ($checkfordead eq "New") { ## this occurs for each 0.02 burn loop of usethisnic.  this might be updating the UI kinda too often. change to only change things when events occur or when timers warrant it.
				$precat = "";
				$chatrooms{$checkfordead}[0][2]->delete('0.0','end');
				foreach my $uname (sort keys %{$chatrooms{$checkfordead}[2]}) {
					if (defined($chatrooms{$checkfordead}[2]{$uname}[0])) { ## if this is an active heartbeater
						if (($stamp - $chatrooms{$checkfordead}[2]{$uname}[0]) > 700) { ## allow two update intervals before assuming gone
							undef $chatrooms{$checkfordead}[2]{$uname}[0]; # now considered an adaptive(expired) heartbeater
							goto WORMS;
						}
						else {
							$chatrooms{$checkfordead}[0][2]->insert('end',$uname . "\n","hb"); #update with the lucrative active heartbeat colour
						}
					}
					else { # adaptive(pure) and disabled heartbeaters
						WORMS:
						
						if (($stamp - $chatrooms{$checkfordead}[2]{$uname}[1]) > 700) { ## these will have never had an active timestamp, so compared against traffic timestamps
							$counter = 0;
							delete ${$chatrooms{$checkfordead}[2]}{$uname}; # too cold to survive <- what happens if this is me? do i delete myself if i'm disabled mode?
							$chatrooms{$checkfordead}[0][3]->insert('end',"\n$uname froze out","q");  # i freeze myself out when i first join, initialize myself before i get added to the nicklist somehow
							$chatrooms{$checkfordead}[0][3]->yview('moveto','1.0');
						}
						elsif (($stamp - $chatrooms{$checkfordead}[2]{$uname}[1]) > 560) { #ice cold!
							$chatrooms{$checkfordead}[0][2]->insert('end',$uname . "\n","hc5"); 
						}
						elsif (($stamp - $chatrooms{$checkfordead}[2]{$uname}[1]) > 420) { #cool
							$chatrooms{$checkfordead}[0][2]->insert('end',$uname . "\n","hc4"); 
						}
						elsif (($stamp - $chatrooms{$checkfordead}[2]{$uname}[1]) > 280) { #room
							$chatrooms{$checkfordead}[0][2]->insert('end',$uname . "\n","hc3"); 
						}
						elsif (($stamp - $chatrooms{$checkfordead}[2]{$uname}[1]) > 140) { #luke
							$chatrooms{$checkfordead}[0][2]->insert('end',$uname . "\n","hc2"); 
						}
						else { # hot
							$chatrooms{$checkfordead}[0][2]->insert('end',$uname . "\n","hc1"); 
						}
					}
					if ($uname eq $iam && defined($chatrooms{$checkfordead}[2]{$uname})) { ## hey, it's me!  (heartbeats are 0 disabled, 1 adaptive, and 2 active)
						if (defined($chatrooms{$checkfordead}[2]{$uname}[0])) { # my heartbeat on record
							if (($stamp - $chatrooms{$checkfordead}[2]{$uname}[0]) > 300) {
								tosspacket($checkfordead,2,$iam); ## active needs heartbeat, adaptive clears timestamps and wont get here unless you've idled for 5
							}
						}
						else { # no heartbeat on record
							if ($chatrooms{$checkfordead}[4][0] == "2") { ## if active heartbeat
								tosspacket($checkfordead,2,$iam);
							}
							elsif ($chatrooms{$checkfordead}[4][0] == "1") { ## if adaptive heartbeat
								if (($stamp - $chatrooms{$checkfordead}[2]{$uname}[1]) > 300) { # we've done no actions in 5 minutes, we check if define earlier, because i think checking this timestamp makes the uname exist again after it's froze out
									tosspacket($checkfordead,2,$iam); ## force an active heartbeat
								}
							}
						}
					}
				}
			}
		}
	}
}

sub sendfiel { ## Send a file over the network
	my ($betype) = shift;
	my @types = (["All Files", "*"] );
	my $openfile = $hl->getOpenFile(-title => "Send File", -filetypes => \@types);
	$fielslurp = "";
	open(LSETT, $openfile) or return;  ## fail happily if you can't or won't open a file
	while (<LSETT>) {
		$fielslurp .= $_;
	    close(LSETT);
	}
	# ADD: get rid of path information and assign to $openfile
	$fiellen = length($fielslurp);
	$totalsegments = int($fiellen / 1400);
	if ($fiellen % 1400) {
		$totalsegments++;
	}
	
	for ($segnum = 0;$segnum < $totalsegments;$segnum++) {
		$thissegment = substr($fielslurp,$segnum * 1400,1400);  ## does this work, or should i calc len if we're at eof?
		$datums = $openfile . " " . $segnum . " " . $totalsegments . " " . $thissegment;
		$datums = concise($rendecu,$datums,0);
		tosspacket($betype,4,"^fl]" . $datums); ## type 4 is filesend
		#maybe sleep and update UI in between file segments
	}
}

sub tosspacket { ## crafts packets
	## Message \b00, Join \b01, Keepalive \b10, Quit \b11
	my ($tptype,$ptype,$payload) = @_; ## ethertype, opcode, payload
	if ($chatrooms{$tptype}[4][0] == "0") { ## disabled heartbeat mode doesnt send joins, quits, or keepalives
		if ($ptype == "1" || $ptype == "2" || $ptype == "3") {
			return;
		}
	}
	if ($chatrooms{$tptype}[4][0] == "1") { ## adaptive, any traffic negates the need for a heartbeat for now
		if (defined($chatrooms{$tptype}[2]{$iam}[0])) {
			delete $chatrooms{$tptype}[2]{$iam}[0];
		}
	}
	## manual binary generation, to keep automatic zero padding from occuring	
	$bptype = unpack('B8',$ptype);
	(undef,$aptype) = unpack('a5a3', $bptype); ## grab just three bits of data for packet type, i'm not sure this is working either. apparently i'm bad at decimal to binary
	
	$pp = unpack('B*',$payload);
	$pa = unpack('a*', $pp); ## convert ascii payload to bits
	
	$padding = int(rand(64));
	$padding = pack("n*",$padding); ## a short, so 16 bits
	$bpadding = unpack('B*',$padding);
	(undef,$bp) = unpack('a12a4', $bpadding); ## generate four + one bits of random data for padding # not sure if this is going random properly or if it's all ascii representations of numbers
	$bp .= 1;

	my $soy = Win32::NetPacket->new(adapter_name => $dnic) or die $@;
	
	$sourcemac = "";
	for ($octet = 0; $octet < 6; $octet++) { # generate our source mac address
		$toctet = int(rand(256));
		if ($octet == 0) { # for the first octet of the source mac
			$toctet = $toctet >> 2;
			$toctet = $toctet << 2;
			## this keeps the most significant bit (since we are network byte order, and therefore big-endian)
			## of the first octet a multiple of four (by zeroing the one and two bit), to look like a legitmate manufacturer OUI.
			## With any even source MAC address, the radius authenticator sends 802.1x EAP Request Identity to try to identify me.
			## With odd source MACs it does not, but those PROBABLY do not get forwarded by the switch,
			## since responding would cause the destination device to inadvertantly broadcast, 
			## which is usually not a desirable trait.  You could set your MAC to a MAC you sniff off the wire
			## to perhaps evade port security for some while, though it _may_ corrupt ARP tables for some values of ARP, I expect.
			## The radius authenticator seems content to ping me for EAP Identity requests on mod 4=2 source MAC OUIs, which
			## also supports the idea that broad/multicast source MAC addresses aren't being relayed to it, since mod 2=1 OUIs are
			## generally considered broad/multi, and mod 4=2 OUIs are unicast and therefore legit but non-standard and therefore suspect.
			## EAP Identity Request Timeout defaults to 1 second IOS 4.1 and older. and 30 seconds on IOS 4.2 and newer
			## EAP Identify Request Max Retries default to 2, Recommened set to 12.  Removes supplicant entry from MSCB (Mobile Station Control Block)
			## (which should keep me from sending any packets) and the WLC (Wireless LAN Controller) (does this apply only to wireless?)
			## sends a de-auth frame to the client, forcing the EAP process to restart.
			## I'm curious if certain MAC addresses I've used in the past are blocked in any way currently.
		}
		$sourcemac .= chr($toctet);
	}
	#$sourcemac = "\x00\xAA\xBB\xCC\xDD\xEE";  ## uncomment if you're into hardcoding
	$soyeah =  "\xFF\xFF\xFF\xFF\xFF\xFF" . $sourcemac . pack("H*",$tptype) . pack('B*',$aptype . $pa . $bp); ## pack two bits of ptype, eleven bits of size, payload in mults of 8, and two random bits.  This keeps ascii from being displayed overtly on sniffers without having to add another encryption layer
	## TO ADD: If ^^ are odd bits, this will be treated as a multicast MAC address and SHOULD be broadcasted as well, since many devices don't distinguish between broadcast and multicast.  Might be useful for extra evasion.
	## Note: I think my interface or some switch is adding nulls to make my packets a good length, so we account for this in printpackets.
	$soy->SendPacket($soyeah);
}

sub broadcast { ## encrypts text from entry widgets then sends it to the packet crafter
	my ($betype) = shift;
	$datums = $chatrooms{$betype}[0][1]->get();
	$chatrooms{$betype}[0][1]->delete(0.0,'end');
	$datums = concise($rendecu,$datums,0);
	tosspacket($betype,0,$iam . " [" . $myid . "] " . $datums); ## type 0 is message
}

sub print_keysym { ## masks entry fields, input is KeyPressed, Reference to Entry Widget, Reference to Value Scalar
	my($keysym_decimal,$sacredobj,$reftohidden) = ($_[1],$_[2],$_[3]);
	if ($keysym_decimal > 31 && $keysym_decimal < 127) {
		$$reftohidden .= chr($keysym_decimal);
		$sacredobj->delete('0.0','end');
		$sacredobj->insert('end',"*" x length($$reftohidden));
	}
	elsif ($keysym_decimal == 65288 || $keysym_decimal == 65535) { ## backspace and delete
		$$reftohidden = "";
		$sacredobj->delete('0.0','end');
	}
	elsif ($keysym_decimal == 65289 || $keysym_decimal == 65505) { ## return to use default tab and shift bindings
		return;
	}
	$myid = $iam . $tcode; ## salt tripcode with handle
	$myid = concise($rendecu,$myid,0); ## encipher, to add a little more computational cost.
	$myid = encode_base64($myid); ## then base64 to display nicely
	chomp($myid); ## get rid of newline cruft
	$myid =~ s/=//g; ## get rid of base64 cruft
	$myid = substr $myid, -6; ## truncate to the last 6 chars so this doesnt get out of hand.  Being lossy, this also makes the cipher one-way
	##$TOP->title("NoPro - $iam [$myid] " . ("*" x length($rendecu)));

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

sub chkethertype { ## returns ethertypes from numbers
	my ($ethercomp) = shift;
	%suparEther = (
		'0800', 'Internet Protocol version 4 (IPv4)',
		'0802', 'Cisco Discovery Protocol, VLAN Trunking Protocol, or Spanning Tree Protocol',
		'0806', 'Address Resolution Protocol (ARP)',
		'0808', 'RFC1701 (GRE)',
		'0842', 'Wake-on-LAN',
		'22F3', 'IETF TRILL Protocol',
		'6003', 'DECnet Phase IV',
		'8035', 'Reverse Address Resolution Protocol',
		'809B', 'AppleTalk (Ethertalk)',
		'80F3', 'AppleTalk Address Resolution Protocol (AARP)',
		'8100', 'VLAN-tagged frame (IEEE 802.1Q) & Shortest Path Bridging IEEE 802.1aq',
		'8137', 'IPX',
		'8138', 'IPX',
		'8204', 'QNX Qnet',
		'86DD', 'Internet Protocol Version 6 (IPv6)',
		'8808', 'Ethernet Flow Control',
		'8809', 'Ethernet OAM Protocol IEEE 802.3ah (Slow Protocols)',
		'8819', 'CobraNet',
		'8847', 'MPLS unicast',
		'8848', 'MPLS multicast',
		'8863', 'PPPoE Discovery Stage',
		'8864', 'PPPoE Session Stage',
		'8870', 'Jumbo Frames',
		'887B', 'HomePlug 1.0 MME',
		'888E', 'EAP over LAN (IEEE 802.1X)',
		'8892', 'PROFINET Protocol',
		'889A', 'HyperSCSI (SCSI over Ethernet)',
		'88A2', 'ATA over Ethernet',
		'88A4', 'EtherCAT Protocol',
		'88A8', 'Provider Bridging (IEEE 802.1ad) & Shortest Path Bridging IEEE 802.1aq',
		'88AB', 'Ethernet Powerlink[citation needed]',
		'88CC', 'Link Layer Discovery Protocol (LLDP)',
		'88CD', 'SERCOS III',
		'88E1', 'HomePlug AV MME',
		'88E3', 'Media Redundancy Protocol (IEC62439-2)',
		'88E5', 'MAC security (IEEE 802.1AE)',
		'88F7', 'Precision Time Protocol (IEEE 1588)',
		'8902', 'IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)',
		'8906', 'Fibre Channel over Ethernet (FCoE)',
		'8914', 'FCoE Initialization Protocol',
		'8915', 'RDMA over Converged Ethernet (RoCE)',
		'9000', 'Ethernet Configuration Testing Protocol',
		'9100', 'Q-in-Q',
		'CAFE', 'Veritas Low Latency Transport (LLT) for Veritas Cluster Server'
	);
	if (exists $suparEther{$ethercomp}) {
		return $suparEther{$ethercomp};
	}
	else { return "Unassigned"; }
}
