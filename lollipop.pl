#!/usr/bin/perl -w
# 
#    lollipop.pl
#
#    pop3 server v0.3
#     limitations: maildir, cleartext auth, mail length problems
#
#    Copyright (C) 2005 Gergely Gati
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software Foundation,
#    Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#
#    e-mail: gati.gergely@gmail.com
#

use IO::Socket;
use Carp;

sub spawn;

 
$version="V0.3";
$prog="lollipop";
$cachename=".".$prog."_last_";
#$DEBUG=1;

%tokens=
(
  "AUTHORIZATION" => 
  {
  	'' => [ \&do, "",'+OK lollipop POP3 server ready' ],
  	'QUIT' => [ \&do, "UPDATE",'' ],
  	'USER' => [ \&douser, "",'+OK I need password as well|-ERR badly formed username' ],
  	'PASS' => [ \&dopass, "TRANSACTION", '+OK master|-ERR byebye' ],
  	'APOP' => [ \&doapop, "TRANSACTION", '+OK master|-ERR unsupported' ],
        'CAPA' => [ \&docapa, "", '' ],
  },
  "TRANSACTION" =>
  {
    '' => [ \&dotransaction, "", '' ],
    'QUIT' => [ \&do, "UPDATE", '' ],
    'STAT' => [ \&dostat, "", '' ],
    'LIST' => [ \&dolist, "", '' ],
    'RETR' => [ \&doretr, "", '' ],
    'DELE' => [ \&dodele, "", '' ],
    'NOOP' => [ \&donoop, "", '+OK' ],
    'RSET' => [ \&dorset, "", '+OK|-ERR unsupported' ],
    'TOP' => [ \&dotop, "", '' ],
    'UIDL' => [ \&douidl, "", '' ],
    'CAPA' => [ \&docapa, "", '' ],
  },
  "UPDATE" =>
  {
    '' => [ \&doupdate, "", '+OK lollipop signing off' ],
  },
);

$ses{'user'}="";
$ses{'home'}="";
$ses{'size'}=0;
$ses{'last'}=-1;
$ses{'peername'}="UNNAMED";
@mails=();
@mailsiz=();
@mailinf=();   # flag string; _D_elete, _R_etrieved,_N_ewfolder

sub trim($)
{
  my $string = shift;
  $string =~ s/^\s+//;
  $string =~ s/\s+$//;
  return $string;
}

sub mlog($;$)
{
  my ($p,$m);
  
  $p=$_[0];
  $m=$_[1];
  system("logger -i -p mail.$p -t $prog $m");
}

sub topeer($;$;$)
{
  my ($peer,$m);

  $peer=$_[0];
  $m=$_[1];
  if(!defined $_[2] || $_[2]==0) { $m.="\r\n"; }
  if(defined $DEBUG) { print $m; }
  print $peer $m;
}

sub identifypeer($)
{
  my ($pad,$port,$iaddr,$ip,$chost);

  $pad=getpeername($_[0]) || return"UNDEFINED";
  ($port,$iaddr)=unpack_sockaddr_in($pad);
  $ip=inet_ntoa($iaddr);
  $chost=gethostbyaddr($iaddr,AF_INET);
  gethostbyname($chost) || return("?".$chost);
  return($chost);
}


sub server
{
  my ($sock,$new_sock);
  
  $SIG{CHLD} = 'IGNORE';
  $sock = new IO::Socket::INET (
    LocalHost => '0.0.0.0',
    LocalPort => '110',
    Proto => 'tcp',
    Listen => 1,
    Reuse => 1,
  );
  die "Could not create socket: $!\r\n" unless $sock;

  while(1)
  {
    $new_sock = $sock->accept();
    if(fork()==0)
    {
      # child
      $ses{'user'}="";
      $ses{'home'}="";
      $ses{'size'}=0;
      @mails=();
      @mailsiz=();
      @mailinf=();
      dothread($new_sock);
      close($new_sock);
      exit(0);
    }
    close($new_sock);
  }
  close($sock);
}

sub mreaddir
{
  my ($ret,$siz,$dir,$i,$pat,$flg,$nam);
  
  $ret=1;
  if(0 == @mails)
  {
    @mails=();
    @mailsiz=();
    @mailinf=();
    $ses{'size'}=0;
    $ses{'last'}=-1;
    # check user cache file
    $nam=$ses{'home'}."/.maildir/".$cachename.$ses{'peername'};
    if(open(FIL,$nam)) {
      $pat=<FIL>;
      close(FIL);
    } else { $pat=""; }
    $dir=$ses{'home'}."/.maildir/cur";
    for($flg="",$i=0;$i<2;$i++)
    {
      if(opendir(DIRHANDLE,$dir)) {
        foreach $name (sort readdir(DIRHANDLE)) {
          unless($name=~/^\./) {
          $name=$dir."/".$name;
            if("" eq $pat || $name gt $pat) {
              push @mails,$name;
              $siz=-s $name;
              $siz+=int($siz/30);
              push @mailsiz,$siz;
              $ses{'size'}+=$siz;
              push @mailinf,$flg;
            }
          }
        }
        closedir(DIRHANDLE);
      }
      else {
        mlog("warning",("User ".$ses{'user'}." has no .maildir!"));
        $ret=0;
        last;
      }
      $dir=$ses{'home'}."/.maildir/new";
      $pat="";
      $flg="n";
    }
  }
  return $ret;
}


sub douser($) # USER u
{
  $ses{'user'}=$_[2];
  return 0; # mindig sikeres
}

sub dopass($) # PASS p
{
  my ($ret,$name,$pass,$dir,$a);
  
  $ret=-1;		# ez nem mindig sikeres
  if("" ne $ses{'user'} && defined $_[2])
  {
    ($name,$pass,$a,$a,$a,$a,$a,$dir)=getpwnam($ses{'user'});
    if(defined $name) {
      $ses{'home'}=$dir;
      if(crypt($_[2],$pass) eq $pass ) { 
        mlog("info",$ses{'user'}." authenticated");
        $ret=0; 
      }
    }
  }
  if($ret!=0) {
    mlog("warning","access denied for ".$ses{'user'});
  }
  return $ret;
}

sub doapop($) # APOP n d
{
  return -1; # not supported yet
}

sub dotransaction($) # state
{
  # itt nezzuk meg az user cuccait
  return 0;
}

sub dostat($) # spec reply! handle here
{
  my ($peer);

  $peer=$_[0];
  mreaddir();
  topeer($peer,"+OK ".@mails." ".$ses{'size'});
  mlog("info","stat for ".$ses{'user'}." ".@mails." ".$ses{'size'});
  return 0;
}

sub docapa($)
{
  my ($peer);

  $peer=$_[0];
  topeer($peer,"+OK Capability list follows");
  topeer($peer,"TOP");
  topeer($peer,"USER");
  topeer($peer,"UIDL");
  topeer($peer,"IMPLEMENTATION ".$prog." POP3 server ".$version);
  topeer($peer,".");

  return 0;
}

sub dolist($)
{
  my ($peer,$box,$name,$ret,$n,$i);

  $ret=-1;
  $peer=$_[0];

  if(mreaddir()) {
    if(defined $_[2])
    {
      $n=$_[2]-1;
      if($n<@mails&&$n>=0) {
        topeer($peer,"+OK ".($n+1)." ".$mailsiz[$n]);
      } else {
        topeer($peer,"-ERR Message ".($n+1)." does not exist");
      }
    }
    else
    {
      topeer($peer,"+OK list lesz");
      for($i=0;$i<@mails;$i++) {
        topeer($peer,($i+1)." ".$mailsiz[$i]);
      }
      topeer($peer,".");
    }
    $ret=0;
  } else {
    topeer($peer,"-ERR cannot open maildir");
  }
  
  return $ret;
}
sub doretr($)
{
  my ($peer,$ix,@lines);

  $peer=$_[0];
  if(defined $_[2]) {
    $ix=$_[2]-1;
    if($ix>=0&&$ix<@mails) {
      topeer($peer,"+OK ".$mailsiz[$ix]);
      open(FIL,$mails[$ix]);
      while(<FIL>) {
        chomp;
        if($_=~/^\./) { print $peer "."; }
        topeer($peer,$_);
      }
      close(FIL);
      topeer($peer,".");
      unless($mailinf[$ix]=~/r/) { $mailinf[$ix].="r"; }
      if($ix>int($ses{'last'})) { $ses{'last'}=$ix; }
    } else {
      topeer($peer,"-ERR no such mail");
    }
  } else {
    topeer($peer,"-ERR missing parameter");
  }
  
  return 0;
}
sub dodele($)
{
  my ($peer,$ix);

  $peer=$_[0];
  if(defined $_[2]) {
    $ix=$_[2]-1;
    if($ix>=0&&$ix<@mails) {
      unless($mailinf[$ix]=~/d/) { $mailinf[$ix].="d"; }
      topeer($peer,"+OK ".($ix+1)." deleted.");
    } else {
      topeer($peer,"-ERR no such mail");
    }
  } else {
    topeer($peer,"-ERR missing parameter");
  }

  return 0;
}
sub donoop($)
{
  return 0;
}
sub dorset($)
{
  my ($i);

  for($i=0;$i<@mails;$i++) {
    $mailinf[$i]=~s/d//;
  }

  return 0;
}
sub douidl($)
{
  my ($peer,$i,$m,$uid);

  $peer=$_[0];
  if(defined $_[2]) {
    $m=int($_[2])-1;
    if($m>=0&&$m<@mails) {
      $mails[$m]=~/([0-9]+\.[A-Za-z0-9]+)\./;
      $uid=$1;
      $m++;
      topeer($peer,"+OK $m $uid");
    } else {
      topeer($peer,"-ERR no such message");
    }
  } else {
    topeer($peer,"+OK");
    for($i=0;$i<@mails;$i++) {
      unless($mailinf[$i]=~/d/) {
        $mails[$i]=~/([0-9]+\.[A-Za-z0-9]+)\./;
        $uid=$1;
        topeer($peer,($i+1)." ".$uid);
      }
    }
    topeer($peer,".");
  }

  return 0;
}
sub dotop($)
{
  my ($peer,$ix,@lines,$top,$h);

  $peer=$_[0];
  if(defined $_[2] && defined $_[3]) {
    $ix=$_[2]-1;
    $top=$_[3];
    if($ix>=0&&$ix<@mails) {
      topeer($peer,"+OK top ".$top." of ".($ix+1));
      $h=0;
      open(FIL,$mails[$ix]);
      while(<FIL>) {
        chomp;
        if(0==$h) {
          if($_=~/^$/) { $h=1; }
          topeer($peer,$_);
        } else {
          if(--$top<0) { last; }
          if($_=~/^\./) { topeer($peer,".",1); }
          topeer($peer,$_);
        }
      }
      close(FIL);
      topeer($peer,".");
    } else {
      topeer($peer,"-ERR no such mail");
    }
  } else {
    topeer($peer,"-ERR missing parameter");
  }
  
  return 0;
}
sub doupdate($)  # state
{
  my ($nam,$nna,$lst);
  
  # unlink deleted mails
  if("" ne $ses{'user'}) {
    $nam=$ses{'home'}."/.maildir/".$cachename.$ses{'peername'};
    if($ses{'last'}>=0&&open(FIL,">".$nam))
    { 
      if($mailinf[$ses{'last'}]=~/d/) { $lst=""; }
      else { 
        $lst=$mails[$ses{'last'}];
        $lst=~s/\/new\//\/cur\//;
      }
      print FIL $lst;
      close(FIL);
    }
    for($i=0;$i<@mails;$i++) {
      if($mailinf[$i]=~/d/) {
        # unlink
        unlink($mails[$i]);
      } elsif($mailinf[$i]=~/n/&&$mailinf[$i]=~/r/) {
        # retr and new -> move to cur
        $nna=$mails[$i];
        $nna=~s/\/new\//\/cur\//;
        rename($mails[$i],$nna);
      }
    }
    mlog("info","Update mailbox for ".$ses{'user'});
  }

  return 999;
}
sub do($)				# semmi helyett
{
  return 0;
}

sub dothread($)
{
  my (@d,@a,$req,$i,$token,$ans,$peer,$state,$newstate,$peername);
  
  $state=$oldstate='AUTHORIZATION';
  $peer=$_[0];
  $ses{'peername'}=identifypeer($peer);
  if($ses{'peername'} ne "?")
  {
    topeer($peer,"+OK lollipop ".$version." ready.");
    mlog("info","Client connected ".$ses{'peername'});
    while(<$peer>)
    {
      if(defined $DEBUG) { print; }
      chomp;
      @d=split;
      for($i=0;$i<@d;$i++) {
        $d[$i]=trim($d[$i]);
      }
      # token $d[0]-ban, a matrix alapjan csekk:
      $token=uc($d[0]);
      if(exists $tokens{$state}->{$token})
      {
        # ok, ebben a helyzetben ez egy ervenyes token
        $oldstate=$state;
        while(1)
        {
          $ret=$tokens{$state}->{$token}[0]($peer,@d);
          if("" ne $tokens{$state}->{$token}[2])
          {
            @a=split(/[\|]/,$tokens{$state}->{$token}[2]);
            if($ret!=0&&@a>1) { 
              topeer($peer,$a[1]);
            } else { 
              topeer($peer,$a[0]);
            }
          }
          if(0 == $ret && "" ne ($newstate=$tokens{$state}->{$token}[1])) { $state=$newstate; }
          if($oldstate eq $state) { last; }
          $oldstate=$state;
          $token='';
        }
        if($ret==999) { last; }
      }
      else { 
        topeer($peer,"-ERR unexpected command, see rfc1939");
      }
    }
  }
  else
  {
    topeer($peer,"-ERR identify unknown, access denied");
    mlog("warning","Unidentified client, access denied");
  }
  mlog("info","Client disconnected ".$ses{'peername'});
  
  return(0);
}

server();
