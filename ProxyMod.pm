#
# Copyright (c) 2001, Stephanie Wehner <atrak@itsx.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the company ITSX nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# Small tcp proxy package for packet(payload) alteration/debugging.
#
# $Id: ProxyMod.pm,v 1.1 2001/07/17 15:44:04 atrak Exp $

package Net::ProxyMod;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);
use POSIX ":sys_wait_h";

require Exporter;

@ISA = qw(Exporter AutoLoader);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
@EXPORT = qw(
	
);
$VERSION = '0.01';

my $do_debug = 0;

BEGIN {

    my (@mods,$mod);

    @mods = qw(Socket IO::Socket);

    for $mod (@mods) {

        unless(eval "require $mod") {
            die "Can't find required module $mod: $!\n";
        }
    }
}

# create a new proxy object
sub new
{
    my $class = shift;
    my $self = {};

    bless($self, $class);

    # initialize the proxy object
    $self->_init(@_);

    return($self);
}

# initialize

sub _init
{
    my $self = shift;
    my ($host, $port, $to_host,$to_port, $debug) = @_;

    # check if we need root
    if($port < 1024) {
        die "Need to be root to create a socket with port < 1024.\n";
    }

    # record host, port and transparent setting
    $self->{HOST} = $host;
    $self->{PORT} = $port;
    $self->{TOHOST} = $to_host;
    $self->{TOPORT} = $to_port;
    $do_debug = $debug;

    # setup the proxy socket

    $self->{SOCK} = IO::Socket::INET->new(
                    LocalAddr => $host,
                    LocalPort => $port,
                    Listen => Socket::SOMAXCONN,
                    Proto => 'tcp')
                    or die "Can't open socket: $!\n";

    _debug("Started server at " . $host . ":" . $port);

    # set autoflush
    $self->{SOCK}->autoflush(1);

    return;
}

# handle client connections (this is similar to fwdport
# in the perl coobook in some ways) 

sub get_conn
{
    my $self = shift;
    my($infunc,$outfunc) = @_;
    my($client, $remote, $pid);

    # reap childrean
    $SIG{CHLD} = \&_REAPER;

    # get connection
    while($client = $self->{SOCK}->accept()) {

        _debug("Connect from " . _peerinfo($client));

        # connect to remote host
        $remote = $self->_make_conn($client);

        $pid = fork();
        if(!defined($pid)) {
            warn "Cannot fork: $!\n";
            close($client);
            close($remote);
            next;
        }

        if($pid) {                       # mum
            close($client);
            close($remote);
            next;
        }

        # child
        close($self->{SOCK});

        # create a twin handling the other side
        $pid = fork();
        if(!defined($pid)) {
            die "Cannot fork: $!\n";
        }

        if($pid) {                        # mum # 2

            select($client);
            # turn off buffering
            $| = 1;    

            # shovel data from remote to client
            while(<$remote>) { print &$infunc($_); }

            # done, kill child
            kill('TERM',$pid);

        } else {

            select($remote);
            # turn off buffering
            $| = 1;

            # shovel data from client to remote
            while(<$client>) { print &$outfunc($_); }

            # kill parent, since done
            kill('TERM',getppid());
         }

    } # while

    return;
}

# reap kids

sub _REAPER {

    my($child);

    while (($child = waitpid(-1,WNOHANG)) > 0) {
    }

    $SIG{CHLD} = \&_REAPER;
}


#
# Make a connection to the requested destination
#

sub
_make_conn
{
    my $self = shift;
    my($sock) = @_;
    my($dhost, $sockaddr, $daddr, $dport,$newsock,$family);

    # see if this should be transparent proxying or not

    if($self->{TOHOST}) {

        $dhost = $self->{TOHOST};
        $dport = $self->{TOPORT};

    } else {

        # find the actual destination
        $sockaddr = getsockname($sock);
        ($family, $dport, $daddr) = unpack('Sn a4 x8',$sockaddr);
        $dhost = Socket::inet_ntoa($daddr);
    }
        

    _debug("Connecting to " . $dhost . ":" . $dport);

    $newsock = IO::Socket::INET->new(
                    PeerAddr => $dhost,
                    PeerPort => $dport,
                    Proto => 'tcp',
                    Type  => Socket::SOCK_STREAM) or warn "Can't connect: $!\n";

    return($newsock);
}
#
# Get information over the incoming connection
#

sub
_peerinfo
{
    my($sock) = @_;
    my($sockaddr,$family,$port,$addr);

    $sockaddr = getpeername($sock);
    ($family, $port, $addr) = unpack('Sn a4 x8',$sockaddr);

    return(sprintf("%s:%s",Socket::inet_ntoa($addr),$port));
}

#
# print debug info if desired
#

sub
_debug
{
    my($string) = @_;

    if($do_debug != 0) {
        print $string . "\n";
    }
}



# Preloaded methods go here.

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__

=head1 NAME

Net::ProxyMod - Small TCP proxy module for packet alteration.

=head1 SYNOPSIS

  use Net::ProxyMod;

=head1 DESCRIPTION

This is a small module that allows you to create a proxy for packet alteration 
and debugging. You just need to specify two functions in and outgoing packets
will be passed to. In these functions you can then modify the packet if desired.
This is useful to get in between an existing client and server for testing
purposes.

C<ProxyMod> can be used as a standard proxy or as a transparent proxy together 
with a firewall package such as ipfw on FreeBSD. Please refer to the ipfw 
documenation for more information.

new(host,port,dest_host, dest_port, debug) will create a new proxy object.
It will also create a tcp socket bound to the given host and port. If
dest_host and dest_port are emtpy, the destination address and port will
be taken from the original request. If debug is 1, the module will give 
you messages about connects.

get_conn(infunc, outfunc) will wait for packets to arrive. The payload of
packets going from the server to the client will passed on to the function
infunc. Likewise packets going from the client to the original server are passed
on to outfunc. The return value of infunc and outfunc will be taken as the
new payload in that direction.

=head1 EXAMPLE

This is a very simple example, more complex things are of course possible:
This is a transparent proxy bound to localhost port 7777. Since host and port
of the destination are left out, the final destination and port will be taken
out of the original request. For this you have to add to your firewall config. 
On FreeBSD you can do:

C<ipfw add 100 fwd localhost,7777 tcp from [client] to [dest] 1234 (in via [iface])>

#!/usr/bin/perl

use Net::ProxyMod;

# create a new proxy object

$p = Net::ProxyMod->new(localhost, 7777, "", 0, 1);

# wait for connections

$p->get_conn(\&infunc,\&outfunc);

# for packets going from the server to the client:

sub
infunc
{
    my($data) = @_;
    # increase a number
    $data =~/ (10) /;
    $num = $1 + rand(10);
    $data =~ s/ 10 / $num/g;

    return($data);
}

# for packets going from the client to the server:

sub
outfunc
{
    my($data) = @_;

    # adjust the payload, something real simple:
    $data =~ s/index.html/foobar.html/;

    return($data);
}
>

=head1 NOTES

If you run the transparent proxy on the same machine as the client 
request, be careful not to create infinite loops. This can happen
if the outgoing request from the proxy hits the forward rule as well.

ProxyMod is not programmed for efficiency, but as a quick test tool. 
Right now this only proxies TCP connections. If you need UDP you can
use Net::Divert.

=head1 AUTHOR

Stephanie Wehner, atrak@itsx.com

=head1 SEE ALSO

perl(1), ipfw(8), Net::Divert

=cut
