#!/usr/bin/perl
# radius-tamper.pl <strip-ma|bad-ma> [port] -- a test relay between the
# lab's NAS and its RADIUS server, run inside the nas container by
# scripts/test.sh. It forwards each Access-Request to radius:1812 and the
# reply back, but tampers with an Access-Challenge first:
#   strip-ma  removes its Message-Authenticator
#   bad-ma    changes one byte of its Message-Authenticator
# Then it recomputes the Response Authenticator with the shared secret, so
# the Message-Authenticator is the only thing wrong: the NAS must refuse the
# challenge for that reason alone. Accepts and Rejects pass unchanged.
#
# Perl because it's the one interpreter in the NAS image (perl-base), and
# it has UDP sockets and MD5 in its core modules. It reads the shared
# secret from the NAS's own file and never prints it. It exits after 20
# seconds without a request.
use strict;
use warnings;
use IO::Socket::INET;
use Digest::MD5 qw(md5);

my ($mode, $port) = @ARGV;
$port //= 11812;
die "usage: radius-tamper.pl strip-ma|bad-ma [port]\n" unless ($mode // '') =~ /^(strip-ma|bad-ma)$/;

my $secret = do { local $/; open my $fh, '<', '/var/lib/nas/secret' or die "no secret: $!\n"; <$fh> };
my $nas = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => $port, Proto => 'udp')
  or die "radius-tamper: cannot listen on 127.0.0.1:$port: $!\n";
my $server = IO::Socket::INET->new(PeerAddr => 'radius', PeerPort => 1812, Proto => 'udp')
  or die "radius-tamper: cannot reach radius:1812: $!\n";
$SIG{ALRM} = sub { exit 0 };
$| = 1;

while (1) {
  alarm 20;
  my $from = $nas->recv(my $request, 4096);
  next unless defined $from && length $request >= 20;
  $server->send($request);
  my $ready = '';
  vec($ready, fileno($server), 1) = 1;
  next unless select(my $r = $ready, undef, undef, 5);
  $server->recv(my $reply, 4096);
  my ($code, $id, $len) = unpack('C C n', $reply);
  if ($code == 11) {    # Access-Challenge
    my ($attrs, $kept) = (substr($reply, 20, $len - 20), '');
    while (length $attrs >= 2) {
      my (undef, $alen) = unpack('C C', $attrs);
      last if $alen < 2;
      my $attr = substr($attrs, 0, $alen, '');
      if (unpack('C', $attr) == 80) {    # Message-Authenticator
        next if $mode eq 'strip-ma';
        substr($attr, -1, 1) = chr(ord(substr($attr, -1)) ^ 0xff);
      }
      $kept .= $attr;
    }
    my $header = pack('C C n', $code, $id, 20 + length $kept);
    $reply = $header . md5($header . substr($request, 4, 16) . $kept . $secret) . $kept;
    print STDERR "radius-tamper: Access-Challenge relayed with its Message-Authenticator ",
      ($mode eq 'strip-ma' ? 'removed' : 'changed'), "\n";
  }
  $nas->send($reply, 0, $from);
}
