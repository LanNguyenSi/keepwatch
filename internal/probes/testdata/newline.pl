# Listens with a process name (comm) that holds a newline and looks like the
# start of another ss line. Any local process may set its own name like this.
use strict; use warnings;
use Socket qw(:DEFAULT inet_pton sockaddr_in6 AF_INET6 PF_INET6);
open(my $c, '>', '/proc/self/comm') or die "comm: $!";
print $c "a\nLISTEN 0 0 x";
close $c or die "comm: $!";
my @socks;
sub tcp4 { my ($a,$p)=@_; socket(my $s, PF_INET, SOCK_STREAM, 0) or die; setsockopt($s,SOL_SOCKET,SO_REUSEADDR,1); bind($s, sockaddr_in($p, inet_aton($a))) or die "bind $a $p: $!"; listen($s,5) or die; push @socks,$s }
sub tcp6 { my ($a,$p)=@_; socket(my $s, PF_INET6, SOCK_STREAM, 0) or die; setsockopt($s,SOL_SOCKET,SO_REUSEADDR,1); setsockopt($s, 41, 26, pack("i",1)); bind($s, sockaddr_in6($p, inet_pton(AF_INET6,$a))) or die "bind6 $a $p: $!"; listen($s,5) or die; push @socks,$s }
sub udp4 { my ($a,$p)=@_; socket(my $s, PF_INET, SOCK_DGRAM, 0) or die; bind($s, sockaddr_in($p, inet_aton($a))) or die; push @socks,$s }
tcp4("0.0.0.0", 7020);
tcp6("::", 7021);
udp4("0.0.0.0", 7022);
sleep 3600;
