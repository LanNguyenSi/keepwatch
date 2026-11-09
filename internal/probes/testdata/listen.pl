use strict; use warnings;
use Socket qw(:DEFAULT inet_pton sockaddr_in6 AF_INET6 PF_INET6);
my @socks;
sub tcp4 { my ($a,$p)=@_; socket(my $s, PF_INET, SOCK_STREAM, 0) or die; setsockopt($s,SOL_SOCKET,SO_REUSEADDR,1); bind($s, sockaddr_in($p, inet_aton($a))) or die "bind $a $p: $!"; listen($s,5) or die; push @socks,$s }
sub tcp6 { my ($a,$p,$v6only)=@_; socket(my $s, PF_INET6, SOCK_STREAM, 0) or die; setsockopt($s,SOL_SOCKET,SO_REUSEADDR,1); setsockopt($s, 41, 26, pack("i",$v6only)); bind($s, sockaddr_in6($p, inet_pton(AF_INET6,$a))) or die "bind6 $a $p: $!"; listen($s,5) or die; push @socks,$s }
sub udp4 { my ($a,$p)=@_; socket(my $s, PF_INET, SOCK_DGRAM, 0) or die; bind($s, sockaddr_in($p, inet_aton($a))) or die; push @socks,$s }
sub udp6 { my ($a,$p)=@_; socket(my $s, PF_INET6, SOCK_DGRAM, 0) or die; setsockopt($s, 41, 26, pack("i",1)); bind($s, sockaddr_in6($p, inet_pton(AF_INET6,$a))) or die; push @socks,$s }
tcp4("0.0.0.0", 8080);
tcp4("127.0.0.1", 5432);
tcp4("192.0.2.10", 9090) if ($ARGV[0] // "") eq "withdoc";
tcp6("::", 8443, 1);
tcp6("::1", 6379, 1);
tcp6("::", 3000, 0);   # dual stack, ss prints *
udp4("0.0.0.0", 5353);
udp4("127.0.0.1", 8125);
udp6("::", 5355);
sleep 3600;
