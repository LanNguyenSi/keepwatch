# Opens sockets that ss prints with an interface suffix after the address
# (the suffix is outside the brackets of an IPv6 address), plus two
# IPv4-mapped sockets. Needs CAP_NET_RAW (SO_BINDTODEVICE) and an interface
# "dum0" with the link-local address fe80::1 (capture.sh creates it).
use strict; use warnings;
use Socket qw(:DEFAULT inet_pton sockaddr_in6 AF_INET6 PF_INET6);
use constant { SOL_IPV6 => 41, IPV6_V6ONLY => 26, SO_BINDTODEVICE => 25 };
my @socks;
my $dum0 = do { open(my $f, '<', '/sys/class/net/dum0/ifindex') or die "no dum0: $!"; my $i = <$f>; chomp $i; $i };
sub dev { my ($s, $d) = @_; setsockopt($s, SOL_SOCKET, SO_BINDTODEVICE, pack("Z*", $d)) or die "bindtodevice $d: $!" if defined $d }
sub tcp4 { my ($a,$p,$d)=@_; socket(my $s, PF_INET, SOCK_STREAM, 0) or die; setsockopt($s,SOL_SOCKET,SO_REUSEADDR,1); dev($s,$d); bind($s, sockaddr_in($p, inet_aton($a))) or die "bind $a $p: $!"; listen($s,5) or die; push @socks,$s }
sub tcp6 { my ($a,$p,$v6only,$d,$scope)=@_; socket(my $s, PF_INET6, SOCK_STREAM, 0) or die; setsockopt($s,SOL_SOCKET,SO_REUSEADDR,1); setsockopt($s, SOL_IPV6, IPV6_V6ONLY, pack("i",$v6only)); dev($s,$d); bind($s, sockaddr_in6($p, inet_pton(AF_INET6,$a), $scope // 0)) or die "bind6 $a $p: $!"; listen($s,5) or die; push @socks,$s }
sub udp6 { my ($a,$p,$d,$scope)=@_; socket(my $s, PF_INET6, SOCK_DGRAM, 0) or die; setsockopt($s, SOL_IPV6, IPV6_V6ONLY, pack("i",1)); dev($s,$d); bind($s, sockaddr_in6($p, inet_pton(AF_INET6,$a), $scope // 0)) or die "bind6 $a $p: $!"; push @socks,$s }
sub udp4 { my ($a,$p,$d)=@_; socket(my $s, PF_INET, SOCK_DGRAM, 0) or die; dev($s,$d); bind($s, sockaddr_in($p, inet_aton($a))) or die; push @socks,$s }
tcp6("::", 7001, 1, "lo");                 # [::]%lo:7001
tcp6("::", 7002, 0, "lo");                 # *%lo:7002 (dual stack)
tcp4("0.0.0.0", 7003, "lo");               # 0.0.0.0%lo:7003
udp6("::", 7004, "lo");                    # [::]%lo:7004
tcp6("::ffff:127.0.0.1", 7005, 0);         # [::ffff:127.0.0.1]:7005
tcp6("::ffff:0.0.0.0", 7006, 0);           # [::ffff:0.0.0.0]:7006
udp6("fe80::1", 7007, "dum0", $dum0);      # [fe80::1]%dum0:7007
tcp6("fe80::1", 7008, 1, "dum0", $dum0);   # [fe80::1]%dum0:7008
udp4("0.0.0.0", 7009, "lo");               # 0.0.0.0%lo:7009
sleep 3600;
