# guruguru
Transparent IPv4 SOCKS5 proxy via IPv6 addressing

## Prerequisites
A dedicated VM (or real box if you like) is needed to run `guruguru`. In this document we assume Ubuntu 16.04 is installed on the VM.

## Recommended configuration

1. Configure `/etc/network/interfaces` as follows:
```
iface ens18 inet6 static
    address fc00::1 # Or your IPv6 address, remember to adjust iptables rules if this is changed
    netmask 64
    up ip -6 rule add fwmark 1 lookup 100
    up ip -6 route add local fc00::/7 dev lo table 100
    up ip6tables -t mangle -A PREROUTING -m socket -j MARK --set-mark 1
    up ip6tables -t mangle -A PREROUTING -m socket -j ACCEPT
    up ip6tables -t mangle -A PREROUTING -p tcp -d fc00::/16 -j RETURN
    up ip6tables -t mangle -A PREROUTING -p tcp -d fc00::/7 -j TPROXY --tproxy-mark 0x1/0x1 --on-port 44555 --on-ip ::1
    up ip6tables -I INPUT -p tcp -s fc00::/64 -d fc00::/7 -j ACCEPT
```

2. Setup radvd to offer (fake) IPv6 connectivity to LAN. Example configuration:
```
interface ens18 {                                                                                   
        AdvSendAdvert on;                                                                           
                                                                                                    
        prefix ::/64 {                                                                              
                AdvAutonomous on;                                                                   
                AdvOnLink on;                                                                       
        };                                                                                          
        route ::/0 {                                                                                
        };                                                                                          
};                                                                                                  
```

2. Build guruguru with `cargo build --release`

3. Run `guruguru` as root. It will drop root privileges after initialization.

To view log message, run it like: `RUST_LOG=debug guruguru`

## Usage
`guruguru` encodes SOCKS5 server and target domain / address into [IPv6 unique local addresses](https://en.wikipedia.org/wiki/IPv6_address#Unique_local_addresses). It offers a simple DNS server to encode the address. You can use `dig` to query it to get the address:

```
$ dig AAAA google.com.s---t.my.socks.com.s---t.1080.s---t.grgr.rg @fc00::1 +short
fd3b:de76:17f4:b73:b9bc:6b9f:e800:8700
```

IPv4 addresses are also accepted:
```
$ dig AAAA 233.233.233.233.s---t.10.10.10.10.s---t.1080.s---t.grgr.rg @fc00::1 +short
fce9:e9e9:e900::a0a:a0a:438
```

SOCKS server can be omitted. `guruguru` will connect via server specified in command line (Please check `guruguru -h` for more information).
```
$ dig AAAA httpbin.org.s---t.grgr.rg @fc00::1 +short
fd45:2901:25df:c000::
$ curl -L --resolve 'httpbin.org:443:fd45:2901:25df:c000::' "https://httpbin.org/ip"
{"origin":"1.2.3.4"}
```

By default domain names are directly encoded into the IPv6 address, it is not possible to encode the address if domain is too long:
```
$ dig AAAA www.google.com.s---t.my.socks.com.s---t.1080.s---t.grgr.rg @fc00::1 +short
# Nothing returns
```

In this case, we can instruct `guruguru` to pre-resolve domains before encoding:
```
$ dig AAAA r---e.www.google.com.s---t.r---e.my.socks.com.s---t.1080.s---t.grgr.rg @fc00::1 +short
fc45:abe9:2500::a18:e205:438
```
