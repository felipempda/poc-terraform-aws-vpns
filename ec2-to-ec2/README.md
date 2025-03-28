# POC - VPN

This POC creates resources to simulate a VPN between two parts:

- VPC-A uses EC2 with Libreswan (left)
- VPC-B uses EC2 with Libreswan (right)

[Libreswan](https://libreswan.org/) is an open source implementation of VPN protocols IPSsec and IKE.

Given that [VPN Connection](https://docs.aws.amazon.com/vpn/latest/s2svpn/VPC_VPN.html) uses the same protocols I wanted to test if I could do the same thing but with only EC2 instances.

This is for learning purposes only, not meant for any production workload.

## Overview

![architecture](../images/poc-vpn-to-ec2-EC2-to-EC2.drawio.png)

Run:
```bash
terraform plan
terraform apply
```

Example output

```bash
ec2-private-a = {
  "connect_to_ec2_command" = "aws ssm start-session --target i-0fac5f30b85b3c01c --region ca-central-1"
  "ec2_instance_id" = "i-0fac5f30b85b3c01c"
  "network_id" = "eni-06018061d5aa3d92d"
  "private_ip" = "10.88.1.167"
  "public_ip" = ""
}
ec2-private-b = {
  "connect_to_ec2_command" = "aws ssm start-session --target i-0d57a47c9d16ea024 --region us-east-1"
  "ec2_instance_id" = "i-0d57a47c9d16ea024"
  "network_id" = "eni-01b7d41bd8f6cc72f"
  "private_ip" = "10.2.1.92"
  "public_ip" = ""
}
ec2-vpn-a = {
  "connect_to_ec2_command" = "aws ssm start-session --target i-0eb75945a36368b58 --region ca-central-1"
  "ec2_instance_id" = "i-0eb75945a36368b58"
  "network_id" = "eni-03b0e58dd2b22faf6"
  "private_ip" = "10.88.100.246"
  "public_ip" = "99.79.175.155"
}
ec2-vpn-b = {
  "connect_to_ec2_command" = "aws ssm start-session --target i-0896f37404be259e3 --region us-east-1"
  "ec2_instance_id" = "i-0896f37404be259e3"
  "network_id" = "eni-02f99c2d591bf5c59"
  "private_ip" = "10.2.100.192"
  "public_ip" = "3.85.251.173"
}
endpoints-a = {
  "ec2" = {
    "dns_name" = "vpce-021dbcef3371cbfd4-j13v3ibj.ec2.ca-central-1.vpce.amazonaws.com"
    "ipv4s" = tolist([
      "10.88.3.116",
      "10.88.4.30",
    ])
  }
  "ec2messages" = {
    "dns_name" = "vpce-0d058f54f75d4fb3f-n6kcycli.ec2messages.ca-central-1.vpce.amazonaws.com"
    "ipv4s" = tolist([
      "10.88.3.5",
      "10.88.4.254",
    ])
  }
  "kms" = {
    "dns_name" = "vpce-06753f28e9d642c39-q17rzbwf.kms.ca-central-1.vpce.amazonaws.com"
    "ipv4s" = tolist([
      "10.88.3.37",
      "10.88.4.19",
    ])
  }
  "s3" = {
    "dns_name" = ""
    "ipv4s" = []
  }
  "ssm" = {
    "dns_name" = "vpce-0b9d51d1697018bfa-918ln6d4.ssm.ca-central-1.vpce.amazonaws.com"
    "ipv4s" = tolist([
      "10.88.3.136",
      "10.88.4.160",
    ])
  }
  "ssmmessages" = {
    "dns_name" = "vpce-0bedc2c9db5a28b6d-jms8jo82.ssmmessages.ca-central-1.vpce.amazonaws.com"
    "ipv4s" = tolist([
      "10.88.3.238",
      "10.88.4.7",
    ])
  }
}
endpoints-b = {
  "ec2" = {
    "dns_name" = "vpce-0713a2c2ccad3053f-rnmelaak.ec2.us-east-1.vpce.amazonaws.com"
    "ipv4s" = tolist([
      "10.2.3.20",
      "10.2.4.127",
    ])
  }
  "ec2messages" = {
    "dns_name" = "vpce-0f10031c4fe6484af-xn15aqv6.ec2messages.us-east-1.vpce.amazonaws.com"
    "ipv4s" = tolist([
      "10.2.3.227",
      "10.2.4.124",
    ])
  }
  "kms" = {
    "dns_name" = "vpce-063411cb1c7f054f0-9gtinvn3.kms.us-east-1.vpce.amazonaws.com"
    "ipv4s" = tolist([
      "10.2.3.95",
      "10.2.4.94",
    ])
  }
  "s3" = {
    "dns_name" = ""
    "ipv4s" = []
  }
  "ssm" = {
    "dns_name" = "vpce-0ea64bb797211342a-czr5pa14.ssm.us-east-1.vpce.amazonaws.com"
    "ipv4s" = tolist([
      "10.2.3.86",
      "10.2.4.119",
    ])
  }
  "ssmmessages" = {
    "dns_name" = "vpce-08edc88ff35d761eb-k1l31ty1.ssmmessages.us-east-1.vpce.amazonaws.com"
    "ipv4s" = tolist([
      "10.2.3.152",
      "10.2.4.215",
    ])
  }
}
region-a = "ca-central-1"
region-b = "us-east-1"
test-endpoints-a-0-dns = "nslookup vpce-021dbcef3371cbfd4-j13v3ibj.ec2.ca-central-1.vpce.amazonaws.com"
test-endpoints-a-1-connect = "aws ec2 describe-vpcs --query 'Vpcs[].CidrBlock' --region ca-central-1 --endpoint-url https://vpce-021dbcef3371cbfd4-j13v3ibj.ec2.ca-central-1.vpce.amazonaws.com"
test-endpoints-b-0-dns = "nslookup vpce-0713a2c2ccad3053f-rnmelaak.ec2.us-east-1.vpce.amazonaws.com"
test-endpoints-b-1-connect = "aws ec2 describe-vpcs --query 'Vpcs[].CidrBlock' --region us-east-1 --endpoint-url https://vpce-0713a2c2ccad3053f-rnmelaak.ec2.us-east-1.vpce.amazonaws.com"
vpc-a = "vpc-0fa5b6c6511940598"
vpc-b = "vpc-084c9c6bf755c539d"
```

## Testing connectivity

From the public instances running Libreswan we are going to:
-  check for status of ipsec.
-  see policies on [XFRM ](https://man7.org/linux/man-pages/man8/ip-xfrm.8.html).

From the private instances we are going to:
-  ping each other (cross-VPC)
-  call a private endpoint (cross-VPC - flux on the diagram)

We are going to use SSM Session Manager for running the commands on the instances.

Run script `scripts/test_connectivity.sh`

Example result:
```bash
$ ./scripts/test_connectivity.sh


Connecting to instance vpn-a [i-0eb75945a36368b58] to check ipsec tunnel

This session is encrypted using AWS KMS.
+ date
Fri Mar 28 20:49:07 UTC 2025
+ hostname -I
10.88.100.246
+ sudo ipsec status
000 using kernel interface: xfrm
000
000 interface lo UDP [::1]:4500
000 interface lo UDP [::1]:500
000 interface lo UDP 127.0.0.1:4500
000 interface lo UDP 127.0.0.1:500
000 interface ens5 UDP 10.88.100.246:4500
000 interface ens5 UDP 10.88.100.246:500
000
000 fips mode=disabled;
000 SElinux=disabled
000 seccomp=disabled
000
000 config setup options:
000
000 configdir=/etc, configfile=/etc/ipsec.conf, secrets=/etc/ipsec.secrets, ipsecdir=/etc/ipsec.d
000 nssdir=/var/lib/ipsec/nss, dumpdir=/run/pluto, statsbin=unset
000 dnssec-rootkey-file=/var/lib/unbound/root.key, dnssec-trusted=<unset>
000 sbindir=/usr/sbin, libexecdir=/usr/libexec/ipsec
000 pluto_version=4.12, pluto_vendorid=OE-Libreswan-4.12, audit-log=yes
000 nhelpers=-1, uniqueids=yes, dnssec-enable=yes, logappend=yes, logip=yes, shuntlifetime=900s, xfrmlifetime=30s
000 ddos-cookies-threshold=25000, ddos-max-halfopen=50000, ddos-mode=auto, ikev1-policy=accept
000 ikebuf=0, msg_errqueue=yes, crl-strict=no, crlcheckinterval=0, listen=<any>, nflog-all=0
000 ocsp-enable=no, ocsp-strict=no, ocsp-timeout=2, ocsp-uri=<unset>
000 ocsp-trust-name=<unset>
000 ocsp-cache-size=1000, ocsp-cache-min-age=3600, ocsp-cache-max-age=86400, ocsp-method=get
000 global-redirect=no, global-redirect-to=<unset>
000 secctx-attr-type=32001
000 debug:
000
000 nat-traversal=yes, keep-alive=20, nat-ikeport=4500
000 virtual-private (%priv):
000
000 Kernel algorithms supported:
000
000 algorithm ESP encrypt: name=3DES_CBC, keysizemin=192, keysizemax=192
000 algorithm ESP encrypt: name=AES_CBC, keysizemin=128, keysizemax=256
000 algorithm ESP encrypt: name=AES_CCM_12, keysizemin=128, keysizemax=256
000 algorithm ESP encrypt: name=AES_CCM_16, keysizemin=128, keysizemax=256
000 algorithm ESP encrypt: name=AES_CCM_8, keysizemin=128, keysizemax=256
000 algorithm ESP encrypt: name=AES_CTR, keysizemin=128, keysizemax=256
000 algorithm ESP encrypt: name=AES_GCM_12, keysizemin=128, keysizemax=256
000 algorithm ESP encrypt: name=AES_GCM_16, keysizemin=128, keysizemax=256
000 algorithm ESP encrypt: name=AES_GCM_8, keysizemin=128, keysizemax=256
000 algorithm ESP encrypt: name=CAMELLIA_CBC, keysizemin=128, keysizemax=256
000 algorithm ESP encrypt: name=CHACHA20_POLY1305, keysizemin=256, keysizemax=256
000 algorithm ESP encrypt: name=NULL, keysizemin=0, keysizemax=0
000 algorithm ESP encrypt: name=NULL_AUTH_AES_GMAC, keysizemin=128, keysizemax=256
000 algorithm AH/ESP auth: name=AES_CMAC_96, key-length=128
000 algorithm AH/ESP auth: name=AES_XCBC_96, key-length=128
000 algorithm AH/ESP auth: name=HMAC_MD5_96, key-length=128
000 algorithm AH/ESP auth: name=HMAC_SHA1_96, key-length=160
000 algorithm AH/ESP auth: name=HMAC_SHA2_256_128, key-length=256
000 algorithm AH/ESP auth: name=HMAC_SHA2_256_TRUNCBUG, key-length=256
000 algorithm AH/ESP auth: name=HMAC_SHA2_384_192, key-length=384
000 algorithm AH/ESP auth: name=HMAC_SHA2_512_256, key-length=512
000 algorithm AH/ESP auth: name=NONE, key-length=0
000
000 IKE algorithms supported:
000
000 algorithm IKE encrypt: v1id=5, v1name=OAKLEY_3DES_CBC, v2id=3, v2name=3DES, blocksize=8, keydeflen=192
000 algorithm IKE encrypt: v1id=8, v1name=OAKLEY_CAMELLIA_CBC, v2id=23, v2name=CAMELLIA_CBC, blocksize=16, keydeflen=128
000 algorithm IKE encrypt: v1id=-1, v1name=n/a, v2id=20, v2name=AES_GCM_C, blocksize=16, keydeflen=128
000 algorithm IKE encrypt: v1id=-1, v1name=n/a, v2id=19, v2name=AES_GCM_B, blocksize=16, keydeflen=128
000 algorithm IKE encrypt: v1id=-1, v1name=n/a, v2id=18, v2name=AES_GCM_A, blocksize=16, keydeflen=128
000 algorithm IKE encrypt: v1id=13, v1name=OAKLEY_AES_CTR, v2id=13, v2name=AES_CTR, blocksize=16, keydeflen=128
000 algorithm IKE encrypt: v1id=7, v1name=OAKLEY_AES_CBC, v2id=12, v2name=AES_CBC, blocksize=16, keydeflen=128
000 algorithm IKE encrypt: v1id=-1, v1name=n/a, v2id=28, v2name=CHACHA20_POLY1305, blocksize=16, keydeflen=256
000 algorithm IKE PRF: name=HMAC_MD5, hashlen=16
000 algorithm IKE PRF: name=HMAC_SHA1, hashlen=20
000 algorithm IKE PRF: name=HMAC_SHA2_256, hashlen=32
000 algorithm IKE PRF: name=HMAC_SHA2_384, hashlen=48
000 algorithm IKE PRF: name=HMAC_SHA2_512, hashlen=64
000 algorithm IKE PRF: name=AES_XCBC, hashlen=16
000 algorithm IKE DH Key Exchange: name=MODP1536, bits=1536
000 algorithm IKE DH Key Exchange: name=MODP2048, bits=2048
000 algorithm IKE DH Key Exchange: name=MODP3072, bits=3072
000 algorithm IKE DH Key Exchange: name=MODP4096, bits=4096
000 algorithm IKE DH Key Exchange: name=MODP6144, bits=6144
000 algorithm IKE DH Key Exchange: name=MODP8192, bits=8192
000 algorithm IKE DH Key Exchange: name=DH19, bits=512
000 algorithm IKE DH Key Exchange: name=DH20, bits=768
000 algorithm IKE DH Key Exchange: name=DH21, bits=1056
000 algorithm IKE DH Key Exchange: name=DH31, bits=256
000
000 stats db_ops: {curr_cnt, total_cnt, maxsz} :context={0,0,0} trans={0,0,0} attrs={0,0,0}
000
000 Connection list:
000
000 "vpc1-vpc2": 10.88.0.0/16===10.88.100.246[99.79.175.155]---10.88.100.1...3.85.251.173===10.2.0.0/16; erouted; eroute owner: #3
000 "vpc1-vpc2":     oriented; my_ip=unset; their_ip=unset; my_updown=ipsec _updown;
000 "vpc1-vpc2":   xauth us:none, xauth them:none,  my_username=[any]; their_username=[any]
000 "vpc1-vpc2":   our auth:secret, their auth:secret, our autheap:none, their autheap:none;
000 "vpc1-vpc2":   modecfg info: us:none, them:none, modecfg policy:push, dns:unset, domains:unset, cat:unset;
000 "vpc1-vpc2":   sec_label:unset;
000 "vpc1-vpc2":   ike_life: 28800s; ipsec_life: 3600s; ipsec_max_bytes: 2^63B; ipsec_max_packets: 2^63; replay_window: 128; rekey_margin: 540s; rekey_fuzz: 100%; keyingtries: 0;
000 "vpc1-vpc2":   retransmit-interval: 500ms; retransmit-timeout: 60s; iketcp:no; iketcp-port:4500;
000 "vpc1-vpc2":   initial-contact:no; cisco-unity:no; fake-strongswan:no; send-vendorid:no; send-no-esp-tfc:no;
000 "vpc1-vpc2":   policy: IKEv2+PSK+ENCRYPT+TUNNEL+PFS+UP+IKE_FRAG_ALLOW+ESN_NO+ESN_YES;
000 "vpc1-vpc2":   v2-auth-hash-policy: none;
000 "vpc1-vpc2":   conn_prio: 16,16; interface: ens5; metric: 0; mtu: unset; sa_prio:auto; sa_tfc:none;
000 "vpc1-vpc2":   nflog-group: unset; mark: unset; vti-iface:unset; vti-routing:no; vti-shared:no; nic-offload:auto;
000 "vpc1-vpc2":   our idtype: ID_IPV4_ADDR; our id=99.79.175.155; their idtype: ID_IPV4_ADDR; their id=3.85.251.173
000 "vpc1-vpc2":   liveness: active; dpdaction:restart; dpddelay:30s; retransmit-timeout:60s
000 "vpc1-vpc2":   nat-traversal: encaps:auto; keepalive:20s
000 "vpc1-vpc2":   newest IKE SA: #2; newest IPsec SA: #3; conn serial: $1;
000 "vpc1-vpc2":   IKE algorithms: AES_CBC_256-HMAC_SHA2_256-MODP2048, AES_CBC_256-HMAC_SHA1-MODP2048, AES_CBC_128-HMAC_SHA2_256-MODP2048, AES_CBC_128-HMAC_SHA1-MODP2048
000 "vpc1-vpc2":   IKEv2 algorithm newest: AES_CBC_256-HMAC_SHA2_256-MODP2048
000 "vpc1-vpc2":   ESP algorithms: AES_GCM_16_256-NONE, CHACHA20_POLY1305-NONE, AES_CBC_256-HMAC_SHA2_512_256+HMAC_SHA1_96+HMAC_SHA2_256_128, AES_GCM_16_128-NONE, AES_CBC_128-HMAC_SHA1_96+HMAC_SHA2_256_128
000 "vpc1-vpc2":   ESP algorithm newest: AES_GCM_16_256-NONE; pfsgroup=<Phase1>
000
000 Total IPsec connections: loaded 1, active 1
000
000 State Information: DDoS cookies not required, Accepting new IKE connections
000 IKE SAs: total(1), half-open(0), open(0), authenticated(1), anonymous(0)
000 IPsec SAs: total(1), authenticated(1), anonymous(0)
000
000 #2: "vpc1-vpc2":4500 STATE_V2_ESTABLISHED_IKE_SA (established IKE SA); REKEY in 27980s; REPLACE in 28250s; newest; idle;
000 #3: "vpc1-vpc2":4500 STATE_V2_ESTABLISHED_CHILD_SA (established Child SA); LIVENESS in 20s; REKEY in 2780s; REPLACE in 3050s; newest; eroute owner; IKE SA #2; idle;
000 #3: "vpc1-vpc2" esp.b81df6e@3.85.251.173 esp.b9e564dc@10.88.100.246 tun.0@3.85.251.173 tun.0@10.88.100.246 Traffic: ESPin=8KB ESPout=4KB ESPmax=2^63B
000
000 Bare Shunt list:
000
+ sudo ip xfrm policy show
src 10.88.0.0/16 dst 10.2.0.0/16
        dir out priority 1761505 ptype main
        tmpl src 10.88.100.246 dst 3.85.251.173
                proto esp reqid 16389 mode tunnel
src 10.2.0.0/16 dst 10.88.0.0/16
        dir fwd priority 1761505 ptype main
        tmpl src 3.85.251.173 dst 10.88.100.246
                proto esp reqid 16389 mode tunnel
src 10.2.0.0/16 dst 10.88.0.0/16
        dir in priority 1761505 ptype main
        tmpl src 3.85.251.173 dst 10.88.100.246
                proto esp reqid 16389 mode tunnel
src ::/0 dst ::/0
        socket out priority 0 ptype main
src ::/0 dst ::/0
        socket in priority 0 ptype main
src ::/0 dst ::/0
        socket out priority 0 ptype main
src ::/0 dst ::/0
        socket in priority 0 ptype main
src 0.0.0.0/0 dst 0.0.0.0/0
        socket out priority 0 ptype main
src 0.0.0.0/0 dst 0.0.0.0/0
        socket in priority 0 ptype main
src 0.0.0.0/0 dst 0.0.0.0/0
        socket out priority 0 ptype main
src 0.0.0.0/0 dst 0.0.0.0/0
        socket in priority 0 ptype main
src 0.0.0.0/0 dst 0.0.0.0/0
        socket out priority 0 ptype main
src 0.0.0.0/0 dst 0.0.0.0/0
        socket in priority 0 ptype main
src 0.0.0.0/0 dst 0.0.0.0/0
        socket out priority 0 ptype main
src 0.0.0.0/0 dst 0.0.0.0/0
        socket in priority 0 ptype main
src ::/0 dst ::/0 proto ipv6-icmp type 135
        dir out priority 1 ptype main
src ::/0 dst ::/0 proto ipv6-icmp type 135
        dir fwd priority 1 ptype main
src ::/0 dst ::/0 proto ipv6-icmp type 135
        dir in priority 1 ptype main
src ::/0 dst ::/0 proto ipv6-icmp type 136
        dir out priority 1 ptype main
src ::/0 dst ::/0 proto ipv6-icmp type 136
        dir fwd priority 1 ptype main
src ::/0 dst ::/0 proto ipv6-icmp type 136
        dir in priority 1 ptype main
+ sudo ip xfrm state show
src 3.85.251.173 dst 10.88.100.246
        proto esp spi 0xb9e564dc reqid 16389 mode tunnel
        replay-window 0 flag af-unspec esn
        aead rfc4106(gcm(aes)) 0x6ad2a89ad3ff0c5cd3389ba419ce04e7b3a37621bd5f90e58635a63adcb63e1a605987c2 128
        encap type espinudp sport 4500 dport 4500 addr 0.0.0.0
        anti-replay esn context:
         seq-hi 0x0, seq 0x1d, oseq-hi 0x0, oseq 0x0
         replay_window 128, bitmap-length 4
         00000000 00000000 00000000 1fffffff
src 10.88.100.246 dst 3.85.251.173
        proto esp spi 0x0b81df6e reqid 16389 mode tunnel
        replay-window 0 flag af-unspec esn
        aead rfc4106(gcm(aes)) 0xb717b9ffb3ec46f35ec83b4dd124f64d2f32793c0709b0c01ac72a924430a7571eb417ae 128
        encap type espinudp sport 4500 dport 4500 addr 0.0.0.0
        anti-replay esn context:
         seq-hi 0x0, seq 0x0, oseq-hi 0x0, oseq 0x18
         replay_window 128, bitmap-length 4
         00000000 00000000 00000000 00000000





Connecting to instance vpn-b [i-0896f37404be259e3] to check ipsec tunnel

+ date
Fri Mar 28 20:49:10 UTC 2025
+ hostname -I
10.2.100.192
+ sudo ipsec status
000 using kernel interface: xfrm
000
000 interface lo UDP [::1]:4500
000 interface lo UDP [::1]:500
000 interface lo UDP 127.0.0.1:4500
000 interface lo UDP 127.0.0.1:500
000 interface ens5 UDP 10.2.100.192:4500
000 interface ens5 UDP 10.2.100.192:500
000
000 fips mode=disabled;
000 SElinux=disabled
000 seccomp=disabled
000
000 config setup options:
000
000 configdir=/etc, configfile=/etc/ipsec.conf, secrets=/etc/ipsec.secrets, ipsecdir=/etc/ipsec.d
000 nssdir=/var/lib/ipsec/nss, dumpdir=/run/pluto, statsbin=unset
000 dnssec-rootkey-file=/var/lib/unbound/root.key, dnssec-trusted=<unset>
000 sbindir=/usr/sbin, libexecdir=/usr/libexec/ipsec
000 pluto_version=4.12, pluto_vendorid=OE-Libreswan-4.12, audit-log=yes
000 nhelpers=-1, uniqueids=yes, dnssec-enable=yes, logappend=yes, logip=yes, shuntlifetime=900s, xfrmlifetime=30s
000 ddos-cookies-threshold=25000, ddos-max-halfopen=50000, ddos-mode=auto, ikev1-policy=accept
000 ikebuf=0, msg_errqueue=yes, crl-strict=no, crlcheckinterval=0, listen=<any>, nflog-all=0
000 ocsp-enable=no, ocsp-strict=no, ocsp-timeout=2, ocsp-uri=<unset>
000 ocsp-trust-name=<unset>
000 ocsp-cache-size=1000, ocsp-cache-min-age=3600, ocsp-cache-max-age=86400, ocsp-method=get
000 global-redirect=no, global-redirect-to=<unset>
000 secctx-attr-type=32001
000 debug:
000
000 nat-traversal=yes, keep-alive=20, nat-ikeport=4500
000 virtual-private (%priv):
000
000 Kernel algorithms supported:
000
000 algorithm ESP encrypt: name=3DES_CBC, keysizemin=192, keysizemax=192
000 algorithm ESP encrypt: name=AES_CBC, keysizemin=128, keysizemax=256
000 algorithm ESP encrypt: name=AES_CCM_12, keysizemin=128, keysizemax=256
000 algorithm ESP encrypt: name=AES_CCM_16, keysizemin=128, keysizemax=256
000 algorithm ESP encrypt: name=AES_CCM_8, keysizemin=128, keysizemax=256
000 algorithm ESP encrypt: name=AES_CTR, keysizemin=128, keysizemax=256
000 algorithm ESP encrypt: name=AES_GCM_12, keysizemin=128, keysizemax=256
000 algorithm ESP encrypt: name=AES_GCM_16, keysizemin=128, keysizemax=256
000 algorithm ESP encrypt: name=AES_GCM_8, keysizemin=128, keysizemax=256
000 algorithm ESP encrypt: name=CAMELLIA_CBC, keysizemin=128, keysizemax=256
000 algorithm ESP encrypt: name=CHACHA20_POLY1305, keysizemin=256, keysizemax=256
000 algorithm ESP encrypt: name=NULL, keysizemin=0, keysizemax=0
000 algorithm ESP encrypt: name=NULL_AUTH_AES_GMAC, keysizemin=128, keysizemax=256
000 algorithm AH/ESP auth: name=AES_CMAC_96, key-length=128
000 algorithm AH/ESP auth: name=AES_XCBC_96, key-length=128
000 algorithm AH/ESP auth: name=HMAC_MD5_96, key-length=128
000 algorithm AH/ESP auth: name=HMAC_SHA1_96, key-length=160
000 algorithm AH/ESP auth: name=HMAC_SHA2_256_128, key-length=256
000 algorithm AH/ESP auth: name=HMAC_SHA2_256_TRUNCBUG, key-length=256
000 algorithm AH/ESP auth: name=HMAC_SHA2_384_192, key-length=384
000 algorithm AH/ESP auth: name=HMAC_SHA2_512_256, key-length=512
000 algorithm AH/ESP auth: name=NONE, key-length=0
000
000 IKE algorithms supported:
000
000 algorithm IKE encrypt: v1id=5, v1name=OAKLEY_3DES_CBC, v2id=3, v2name=3DES, blocksize=8, keydeflen=192
000 algorithm IKE encrypt: v1id=8, v1name=OAKLEY_CAMELLIA_CBC, v2id=23, v2name=CAMELLIA_CBC, blocksize=16, keydeflen=128
000 algorithm IKE encrypt: v1id=-1, v1name=n/a, v2id=20, v2name=AES_GCM_C, blocksize=16, keydeflen=128
000 algorithm IKE encrypt: v1id=-1, v1name=n/a, v2id=19, v2name=AES_GCM_B, blocksize=16, keydeflen=128
000 algorithm IKE encrypt: v1id=-1, v1name=n/a, v2id=18, v2name=AES_GCM_A, blocksize=16, keydeflen=128
000 algorithm IKE encrypt: v1id=13, v1name=OAKLEY_AES_CTR, v2id=13, v2name=AES_CTR, blocksize=16, keydeflen=128
000 algorithm IKE encrypt: v1id=7, v1name=OAKLEY_AES_CBC, v2id=12, v2name=AES_CBC, blocksize=16, keydeflen=128
000 algorithm IKE encrypt: v1id=-1, v1name=n/a, v2id=28, v2name=CHACHA20_POLY1305, blocksize=16, keydeflen=256
000 algorithm IKE PRF: name=HMAC_MD5, hashlen=16
000 algorithm IKE PRF: name=HMAC_SHA1, hashlen=20
000 algorithm IKE PRF: name=HMAC_SHA2_256, hashlen=32
000 algorithm IKE PRF: name=HMAC_SHA2_384, hashlen=48
000 algorithm IKE PRF: name=HMAC_SHA2_512, hashlen=64
000 algorithm IKE PRF: name=AES_XCBC, hashlen=16
000 algorithm IKE DH Key Exchange: name=MODP1536, bits=1536
000 algorithm IKE DH Key Exchange: name=MODP2048, bits=2048
000 algorithm IKE DH Key Exchange: name=MODP3072, bits=3072
000 algorithm IKE DH Key Exchange: name=MODP4096, bits=4096
000 algorithm IKE DH Key Exchange: name=MODP6144, bits=6144
000 algorithm IKE DH Key Exchange: name=MODP8192, bits=8192
000 algorithm IKE DH Key Exchange: name=DH19, bits=512
000 algorithm IKE DH Key Exchange: name=DH20, bits=768
000 algorithm IKE DH Key Exchange: name=DH21, bits=1056
000 algorithm IKE DH Key Exchange: name=DH31, bits=256
000
000 stats db_ops: {curr_cnt, total_cnt, maxsz} :context={0,0,0} trans={0,0,0} attrs={0,0,0}
000
000 Connection list:
000
000 "vpc1-vpc2": 10.2.0.0/16===10.2.100.192[3.85.251.173]---10.2.100.1...99.79.175.155===10.88.0.0/16; erouted; eroute owner: #2
000 "vpc1-vpc2":     oriented; my_ip=unset; their_ip=unset; my_updown=ipsec _updown;
000 "vpc1-vpc2":   xauth us:none, xauth them:none,  my_username=[any]; their_username=[any]
000 "vpc1-vpc2":   our auth:secret, their auth:secret, our autheap:none, their autheap:none;
000 "vpc1-vpc2":   modecfg info: us:none, them:none, modecfg policy:push, dns:unset, domains:unset, cat:unset;
000 "vpc1-vpc2":   sec_label:unset;
000 "vpc1-vpc2":   ike_life: 28800s; ipsec_life: 3600s; ipsec_max_bytes: 2^63B; ipsec_max_packets: 2^63; replay_window: 128; rekey_margin: 540s; rekey_fuzz: 100%; keyingtries: 0;
000 "vpc1-vpc2":   retransmit-interval: 500ms; retransmit-timeout: 60s; iketcp:no; iketcp-port:4500;
000 "vpc1-vpc2":   initial-contact:no; cisco-unity:no; fake-strongswan:no; send-vendorid:no; send-no-esp-tfc:no;
000 "vpc1-vpc2":   policy: IKEv2+PSK+ENCRYPT+TUNNEL+PFS+UP+IKE_FRAG_ALLOW+ESN_NO+ESN_YES;
000 "vpc1-vpc2":   v2-auth-hash-policy: none;
000 "vpc1-vpc2":   conn_prio: 16,16; interface: ens5; metric: 0; mtu: unset; sa_prio:auto; sa_tfc:none;
000 "vpc1-vpc2":   nflog-group: unset; mark: unset; vti-iface:unset; vti-routing:no; vti-shared:no; nic-offload:auto;
000 "vpc1-vpc2":   our idtype: ID_IPV4_ADDR; our id=3.85.251.173; their idtype: ID_IPV4_ADDR; their id=99.79.175.155
000 "vpc1-vpc2":   liveness: active; dpdaction:restart; dpddelay:30s; retransmit-timeout:60s
000 "vpc1-vpc2":   nat-traversal: encaps:auto; keepalive:20s
000 "vpc1-vpc2":   newest IKE SA: #1; newest IPsec SA: #2; conn serial: $1;
000 "vpc1-vpc2":   IKE algorithms: AES_CBC_256-HMAC_SHA2_256-MODP2048, AES_CBC_256-HMAC_SHA1-MODP2048, AES_CBC_128-HMAC_SHA2_256-MODP2048, AES_CBC_128-HMAC_SHA1-MODP2048
000 "vpc1-vpc2":   IKEv2 algorithm newest: AES_CBC_256-HMAC_SHA2_256-MODP2048
000 "vpc1-vpc2":   ESP algorithms: AES_GCM_16_256-NONE, CHACHA20_POLY1305-NONE, AES_CBC_256-HMAC_SHA2_512_256+HMAC_SHA1_96+HMAC_SHA2_256_128, AES_GCM_16_128-NONE, AES_CBC_128-HMAC_SHA1_96+HMAC_SHA2_256_128
000 "vpc1-vpc2":   ESP algorithm newest: AES_GCM_16_256-NONE; pfsgroup=<Phase1>
000
000 Total IPsec connections: loaded 1, active 1
000
000 State Information: DDoS cookies not required, Accepting new IKE connections
000 IKE SAs: total(1), half-open(0), open(0), authenticated(1), anonymous(0)
000 IPsec SAs: total(1), authenticated(1), anonymous(0)
000
000 #1: "vpc1-vpc2":4500 STATE_V2_ESTABLISHED_IKE_SA (established IKE SA); REKEY in 27476s; REPLACE in 28248s; newest; idle;
000 #2: "vpc1-vpc2":4500 STATE_V2_ESTABLISHED_CHILD_SA (established Child SA); LIVENESS in 18s; REKEY in 2487s; REPLACE in 3048s; newest; eroute owner; IKE SA #1; idle;
000 #2: "vpc1-vpc2" esp.b9e564dc@99.79.175.155 esp.b81df6e@10.2.100.192 tun.0@99.79.175.155 tun.0@10.2.100.192 Traffic: ESPin=4KB ESPout=8KB ESPmax=2^63B
000
000 Bare Shunt list:
000
+ sudo ip xfrm policy show
src 10.2.0.0/16 dst 10.88.0.0/16
        dir out priority 1761505 ptype main
        tmpl src 10.2.100.192 dst 99.79.175.155
                proto esp reqid 16389 mode tunnel
src 10.88.0.0/16 dst 10.2.0.0/16
        dir fwd priority 1761505 ptype main
        tmpl src 99.79.175.155 dst 10.2.100.192
                proto esp reqid 16389 mode tunnel
src 10.88.0.0/16 dst 10.2.0.0/16
        dir in priority 1761505 ptype main
        tmpl src 99.79.175.155 dst 10.2.100.192
                proto esp reqid 16389 mode tunnel
src ::/0 dst ::/0
        socket out priority 0 ptype main
src ::/0 dst ::/0
        socket in priority 0 ptype main
src ::/0 dst ::/0
        socket out priority 0 ptype main
src ::/0 dst ::/0
        socket in priority 0 ptype main
src 0.0.0.0/0 dst 0.0.0.0/0
        socket out priority 0 ptype main
src 0.0.0.0/0 dst 0.0.0.0/0
        socket in priority 0 ptype main
src 0.0.0.0/0 dst 0.0.0.0/0
        socket out priority 0 ptype main
src 0.0.0.0/0 dst 0.0.0.0/0
        socket in priority 0 ptype main
src 0.0.0.0/0 dst 0.0.0.0/0
        socket out priority 0 ptype main
src 0.0.0.0/0 dst 0.0.0.0/0
        socket in priority 0 ptype main
src 0.0.0.0/0 dst 0.0.0.0/0
        socket out priority 0 ptype main
src 0.0.0.0/0 dst 0.0.0.0/0
        socket in priority 0 ptype main
src ::/0 dst ::/0 proto ipv6-icmp type 135
        dir out priority 1 ptype main
src ::/0 dst ::/0 proto ipv6-icmp type 135
        dir fwd priority 1 ptype main
src ::/0 dst ::/0 proto ipv6-icmp type 135
        dir in priority 1 ptype main
src ::/0 dst ::/0 proto ipv6-icmp type 136
        dir out priority 1 ptype main
src ::/0 dst ::/0 proto ipv6-icmp type 136
        dir fwd priority 1 ptype main
src ::/0 dst ::/0 proto ipv6-icmp type 136
        dir in priority 1 ptype main
+ sudo ip xfrm state show
src 99.79.175.155 dst 10.2.100.192
        proto esp spi 0x0b81df6e reqid 16389 mode tunnel
        replay-window 0 flag af-unspec esn
        aead rfc4106(gcm(aes)) 0xb717b9ffb3ec46f35ec83b4dd124f64d2f32793c0709b0c01ac72a924430a7571eb417ae 128
        encap type espinudp sport 4500 dport 4500 addr 0.0.0.0
        anti-replay esn context:
         seq-hi 0x0, seq 0x18, oseq-hi 0x0, oseq 0x0
         replay_window 128, bitmap-length 4
         00000000 00000000 00000000 00ffffff
src 10.2.100.192 dst 99.79.175.155
        proto esp spi 0xb9e564dc reqid 16389 mode tunnel
        replay-window 0 flag af-unspec esn
        aead rfc4106(gcm(aes)) 0x6ad2a89ad3ff0c5cd3389ba419ce04e7b3a37621bd5f90e58635a63adcb63e1a605987c2 128
        encap type espinudp sport 4500 dport 4500 addr 0.0.0.0
        anti-replay esn context:
         seq-hi 0x0, seq 0x0, oseq-hi 0x0, oseq 0x1d
         replay_window 128, bitmap-length 4
         00000000 00000000 00000000 00000000





Connecting to instance private-a [i-0fac5f30b85b3c01c] to test connectivity with vpc-b

This session is encrypted using AWS KMS.
+ date
Fri Mar 28 20:49:13 UTC 2025
+ hostname -I
10.88.1.167
+ ping -c 10 10.2.1.92
PING 10.2.1.92 (10.2.1.92) 56(84) bytes of data.
64 bytes from 10.2.1.92: icmp_seq=1 ttl=125 time=16.3 ms
64 bytes from 10.2.1.92: icmp_seq=2 ttl=125 time=15.3 ms
64 bytes from 10.2.1.92: icmp_seq=3 ttl=125 time=15.4 ms
64 bytes from 10.2.1.92: icmp_seq=4 ttl=125 time=15.3 ms
64 bytes from 10.2.1.92: icmp_seq=5 ttl=125 time=16.3 ms
64 bytes from 10.2.1.92: icmp_seq=6 ttl=125 time=15.3 ms
64 bytes from 10.2.1.92: icmp_seq=7 ttl=125 time=15.2 ms
64 bytes from 10.2.1.92: icmp_seq=8 ttl=125 time=15.3 ms
64 bytes from 10.2.1.92: icmp_seq=9 ttl=125 time=15.3 ms
64 bytes from 10.2.1.92: icmp_seq=10 ttl=125 time=15.3 ms

--- 10.2.1.92 ping statistics ---
10 packets transmitted, 10 received, 0% packet loss, time 9013ms
rtt min/avg/max/mdev = 15.215/15.493/16.349/0.406 ms
+ nslookup vpce-0713a2c2ccad3053f-rnmelaak.ec2.us-east-1.vpce.amazonaws.com
Server:         10.88.0.2
Address:        10.88.0.2#53

Non-authoritative answer:
Name:   vpce-0713a2c2ccad3053f-rnmelaak.ec2.us-east-1.vpce.amazonaws.com
Address: 10.2.3.20
Name:   vpce-0713a2c2ccad3053f-rnmelaak.ec2.us-east-1.vpce.amazonaws.com
Address: 10.2.4.127

+ aws ec2 describe-vpcs --region us-east-1 --endpoint-url https://vpce-0713a2c2ccad3053f-rnmelaak.ec2.us-east-1.vpce.amazonaws.com
+ grep VpcId
            "VpcId": "vpc-084c9c6bf755c539d",
+ echo it works
it works





Connecting to instance private-b [i-0d57a47c9d16ea024] to test connectivity with vpc-a

+ date
Fri Mar 28 20:50:08 UTC 2025
+ hostname -I
10.2.1.92
+ ping -c 10 10.88.1.167
PING 10.88.1.167 (10.88.1.167) 56(84) bytes of data.
64 bytes from 10.88.1.167: icmp_seq=1 ttl=125 time=15.2 ms
64 bytes from 10.88.1.167: icmp_seq=2 ttl=125 time=15.2 ms
64 bytes from 10.88.1.167: icmp_seq=3 ttl=125 time=15.5 ms
64 bytes from 10.88.1.167: icmp_seq=4 ttl=125 time=15.2 ms
64 bytes from 10.88.1.167: icmp_seq=5 ttl=125 time=15.2 ms
64 bytes from 10.88.1.167: icmp_seq=6 ttl=125 time=15.3 ms
64 bytes from 10.88.1.167: icmp_seq=7 ttl=125 time=15.3 ms
64 bytes from 10.88.1.167: icmp_seq=8 ttl=125 time=15.4 ms
64 bytes from 10.88.1.167: icmp_seq=9 ttl=125 time=15.2 ms
64 bytes from 10.88.1.167: icmp_seq=10 ttl=125 time=15.4 ms

--- 10.88.1.167 ping statistics ---
10 packets transmitted, 10 received, 0% packet loss, time 9013ms
rtt min/avg/max/mdev = 15.170/15.294/15.549/0.116 ms
+ nslookup vpce-021dbcef3371cbfd4-j13v3ibj.ec2.ca-central-1.vpce.amazonaws.com
Server:         10.2.0.2
Address:        10.2.0.2#53

Non-authoritative answer:
Name:   vpce-021dbcef3371cbfd4-j13v3ibj.ec2.ca-central-1.vpce.amazonaws.com
Address: 10.88.4.30
Name:   vpce-021dbcef3371cbfd4-j13v3ibj.ec2.ca-central-1.vpce.amazonaws.com
Address: 10.88.3.116

+ aws ec2 describe-vpcs --region ca-central-1 --endpoint-url https://vpce-021dbcef3371cbfd4-j13v3ibj.ec2.ca-central-1.vpce.amazonaws.com
+ grep VpcId
            "VpcId": "vpc-08cf404f80dd5443a",
            "VpcId": "vpc-0fa5b6c6511940598",
+ echo it works
it works
```

Destroying ressources

```bash
terraform destroy -auto-approve
```

## Issues

[IKE DH algorithm 'modp1024' is not supported #123](https://github.com/nm-l2tp/NetworkManager-l2tp/issues/123)

> A stronger algorith was used

## Debugging with Cloud Watch Insights

If you have errors, please consult clouwd watch logs created for VPC flow log:

```bash
fields @timestamp, @message, @logStream, @log
| sort @timestamp desc
#| filter interface-id = "eni-079933fd84f4cae9a"
#| filter dstAddr = "10.2.9.1"
| filter action = "REJECT"
| stats count(*) by dstAddr, dstPort, dstProtocol
| limit 10000
```

## Docs


<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.1 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 3.0 |
| <a name="requirement_random"></a> [random](#requirement\_random) | >= 3.7.1 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws.provider_a"></a> [aws.provider\_a](#provider\_aws.provider\_a) | >= 3.0 |
| <a name="provider_aws.provider_b"></a> [aws.provider\_b](#provider\_aws.provider\_b) | >= 3.0 |
| <a name="provider_random"></a> [random](#provider\_random) | >= 3.7.1 |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_ec2-private-a"></a> [ec2-private-a](#module\_ec2-private-a) | ../modules/ec2 | n/a |
| <a name="module_ec2-private-b"></a> [ec2-private-b](#module\_ec2-private-b) | ../modules/ec2 | n/a |
| <a name="module_ec2-vpn-a"></a> [ec2-vpn-a](#module\_ec2-vpn-a) | ../modules/ec2 | n/a |
| <a name="module_ec2-vpn-b"></a> [ec2-vpn-b](#module\_ec2-vpn-b) | ../modules/ec2 | n/a |
| <a name="module_vpc-a"></a> [vpc-a](#module\_vpc-a) | terraform-aws-modules/vpc/aws | >= 5.19.0 |
| <a name="module_vpc-a-endpoints"></a> [vpc-a-endpoints](#module\_vpc-a-endpoints) | terraform-aws-modules/vpc/aws//modules/vpc-endpoints | >= 5.19.0 |
| <a name="module_vpc-b"></a> [vpc-b](#module\_vpc-b) | terraform-aws-modules/vpc/aws | >= 5.19.0 |
| <a name="module_vpc-b-endpoints"></a> [vpc-b-endpoints](#module\_vpc-b-endpoints) | terraform-aws-modules/vpc/aws//modules/vpc-endpoints | >= 5.19.0 |

## Resources

| Name | Type |
|------|------|
| [aws_eip.vpc-a-public](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eip) | resource |
| [aws_eip.vpc-b-public](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eip) | resource |
| [aws_route.vpn-a-private](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route) | resource |
| [aws_route.vpn-a-public](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route) | resource |
| [aws_route.vpn-b-private](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route) | resource |
| [aws_route.vpn-b-public](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route) | resource |
| [random_string.secret](https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/string) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_azs_a"></a> [azs\_a](#input\_azs\_a) | n/a | `list(string)` | <pre>[<br/>  "ca-central-1a",<br/>  "ca-central-1b"<br/>]</pre> | no |
| <a name="input_azs_b"></a> [azs\_b](#input\_azs\_b) | n/a | `list(string)` | <pre>[<br/>  "us-east-1a",<br/>  "us-east-1b"<br/>]</pre> | no |
| <a name="input_iam_instance_profile"></a> [iam\_instance\_profile](#input\_iam\_instance\_profile) | EC2 IAM instance profile | `string` | `"AWSAccelerator-SessionManagerEc2Role"` | no |
| <a name="input_region_a"></a> [region\_a](#input\_region\_a) | n/a | `string` | `"ca-central-1"` | no |
| <a name="input_region_b"></a> [region\_b](#input\_region\_b) | n/a | `string` | `"us-east-1"` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | Tags to be used on all resources | `map(string)` | <pre>{<br/>  "CreatedBy": "Terraform",<br/>  "Project": "POC-VPN"<br/>}</pre> | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_ec2-private-a"></a> [ec2-private-a](#output\_ec2-private-a) | EC2 on VPC-A private subnet |
| <a name="output_ec2-private-b"></a> [ec2-private-b](#output\_ec2-private-b) | EC2 on VPC-B private subnet |
| <a name="output_ec2-vpn-a"></a> [ec2-vpn-a](#output\_ec2-vpn-a) | EC2 on VPC-a public subnet |
| <a name="output_ec2-vpn-b"></a> [ec2-vpn-b](#output\_ec2-vpn-b) | EC2 on VPC-B public subnet |
| <a name="output_endpoints-a"></a> [endpoints-a](#output\_endpoints-a) | Endpoints on VPC-A |
| <a name="output_endpoints-b"></a> [endpoints-b](#output\_endpoints-b) | Endpoints on VPC-B |
| <a name="output_region-a"></a> [region-a](#output\_region-a) | Region A |
| <a name="output_region-b"></a> [region-b](#output\_region-b) | Region B |
| <a name="output_test-endpoints-a-0-dns"></a> [test-endpoints-a-0-dns](#output\_test-endpoints-a-0-dns) | Test B-A communication - 1-check IPs |
| <a name="output_test-endpoints-a-1-connect"></a> [test-endpoints-a-1-connect](#output\_test-endpoints-a-1-connect) | Test B-A communication - 2-from B use A endpoint |
| <a name="output_test-endpoints-b-0-dns"></a> [test-endpoints-b-0-dns](#output\_test-endpoints-b-0-dns) | Test A-B communication - 1-check IPs |
| <a name="output_test-endpoints-b-1-connect"></a> [test-endpoints-b-1-connect](#output\_test-endpoints-b-1-connect) | Test A-B communication - 2-from A use B endpoint |
| <a name="output_vpc-a"></a> [vpc-a](#output\_vpc-a) | VPC-A Id |
| <a name="output_vpc-b"></a> [vpc-b](#output\_vpc-b) | VPC-B Id |
<!-- END_TF_DOCS -->
