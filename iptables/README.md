# What is iptables

The `iptables` firewall works by interacting with the packet filtering hooks in the Linux kernel's networking stack. These kernel **hooks** are known as the Netfilter framework.

`iptables` is a userspace tool used to set up, maintain, and inspect the tables of IPv4 and IPv6 packet filter rules in the Linux kernel.

Kernel module `ip_tables` is the one that provide this table-based system for `iptables` to define firewall rules.

If it is not loaded, `iptables` cmd will complain.

```sh
# iptables -L
modprobe: FATAL: Module ip_tables not found.
iptables v1.4.21: can't initialize iptables table `filter': Table does not exist (do you need to insmod?)
Perhaps iptables or your kernel needs to be upgraded.
```

* [reference #1](https://www.digitalocean.com/community/tutorials/a-deep-dive-into-iptables-and-netfilter-architecture)
* [reference #2](https://cateee.net/lkddb/web-lkddb/IP_NF_RAW.html)

# Tables

**tables** are used to organize firewall rules. These tables classify rules according to the type of decisions they are used to make.

`iptables` contains 5 tables:

* **raw** is used only for configuring packets so that they are exempt from **connection tracking**
* **filter** is the default table, and is where all the actions typically associated with a firewall take place
* **nat** is used for network address translation
* **mangle** is used for specialized packet alterations. (i.e toc, tcpmss, ttl etc)
* **security** is used for Mandatory Access Control (MAC) networking rules

The following kernel modules are loaded automatically to support these tables.

These tables/modules are registered with one or more Netfilter hooks.

```sh
# lsmod | grep table | grep ^ip
iptable_security       12705  0
iptable_raw            12678  0
iptable_mangle         12695  0
iptable_nat            12875  0
iptable_filter         12810  1
ip_tables              27078  5 iptable_security,iptable_filter,iptable_mangle,iptable_nat,iptable_raw
```

[reference](https://lwn.net/Articles/267140/)

# Netfilter Hooks


There are 5 Netfilter hooks that modules can register with. As packets progress through the stack, they will trigger the kernel modules that have registered with these hooks.

The following hooks represent various well-defined points in the networking stack:

* **NF_IP_PRE_ROUTING**
  > This hook will be triggered by any incoming traffic very soon after entering the network stack. This hook is processed before any routing decisions have been made regarding where to send the packet.

* **NF_IP_LOCAL_IN**
  > This hook is triggered after an incoming packet has been routed if the packet is destined for the local system.

* **NF_IP_FORWARD**
  > This hook is triggered after an incoming packet has been routed if the packet is to be forwarded to another host.

* **NF_IP_LOCAL_OUT**
  > This hook is triggered by any locally created outbound traffic as soon it hits the network stack.

* **NF_IP_POST_ROUTING**
  > This hook is triggered by any outgoing or forwarded traffic after routing has taken place and just before being put out on the wire.

The following graph shows the flow of packet traverse through the networking stack and where the hooks sit.

The tables are shown in the order that they are actually called by the hooks.

```sh
---> PREROUTING ------> [ROUTE] ---> FWD ----------> POSTROUTING ------>
     Raw                   |        Mangle     ^     Mangle
     Conntrack             |        Filter     |     NAT (Src)
     Mangle                |                   |     Conntrack
     NAT (Dst)             |                   |
     (QDisc)               |                [ROUTE]
                           v                   |
                         INPUT Filter        OUTPUT Raw
                           |   Conntrack       ^    Conntrack
                           |   Mangle          |    Mangle
                           |                   |    NAT (Dst)
                           v                   |    Filter
```

* [reference #1](https://www.netfilter.org/documentation/HOWTO/netfilter-hacking-HOWTO-3.html)
* [reference #2](https://www.digitalocean.com/community/tutorials/a-deep-dive-into-iptables-and-netfilter-architecture)

# Chains

## built-in Chains

The names of the built-in chains mirror the names of the Netfilter hooks they are associated with:

* **PREROUTING**: Triggered by the `NF_IP_PRE_ROUTING` hook.
* **INPUT**: Triggered by the `NF_IP_LOCAL_IN` hook.
* **FORWARD**: Triggered by the `NF_IP_FORWARD` hook.
* **OUTPUT**: Triggered by the `NF_IP_LOCAL_OUT` hook.
* **POSTROUTING**: Triggered by the `NF_IP_POST_ROUTING` hook.

## user-defined Chain

The `-N` option is used to create a user chain. But like the built in chains, you must put rules in it for it to do anything. And you must have one or more rules that jump (`-j`) to it for it to ever come into play.

*A packet that enters a user chain but does not match any rules in it is then returned to the calling chain for further processing.*

**Fun Fact**

One cannot create a chain loop using a user-defined chain.

```sh
# iptables -N test1
# iptables -N test2
# iptables -A test1 -p tcp --dport 8000 -j test2
# iptables -A test2 -p tcp --dport 8000 -j test1
# iptables -A INPUT -p tcp --dport 8000 -j test1
iptables: Too many levels of symbolic links.
# iptables -A INPUT -p tcp --dport 8000 -j test2
iptables: Too many levels of symbolic links.
```

# Targets

(stole from `man iptables`)

A firewall rule specifies criteria for a packet and a target.  If the packet does not match, the next rule in the chain is examined; if it does match, then the next rule is specified by the value of the target, which can be:

* the name of a **user-defined chain**
* one of the targets described in **iptables-extensions**(8)
* one of the special values `ACCEPT`, `DROP`, or `RETURN`

> **REJECT** is described in **iptables-extensions**. (`man iptables-extensions`)

> **RETURN** means stop traversing this chain and resume at the next rule in the previous (calling) chain. If the end of a built-in chain is reached or a rule in a built-in chain with target RETURN is matched, the target specified by the chain policy determines the fate of the packet.

# Conntrack

Connection tracking allows the kernel to keep track of all logical network connections or sessions, and thereby relate all of the packets which may make up that connection. NAT relies on this information to translate all related packets in the same way.

## Connection State

Connection tracking tracks the connections by their state:

* **NEW**: trying to create a new connection
* **ESTABLISHED**: part of an already-existing connection
* **RELATED**: assigned to a packet that is initiating a new connection and which has been "expected"; the aforementioned mini-ALGs set up these expectations, for example, when the nf_conntrack_ftp module sees an FTP "PASV" command
* **INVALID**: the packet was found to be invalid, e.g. it would not adhere to the TCP state diagram
* **UNTRACKED**: a special state that can be assigned by the administrator to bypass connection tracking for a particular packet (see raw table, above).

> **Note**: connection states are completely independent of any upper-level state, such as TCP's state. the connection states are purely used for tracking if packets are related to any known connections

```sh
# cat /proc/net/nf_conntrack
ipv4     2 tcp      6 116 TIME_WAIT src=10.128.0.19 dst=169.254.169.254 sport=57724 dport=80 src=169.254.169.254 dst=10.128.0.19 sport=80 dport=57724 [ASSURED] mark=0 secctx=system_u:object_r:unlabeled_t:s0 zone=0 use=2
ipv4     2 tcp      6 431996 ESTABLISHED src=10.128.0.19 dst=169.254.169.254 sport=57734 dport=80 src=169.254.169.254 dst=10.128.0.19 sport=80 dport=57734 [ASSURED] mark=0 secctx=system_u:object_r:unlabeled_t:s0 zone=0 use=2
ipv4     2 tcp      6 55 TIME_WAIT src=10.128.0.19 dst=169.254.169.254 sport=57722 dport=80 src=169.254.169.254 dst=10.128.0.19 sport=80 dport=57722 [ASSURED] mark=0 secctx=system_u:object_r:unlabeled_t:s0 zone=0 use=2
ipv4     2 tcp      6 56 CLOSE_WAIT src=10.128.0.19 dst=169.254.169.254 sport=57730 dport=80 src=169.254.169.254 dst=10.128.0.19 sport=80 dport=57730 [ASSURED] mark=0 secctx=system_u:object_r:unlabeled_t:s0 zone=0 use=2
...
```

### How to read `/proc/net/conntrack`

|Column|Meaning                                       |Example          |
|------|----------------------------------------------|-----------------|
|1     |The network layer protocol name (eg. ipv4)    |ipv4             |
|2     |The network layer protocol number             |2                |
|3     |The transmission layer protocol name (eg. tcp)|tcp              |
|4     |The transmission layer protocol number        |6                |
|5     |The seconds until the entry is invalidated    |116              |
|6     |The connection state                          |(explained below)|


**Connection State Column**

* Request Direction
  * `src=10.128.0.19 dst=169.254.169.254 sport=57724 dport=80`
* Response Direction
  * `src=169.254.169.254 dst=10.128.0.19 sport=80 dport=57724`
* Flags
  * `[ASSURED]`: Traffic has been seen in both direction.
  * `[UNREPLIED]`: Traffic has not been seen in response direction yet. In case the connection tracking cache overflows, these connections are dropped first.
* Other column names
    * `mark`: *when `CONFIG_NF_CONNTRACK_MARK` is enabled*
    * `secctx`: *when `CONFIG_NF_CONNTRACK_SECMARK` is enabled*
    * `zone`: *when `CONFIG_NF_CONNTRACK_ZONES` is enabled*

## Conntrack-tools

```sh
# rpm -ql conntrack-tools | grep bin
/usr/sbin/conntrack
/usr/sbin/conntrackd
```

* `conntrack`
  > command line interface for netfilter connection tracking
* `conntrackd`
  > Userspace daemon for the netfilter connection tracking system. This daemon synchronizes connection tracking states among several replica firewalls. Thus, conntrackd can be used to implement highly available stateful firewalls

# GKE node iptables

```sh
# k get service
NAME              TYPE           CLUSTER-IP      EXTERNAL-IP    PORT(S)        AGE
php-svc-cluster   LoadBalancer   10.51.245.210   35.194.9.137   80:31334/TCP   51s
```

```sh
# k get pods -o wide
NAME                             READY     STATUS    RESTARTS   AGE       IP          NODE
nm-php-apache-7f6664bc86-5hlcs   1/1       Running   0          5m        10.48.0.8   gke-rei-default-pool-394a596a-8q2w
nm-php-apache-7f6664bc86-cg7hm   1/1       Running   0          5m        10.48.2.9   gke-rei-default-pool-394a596a-7hvp
```

## Filter table

```sh
# iptables -S
-P INPUT DROP
-P FORWARD DROP
-P OUTPUT DROP
-N DOCKER
-N DOCKER-ISOLATION
-N KUBE-FIREWALL
-N KUBE-FORWARD
-N KUBE-SERVICES
-A INPUT -m comment --comment "kubernetes service portals" -j KUBE-SERVICES
-A INPUT -j KUBE-FIREWALL
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -j ACCEPT
-A INPUT -p udp -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A FORWARD -m comment --comment "kubernetes forward rules" -j KUBE-FORWARD
-A FORWARD -j DOCKER-ISOLATION
-A FORWARD -o docker0 -j DOCKER
-A FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -i docker0 ! -o docker0 -j ACCEPT
-A FORWARD -i docker0 -o docker0 -j ACCEPT
-A FORWARD -p tcp -j ACCEPT
-A FORWARD -p udp -j ACCEPT
-A FORWARD -p icmp -j ACCEPT
-A OUTPUT -m comment --comment "kubernetes service portals" -j KUBE-SERVICES
-A OUTPUT -j KUBE-FIREWALL
-A OUTPUT -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
-A DOCKER-ISOLATION -j RETURN
-A KUBE-FIREWALL -m comment --comment "kubernetes firewall for dropping marked packets" -m mark --mark 0x8000/0x8000 -j DROP
-A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
-A KUBE-FORWARD -s 10.48.0.0/14 -m comment --comment "kubernetes forwarding conntrack pod source rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A KUBE-FORWARD -d 10.48.0.0/14 -m comment --comment "kubernetes forwarding conntrack pod destination rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
```

## NAT table

```sh
# iptables -S -t nat
-P PREROUTING ACCEPT
-P INPUT ACCEPT
-P OUTPUT ACCEPT
-P POSTROUTING ACCEPT
-N DOCKER
-N KUBE-FW-G7IQRGQTLD7QNWZ3
-N KUBE-MARK-DROP
-N KUBE-MARK-MASQ
-N KUBE-NODEPORTS
-N KUBE-POSTROUTING
-N KUBE-SEP-2D2HJ4OCY4HAWBOD
-N KUBE-SEP-4JCKH2KHUYRHF7HZ
-N KUBE-SEP-5RHSZUR2PWOQ3NTM
-N KUBE-SEP-CPXCLP32ZKDAPKUH
-N KUBE-SEP-CXUJ2M5ZPG4H3H7X
-N KUBE-SEP-JDV2BSYHCKXHJZXV
-N KUBE-SEP-JHTE4CU765CAHTPG
-N KUBE-SEP-MLCZHMTK7QKZGSQJ
-N KUBE-SEP-QFBR6SVREQLGBTDF
-N KUBE-SEP-T7B33FRVAHNJ7XW7
-N KUBE-SEP-YMH4C5UZTUSMGEKH
-N KUBE-SERVICES
-N KUBE-SVC-BJM46V3U5RZHCFRZ
-N KUBE-SVC-ERIFXISQEP7F7OF4
-N KUBE-SVC-G7IQRGQTLD7QNWZ3
-N KUBE-SVC-LC5QY66VUV2HJ6WZ
-N KUBE-SVC-NPX46M4PTMTKRN6Y
-N KUBE-SVC-TCOU7JCQXEZGVUNU
-N KUBE-SVC-XGLOHA7QRQ3V22RZ
-N KUBE-SVC-XP4WJ6VSLGWALMW5
-A PREROUTING -m comment --comment "kubernetes service portals" -j KUBE-SERVICES
-A OUTPUT -m comment --comment "kubernetes service portals" -j KUBE-SERVICES
-A POSTROUTING -m comment --comment "kubernetes postrouting rules" -j KUBE-POSTROUTING
-A POSTROUTING ! -d 10.0.0.0/8 -m comment --comment "kubenet: SNAT for outbound traffic from cluster" -m addrtype ! --dst-type LOCAL -j MASQUERADE
-A KUBE-FW-G7IQRGQTLD7QNWZ3 -m comment --comment "default/php-svc-cluster:http loadbalancer IP" -j KUBE-MARK-MASQ
-A KUBE-FW-G7IQRGQTLD7QNWZ3 -m comment --comment "default/php-svc-cluster:http loadbalancer IP" -j KUBE-SVC-G7IQRGQTLD7QNWZ3
-A KUBE-FW-G7IQRGQTLD7QNWZ3 -m comment --comment "default/php-svc-cluster:http loadbalancer IP" -j KUBE-MARK-DROP
-A KUBE-MARK-DROP -j MARK --set-xmark 0x8000/0x8000
-A KUBE-MARK-MASQ -j MARK --set-xmark 0x4000/0x4000
-A KUBE-NODEPORTS -p tcp -m comment --comment "default/php-svc-cluster:http" -m tcp --dport 31334 -j KUBE-MARK-MASQ
-A KUBE-NODEPORTS -p tcp -m comment --comment "default/php-svc-cluster:http" -m tcp --dport 31334 -j KUBE-SVC-G7IQRGQTLD7QNWZ3
-A KUBE-NODEPORTS -p tcp -m comment --comment "kube-system/default-http-backend:http" -m tcp --dport 30940 -j KUBE-MARK-MASQ
-A KUBE-NODEPORTS -p tcp -m comment --comment "kube-system/default-http-backend:http" -m tcp --dport 30940 -j KUBE-SVC-XP4WJ6VSLGWALMW5
-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -m mark --mark 0x4000/0x4000 -j MASQUERADE
-A KUBE-SEP-2D2HJ4OCY4HAWBOD -s 10.48.0.8/32 -m comment --comment "default/php-svc-cluster:http" -j KUBE-MARK-MASQ
-A KUBE-SEP-2D2HJ4OCY4HAWBOD -p tcp -m comment --comment "default/php-svc-cluster:http" -m tcp -j DNAT --to-destination 10.48.0.8:80
-A KUBE-SEP-4JCKH2KHUYRHF7HZ -s 10.48.0.4/32 -m comment --comment "kube-system/kube-dns:dns" -j KUBE-MARK-MASQ
-A KUBE-SEP-4JCKH2KHUYRHF7HZ -p udp -m comment --comment "kube-system/kube-dns:dns" -m udp -j DNAT --to-destination 10.48.0.4:53
-A KUBE-SEP-5RHSZUR2PWOQ3NTM -s 10.48.0.3/32 -m comment --comment "kube-system/default-http-backend:http" -j KUBE-MARK-MASQ
-A KUBE-SEP-5RHSZUR2PWOQ3NTM -p tcp -m comment --comment "kube-system/default-http-backend:http" -m tcp -j DNAT --to-destination 10.48.0.3:8080
-A KUBE-SEP-CPXCLP32ZKDAPKUH -s 10.48.2.8/32 -m comment --comment "kube-system/kube-dns:dns" -j KUBE-MARK-MASQ
-A KUBE-SEP-CPXCLP32ZKDAPKUH -p udp -m comment --comment "kube-system/kube-dns:dns" -m udp -j DNAT --to-destination 10.48.2.8:53
-A KUBE-SEP-CXUJ2M5ZPG4H3H7X -s 35.188.99.132/32 -m comment --comment "default/kubernetes:https" -j KUBE-MARK-MASQ
-A KUBE-SEP-CXUJ2M5ZPG4H3H7X -p tcp -m comment --comment "default/kubernetes:https" -m recent --set --name KUBE-SEP-CXUJ2M5ZPG4H3H7X --mask 255.255.255.255 --rsource -m tcp -j DNAT --to-destination 35.188.99.132:443
-A KUBE-SEP-JDV2BSYHCKXHJZXV -s 10.48.2.8/32 -m comment --comment "kube-system/kube-dns:dns-tcp" -j KUBE-MARK-MASQ
-A KUBE-SEP-JDV2BSYHCKXHJZXV -p tcp -m comment --comment "kube-system/kube-dns:dns-tcp" -m tcp -j DNAT --to-destination 10.48.2.8:53
-A KUBE-SEP-JHTE4CU765CAHTPG -s 10.48.2.6/32 -m comment --comment "kube-system/kubernetes-dashboard:" -j KUBE-MARK-MASQ
-A KUBE-SEP-JHTE4CU765CAHTPG -p tcp -m comment --comment "kube-system/kubernetes-dashboard:" -m tcp -j DNAT --to-destination 10.48.2.6:8443
-A KUBE-SEP-MLCZHMTK7QKZGSQJ -s 10.48.2.9/32 -m comment --comment "default/php-svc-cluster:http" -j KUBE-MARK-MASQ
-A KUBE-SEP-MLCZHMTK7QKZGSQJ -p tcp -m comment --comment "default/php-svc-cluster:http" -m tcp -j DNAT --to-destination 10.48.2.9:80
-A KUBE-SEP-QFBR6SVREQLGBTDF -s 10.48.2.7/32 -m comment --comment "kube-system/metrics-server:" -j KUBE-MARK-MASQ
-A KUBE-SEP-QFBR6SVREQLGBTDF -p tcp -m comment --comment "kube-system/metrics-server:" -m tcp -j DNAT --to-destination 10.48.2.7:443
-A KUBE-SEP-T7B33FRVAHNJ7XW7 -s 10.48.0.6/32 -m comment --comment "kube-system/heapster:" -j KUBE-MARK-MASQ
-A KUBE-SEP-T7B33FRVAHNJ7XW7 -p tcp -m comment --comment "kube-system/heapster:" -m tcp -j DNAT --to-destination 10.48.0.6:8082
-A KUBE-SEP-YMH4C5UZTUSMGEKH -s 10.48.0.4/32 -m comment --comment "kube-system/kube-dns:dns-tcp" -j KUBE-MARK-MASQ
-A KUBE-SEP-YMH4C5UZTUSMGEKH -p tcp -m comment --comment "kube-system/kube-dns:dns-tcp" -m tcp -j DNAT --to-destination 10.48.0.4:53
-A KUBE-SERVICES ! -s 10.48.0.0/14 -d 10.51.254.224/32 -p tcp -m comment --comment "kube-system/kubernetes-dashboard: cluster IP" -m tcp --dport 443 -j KUBE-MARK-MASQ
-A KUBE-SERVICES -d 10.51.254.224/32 -p tcp -m comment --comment "kube-system/kubernetes-dashboard: cluster IP" -m tcp --dport 443 -j KUBE-SVC-XGLOHA7QRQ3V22RZ
-A KUBE-SERVICES ! -s 10.48.0.0/14 -d 10.51.240.10/32 -p udp -m comment --comment "kube-system/kube-dns:dns cluster IP" -m udp --dport 53 -j KUBE-MARK-MASQ
-A KUBE-SERVICES -d 10.51.240.10/32 -p udp -m comment --comment "kube-system/kube-dns:dns cluster IP" -m udp --dport 53 -j KUBE-SVC-TCOU7JCQXEZGVUNU
-A KUBE-SERVICES ! -s 10.48.0.0/14 -d 10.51.240.10/32 -p tcp -m comment --comment "kube-system/kube-dns:dns-tcp cluster IP" -m tcp --dport 53 -j KUBE-MARK-MASQ
-A KUBE-SERVICES -d 10.51.240.10/32 -p tcp -m comment --comment "kube-system/kube-dns:dns-tcp cluster IP" -m tcp --dport 53 -j KUBE-SVC-ERIFXISQEP7F7OF4
-A KUBE-SERVICES ! -s 10.48.0.0/14 -d 10.51.252.202/32 -p tcp -m comment --comment "kube-system/metrics-server: cluster IP" -m tcp --dport 443 -j KUBE-MARK-MASQ
-A KUBE-SERVICES -d 10.51.252.202/32 -p tcp -m comment --comment "kube-system/metrics-server: cluster IP" -m tcp --dport 443 -j KUBE-SVC-LC5QY66VUV2HJ6WZ
-A KUBE-SERVICES ! -s 10.48.0.0/14 -d 10.51.240.1/32 -p tcp -m comment --comment "default/kubernetes:https cluster IP" -m tcp --dport 443 -j KUBE-MARK-MASQ
-A KUBE-SERVICES -d 10.51.240.1/32 -p tcp -m comment --comment "default/kubernetes:https cluster IP" -m tcp --dport 443 -j KUBE-SVC-NPX46M4PTMTKRN6Y
-A KUBE-SERVICES ! -s 10.48.0.0/14 -d 10.51.245.210/32 -p tcp -m comment --comment "default/php-svc-cluster:http cluster IP" -m tcp --dport 80 -j KUBE-MARK-MASQ
-A KUBE-SERVICES -d 10.51.245.210/32 -p tcp -m comment --comment "default/php-svc-cluster:http cluster IP" -m tcp --dport 80 -j KUBE-SVC-G7IQRGQTLD7QNWZ3
-A KUBE-SERVICES -d 35.194.9.137/32 -p tcp -m comment --comment "default/php-svc-cluster:http loadbalancer IP" -m tcp --dport 80 -j KUBE-FW-G7IQRGQTLD7QNWZ3
-A KUBE-SERVICES ! -s 10.48.0.0/14 -d 10.51.247.208/32 -p tcp -m comment --comment "kube-system/default-http-backend:http cluster IP" -m tcp --dport 80 -j KUBE-MARK-MASQ
-A KUBE-SERVICES -d 10.51.247.208/32 -p tcp -m comment --comment "kube-system/default-http-backend:http cluster IP" -m tcp --dport 80 -j KUBE-SVC-XP4WJ6VSLGWALMW5
-A KUBE-SERVICES ! -s 10.48.0.0/14 -d 10.51.245.213/32 -p tcp -m comment --comment "kube-system/heapster: cluster IP" -m tcp --dport 80 -j KUBE-MARK-MASQ
-A KUBE-SERVICES -d 10.51.245.213/32 -p tcp -m comment --comment "kube-system/heapster: cluster IP" -m tcp --dport 80 -j KUBE-SVC-BJM46V3U5RZHCFRZ
-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
-A KUBE-SVC-BJM46V3U5RZHCFRZ -m comment --comment "kube-system/heapster:" -j KUBE-SEP-T7B33FRVAHNJ7XW7
-A KUBE-SVC-ERIFXISQEP7F7OF4 -m comment --comment "kube-system/kube-dns:dns-tcp" -m statistic --mode random --probability 0.50000000000 -j KUBE-SEP-YMH4C5UZTUSMGEKH
-A KUBE-SVC-ERIFXISQEP7F7OF4 -m comment --comment "kube-system/kube-dns:dns-tcp" -j KUBE-SEP-JDV2BSYHCKXHJZXV
-A KUBE-SVC-G7IQRGQTLD7QNWZ3 -m comment --comment "default/php-svc-cluster:http" -m statistic --mode random --probability 0.50000000000 -j KUBE-SEP-2D2HJ4OCY4HAWBOD
-A KUBE-SVC-G7IQRGQTLD7QNWZ3 -m comment --comment "default/php-svc-cluster:http" -j KUBE-SEP-MLCZHMTK7QKZGSQJ
-A KUBE-SVC-LC5QY66VUV2HJ6WZ -m comment --comment "kube-system/metrics-server:" -j KUBE-SEP-QFBR6SVREQLGBTDF
-A KUBE-SVC-NPX46M4PTMTKRN6Y -m comment --comment "default/kubernetes:https" -m recent --rcheck --seconds 10800 --reap --name KUBE-SEP-CXUJ2M5ZPG4H3H7X --mask 255.255.255.255 --rsource -j KUBE-SEP-CXUJ2M5ZPG4H3H7X
-A KUBE-SVC-NPX46M4PTMTKRN6Y -m comment --comment "default/kubernetes:https" -j KUBE-SEP-CXUJ2M5ZPG4H3H7X
-A KUBE-SVC-TCOU7JCQXEZGVUNU -m comment --comment "kube-system/kube-dns:dns" -m statistic --mode random --probability 0.50000000000 -j KUBE-SEP-4JCKH2KHUYRHF7HZ
-A KUBE-SVC-TCOU7JCQXEZGVUNU -m comment --comment "kube-system/kube-dns:dns" -j KUBE-SEP-CPXCLP32ZKDAPKUH
-A KUBE-SVC-XGLOHA7QRQ3V22RZ -m comment --comment "kube-system/kubernetes-dashboard:" -j KUBE-SEP-JHTE4CU765CAHTPG
-A KUBE-SVC-XP4WJ6VSLGWALMW5 -m comment --comment "kube-system/default-http-backend:http" -j KUBE-SEP-5RHSZUR2PWOQ3NTM
```

## Others

```sh
# iptables -S -t mangle
-P PREROUTING ACCEPT
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-P POSTROUTING ACCEPT

# iptables -S -t raw
-P PREROUTING ACCEPT
-P OUTPUT ACCEPT
```
