# What is iptables

The iptables firewall works by interacting with the packet filtering hooks in the Linux kernel's networking stack. These kernel hooks are known as the netfilter framework.

iptables are userspace tools used to set up, maintain, and inspect the tables of IPv4 and IPv6 packet filter rules in the Linux kernel.

Kernel module **ip_tables** is the one that provide this table-based system for iptables to define firewall rules.

If it is not loaded, iptables cmd will complain.

```sh
# iptables -L
modprobe: FATAL: Module ip_tables not found.
iptables v1.4.21: can't initialize iptables table `filter': Table does not exist (do you need to insmod?)
Perhaps iptables or your kernel needs to be upgraded.
```

[reference](https://www.digitalocean.com/community/tutorials/a-deep-dive-into-iptables-and-netfilter-architecture)

# What is iptables Tables

`tables` are used to organize firewall rules. These tables classify rules according to the type of decisions they are used to make.

iptables contains 5 tables:

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
--->PRE------>[ROUTE]--->FWD---------->POST------>
   Raw          |       Mangle   ^    Mangle
   Conntrack    |       Filter   |    NAT (Src)
   Mangle       |                |    Conntrack
   NAT (Dst)    |                |
   (QDisc)      |             [ROUTE]
                v                |
                IN Filter       OUT Raw
                |  Conntrack     ^  Conntrack
                |  Mangle        |  Mangle
                |                |  NAT (Dst)
                v                |  Filter
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

The `-N` option is used to create a user chain. But like the built in chains, you must put rules in it for it to do anything. And you must have one or more rules that **jump** to it for it to ever come into play.

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

Each rule specifies what to do with a packet that matches. This is called a **target**, which may be a jump to a user-defined chain in the same table.

# Conntrack

```sh
# cat /proc/net/nf_conntrack
ipv4     2 tcp      6 116 TIME_WAIT src=10.128.0.19 dst=169.254.169.254 sport=57724 dport=80 src=169.254.169.254 dst=10.128.0.19 sport=80 dport=57724 [ASSURED] mark=0 secctx=system_u:object_r:unlabeled_t:s0 zone=0 use=2
ipv4     2 tcp      6 431996 ESTABLISHED src=10.128.0.19 dst=169.254.169.254 sport=57734 dport=80 src=169.254.169.254 dst=10.128.0.19 sport=80 dport=57734 [ASSURED] mark=0 secctx=system_u:object_r:unlabeled_t:s0 zone=0 use=2
ipv4     2 tcp      6 55 TIME_WAIT src=10.128.0.19 dst=169.254.169.254 sport=57722 dport=80 src=169.254.169.254 dst=10.128.0.19 sport=80 dport=57722 [ASSURED] mark=0 secctx=system_u:object_r:unlabeled_t:s0 zone=0 use=2
ipv4     2 tcp      6 56 CLOSE_WAIT src=10.128.0.19 dst=169.254.169.254 sport=57730 dport=80 src=169.254.169.254 dst=10.128.0.19 sport=80 dport=57730 [ASSURED] mark=0 secctx=system_u:object_r:unlabeled_t:s0 zone=0 use=2
...
```
