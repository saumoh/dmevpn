# dmevpn
Dynamic Multipoint E-VPN. Use NHRP to build shortcut VxLAN Tunnels across a non-broadcast network.

# Origin
This work is based off opennhrp source code.

# RFC's Implemented
Opennhrp implements RFC-2332 (nhrp). https://tools.ietf.org/html/rfc2332
This works extends nhrp with RFC-2735 (Nhrp support for Virtual Private
Networks). https://tools.ietf.org/html/rfc2735.

# What it does?
Like DMVPN which enables interconnection of layer-3 networks across
non-broadcast networks DMEVPN enables interconnecting layer-2 networks across a
non-broadcast networks (like Internet).
Specifically, if you have a requirement to extend Vxlan islands across a non-broadcast network then you can use DMEVPN.
DMEVPN can be an alternative to existing, propiterary, offerings like EVPN.
## Feautres
* Support for multiple Virtual Networks (VN). Each virtual network can be distributed across datacenters.
* At a Data center each virtual network's vxlan may have it's own vnid.
  DMEVPN will take care of corellating and mapping vnid's across datacenters.
* Spokes dynamically register with the Hub with their VN and VNID mappings.
* The Hub acts as a learning layer-2 switch therefore across DC mac-addresses are learned dynamically. There is no need for propogating/distributing mac-addresses beyond a single data center.
* Once Hub has learned a mac-address spokes can use NHRP protocol to resolve mac address.
* Spokes then build 'short-cut' Vxlan tunnels to other spokes dynamically.

## Deployment
* DMEVPN spokes would be deployed at the edge of virtual networks in a virtualized data center.
* Hub can be deployed independent of spokes as long as all spokes can reach it.
* DMEVPN spokes act as layer-2 gateways.
** Inside a DC it is safe to assume all mac address that are local to it are
known/discovered. Only unknown mac's would get forwarded to DMEVPN spoke.

## Depenedencies
* At the HUB only, you will need to update the vxlan.ko (4.4.0, drivers/net/vxlan.c) with the provided patch in the patches/ directory. This patch enables learning of ip+vni for a mac-address.

## Example
### Topology:
			+-------------------+
                        |         Hub       |
                        |        br-test    |
                        |         tun2      |
                        |         eth1      |
			|       (10.0.0.1)  |
                        +----------+---------+
                                   |
                +------------------------------------+
    Spoke1      |                                    |     Spoke2  
    +-----------+-------+                   +--------+----------+
    |       (10.0.0.2)  |                   |     (10.0.0.3)    |
    |         eth1      |                   |        eth1       |
    |         tun2      |                   |        tun2       |
    |        br-test    |                   |        br-test    |    
    |          eth2     |                   |      (11.0.0.11)  |
    +-----------+-------+                   +-------------------+
                |
                |
          +-----+-----+
          |11.0.0.10  | 'ping 11.0.0.11'
          |    Vm1    |
          +-----------+

### Spoke1 Configuration
#### Interface and Bridge setup
```
ip addr add dev eth1 10.0.0.2/24
ip link set eth1 up
# GRE Tunnel for NHRP Traffic
ip link add name tunnel1 type gre remote 10.0.0.1 local 10.0.0.2
ip link set tunnel1 up
ip addr add dev tunnel1 1.0.0.2/24
# Vxlan tunnel for layer-2 traffic (to Hub)
ip link add name tunnel2 type vxlan id 100 remote 10.0.0.1 local 10.0.0.2 \
 l2miss nolearning
ip link set tunnel2 up
# setup interface to VM
ip link set eth2 up
# Create the bridge
brctl addbr br-test
ip link set br-test up
# Add interfaces to the bridge
brctl addif br-test eth2 tunnel2
bridge fdb del 00:00:00:00:00:00 dev tunnel2
# For Broadcast forwarding to Hub
bridge fdb add ff:ff:ff:ff:ff:ff dev tunnel2 dst 10.0.0.1 vni 100
```

#### opennhrp.conf
```
# GRE tunnel for NHRP.
interface tunnel1
    vpn-id 1
    map-vni 100 1.0.0.1 2e:cd:9a:5c:ae:c7 register

# Vxlan tunnel for dataplane. VPN, Vnid and NHRP controller intf.
interface tunnel2
    vpn-id 1
    default-vni 100 10.0.0.1
    controller tunnel1

interface br-test
    vpn-id 1
```

### Spoke2 Configuration
#### Interface and Bridge setup
```
ip addr add dev eth1 10.0.0.3/24
ip link set eth1 up
# GRE Tunnel
ip link add name tunnel1 type gre remote 10.0.0.1 local 10.0.0.3
ip link set tunnel1 up
ip addr add dev tunnel1 1.0.0.3/24
# Vxlan tunnel
ip link add name tunnel2 type vxlan id 101 remote 10.0.0.1 local 10.0.0.3 \
 l2miss nolearning
ip link set tunnel2 up
#ip link set eth2 up
brctl addbr br-test
ip link set br-test up
brctl addif br-test tunnel2
bridge fdb del 00:00:00:00:00:00 dev tunnel2 
ip addr add 11.0.0.11/24 dev br-test
# For Broadcast forwarding to Hub
bridge fdb add ff:ff:ff:ff:ff:ff dev tunnel2 dst 10.0.0.1 vni 101
```

#### opennhrp.conf
```
interface tunnel1
    vpn-id 1
    map-vni 101 1.0.0.1 8a:86:2e:ef:9e:ff register

interface tunnel2
    vpn-id 1
    default-vni 101 10.0.0.1
    controller tunnel1
```

### Hub Configuration
#### Interface and Bridge setup

```
ip addr add dev eth1 10.0.0.1/24
ip link set eth1 up

# mGRE Tunnel
ip link add tunnel1 type gre remote any local 10.0.0.1
ip addr add dev tunnel1 1.0.0.1/24
ip link set tunnel1 up
# Vxlan tunnel to all spokes
ip link add tunnel2 type vxlan remote 0.0.0.0 local 10.0.0.1 external learning
ip link set tunnel2 up
```

#### Hub opennhrp.conf
```
# For NHRP
interface tunnel1

# For Dataplane traffic
interface tunnel2
	vpn-id 1
	l2learnonly
	shortcut-destination
	controller tunnel1

# For handling broadcast traffic
interface eth1
	shortcut-destination
	l2learnonly
	controller tunnel1
```

## Why not use EVPN
* EVPN is based of BGP which you may or may not use.
* EVPN protocol stack is not readily available.
* You may already be familiar or using DMVPN.
