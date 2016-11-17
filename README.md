# dmevpn
Dynamic Multipoint E-VPN. Using NHRP to build cross DC VxLAN Tunnels.

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
* Spokes, dynamically register with the Hub with their VN and VNID mappings.
* The Hub acts as a learning layer-2 switch therefore across DC mac-addresses are learned
 dynamically. Therefore there is no need for propogating/distributing
 mac-addresses beyond a single data center.
* Once Hub has learned a mac-address it can use NHRP protocol to resolve mac address.
* Spokes then build 'short-cut' Vxlan tunnels to each other dynamically.

## Deployment
* DMEVPN spokes would be deployed at the edge of virtual networks at the virtual data center.
* Hub can be deployed independent of spokes as long as all spokes can reach it.
* DMEVPN spokes act as layer-2 gateways.
** Inside a DC it is safe to assume all mac address that are local to it are
known/discovered. Only unknown mac's would get forwarded to DMEVPN spoke.

## Example


## Why not use EVPN
* EVPN is based of BGP which you may or may not use.
* EVPN protocol stack is not readily available.
* You may already be familiar or using DMVPN.
