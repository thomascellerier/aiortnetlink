#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/genetlink.h>
#include <linux/icmpv6.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    // NLFamily
#ifdef NETLINK_ROUTE
    printf("NLFamily NETLINK_ROUTE %d\n", NETLINK_ROUTE);
#endif
#ifdef NETLINK_W1
    printf("NLFamily NETLINK_W1 %d\n", NETLINK_W1);
#endif
#ifdef NETLINK_USERSOCK
    printf("NLFamily NETLINK_USERSOCK %d\n", NETLINK_USERSOCK);
#endif
#ifdef NETLINK_FIREWALL
    printf("NLFamily NETLINK_FIREWALL %d\n", NETLINK_FIREWALL);
#endif
#ifdef NETLINK_SOCK_DIAG
    printf("NLFamily NETLINK_SOCK_DIAG %d\n", NETLINK_SOCK_DIAG);
#endif
#ifdef NETLINK_INET_DIAG
    printf("NLFamily NETLINK_INET_DIAG %d\n", NETLINK_INET_DIAG);
#endif
#ifdef NETLINK_NFLOG
    printf("NLFamily NETLINK_NFLOG %d\n", NETLINK_NFLOG);
#endif
#ifdef NETLINK_XFRM
    printf("NLFamily NETLINK_XFRM %d\n", NETLINK_XFRM);
#endif
#ifdef NETLINK_SELINUX
    printf("NLFamily NETLINK_SELINUX %d\n", NETLINK_SELINUX);
#endif
#ifdef NETLINK_ISCSI
    printf("NLFamily NETLINK_ISCSI %d\n", NETLINK_ISCSI);
#endif
#ifdef NETLINK_AUDIT
    printf("NLFamily NETLINK_AUDIT %d\n", NETLINK_AUDIT);
#endif
#ifdef NETLINK_FIB_LOOKUP
    printf("NLFamily NETLINK_FIB_LOOKUP %d\n", NETLINK_FIB_LOOKUP);
#endif
#ifdef NETLINK_CONNECTOR
    printf("NLFamily NETLINK_CONNECTOR %d\n", NETLINK_CONNECTOR);
#endif
#ifdef NETLINK_NETFILTER
    printf("NLFamily NETLINK_NETFILTER %d\n", NETLINK_NETFILTER);
#endif
#ifdef NETLINK_IP6_FW
    printf("NLFamily NETLINK_IP6_FW %d\n", NETLINK_IP6_FW);
#endif
#ifdef NETLINK_DNRTMSG
    printf("NLFamily NETLINK_DNRTMSG %d\n", NETLINK_DNRTMSG);
#endif
#ifdef NETLINK_KOBJECT_UEVENT
    printf("NLFamily NETLINK_KOBJECT_UEVENT %d\n", NETLINK_KOBJECT_UEVENT);
#endif
#ifdef NETLINK_GENERIC
    printf("NLFamily NETLINK_GENERIC %d\n", NETLINK_GENERIC);
#endif
#ifdef NETLINK_CRYPTO
    printf("NLFamily NETLINK_CRYPTO %d\n", NETLINK_CRYPTO);
#endif

    // NLMsgType
#ifdef NLMSG_NOOP
    printf("NLMsgType NLMSG_NOOP %d\n", NLMSG_NOOP);
#endif
#ifdef NLMSG_ERROR
    printf("NLMsgType NLMSG_ERROR %d\n", NLMSG_ERROR);
#endif
#ifdef NLMSG_DONE
    printf("NLMsgType NLMSG_DONE %d\n", NLMSG_DONE);
#endif
#ifdef NLMSG_OVERRUN
    printf("NLMsgType NLMSG_OVERRUN %d\n", NLMSG_OVERRUN);
#endif
#ifdef NLMSG_MIN_TYPE
    printf("NLMsgType NLMSG_MIN_TYPE %d\n", NLMSG_MIN_TYPE);
#endif

    // NLFlag
#ifdef NLM_F_REQUEST
    printf("NLFlag NLM_F_REQUEST %d\n", NLM_F_REQUEST);
#endif
#ifdef NLM_F_MULTI
    printf("NLFlag NLM_F_MULTI %d\n", NLM_F_MULTI);
#endif
#ifdef NLM_F_ACK
    printf("NLFlag NLM_F_ACK %d\n", NLM_F_ACK);
#endif
#ifdef NLM_F_ECHO
    printf("NLFlag NLM_F_ECHO %d\n", NLM_F_ECHO);
#endif
#ifdef NLM_F_DUMP_INTR
    printf("NLFlag NLM_F_DUMP_INTR %d\n", NLM_F_DUMP_INTR);
#endif
#ifdef NLM_F_DUMP_FILTERED
    printf("NLFlag NLM_F_DUMP_FILTERED %d\n", NLM_F_DUMP_FILTERED);
#endif
#ifdef NLM_F_ROOT
    printf("NLFlag NLM_F_ROOT %d\n", NLM_F_ROOT);
#endif
#ifdef NLM_F_MATCH
    printf("NLFlag NLM_F_MATCH %d\n", NLM_F_MATCH);
#endif
#ifdef NLM_F_ATOMIC
    printf("NLFlag NLM_F_ATOMIC %d\n", NLM_F_ATOMIC);
#endif
#ifdef NLM_F_DUMP
    printf("NLFlag NLM_F_DUMP %d\n", NLM_F_DUMP);
#endif
#ifdef NLM_F_REPLACE
    printf("NLFlag NLM_F_REPLACE %d\n", NLM_F_REPLACE);
#endif
#ifdef NLM_F_EXCL
    printf("NLFlag NLM_F_EXCL %d\n", NLM_F_EXCL);
#endif
#ifdef NLM_F_CREATE
    printf("NLFlag NLM_F_CREATE %d\n", NLM_F_CREATE);
#endif
#ifdef NLM_F_APPEND
    printf("NLFlag NLM_F_APPEND %d\n", NLM_F_APPEND);
#endif

    // RTNType
    printf("RTNType RTN_UNSPEC %d\n", RTN_UNSPEC);
    printf("RTNType RTN_UNICAST %d\n", RTN_UNICAST);
    printf("RTNType RTN_LOCAL %d\n", RTN_LOCAL);
    printf("RTNType RTN_BROADCAST %d\n", RTN_BROADCAST);
    printf("RTNType RTN_ANYCAST %d\n", RTN_ANYCAST);
    printf("RTNType RTN_MULTICAST %d\n", RTN_MULTICAST);
    printf("RTNType RTN_BLACKHOLE %d\n", RTN_BLACKHOLE);
    printf("RTNType RTN_UNREACHABLE %d\n", RTN_UNREACHABLE);
    printf("RTNType RTN_PROHIBIT %d\n", RTN_PROHIBIT);
    printf("RTNType RTN_THROW %d\n", RTN_THROW);
    printf("RTNType RTN_NAT %d\n", RTN_NAT);
    printf("RTNType RTN_XRESOLVE %d\n", RTN_XRESOLVE);

    // IFLAType
    printf("IFLAType IFLA_UNSPEC %d\n", IFLA_UNSPEC);
    printf("IFLAType IFLA_ADDRESS %d\n", IFLA_ADDRESS);
    printf("IFLAType IFLA_BROADCAST %d\n", IFLA_BROADCAST);
    printf("IFLAType IFLA_IFNAME %d\n", IFLA_IFNAME);
    printf("IFLAType IFLA_MTU %d\n", IFLA_MTU);
    printf("IFLAType IFLA_LINK %d\n", IFLA_LINK);
    printf("IFLAType IFLA_QDISC %d\n", IFLA_QDISC);
    printf("IFLAType IFLA_STATS %d\n", IFLA_STATS);
    printf("IFLAType IFLA_COST %d\n", IFLA_COST);
    printf("IFLAType IFLA_PRIORITY %d\n", IFLA_PRIORITY);
    printf("IFLAType IFLA_MASTER %d\n", IFLA_MASTER);
    printf("IFLAType IFLA_WIRELESS %d\n", IFLA_WIRELESS);
    printf("IFLAType IFLA_PROTINFO %d\n", IFLA_PROTINFO);
    printf("IFLAType IFLA_TXQLEN %d\n", IFLA_TXQLEN);
    printf("IFLAType IFLA_MAP %d\n", IFLA_MAP);
    printf("IFLAType IFLA_WEIGHT %d\n", IFLA_WEIGHT);
    printf("IFLAType IFLA_OPERSTATE %d\n", IFLA_OPERSTATE);
    printf("IFLAType IFLA_LINKMODE %d\n", IFLA_LINKMODE);
    printf("IFLAType IFLA_LINKINFO %d\n", IFLA_LINKINFO);
    printf("IFLAType IFLA_NET_NS_PID %d\n", IFLA_NET_NS_PID);
    printf("IFLAType IFLA_IFALIAS %d\n", IFLA_IFALIAS);
    printf("IFLAType IFLA_NUM_VF %d\n", IFLA_NUM_VF);
    printf("IFLAType IFLA_VFINFO_LIST %d\n", IFLA_VFINFO_LIST);
    printf("IFLAType IFLA_STATS64 %d\n", IFLA_STATS64);
    printf("IFLAType IFLA_VF_PORTS %d\n", IFLA_VF_PORTS);
    printf("IFLAType IFLA_PORT_SELF %d\n", IFLA_PORT_SELF);
    printf("IFLAType IFLA_AF_SPEC %d\n", IFLA_AF_SPEC);
    printf("IFLAType IFLA_GROUP %d\n", IFLA_GROUP);
    printf("IFLAType IFLA_NET_NS_FD %d\n", IFLA_NET_NS_FD);
    printf("IFLAType IFLA_EXT_MASK %d\n", IFLA_EXT_MASK);
    printf("IFLAType IFLA_PROMISCUITY %d\n", IFLA_PROMISCUITY);
    printf("IFLAType IFLA_NUM_TX_QUEUES %d\n", IFLA_NUM_TX_QUEUES);
    printf("IFLAType IFLA_NUM_RX_QUEUES %d\n", IFLA_NUM_RX_QUEUES);
    printf("IFLAType IFLA_CARRIER %d\n", IFLA_CARRIER);
    printf("IFLAType IFLA_PHYS_PORT_ID %d\n", IFLA_PHYS_PORT_ID);
    printf("IFLAType IFLA_CARRIER_CHANGES %d\n", IFLA_CARRIER_CHANGES);
    printf("IFLAType IFLA_PHYS_SWITCH_ID %d\n", IFLA_PHYS_SWITCH_ID);
    printf("IFLAType IFLA_LINK_NETNSID %d\n", IFLA_LINK_NETNSID);
    printf("IFLAType IFLA_PHYS_PORT_NAME %d\n", IFLA_PHYS_PORT_NAME);
    printf("IFLAType IFLA_PROTO_DOWN %d\n", IFLA_PROTO_DOWN);

    // IFFlag
    printf("IFFlag IFF_UP %d\n", IFF_UP);
    printf("IFFlag IFF_BROADCAST %d\n", IFF_BROADCAST);
    printf("IFFlag IFF_DEBUG %d\n", IFF_DEBUG);
    printf("IFFlag IFF_LOOPBACK %d\n", IFF_LOOPBACK);
    printf("IFFlag IFF_POINTOPOINT %d\n", IFF_POINTOPOINT);
    printf("IFFlag IFF_NOTRAILERS %d\n", IFF_NOTRAILERS);
    printf("IFFlag IFF_RUNNING %d\n", IFF_RUNNING);
    printf("IFFlag IFF_NOARP %d\n", IFF_NOARP);
    printf("IFFlag IFF_PROMISC %d\n", IFF_PROMISC);
    printf("IFFlag IFF_ALLMULTI %d\n", IFF_ALLMULTI);
    printf("IFFlag IFF_MASTER %d\n", IFF_MASTER);
    printf("IFFlag IFF_SLAVE %d\n", IFF_SLAVE);
    printf("IFFlag IFF_MULTICAST %d\n", IFF_MULTICAST);
    printf("IFFlag IFF_PORTSEL %d\n", IFF_PORTSEL);
    printf("IFFlag IFF_AUTOMEDIA %d\n", IFF_AUTOMEDIA);
    printf("IFFlag IFF_DYNAMIC %d\n", IFF_DYNAMIC);
    printf("IFFlag IFF_LOWER_UP %d\n", IFF_LOWER_UP);
    printf("IFFlag IFF_DORMANT %d\n", IFF_DORMANT);
    printf("IFFlag IFF_ECHO %d\n", IFF_ECHO);

    // IFAType
    printf("IFAType IFA_UNSPEC %d\n", IFA_UNSPEC);
    printf("IFAType IFA_ADDRESS %d\n", IFA_ADDRESS);
    printf("IFAType IFA_LOCAL %d\n", IFA_LOCAL);
    printf("IFAType IFA_LABEL %d\n", IFA_LABEL);
    printf("IFAType IFA_BROADCAST %d\n", IFA_BROADCAST);
    printf("IFAType IFA_ANYCAST %d\n", IFA_ANYCAST);
    printf("IFAType IFA_CACHEINFO %d\n", IFA_CACHEINFO);
    printf("IFAType IFA_MULTICAST %d\n", IFA_MULTICAST);
    printf("IFAType IFA_FLAGS %d\n", IFA_FLAGS);
    printf("IFAType IFA_RT_PRIORITY %d\n", IFA_RT_PRIORITY);
    printf("IFAType IFA_TARGET_NETNSID %d\n", IFA_TARGET_NETNSID);
    printf("IFAType IFA_PROTO %d\n", IFA_PROTO);

    // IFAFlag
    printf("IFAFlag IFA_F_SECONDARY %d\n", IFA_F_SECONDARY);
    printf("IFAFlag IFA_F_NODAD %d\n", IFA_F_NODAD);
    printf("IFAFlag IFA_F_OPTIMISTIC %d\n", IFA_F_OPTIMISTIC);
    printf("IFAFlag IFA_F_DADFAILED %d\n", IFA_F_DADFAILED);
    printf("IFAFlag IFA_F_HOMEADDRESS %d\n", IFA_F_HOMEADDRESS);
    printf("IFAFlag IFA_F_DEPRECATED %d\n", IFA_F_DEPRECATED);
    printf("IFAFlag IFA_F_TENTATIVE %d\n", IFA_F_TENTATIVE);
    printf("IFAFlag IFA_F_PERMANENT %d\n", IFA_F_PERMANENT);
    printf("IFAFlag IFA_F_MANAGETEMPADDR %d\n", IFA_F_MANAGETEMPADDR);
    printf("IFAFlag IFA_F_NOPREFIXROUTE %d\n", IFA_F_NOPREFIXROUTE);
    printf("IFAFlag IFA_F_MCAUTOJOIN %d\n", IFA_F_MCAUTOJOIN);
    printf("IFAFlag IFA_F_STABLE_PRIVACY %d\n", IFA_F_STABLE_PRIVACY);

    // ICMPv6RouterPref
    printf("ICMPv6RouterPref ICMPV6_ROUTER_PREF_LOW %d\n", ICMPV6_ROUTER_PREF_LOW);
    printf("ICMPv6RouterPref ICMPV6_ROUTER_PREF_MEDIUM %d\n", ICMPV6_ROUTER_PREF_MEDIUM);
    printf("ICMPv6RouterPref ICMPV6_ROUTER_PREF_HIGH %d\n", ICMPV6_ROUTER_PREF_HIGH);
    printf("ICMPv6RouterPref ICMPV6_ROUTER_PREF_INVALID %d\n", ICMPV6_ROUTER_PREF_INVALID);

    // CtrlCmd
    printf("CtrlCmd CTRL_CMD_UNSPEC %d\n", CTRL_CMD_UNSPEC);
    printf("CtrlCmd CTRL_CMD_NEWFAMILY %d\n", CTRL_CMD_NEWFAMILY);
    printf("CtrlCmd CTRL_CMD_DELFAMILY %d\n", CTRL_CMD_DELFAMILY);
    printf("CtrlCmd CTRL_CMD_GETFAMILY %d\n", CTRL_CMD_GETFAMILY);
    printf("CtrlCmd CTRL_CMD_NEWOPS %d\n", CTRL_CMD_NEWOPS);
    printf("CtrlCmd CTRL_CMD_DELOPS %d\n", CTRL_CMD_DELOPS);
    printf("CtrlCmd CTRL_CMD_GETOPS %d\n", CTRL_CMD_GETOPS);
    printf("CtrlCmd CTRL_CMD_NEWMCAST_GRP %d\n", CTRL_CMD_NEWMCAST_GRP);
    printf("CtrlCmd CTRL_CMD_DELMCAST_GRP %d\n", CTRL_CMD_DELMCAST_GRP);
    printf("CtrlCmd CTRL_CMD_GETMCAST_GRP %d\n", CTRL_CMD_GETMCAST_GRP);

    // CtrlAttr
    printf("CtrlAttr CTRL_ATTR_UNSPEC %d\n", CTRL_ATTR_UNSPEC);
    printf("CtrlAttr CTRL_ATTR_FAMILY_ID %d\n", CTRL_ATTR_FAMILY_ID);
    printf("CtrlAttr CTRL_ATTR_FAMILY_NAME %d\n", CTRL_ATTR_FAMILY_NAME);
    printf("CtrlAttr CTRL_ATTR_VERSION %d\n", CTRL_ATTR_VERSION);
    printf("CtrlAttr CTRL_ATTR_HDRSIZE %d\n", CTRL_ATTR_HDRSIZE);
    printf("CtrlAttr CTRL_ATTR_MAXATTR %d\n", CTRL_ATTR_MAXATTR);
    printf("CtrlAttr CTRL_ATTR_OPS %d\n", CTRL_ATTR_OPS);
    printf("CtrlAttr CTRL_ATTR_MCAST_GROUPS %d\n", CTRL_ATTR_MCAST_GROUPS);

    return 0;
}
