#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
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

    return 0;
}
