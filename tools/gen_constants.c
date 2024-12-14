#include <linux/fib_rules.h>
#include <linux/genetlink.h>
#include <linux/icmpv6.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_tun.h>
#include <linux/in_route.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <sys/ioctl.h>

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

    // RTNLFamily
    printf("RTNLFamily RTNL_FAMILY_IPMR %d\n", RTNL_FAMILY_IPMR);
    printf("RTNLFamily RTNL_FAMILY_IP6MR %d\n", RTNL_FAMILY_IP6MR);

    // RTMType
    printf("RTMType RTM_NEWLINK %d\n", RTM_NEWLINK);
    printf("RTMType RTM_DELLINK %d\n", RTM_DELLINK);
    printf("RTMType RTM_GETLINK %d\n", RTM_GETLINK);
    printf("RTMType RTM_SETLINK %d\n", RTM_SETLINK);
    printf("RTMType RTM_NEWADDR %d\n", RTM_NEWADDR);
    printf("RTMType RTM_DELADDR %d\n", RTM_DELADDR);
    printf("RTMType RTM_GETADDR %d\n", RTM_GETADDR);
    printf("RTMType RTM_NEWROUTE %d\n", RTM_NEWROUTE);
    printf("RTMType RTM_DELROUTE %d\n", RTM_DELROUTE);
    printf("RTMType RTM_GETROUTE %d\n", RTM_GETROUTE);
    printf("RTMType RTM_NEWNEIGH %d\n", RTM_NEWNEIGH);
    printf("RTMType RTM_DELNEIGH %d\n", RTM_DELNEIGH);
    printf("RTMType RTM_GETNEIGH %d\n", RTM_GETNEIGH);
    printf("RTMType RTM_NEWRULE %d\n", RTM_NEWRULE);
    printf("RTMType RTM_DELRULE %d\n", RTM_DELRULE);
    printf("RTMType RTM_GETRULE %d\n", RTM_GETRULE);
    printf("RTMType RTM_NEWQDISC %d\n", RTM_NEWQDISC);
    printf("RTMType RTM_DELQDISC %d\n", RTM_DELQDISC);
    printf("RTMType RTM_GETQDISC %d\n", RTM_GETQDISC);
    printf("RTMType RTM_NEWTCLASS %d\n", RTM_NEWTCLASS);
    printf("RTMType RTM_DELTCLASS %d\n", RTM_DELTCLASS);
    printf("RTMType RTM_GETTCLASS %d\n", RTM_GETTCLASS);
    printf("RTMType RTM_NEWTFILTER %d\n", RTM_NEWTFILTER);
    printf("RTMType RTM_DELTFILTER %d\n", RTM_DELTFILTER);
    printf("RTMType RTM_GETTFILTER %d\n", RTM_GETTFILTER);
    printf("RTMType RTM_NEWACTION %d\n", RTM_NEWACTION);
    printf("RTMType RTM_DELACTION %d\n", RTM_DELACTION);
    printf("RTMType RTM_GETACTION %d\n", RTM_GETACTION);
    printf("RTMType RTM_NEWPREFIX %d\n", RTM_NEWPREFIX);
    printf("RTMType RTM_GETMULTICAST %d\n", RTM_GETMULTICAST);
    printf("RTMType RTM_GETANYCAST %d\n", RTM_GETANYCAST);
    printf("RTMType RTM_NEWNEIGHTBL %d\n", RTM_NEWNEIGHTBL);
    printf("RTMType RTM_GETNEIGHTBL %d\n", RTM_GETNEIGHTBL);
    printf("RTMType RTM_SETNEIGHTBL %d\n", RTM_SETNEIGHTBL);
    printf("RTMType RTM_NEWNDUSEROPT %d\n", RTM_NEWNDUSEROPT);
    printf("RTMType RTM_NEWADDRLABEL %d\n", RTM_NEWADDRLABEL);
    printf("RTMType RTM_DELADDRLABEL %d\n", RTM_DELADDRLABEL);
    printf("RTMType RTM_GETADDRLABEL %d\n", RTM_GETADDRLABEL);
    printf("RTMType RTM_GETDCB %d\n", RTM_GETDCB);
    printf("RTMType RTM_SETDCB %d\n", RTM_SETDCB);

    // RTNLGroup
    printf("RTNLGroup RTNLGRP_NONE %d\n", RTNLGRP_NONE);
    printf("RTNLGroup RTNLGRP_LINK %d\n", RTNLGRP_LINK);
    printf("RTNLGroup RTNLGRP_NOTIFY %d\n", RTNLGRP_NOTIFY);
    printf("RTNLGroup RTNLGRP_NEIGH %d\n", RTNLGRP_NEIGH);
    printf("RTNLGroup RTNLGRP_TC %d\n", RTNLGRP_TC);
    printf("RTNLGroup RTNLGRP_IPV4_IFADDR %d\n", RTNLGRP_IPV4_IFADDR);
    printf("RTNLGroup RTNLGRP_IPV4_MROUTE %d\n", RTNLGRP_IPV4_MROUTE);
    printf("RTNLGroup RTNLGRP_IPV4_ROUTE %d\n", RTNLGRP_IPV4_ROUTE);
    printf("RTNLGroup RTNLGRP_IPV4_RULE %d\n", RTNLGRP_IPV4_RULE);
    printf("RTNLGroup RTNLGRP_IPV6_IFADDR %d\n", RTNLGRP_IPV6_IFADDR);
    printf("RTNLGroup RTNLGRP_IPV6_MROUTE %d\n", RTNLGRP_IPV6_MROUTE);
    printf("RTNLGroup RTNLGRP_IPV6_ROUTE %d\n", RTNLGRP_IPV6_ROUTE);
    printf("RTNLGroup RTNLGRP_IPV6_IFINFO %d\n", RTNLGRP_IPV6_IFINFO);
    printf("RTNLGroup RTNLGRP_DECnet_IFADDR %d\n", RTNLGRP_DECnet_IFADDR);
    printf("RTNLGroup RTNLGRP_NOP2 %d\n", RTNLGRP_NOP2);
    printf("RTNLGroup RTNLGRP_DECnet_ROUTE %d\n", RTNLGRP_DECnet_ROUTE);
    printf("RTNLGroup RTNLGRP_DECnet_RULE %d\n", RTNLGRP_DECnet_RULE);
    printf("RTNLGroup RTNLGRP_NOP4 %d\n", RTNLGRP_NOP4);
    printf("RTNLGroup RTNLGRP_IPV6_PREFIX %d\n", RTNLGRP_IPV6_PREFIX);
    printf("RTNLGroup RTNLGRP_IPV6_RULE %d\n", RTNLGRP_IPV6_RULE);
    printf("RTNLGroup RTNLGRP_ND_USEROPT %d\n", RTNLGRP_ND_USEROPT);
    printf("RTNLGroup RTNLGRP_PHONET_IFADDR %d\n", RTNLGRP_PHONET_IFADDR);
    printf("RTNLGroup RTNLGRP_PHONET_ROUTE %d\n", RTNLGRP_PHONET_ROUTE);

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

    // RTMFlag
    printf("RTMFlag RTM_F_NOTIFY %d\n", RTM_F_NOTIFY);
    printf("RTMFlag RTM_F_CLONED %d\n", RTM_F_CLONED);
    printf("RTMFlag RTM_F_EQUALIZE %d\n", RTM_F_EQUALIZE);

    // RTCFlag
    printf("RTCFlag RTCF_DEAD %u\n", RTCF_DEAD);
    printf("RTCFlag RTCF_ONLINK %u\n", RTCF_ONLINK);
    printf("RTCFlag RTCF_NOTIFY %u\n", RTCF_NOTIFY);
    printf("RTCFlag RTCF_DIRECTDST %u\n", RTCF_DIRECTDST);
    printf("RTCFlag RTCF_REDIRECTED %u\n", RTCF_REDIRECTED);
    printf("RTCFlag RTCF_TPROXY %u\n", RTCF_TPROXY);
    printf("RTCFlag RTCF_FAST %u\n", RTCF_FAST);
    printf("RTCFlag RTCF_MASQ %u\n", RTCF_MASQ);
    printf("RTCFlag RTCF_SNAT %u\n", RTCF_SNAT);
    printf("RTCFlag RTCF_DOREDIRECT %u\n", RTCF_DOREDIRECT);
    printf("RTCFlag RTCF_DIRECTSRC %u\n", RTCF_DIRECTSRC);
    printf("RTCFlag RTCF_DNAT %u\n", RTCF_DNAT);
    printf("RTCFlag RTCF_BROADCAST %u\n", RTCF_BROADCAST);
    printf("RTCFlag RTCF_MULTICAST %u\n", RTCF_MULTICAST);
    printf("RTCFlag RTCF_REJECT %u\n", RTCF_REJECT);
    printf("RTCFlag RTCF_LOCAL %u\n", RTCF_LOCAL);

    // RTAType
    printf("RTAType RTA_UNSPEC %d\n", RTA_UNSPEC);
    printf("RTAType RTA_DST %d\n", RTA_DST);
    printf("RTAType RTA_SRC %d\n", RTA_SRC);
    printf("RTAType RTA_IIF %d\n", RTA_IIF);
    printf("RTAType RTA_OIF %d\n", RTA_OIF);
    printf("RTAType RTA_GATEWAY %d\n", RTA_GATEWAY);
    printf("RTAType RTA_PRIORITY %d\n", RTA_PRIORITY);
    printf("RTAType RTA_PREFSRC %d\n", RTA_PREFSRC);
    printf("RTAType RTA_METRICS %d\n", RTA_METRICS);
    printf("RTAType RTA_MULTIPATH %d\n", RTA_MULTIPATH);
    printf("RTAType RTA_PROTOINFO %d\n", RTA_PROTOINFO);
    printf("RTAType RTA_FLOW %d\n", RTA_FLOW);
    printf("RTAType RTA_CACHEINFO %d\n", RTA_CACHEINFO);
    printf("RTAType RTA_SESSION %d\n", RTA_SESSION);
    printf("RTAType RTA_MP_ALGO %d\n", RTA_MP_ALGO);
    printf("RTAType RTA_TABLE %d\n", RTA_TABLE);
    printf("RTAType RTA_MARK %d\n", RTA_MARK);
    printf("RTAType RTA_MFC_STATS %d\n", RTA_MFC_STATS);
    printf("RTAType RTA_VIA %d\n", RTA_VIA);
    printf("RTAType RTA_NEWDST %d\n", RTA_NEWDST);
    printf("RTAType RTA_PREF %d\n", RTA_PREF);
    printf("RTAType RTA_ENCAP_TYPE %d\n", RTA_ENCAP_TYPE);
    printf("RTAType RTA_ENCAP %d\n", RTA_ENCAP);
    printf("RTAType RTA_EXPIRES %d\n", RTA_EXPIRES);
    printf("RTAType RTA_PAD %d\n", RTA_PAD);
    printf("RTAType RTA_UID %d\n", RTA_UID);
    printf("RTAType RTA_TTL_PROPAGATE %d\n", RTA_TTL_PROPAGATE);
    printf("RTAType RTA_IP_PROTO %d\n", RTA_IP_PROTO);
    printf("RTAType RTA_SPORT %d\n", RTA_SPORT);
    printf("RTAType RTA_DPORT %d\n", RTA_DPORT);
    printf("RTAType RTA_NH_ID %d\n", RTA_NH_ID);

    // ARPHRDType
    printf("ARPHRDType ARPHRD_ETHER %d\n", ARPHRD_ETHER);
    printf("ARPHRDType ARPHRD_NONE %d\n", ARPHRD_NONE);
    printf("ARPHRDType ARPHRD_LOOPBACK %d\n", ARPHRD_LOOPBACK);

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

    // IFOper
    printf("IFOper IF_OPER_UNKNOWN %d\n", IF_OPER_UNKNOWN);
    printf("IFOper IF_OPER_NOTPRESENT %d\n", IF_OPER_NOTPRESENT);
    printf("IFOper IF_OPER_DOWN %d\n", IF_OPER_DOWN);
    printf("IFOper IF_OPER_LOWERLAYERDOWN %d\n", IF_OPER_LOWERLAYERDOWN);
    printf("IFOper IF_OPER_TESTING %d\n", IF_OPER_TESTING);
    printf("IFOper IF_OPER_DORMANT %d\n", IF_OPER_DORMANT);
    printf("IFOper IF_OPER_UP %d\n", IF_OPER_UP);

    // IFLinkMode
    printf("IFLinkMode IF_LINK_MODE_DEFAULT %d\n", IF_LINK_MODE_DEFAULT);
    printf("IFLinkMode IF_LINK_MODE_DORMANT %d\n", IF_LINK_MODE_DORMANT);
    printf("IFLinkMode IF_LINK_MODE_TESTING %d\n", IF_LINK_MODE_TESTING);

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

    // FRAType
    printf("FRAType FRA_UNSPEC %d\n", FRA_UNSPEC);
    printf("FRAType FRA_DST %d\n", FRA_DST);
    printf("FRAType FRA_SRC %d\n", FRA_SRC);
    printf("FRAType FRA_IIFNAME %d\n", FRA_IIFNAME);
    printf("FRAType FRA_GOTO %d\n", FRA_GOTO);
    printf("FRAType FRA_UNUSED2 %d\n", FRA_UNUSED2);
    printf("FRAType FRA_PRIORITY %d\n", FRA_PRIORITY);
    printf("FRAType FRA_UNUSED3 %d\n", FRA_UNUSED3);
    printf("FRAType FRA_UNUSED4 %d\n", FRA_UNUSED4);
    printf("FRAType FRA_UNUSED5 %d\n", FRA_UNUSED5);
    printf("FRAType FRA_FWMARK %d\n", FRA_FWMARK);
    printf("FRAType FRA_FLOW %d\n", FRA_FLOW);
    printf("FRAType FRA_TUN_ID %d\n", FRA_TUN_ID);
    printf("FRAType FRA_SUPPRESS_IFGROUP %d\n", FRA_SUPPRESS_IFGROUP);
    printf("FRAType FRA_SUPPRESS_PREFIXLEN %d\n", FRA_SUPPRESS_PREFIXLEN);
    printf("FRAType FRA_TABLE %d\n", FRA_TABLE);
    printf("FRAType FRA_FWMASK %d\n", FRA_FWMASK);
    printf("FRAType FRA_OIFNAME %d\n", FRA_OIFNAME);
    printf("FRAType FRA_PAD %d\n", FRA_PAD);
    printf("FRAType FRA_L3MDEV %d\n", FRA_L3MDEV);
    printf("FRAType FRA_UID_RANGE %d\n", FRA_UID_RANGE);
    printf("FRAType FRA_PROTOCOL %d\n", FRA_PROTOCOL);
    printf("FRAType FRA_IP_PROTO %d\n", FRA_IP_PROTO);
    printf("FRAType FRA_SPORT_RANGE %d\n", FRA_SPORT_RANGE);
    printf("FRAType FRA_DPORT_RANGE %d\n", FRA_DPORT_RANGE);

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

    // TunIoctl
    printf("TunIoctl TUNSETNOCSUM %ld\n", TUNSETNOCSUM);
    printf("TunIoctl TUNSETDEBUG %ld\n", TUNSETDEBUG);
    printf("TunIoctl TUNSETIFF %ld\n", TUNSETIFF);
    printf("TunIoctl TUNSETPERSIST %ld\n", TUNSETPERSIST);
    printf("TunIoctl TUNSETOWNER %ld\n", TUNSETOWNER);
    printf("TunIoctl TUNSETLINK %ld\n", TUNSETLINK);
    printf("TunIoctl TUNSETGROUP %ld\n", TUNSETGROUP);
    printf("TunIoctl TUNGETFEATURES %ld\n", TUNGETFEATURES);
    printf("TunIoctl TUNSETOFFLOAD %ld\n", TUNSETOFFLOAD);
    printf("TunIoctl TUNSETTXFILTER %ld\n", TUNSETTXFILTER);
    printf("TunIoctl TUNGETIFF %ld\n", TUNGETIFF);
    printf("TunIoctl TUNGETSNDBUF %ld\n", TUNGETSNDBUF);
    printf("TunIoctl TUNSETSNDBUF %ld\n", TUNSETSNDBUF);
    printf("TunIoctl TUNATTACHFILTER %ld\n", TUNATTACHFILTER);
    printf("TunIoctl TUNDETACHFILTER %ld\n", TUNDETACHFILTER);
    printf("TunIoctl TUNGETVNETHDRSZ %ld\n", TUNGETVNETHDRSZ);
    printf("TunIoctl TUNSETVNETHDRSZ %ld\n", TUNSETVNETHDRSZ);
    printf("TunIoctl TUNSETVNETBE %ld\n", TUNSETVNETBE);
    printf("TunIoctl TUNGETVNETBE %ld\n", TUNGETVNETBE);
    printf("TunIoctl TUNSETSTEERINGEBPF %ld\n", TUNSETSTEERINGEBPF);
    printf("TunIoctl TUNSETFILTEREBPF %ld\n", TUNSETFILTEREBPF);
    printf("TunIoctl TUNSETCARRIER %ld\n", TUNSETCARRIER);
    printf("TunIoctl TUNGETDEVNETNS %u\n", TUNGETDEVNETNS);

    // TunIffFlag
    printf("TunIffFlag IFF_TUN %d\n", IFF_TUN);
    printf("TunIffFlag IFF_TAP %d\n", IFF_TAP);
    printf("TunIffFlag IFF_NO_PI %d\n", IFF_NO_PI);
    printf("TunIffFlag IFF_ONE_QUEUE %d\n", IFF_ONE_QUEUE);
    printf("TunIffFlag IFF_VNET_HDR %d\n", IFF_VNET_HDR);
    printf("TunIffFlag IFF_TUN_EXCL %d\n", IFF_TUN_EXCL);

    // MiscConstants
    printf("MiscConstants IFNAMSIZ %d\n", IFNAMSIZ);

    return 0;
}
