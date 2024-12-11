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

    return 0;
}
