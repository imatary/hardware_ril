#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/netlink.h>
#include <linux/route.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include "QMIThread.h"

static int ifc_ctl_sock = -1;

static int ifc_init(void)
{
    int ret;
    if (ifc_ctl_sock == -1) {
        ifc_ctl_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (ifc_ctl_sock < 0) {
            dbg_time("socket() failed: %s\n", strerror(errno));
        }
    }

    ret = ifc_ctl_sock < 0 ? -1 : 0;
    return ret;
}

static void ifc_close(void)
{
    if (ifc_ctl_sock != -1) {
        (void)close(ifc_ctl_sock);
        ifc_ctl_sock = -1;
    }
}

static void ifc_init_ifr(const char *name, struct ifreq *ifr)
{
    memset(ifr, 0, sizeof(struct ifreq));
    strncpy(ifr->ifr_name, name, IFNAMSIZ);
    ifr->ifr_name[IFNAMSIZ - 1] = 0;
}

static int ifc_set_flags(const char *name, unsigned set, unsigned clr)
{
    struct ifreq ifr;
    ifc_init_ifr(name, &ifr);

    if(ioctl(ifc_ctl_sock, SIOCGIFFLAGS, &ifr) < 0) return -1;
    ifr.ifr_flags = (ifr.ifr_flags & (~clr)) | set;
    return ioctl(ifc_ctl_sock, SIOCSIFFLAGS, &ifr);
}

static int ifc_up(const char *name, int rawIP)
{
    int ret = ifc_set_flags(name, IFF_UP | (rawIP ? IFF_NOARP : 0), 0);
    return ret;
}

static int ifc_down(const char *name)
{
    int ret = ifc_set_flags(name, 0, IFF_UP);
    return ret;
}

static void init_sockaddr_in(struct sockaddr *sa, in_addr_t addr)
{
    struct sockaddr_in *sin = (struct sockaddr_in *) sa;
    sin->sin_family = AF_INET;
    sin->sin_port = 0;
    sin->sin_addr.s_addr = addr;
}

static int ifc_set_addr(const char *name, in_addr_t addr)
{
    struct ifreq ifr;
    int ret;

    ifc_init_ifr(name, &ifr);
    init_sockaddr_in(&ifr.ifr_addr, addr);

    ret = ioctl(ifc_ctl_sock, SIOCSIFADDR, &ifr);
    return ret;
}

static pthread_attr_t udhcpc_thread_attr;
static pthread_t udhcpc_thread_id;

#ifdef ANDROID
void do_dhcp_request(const char *ifname);
static void* udhcpc_thread_function(void*  arg) {
    do_dhcp_request((const char *)arg);
    return NULL;
}
#else
static void* udhcpc_thread_function(void*  arg) {
    FILE * udhcpc_fp;
    char udhcpc_cmd[64];

    if (access("/usr/share/udhcpc/default.script", X_OK)) {
        dbg_time("Fail to access /usr/share/udhcpc/default.script, errno: %d (%s)", errno, strerror(errno));
    }

    //-f,--foreground	Run in foreground
    //-b,--background	Background if lease is not obtained
    //-n,--now		Exit if lease is not obtained
    //-q,--quit		Exit after obtaining lease
    //-t,--retries N		Send up to N discover packets (default 3)
    snprintf(udhcpc_cmd, sizeof(udhcpc_cmd), "udhcpc -f -n -q -t 5 -i %s", (char *)arg);

    udhcpc_fp = popen(udhcpc_cmd, "r");
    if (udhcpc_fp) {
        char buf[0xff];
        while((fgets(buf, sizeof(buf), udhcpc_fp)) != NULL) {
            if ((strlen(buf) > 1) && (buf[strlen(buf) - 1] == '\n'))
                buf[strlen(buf) - 1] = '\0';
            dbg_time("%s", buf);
        }
        pclose(udhcpc_fp);
    }

    return NULL;
}
#endif

void udhcpc_start(const char *ifname, int IPType, int rawIP) {
    ifc_init();
    if (ifc_set_addr(ifname, 0)) {
        dbg_time("failed to set ip addr for %s to 0.0.0.0: %s\n", ifname, strerror(errno));
        return;
    }

    if (ifc_up(ifname, rawIP)) {
        dbg_time("failed to bring up interface %s: %s\n", ifname, strerror(errno));
        return;
    }
    ifc_close();

    pthread_attr_init(&udhcpc_thread_attr);
    pthread_attr_setdetachstate(&udhcpc_thread_attr, PTHREAD_CREATE_DETACHED);
    if(pthread_create(&udhcpc_thread_id, &udhcpc_thread_attr, udhcpc_thread_function, (void*)ifname) !=0 ) {
        dbg_time("failed to create udhcpc_thread for %s: %s\n", ifname, strerror(errno));
    }
    pthread_attr_destroy(&udhcpc_thread_attr);
}

void udhcpc_stop(const char *ifname) {
    ifc_init();
    ifc_set_addr(ifname, 0);
    ifc_down(ifname);
    ifc_close();
}

unsigned long ifc_get_addr(const char *ifname) {
    int inet_sock;
    struct ifreq ifr;
    unsigned long addr = 0;
    
    inet_sock = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, ifname);

    if (ioctl(inet_sock, SIOCGIFADDR, &ifr) < 0) {
        goto error;
    }
    addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
error:
    close(inet_sock);

    return addr;
}
