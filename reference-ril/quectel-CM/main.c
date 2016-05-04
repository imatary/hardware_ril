#include "QMIThread.h"
#include <sys/wait.h>
#include <sys/utsname.h>
#include <dirent.h>

#define POLL_DATA_CALL_STATE_SECONDS 0 //poll data call state, for qmi ind maybe not work well

char * qmichannel = NULL;
char * usbnet_adapter = NULL;
int debug_qmi = 0;
int qmidevice_control_fd[2];

static int signal_control_fd[2];

static struct utsname utsname;	/* for the kernel version */
static int kernel_version;
#define KVERSION(j,n,p)	((j)*1000000 + (n)*1000 + (p))

static void usbnet_link_change(int link, int IPType, int rawIP) {
    static int s_link = -1;

    if (s_link == link)
        return;
    s_link = link;

    if (link)
        udhcpc_start(usbnet_adapter, IPType, rawIP);
    else
        udhcpc_stop(usbnet_adapter);
}

#if POLL_DATA_CALL_STATE_SECONDS
unsigned long ifc_get_addr(const char *ifname);
static int check_ipv4_address(void) {
    IPV4_T ipv4Addrs;
    if (requestGetIPAddress(&ipv4Addrs) == 0)
    {
        unsigned long localAddress = ifc_get_addr(usbnet_adapter);
        unsigned long tmp = ipv4Addrs.Address;
        ipv4Addrs.Address = 0;
        ipv4Addrs.Address |= ((tmp>>24)&0xff) << 0;
        ipv4Addrs.Address |= ((tmp>>16)&0xff) << 8;
        ipv4Addrs.Address |= ((tmp>>8)&0xff) << 16;
        ipv4Addrs.Address |= ((tmp>>0)&0xff) << 24;
        dbg_time("Address: %08x / %08x", ipv4Addrs.Address, localAddress);
        return (localAddress == ipv4Addrs.Address);
    }
    return 0;
}
#endif

static void main_send_event_to_qmidevice(int triger_event) {
    write(qmidevice_control_fd[0], &triger_event, sizeof(triger_event));
}

static void send_signo_to_main(int signo) {
    write(signal_control_fd[0], &signo, sizeof(signo));
}

void qmidevice_send_event_to_main(int triger_event) {
    write(qmidevice_control_fd[1], &triger_event, sizeof(triger_event));
}

static void ql_sigaction(int signo) {
    if (SIGCHLD == signo)
        waitpid(-1, NULL, WNOHANG);
    else if (SIGALRM == signo)
        send_signo_to_main(SIGUSR1);
    else {
        send_signo_to_main(signo);
        //donot send SIGTERM to qmi thread, for wait requestDeactivateDefaultPDP() get response
        //main_send_event_to_qmidevice(signo);
    }
}

pthread_t gQmiThreadID;

static int usage(const char *progname) {
    dbg_time("Usage: %s [-s [apn [user password auth]]] [-p pincode] [-f logfilename] ", progname);
    dbg_time("-s [apn [user password auth]] Set apn/user/password/auth get from your network provider");
    dbg_time("-p pincode                    Verify sim card pin if sim card is locked");
    dbg_time("-f logfilename                Save log message of this program to file");
    dbg_time("Example 1: %s ", progname);
    dbg_time("Example 2: %s -s 3gnet ", progname);
    dbg_time("Example 3: %s -s 3gnet carl 1234 0 -p 1234 -f gobinet_log.txt", progname);
    return 0;
}

static int qmidevice_detect(void) {
    struct dirent* ent = NULL;
    DIR *pDir;
    int osmaj, osmin, ospatch;

    /* get the kernel version now, since we are called before sys_init */
    uname(&utsname);
    osmaj = osmin = ospatch = 0;
    sscanf(utsname.release, "%d.%d.%d", &osmaj, &osmin, &ospatch);
    kernel_version = KVERSION(osmaj, osmin, ospatch);

    if ((pDir = opendir("/dev")) == NULL)  {
        dbg_time("Cannot open directory: %s, errno:%d (%s)", "/dev", errno, strerror(errno));
        return -ENODEV;
    }

    while ((ent = readdir(pDir)) != NULL) {
        if ((strncmp(ent->d_name, "cdc-wdm", strlen("cdc-wdm")) == 0) || (strncmp(ent->d_name, "qcqmi", strlen("qcqmi")) == 0)) {
            char *net_path = (char *)malloc(32);

            qmichannel = (char *)malloc(32);
            sprintf(qmichannel, "/dev/%s", ent->d_name);
            dbg_time("Find qmichannel = %s", qmichannel);

            if (strncmp(ent->d_name, "cdc-wdm", strlen("cdc-wdm")) == 0)
                sprintf(net_path, "/sys/class/net/wwan%s", &ent->d_name[strlen("cdc-wdm")]);
            else if (kernel_version >= KVERSION( 2,6,39 ))
            #ifdef ANDROID
                sprintf(net_path, "/sys/class/net/usb%s", &ent->d_name[strlen("qcqmi")]);
            #else
                sprintf(net_path, "/sys/class/net/eth%s", &ent->d_name[strlen("qcqmi")]);
            #endif
            else
                sprintf(net_path, "/sys/class/net/usb%s", &ent->d_name[strlen("qcqmi")]);

            if (access(net_path, R_OK) == 0) {
                usbnet_adapter = strdup(net_path + strlen("/sys/class/net/"));
                dbg_time("Find usbnet_adapter = %s", usbnet_adapter);
                break;
            } else {
                dbg_time("Failed to access %s, errno:%d (%s)", net_path, errno, strerror(errno));
                free(qmichannel); qmichannel = NULL;
            }

            free(net_path);
        }
    }
    closedir(pDir);

    return !(qmichannel && usbnet_adapter);
}

#ifdef ANDROID
int quectel_CM(int argc, char *argv[])
#else
int main(int argc, char *argv[])
#endif
{
    int triger_event = 0;
    int i = 1;
    int signo;
#ifdef CONFIG_SIM
    SIM_Status SIMStatus;
#endif
    UCHAR PSAttachedState;
    UCHAR  ConnectionStatus;
#ifdef ANDROID
    UCHAR oldConnectionStatus;
#endif
    PROFILE_T profile;

    memset(&profile, 0x00, sizeof(profile));
#if CONFIG_DEFAULT_PDP 
    profile.pdp = CONFIG_DEFAULT_PDP;
#else
    profile.pdp = 1;
#endif
    
    if (!strcmp(argv[argc-1], "&"))
        argc--;

    i = 1;
    while  (i < argc) {
        if (!strcmp(argv[i], "-s")) {
            i++;
            profile.apn = profile.user = profile.password = "";
            if ((i < argc) && (argv[i][0] != '-'))
                profile.apn = argv[i++];
            if ((i < argc) && (argv[i][0] != '-'))
                profile.user = argv[i++];
            if ((i < argc) && (argv[i][0] != '-')) {
                profile.password = argv[i++];
                if (profile.password && profile.password[0])
                    profile.auth = 2; //default chap, customers may miss auth
            }
            if ((i < argc) && (argv[i][0] != '-')) {
                profile.auth = argv[i++][0] - '0';
            }
        } else if (!strcmp(argv[i], "-p")) {
            i++;
            if ((i < argc) && (argv[i][0] != '-'))
                profile.pincode = argv[i++];
        } else if (!strcmp(argv[i], "-n")) {
            i++;
            if ((i < argc) && (argv[i][0] != '-'))
                profile.pdp = argv[i++][0] - '0';
        } else if (!strcmp(argv[i], "-f")) {
            i++;
            if ((i < argc) && (argv[i][0] != '-')) {
                const char * filename = argv[i++];
                logfilefp = fopen(filename, "a+");
                if (!logfilefp) {
                    dbg_time("Fail to open %s, errno: %d(%s)", filename, errno, strerror(errno));
                 }
            }
        } else if (!strcmp(argv[i], "-v")) {
            i++;
            debug_qmi = 1;
        } else if (!strcmp(argv[i], "-h")) {
            i++;
            return usage(argv[0]);
        }  else {
            return usage(argv[0]);
        }
    }

    dbg_time("Quectel_ConnectManager_SR01A01V13");
    dbg_time("%s profile[%d] = %s/%s/%s/%d, pincode = %s", argv[0], profile.pdp, profile.apn, profile.user, profile.password, profile.auth, profile.pincode);

#if 0
    qmichannel = "/dev/qcqmi1";
    usbnet_adapter = "eth1";
#endif

//sudo apt-get install udhcpc
//sudo apt-get remove ModemManager
    while (!qmichannel) {
        if (!qmidevice_detect())
            break;
        dbg_time("Cannot find qmichannel(%s) usbnet_adapter(%s) for Quectel UC20/EC20",
        qmichannel, usbnet_adapter);
        return -ENODEV;
    }

    if (access(qmichannel, R_OK | W_OK)) {
        dbg_time("Fail to access %s, errno: %d (%s)", qmichannel, errno, strerror(errno));
        return errno;
    }

    signal(SIGUSR1, ql_sigaction);
    signal(SIGUSR2, ql_sigaction);
    signal(SIGINT, ql_sigaction);
    signal(SIGTERM, ql_sigaction);
    signal(SIGHUP, ql_sigaction);
    signal(SIGCHLD, ql_sigaction);
    signal(SIGALRM, ql_sigaction);

    if (socketpair( AF_LOCAL, SOCK_STREAM, 0, signal_control_fd) < 0 ) {
        dbg_time("%s Faild to create main_control_fd: %d (%s)", __func__, errno, strerror(errno));
        return -1;
    }

    if ( socketpair( AF_LOCAL, SOCK_STREAM, 0, qmidevice_control_fd ) < 0 ) {
        dbg_time("%s Failed to create thread control socket pair: %d (%s)", __func__, errno, strerror(errno));
        return 0;
    }

    if (!strncmp(qmichannel, "/dev/qcqmi", strlen("/dev/qcqmi"))) {
        if (pthread_create( &gQmiThreadID, 0, GobiNetThread, NULL) != 0) {
            dbg_time("%s Failed to create GobiNetThread: %d (%s)", __func__, errno, strerror(errno));
            return 0;
        }
    } else {
        if (pthread_create( &gQmiThreadID, 0, QmiWwanThread, NULL) != 0) {
            dbg_time("%s Failed to create QmiWwanThread: %d (%s)", __func__, errno, strerror(errno));
            return 0;
        }
    }

    if ((read(qmidevice_control_fd[0], &triger_event, sizeof(triger_event)) != sizeof(triger_event))
        || (triger_event != RIL_INDICATE_DEVICE_CONNECTED)) {
        dbg_time("%s Failed to init QMIThread: %d (%s)", __func__, errno, strerror(errno));
        return 0;
    }

    if (!strncmp(qmichannel, "/dev/cdc-wdm", strlen("/dev/cdc-wdm"))) {
        if (QmiWwanInit()) {
            dbg_time("%s Failed to QmiWwanInit: %d (%s)", __func__, errno, strerror(errno));
            return 0;
        }
    }

#ifdef CONFIG_VERSION
    requestBaseBandVersion(NULL);
#endif
    requestSetEthMode(&profile);
#ifdef CONFIG_SIM
    requestGetSIMStatus(&SIMStatus);
    if ((SIMStatus == SIM_PIN) && profile.pincode) {
        requestEnterSimPin(profile.pincode);
    }
#endif
#ifdef CONFIG_APN
    if (profile.apn || profile.user || profile.password) {
        requestSetProfile(&profile);
    }
    requestGetProfile(&profile);
#endif
    requestRegistrationState(&PSAttachedState);

    if (!requestQueryDataCall(&ConnectionStatus) && (QWDS_PKT_DATA_CONNECTED == ConnectionStatus))
        usbnet_link_change(1, profile.IPType, profile.rawIP);
     else
        usbnet_link_change(0, profile.IPType, profile.rawIP);
#ifdef ANDROID
    oldConnectionStatus = ConnectionStatus;
#endif

    triger_event = SIGUSR1;
    write(signal_control_fd[0], &triger_event, sizeof(triger_event));

    while (1) {
        struct pollfd pollfds[] = {{signal_control_fd[1], POLLIN, 0}, {qmidevice_control_fd[0], POLLIN, 0}};
        int ne, ret, nevents = sizeof(pollfds)/sizeof(pollfds[0]);

        do {
            ret = poll(pollfds, nevents, -1);
         } while ((ret < 0) && (errno == EINTR));

        if (ret <= 0) {
            dbg_time("%s poll=%d, errno: %d (%s)", __func__, ret, errno, strerror(errno));
            goto __main_quit;
        }

        for (ne = 0; ne < nevents; ne++) {
            int fd = pollfds[ne].fd;
            short revents = pollfds[ne].revents;

            if (revents & (POLLERR | POLLHUP | POLLNVAL)) {
                dbg_time("%s poll err/hup", __func__);
                dbg_time("epoll fd = %d, events = 0x%04x", fd, revents);
                main_send_event_to_qmidevice(RIL_REQUEST_QUIT);
                if (revents & POLLHUP)
                    goto __main_quit;
            }

            if ((revents & POLLIN) == 0)
                continue;

            if (fd == signal_control_fd[1]) {
                if (read(fd, &signo, sizeof(signo)) == sizeof(signo)) {
                    //DBG("triger_event = 0x%x", triger_event);
                    alarm(0);
                    switch (signo) {
                        case SIGUSR1:
                            requestQueryDataCall(&ConnectionStatus);
                            if (QWDS_PKT_DATA_CONNECTED != ConnectionStatus) {
                                usbnet_link_change(0, profile.IPType, profile.rawIP);
                                requestRegistrationState(&PSAttachedState);
                                if (PSAttachedState == 1 && requestSetupDataCall(&profile) == 0) { //succssful setup data call
#if POLL_DATA_CALL_STATE_SECONDS
                                    usbnet_link_change(1, profile.IPType, profile.rawIP);
                                    alarm(POLL_DATA_CALL_STATE_SECONDS); //poll data call state, for qmi ind maybe not work well
#endif
                                } else {
                                    alarm(5); //try to setup data call 5 seconds later
                                }                                    
                            } else {
#if POLL_DATA_CALL_STATE_SECONDS
                                if (check_ipv4_address() == 0) {
                                    usbnet_link_change(0, profile.IPType, profile.rawIP);
                                    triger_event = SIGUSR2; //to disconnect
                                    write(signal_control_fd[0], &triger_event, sizeof(triger_event));
                                    triger_event = SIGUSR1; //to connect
                                    write(signal_control_fd[0], &triger_event, sizeof(triger_event));                                    
                                } else {
                                    alarm(POLL_DATA_CALL_STATE_SECONDS); //poll data call state, for qmi ind maybe not work well
                                }
#endif
                            }
                        break;
                        case SIGUSR2:
                            requestQueryDataCall(&ConnectionStatus);
                            if (QWDS_PKT_DATA_DISCONNECTED != ConnectionStatus) {
                                requestDeactivateDefaultPDP();
                             }
                        break;
                        case SIGTERM:
                        case SIGHUP:
                        case SIGINT:
                            requestDeactivateDefaultPDP();
                            usbnet_link_change(0, profile.IPType, profile.rawIP);
                            if (!strncmp(qmichannel, "/dev/cdc-wdm", strlen("/dev/cdc-wdm")))
                                QmiWwanDeInit();
                            main_send_event_to_qmidevice(RIL_REQUEST_QUIT);
                            goto __main_quit;
                        break;
                        default:
                        break;
                    }
                }
            }

            if (fd == qmidevice_control_fd[0]) {
                if (read(fd, &triger_event, sizeof(triger_event)) == sizeof(triger_event)) {
                    switch (triger_event) {
                        case RIL_INDICATE_DEVICE_DISCONNECTED:
                            goto __main_quit;
                        break;
                        case RIL_UNSOL_RESPONSE_VOICE_NETWORK_STATE_CHANGED:
                            requestRegistrationState(&PSAttachedState);
                            if ((signo == SIGUSR1) && (PSAttachedState == 1) && (QWDS_PKT_DATA_DISCONNECTED == ConnectionStatus))
                                send_signo_to_main(SIGUSR1);
                        break;
                        case RIL_UNSOL_DATA_CALL_LIST_CHANGED: {
                            requestQueryDataCall(&ConnectionStatus);
                            if (QWDS_PKT_DATA_DISCONNECTED == ConnectionStatus) {
                                usbnet_link_change(0, profile.IPType, profile.rawIP);
                                if (signo == SIGUSR1) {
                                    alarm(5);
                                }
                                #ifdef ANDROID
                                if (oldConnectionStatus == QWDS_PKT_DATA_CONNECTED) {
                                    kill(getpid(), SIGTERM);
                                }
                                #endif
                            } else if (QWDS_PKT_DATA_CONNECTED == ConnectionStatus) {
                                usbnet_link_change(1, profile.IPType, profile.rawIP);
                            }
                            #ifdef ANDROID
                            oldConnectionStatus = ConnectionStatus;
                            #endif
                        }
                        break;
                        default:
                        break;
                    }
                }
            }
        }
    }

__main_quit:
    if (pthread_join(gQmiThreadID, NULL)) {
        dbg_time("%s Error joining to listener thread (%s)", __func__, strerror(errno));
    }
    close(signal_control_fd[0]);
    close(signal_control_fd[1]);
    close(qmidevice_control_fd[0]);
    close(qmidevice_control_fd[1]);
    dbg_time("%s exit", __func__);
    if (logfilefp)
        fclose(logfilefp);

    return 0;
}
