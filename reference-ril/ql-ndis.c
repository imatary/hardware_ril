#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <termios.h>
#include <pthread.h>
#include <sys/utsname.h>
#include <linux/kdev_t.h>
#define LOG_NDEBUG 0
#define LOG_TAG "NDIS"
#include "ql-log.h"

int quectel_CM(int argc, char *argv[]);
int notifyDataCallProcessExit(void);
static struct utsname utsname;  /* for the kernel version */
static int kernel_version;
#define KVERSION(j,n,p) ((j)*1000000 + (n)*1000 + (p))
#define MAX_PATH 256
int ql_get_ndisname(char **pp_usbnet_adapter) {
    struct dirent* ent = NULL;  
    struct dirent* subent = NULL;  
    DIR *pDir, *pSubDir;  
    char dir[MAX_PATH], subdir[MAX_PATH];
    int fd;
    int find_usb_device = 0;
    int find_qmichannel = 0;

    *pp_usbnet_adapter = NULL;
#define CDCWDM_UEVENT_LEN 256
#ifndef MKDEV
#define MKDEV(ma,mi) ((ma)<<8 | (mi))
#endif
	int fd_uevent = -1;
	char uevent_path[MAX_PATH] = {0};
	char cdc_nod[MAX_PATH] = {0};
	char uevent_buf[CDCWDM_UEVENT_LEN] = {0};
	char *pmajor = NULL;
	char *pminor = NULL;
	char *pcr = NULL;
	int cdc_major = 0;
	int cdc_minor = 0;
	struct stat st = {0};
	int need_newnod = 0;
    int osmaj, osmin, ospatch;
    char *usb_class_name = NULL;

    /* get the kernel version now, since we are called before sys_init */
    uname(&utsname);
    osmaj = osmin = ospatch = 0;
    sscanf(utsname.release, "%d.%d.%d", &osmaj, &osmin, &ospatch);
    kernel_version = KVERSION(osmaj, osmin, ospatch);
    if (kernel_version < KVERSION(3, 6, 0)) {
        usb_class_name = "usb";
    } else {
        usb_class_name = "usbmisc";
    }

    strcpy(dir, "/sys/bus/usb/devices");
    if ((pDir = opendir(dir)) == NULL)  {  
        LOGE("Cannot open directory: %s", dir);  
        return -ENODEV;  
    }  

    while ((ent = readdir(pDir)) != NULL) {
        char idVendor[5] = "";
        char idProduct[5] = "";
                  
        sprintf(subdir, "%s/%s/idVendor", dir, ent->d_name);
        fd = open(subdir, O_RDONLY);
        if (fd > 0) {
            read(fd, idVendor, 4);
            close(fd);
        //dbg_time("idVendor = %s\n", idVendor);
            if (strncasecmp(idVendor, "05c6", 4) && strncasecmp(idVendor, "2c7c", 4)) {
                continue;
            }
        } else {
            continue;
        }

        sprintf(subdir, "%s/%s/idProduct", dir, ent->d_name);
        fd = open(subdir, O_RDONLY);
        if (fd > 0) {
            read(fd, idProduct, 4);
            close(fd);
            //dbg_time("idProduct = %s\n", idProduct);
            if (!strncasecmp(idVendor, "05c6", 4) && strncasecmp(idProduct, "9003", 4) && strncasecmp(idProduct, "9215", 4) && strncasecmp(idProduct, "9025", 4)) {
                continue;
            }
            if (!strncasecmp(idVendor, "2c7c", 4) && strncasecmp(idProduct, "0125", 4) && strncasecmp(idProduct, "0121", 4)) {
                continue;
            }
        } else {
            continue;
        }
    
        LOGE("Find idVendor=%s, idProduct=%s", idVendor, idProduct);
        find_usb_device = 1;
        break;
    }
    closedir(pDir);

    if (!find_usb_device) {
        LOGE("Cannot find Quectel UC20/EC20");
        return -ENODEV;  
    }      

    sprintf(subdir, "/%s:1.%d", ent->d_name, 4);
    strcat(dir, subdir);
    if ((pDir = opendir(dir)) == NULL)  {  
        LOGE("Cannot open directory:%s/", dir);  
        return -ENODEV;  
    }
                       
    while ((ent = readdir(pDir)) != NULL) {
        //dbg_time("%s\n", ent->d_name);
        if ((strlen(ent->d_name) == strlen(usb_class_name) && !strncmp(ent->d_name, usb_class_name, strlen(usb_class_name)))) {
            strcpy(subdir, dir);
            strncat(subdir, "/", strlen("/"));
            strncat(subdir, ent->d_name, strlen(ent->d_name));
            if ((pSubDir = opendir(subdir)) == NULL)  {  
                LOGE("Cannot open directory:%s/", subdir);
                break;
            }
            while ((subent = readdir(pSubDir)) != NULL) {
                if (strncmp(subent->d_name, "cdc-wdm", strlen("cdc-wdm")) == 0) {
                    LOGD("Find qmichannel = %s", subent->d_name);
                    find_qmichannel = 1;
                    #if 1
					snprintf(uevent_path, MAX_PATH, "%s/%s/%s", subdir, subent->d_name, "uevent");
					fd_uevent = open(uevent_path, O_RDONLY);
					if (fd_uevent < 0) {
					    LOGE("Cannot open file:%s, errno = %d(%s)", uevent_path, errno, strerror(errno));
					} else {
					    snprintf(cdc_nod, MAX_PATH, "/dev/%s", subent->d_name);
						read(fd_uevent, uevent_buf, CDCWDM_UEVENT_LEN);
                        close(fd_uevent);
						pmajor = strstr(uevent_buf, "MAJOR");
						pminor = strstr(uevent_buf, "MINOR");
						if (pmajor && pminor) {
						    pmajor += sizeof("MAJOR");
							pminor += sizeof("MINOR");
							pcr = pmajor;
							while (0 != strncmp(pcr++, "\n", 1));
							*(pcr - 1) = 0;
							pcr = pminor;
							while (0 != strncmp(pcr++, "\n", 1));
							*(pcr - 1) = 0;
							cdc_major = atoi((const char *)pmajor);
							cdc_minor = atoi((const char *)pminor);
							if (0 == stat(cdc_nod, &st)) {
								if (st.st_rdev != (unsigned)MKDEV(cdc_major, cdc_minor)) {
									need_newnod = 1;
									if (0 != remove(cdc_nod)) {
									    LOGE("remove %s failed. errno = %d(%s)", cdc_nod, errno, strerror(errno));
									}
								} else {
								    need_newnod = 0;
								}
							} else {
							    need_newnod = 1;
							}
						    if ((1 == need_newnod) && (0 != mknod(cdc_nod, S_IRUSR | S_IWUSR | S_IFCHR, MKDEV(cdc_major, cdc_minor)))) {
						        LOGE("mknod for %s failed, MAJOR = %d, MINOR =%d, errno = %d(%s)", cdc_nod, cdc_major,
								    cdc_minor, errno, strerror(errno));
						    }
						} else {
						    LOGE("major or minor get failed, uevent_buf = %s", uevent_buf);
						}
					}
                    #endif
                    break;
                }                  
            }
            closedir(pSubDir);
        } 

        else if (strncmp(ent->d_name, "GobiQMI", strlen("GobiQMI")) == 0) {
            strcpy(subdir, dir);
            strcat(subdir, "/GobiQMI");
            if ((pSubDir = opendir(subdir)) == NULL)  {  
                LOGE("Cannot open directory:%s/", subdir);
                break;
            }
            while ((subent = readdir(pSubDir)) != NULL) {
                if (strncmp(subent->d_name, "qcqmi", strlen("qcqmi")) == 0) {
                    LOGD("Find qmichannel = %s", subent->d_name);
                    find_qmichannel = 1;
                    break;
                }                         
            }
            closedir(pSubDir);
        }         

        else if (strncmp(ent->d_name, "net", strlen("net")) == 0) {
            strcpy(subdir, dir);
            strcat(subdir, "/net");
            if ((pSubDir = opendir(subdir)) == NULL)  {  
                LOGE("Cannot open directory:%s/", subdir);
                break;
            }
            while ((subent = readdir(pSubDir)) != NULL) {
                if ((strncmp(subent->d_name, "wwan", strlen("wwan")) == 0)
                    || (strncmp(subent->d_name, "eth", strlen("eth")) == 0)
                    || (strncmp(subent->d_name, "usb", strlen("usb")) == 0)) {
                    static char s_pp_usbnet_adapter[32];
                    strcpy(s_pp_usbnet_adapter, subent->d_name);
                    *pp_usbnet_adapter = s_pp_usbnet_adapter;
                    LOGD("Find usbnet_adapter = %s", *pp_usbnet_adapter );
                    break;
                }                         
            }
            closedir(pSubDir);
        } 

        if (find_qmichannel && *pp_usbnet_adapter)
            break;
    }
    closedir(pDir);     

    return (find_qmichannel && *pp_usbnet_adapter) ? 0 : -1;
}

static pid_t ql_ndis_pid = 0;
static int ql_ndis_quit = 0;
static pthread_t ql_ndis_thread;
static int ndis_create_thread(pthread_t * thread_id, void * thread_function, void * thread_function_arg ) {
    static pthread_attr_t thread_attr;
    pthread_attr_init(&thread_attr);
    pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(thread_id, &thread_attr, thread_function, thread_function_arg)!=0) {
        LOGE("%s %s errno: %d (%s)", __FILE__, __func__, errno, strerror(errno));
        return 1;
    }
    pthread_attr_destroy(&thread_attr); /* Not strictly necessary */
    return 0; //thread created successfully
}

static void ql_sleep(int sec) {
    int msec = sec * 1000;
    while (!ql_ndis_quit && (msec > 0)) {
        msec -= 200;
        usleep(200*1000);
    }
}

static char s_ndis_apn[128];
static char s_ndis_user[128];
static char s_ndis_password[128];
static char s_ndis_auth_type[2];
static int s_ndis_default_pdp;
static void* ndis_thread_function(void*  arg) {
    const char *argv[20];
    int argc = 0;
    const char *pdpv[10] = {"0", "1", "2", "3", "4", "5", "6", "7", "8"};

    LOGD("%s %s/%s/%s/%s enter", __func__, s_ndis_apn, s_ndis_user, s_ndis_password, s_ndis_auth_type);
        
    //LOGD("apn = %s", apn);
    //LOGD("user = %s", user);
    //LOGD("password = %s", password);
    //LOGD("auth_type = %s", auth_type);

    argv[argc++] = "quectel-CM";
    //argv[argc++] = "-v";
    argv[argc++] = "-s";
    if (s_ndis_apn[0])
        argv[argc++] = s_ndis_apn;
    if (s_ndis_user[0])
        argv[argc++] = s_ndis_user;
    if (s_ndis_user[0] && s_ndis_password[0])
        argv[argc++] = s_ndis_password;
    if (s_ndis_user[0] && s_ndis_password[0] && s_ndis_auth_type[0])
        argv[argc++] = s_ndis_auth_type;
    argv[argc++] = "-n";
    argv[argc++] = pdpv[s_ndis_default_pdp]; 
    //argv[argc++] = "-v";
    argv[argc] = NULL;   
        
    while (!ql_ndis_quit) {
        int child_pid = fork();
        if (child_pid == 0) {
            exit(quectel_CM(argc, (char**) argv));
        } else if (child_pid < 0) {
            LOGE("failed to start ('%s'): %s\n", "quectel-CM", strerror(errno));
            break;
        } else {
            int sleep_msec = 3000;
            int status, retval = 0;
            ql_ndis_pid = child_pid;
            waitpid(child_pid, &status, 0);
            ql_ndis_pid = 0;
            if (WIFSIGNALED(status)) {
                retval = WTERMSIG(status);
                LOGD("*** %s: Killed by signal %d retval = %d\n", "quectel-CM", WTERMSIG(status), retval);
            } else if (WIFEXITED(status) && WEXITSTATUS(status) > 0) {
                retval = WEXITSTATUS(status);
                LOGD("*** %s: Exit code %d retval = %d\n", "quectel-CM", WEXITSTATUS(status), retval);
            }
            if (notifyDataCallProcessExit() || ql_ndis_quit)
                break;
            else
                ql_sleep(3);
        }
    }
        
    ql_ndis_thread = 0;
    LOGD("%s exit", __func__);
    pthread_exit(NULL);
    return NULL;     
}

int ql_ndis_stop(int signo);
int ql_ndis_start(const char *apn, const char *user, const char *password, const char *auth_type, int default_pdp) {    
    static char *argv[4] = {NULL, NULL, NULL, NULL};
    ql_ndis_stop(SIGKILL);

    //LOGD("apn = %s", apn);
    //LOGD("user = %s", user);
    //LOGD("password = %s", password);
    //LOGD("auth_type = %s", auth_type);
    
    s_ndis_apn[0] = s_ndis_user[0] = s_ndis_password[0] = s_ndis_auth_type[0] = '\0';
    if (apn != NULL) strncpy(s_ndis_apn, apn, sizeof(s_ndis_apn) - 1);
    if (user != NULL) strncpy(s_ndis_user, user, sizeof(s_ndis_user) - 1);
    if (password != NULL) strncpy(s_ndis_password, password, sizeof(s_ndis_password) - 1);
    if (auth_type != NULL) strncpy(s_ndis_auth_type, auth_type, sizeof(s_ndis_auth_type) - 1);
    s_ndis_default_pdp = default_pdp;

    ql_ndis_quit = 0;
    if (!ndis_create_thread(&ql_ndis_thread, ndis_thread_function, NULL))
        return getpid();
    else
        return -1;
}

int ql_ndis_stop(int signo) {
    unsigned int kill_time = 15000;
    ql_ndis_quit = 1;

    if (ql_ndis_pid == 0 && ql_ndis_thread == 0)
        return 0;
    
    if (ql_ndis_pid != 0) {
        if (fork() == 0) {//kill may take long time, so do it in child process
            int kill_time = 10;
            kill(ql_ndis_pid, signo);
            while(kill_time--&& ql_ndis_pid != 0) //wait pppd quit
                sleep(1);
            if (signo != SIGKILL && ql_ndis_pid != 0)
                kill(ql_ndis_pid, signo);
            exit(0);
        } 
    }

    do {
        usleep(100*1000);
        kill_time -= 100;
    } while ((kill_time > 0) && (ql_ndis_pid != 0 || ql_ndis_thread != 0));

    LOGD("%s cost %d msec", __func__, (15000 - kill_time));
    return 0;
}

