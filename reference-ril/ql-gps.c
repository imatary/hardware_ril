#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <pthread.h>
#include <alloca.h>
#include "atchannel.h"
#include "at_tok.h"
#include "misc.h"
#include <getopt.h>
#include <linux/sockios.h>
#include <termios.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../include/telephony/ril.h"
#include <linux/un.h>
#include <linux/poll.h>

#define LOG_NDEBUG 0
#define LOG_TAG "GPS"
#include "ql-log.h"

extern void RILC_requestTimedCallback (RIL_TimedCallback callback, void *param,
                                const struct timeval *relativeTime);
static const struct timeval TIMEVAL_1 = {1,0};

typedef struct _GPS_TLV {
   int type;
   int length;
   unsigned char data[0];
} GPS_TLV;

static int s_gps_state = 0;
static pthread_t s_gps_thread;
static int s_agps_check_times = 0;
static void pollXTRAStateChange (void *param) {
    if (s_gps_state && s_agps_check_times--) {
        int xtradatadurtime = 0;
        ATResponse *p_response = NULL;
        int err = at_send_command_singleline("AT+QGPSXTRADATA?", "+QGPSXTRADATA: ", &p_response);
        if (err == 0 && p_response != NULL && p_response->success == 1) {
            char *line = p_response->p_intermediates->line;
            if (at_tok_start(&line) == 0) {
                at_tok_nextint(&line, &xtradatadurtime);
            }
        }   
        at_response_free(p_response);
        if (xtradatadurtime == 0)
            RILC_requestTimedCallback (pollXTRAStateChange, NULL, &TIMEVAL_1);
    }    
}

static time_t s_last_inject_time = 0;
static int s_last_inject_uncertainty = 10;
static void *s_last_inject_xtra_data = NULL;
static int s_last_inject_xtra_length = 0;
static void onGPSStateChange (void *param)
{
    char *cmd;
    ATResponse *p_response = NULL;
    int oldState = 0xff;
    GPS_TLV *extra_gps_tlv = (GPS_TLV *)param;
    int err = at_send_command_singleline("AT+QGPS?", "+QGPS: ", &p_response);

    if (err == 0 && p_response != NULL && p_response->success == 1) {
        char *line = p_response->p_intermediates->line;
        if (at_tok_start(&line) == 0) {
            at_tok_nextint(&line, &oldState);
        }
    }   
    at_response_free(p_response);

    LOGD("onGPSStateChange = {type=%d, length=%d}", extra_gps_tlv->type, extra_gps_tlv->length);
    if (extra_gps_tlv->type == 0)
    {
        if (oldState == 0)
            return;
        s_gps_state = 0;
        at_send_command("AT+QGPSEND", NULL);
    } 
    else if (extra_gps_tlv->type == 1)
    {
        if (oldState != 0)
            return;

        if (s_last_inject_xtra_data != NULL)
        {
            struct tm tm;
            time_t now = time(NULL);

            if (s_last_inject_time > now)
                now = s_last_inject_time;
            gmtime_r(&now, &tm);
  
            at_send_command("AT+QGPSXTRATAUTO=0", NULL);
            at_send_command("AT+QGPSXTRA=1", NULL);
            at_send_command("AT+QFDEL=\"RAM:xtra2.bin\"", NULL);
            
            asprintf(&cmd, "AT+QFUPL=\"RAM:xtra2.bin\",%d,%d", s_last_inject_xtra_length, 60);
            at_send_command_raw(cmd, s_last_inject_xtra_data, s_last_inject_xtra_length, "+QFUPL:", NULL);
            free(cmd);    
            
            asprintf(&cmd, "AT+QGPSXTRATIME=0, \"%d/%d/%d,%d:%d:%d\",1,1,%d",
                tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, s_last_inject_uncertainty);
            at_send_command(cmd, NULL);
            free(cmd);    
            
            at_send_command("AT+QGPSXTRADATA=\"RAM:xtra2.bin\"", NULL);
            at_send_command("AT+QFDEL=\"RAM:xtra2.bin\"", NULL);
            free(s_last_inject_xtra_data);
            s_last_inject_xtra_data = NULL;

            s_gps_state = 1;
            s_agps_check_times = 15;
            RILC_requestTimedCallback (pollXTRAStateChange, NULL, &TIMEVAL_1);
        }
        
        at_send_command("AT+QGPS=1", NULL);
    }
    else if (extra_gps_tlv->type == 23)
    { //inject time
        /** Milliseconds since January 1, 1970 */
        typedef int64_t GpsUtcTime;
        GpsUtcTime gpsutctime; int64_t timeReference; int uncertainty;
        struct tm tm;
        
        memcpy(&gpsutctime, extra_gps_tlv->data, sizeof(gpsutctime));
        memcpy(&timeReference, extra_gps_tlv->data + sizeof(gpsutctime), sizeof(timeReference));
        memcpy(&uncertainty, extra_gps_tlv->data + sizeof(gpsutctime) + sizeof(uncertainty), sizeof(uncertainty));
            
        LOGD("%s(time=%lld, timeReference=%lld, uncertainty=%d)",__FUNCTION__,
            *((int64_t *)&gpsutctime), timeReference, uncertainty);
        
        s_last_inject_time = (gpsutctime+999)/1000;
        s_last_inject_uncertainty = uncertainty;

        gmtime_r(&s_last_inject_time, &tm);

        LOGD("%s GpsUtcTime: \"%d/%d/%d,%d:%d:%d\", uncertainty=%d", __func__,
                tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, s_last_inject_uncertainty);
    }
    else if (extra_gps_tlv->type == 34) 
    { //inject xtra
        if (s_last_inject_xtra_data)
            free(s_last_inject_xtra_data);

        s_last_inject_xtra_data = malloc(extra_gps_tlv->length);
        s_last_inject_xtra_length = extra_gps_tlv->length;
        if (s_last_inject_xtra_data != NULL)
            memcpy(s_last_inject_xtra_data, extra_gps_tlv->data, extra_gps_tlv->length);
    }

    free(extra_gps_tlv);
}

static void * GpsMainLoop(void *param) {
    struct sockaddr_un addr;
    struct sockaddr_un *p_addr = &addr;
    const char *name = "rild-gps";
    int type = SOCK_STREAM;
    int n;
    int err;
    
    int s = socket(AF_LOCAL, type, 0);
    if (s < 0) return NULL;

    memset (p_addr, 0, sizeof (*p_addr));
    p_addr->sun_family = AF_LOCAL;
    p_addr->sun_path[0] = 0;
    memcpy(p_addr->sun_path + 1, name, strlen(name) );

    n = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &n, sizeof(n));

    if (bind(s, (struct sockaddr *) &addr,  strlen(name) + offsetof(struct sockaddr_un, sun_path) + 1) < 0) {
        return NULL;
    }

    if (type == SOCK_STREAM) {
        int ret;

        ret = listen(s, 1);

        if (ret < 0) {
            close(s);
            return NULL;
        }
    }

    for(;;) {
        struct sockaddr addr;
        socklen_t alen;
        int fd;
        int ret;
        struct pollfd pollfds[1];
        GPS_TLV gps_tlv;
        GPS_TLV *extra_gps_tlv = NULL;

        alen = sizeof(addr);
        LOGD("waiting for gps connect");
        fd = accept(s, &addr, &alen);
        if(fd < 0) {
            LOGD("accept failed: %s\n", strerror(errno));
            continue;
        }

        fcntl(fd, F_SETFD, FD_CLOEXEC);

        LOGD("reading gps cmd");
        fcntl(fd, F_SETFL, O_NONBLOCK);

        pollfds[0].fd = fd;
        pollfds[0].events = POLLIN;
        pollfds[0].revents = 0;
        gps_tlv.type = -1;
        gps_tlv.length = 0;
        extra_gps_tlv = NULL;

        do {
            do {
                ret = poll(pollfds, 1, -1);
            } while ((ret < 0) && (errno == EINTR));

            if (pollfds[0].revents & POLLIN) {
                ssize_t nreads;
                if (gps_tlv.length == 0) {
                    nreads = read(fd, &gps_tlv, sizeof(gps_tlv));
                    if (nreads <= 0) {
                        LOGE("%s read=%d errno: %d (%s)",  __func__, (int)nreads, errno, strerror(errno));
                        break;
                    }

                    if (nreads == 1) { //old gps hal only send gps_cmd
                        unsigned char gps_cmd = *((unsigned char *)&gps_tlv);
                        gps_tlv.type = gps_cmd;
                        gps_tlv.length = 0;
                    } 
                    
                    extra_gps_tlv = (GPS_TLV *)malloc(sizeof(gps_tlv) + gps_tlv.length);
                    extra_gps_tlv->type = gps_tlv.type;
                    extra_gps_tlv->length = 0;
                } else {
                    nreads = read(fd, extra_gps_tlv->data + extra_gps_tlv->length, gps_tlv.length);
                    if (nreads <= 0) {
                        LOGE("%s read=%d errno: %d (%s)",  __func__, (int)nreads, errno, strerror(errno));
                        break;
                    }  
                    extra_gps_tlv->length += nreads;
                    gps_tlv.length -= nreads;
                }
            }
            else if (pollfds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                break;
            }
        }
        while (gps_tlv.length);

        LOGD("gps_tlv = {type=%d, length=%d}", gps_tlv.type, gps_tlv.length);
        if (extra_gps_tlv) {
            LOGD("extra_gps_tlv = {type=%d, length=%d}", extra_gps_tlv->type, extra_gps_tlv->length);
        }

        if (extra_gps_tlv) {
            RILC_requestTimedCallback (onGPSStateChange, extra_gps_tlv, NULL);
        }
done:
        close(fd);
    }

    return NULL;
}

void ql_gps_init(void) {
    if (s_gps_thread == 0) {
        pthread_create(&s_gps_thread, NULL, GpsMainLoop, NULL);
    }
}
