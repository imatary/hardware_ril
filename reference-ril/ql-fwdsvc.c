#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/un.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <poll.h>

#include "ql-datafwd.h"

#define LOG_NDEBUG 0
#define LOG_TAG "FWDSVC"
#include "ql-log.h"

void * send_to_app_thread(void *param);
void * send_to_module_thread(void *param);
void * FwdSvcMainLoop(void *param)
{
    int ret = 0;
    int backlog = 1;
    int s_fd = -1;
    int c_fd = -1;
    int opt = 1; //for address reuse
    struct sockaddr_un s_addr;
    struct sockaddr c_addr;
    socklen_t addr_len;
    struct pollfd poll_fd;
    struct pollfd s_poll_fd;
    int flags = 0;
    char *s_name = "@rild-fwd"; //first byte use for abstract namespace
    char buf[MAX_SINGLE_BUFFER_SIZE + sizeof(struct ql_fwd_pdu)] = {0};
    struct ql_fwd_pdu *p_pdu = NULL;
    struct ql_data_buffer *q_data = NULL;
    struct ql_data_buffer_head *q_head = NULL;
    struct ql_data_buffer_queue *ql_fwd_queue = NULL;
    time_t cur_time = 0;
    pthread_t to_app_thread = 0;
    pthread_t to_module_thread = 0;
    int err_count = 0;
#define READ_RETRY 5
    int client_recv_count = 0;

    LOGD("DataFwd service starting\n");
    if (NULL == param) {
        LOGE("Fwd Svc got a null param -_-!\n");
        return NULL;
    }
    ql_fwd_queue = (struct ql_data_buffer_queue *)param;

    ret = ql_data_fwd_svc_init_queue(ql_fwd_queue);
    if (ret < 0) {
        LOGE("init queue failed\n");
        goto err_init_queue;
    }

    s_fd = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (s_fd < 0) {
        LOGE("create socket failed, errno = %d(%s)\n", errno, strerror(errno));
        goto err_create_socket;
    }

    flags = fcntl(s_fd, F_GETFL, 0);
    fcntl(s_fd, F_SETFL, flags | O_NONBLOCK);

    ql_fwd_queue->server_fd = s_fd;
    bzero(&s_addr, sizeof(s_addr));
    s_addr.sun_family = AF_LOCAL;
    memcpy(&(s_addr.sun_path[0]), s_name, strlen(s_name));
    s_addr.sun_path[0] = 0; //use abstract namespace

    setsockopt(s_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(s_fd, (struct sockaddr *)&s_addr, (strlen(s_name) + offsetof(struct sockaddr_un, sun_path))) < 0) {
        LOGE("bind socket failed, errno = %d(%s)\n", errno, strerror(errno));
        goto err;
    }

    if (listen(s_fd, backlog) < 0) {
        LOGE("listen socket failed, errno = %d(%s)\n", errno, strerror(errno));
    }

    ql_fwd_queue->server_alive = 1;
    pthread_create(&to_app_thread, NULL, send_to_app_thread, &(ql_fwd_queue->queue[QUEUE_TO_APP]));
    ql_fwd_queue->queue[QUEUE_TO_APP].sender_thread = to_app_thread;
    pthread_create(&to_module_thread, NULL, send_to_module_thread, &(ql_fwd_queue->queue[QUEUE_TO_MODULE]));
    ql_fwd_queue->queue[QUEUE_TO_MODULE].sender_thread = to_module_thread;
    usleep(20);

    bzero(&s_poll_fd, sizeof(s_poll_fd));
    s_poll_fd.fd = s_fd;
    s_poll_fd.events = POLLIN;
    while (ql_fwd_queue->server_alive) {
        bzero(&c_addr, sizeof(c_addr));
        s_poll_fd.revents = 0;
        if ((ret = poll(&s_poll_fd, 1, 200)) <= 0) {
            if ((0 == ret) || (EINTR == errno)) {
                continue;
            } else {
                LOGE("server error, exit now!\n");
                break;
            }
        }

        //kick sender for empty the queue
        ql_fwd_queue->queue[QUEUE_TO_MODULE].kick_sender(&ql_fwd_queue->queue[QUEUE_TO_MODULE]);
        usleep(20);
        LOGD("now accept client...\n");
        if (s_poll_fd.revents && (s_poll_fd.revents & POLLIN)) {
            c_fd = accept(s_fd, &c_addr, &addr_len);
            if (c_fd < 0) {
                LOGE("accept failed, errno = %d(%s)\n", errno, strerror(errno));
                continue;
            }
		} else {
            LOGD("s_poll_fd.revents = 0x%x\n", s_poll_fd.revents);
            continue;
        }
        LOGD("client connected...\n");
        flags = fcntl(c_fd, F_GETFD, 0);
        fcntl(c_fd, F_SETFD, flags | FD_CLOEXEC);
        flags = fcntl(c_fd, F_GETFL, 0);
        fcntl(c_fd, F_SETFL, flags | O_NONBLOCK);
        ql_fwd_queue->client_alive = 1;
        ql_fwd_queue->client_fd = c_fd;
        bzero(&poll_fd, sizeof(poll_fd));
        poll_fd.fd = c_fd;
        poll_fd.events = POLLIN;
        ql_fwd_queue->heart_beat = 0;
        err_count = 0;
        client_recv_count = 0;
        while (ql_fwd_queue->client_alive) {
            ql_fwd_queue->queue[QUEUE_TO_MODULE].kick_sender(&ql_fwd_queue->queue[QUEUE_TO_MODULE]); //empty the fwd queue
            if (ql_fwd_queue->watchdog_on) {
                cur_time = time(&cur_time);
                if (0 == ql_fwd_queue->heart_beat) {
                    ql_fwd_queue->heart_beat = cur_time;
                }

                if ((cur_time - ql_fwd_queue->heart_beat) > ql_fwd_queue->heart_beat_timeout) {
                    LOGE("watchdog timeout, client may dead,disconnecting...\n");
                    close(c_fd);
                    c_fd = -1;
                    ql_fwd_queue->client_fd = c_fd;
                    ql_fwd_queue->client_alive = 0;
                    ql_fwd_queue->heart_beat = 0;
                    break;
                }
            }

            poll_fd.revents = 0;
            if ((ret = poll(&poll_fd, 1, 200)) <= 0) {
                if ((0 == ret) || (EINTR == errno)) {
                    continue;
                } else {
                    LOGE("poll client fd failed, errno = %d(%s)\n", errno, strerror(errno));
                    LOGE("disconnecting from client...\n");
                    close(c_fd);
                    c_fd = -1;
                    ql_fwd_queue->client_fd = c_fd;
                    ql_fwd_queue->client_alive = 0;
                    ql_fwd_queue->heart_beat = 0;
                    break;
                }
            }

            if (poll_fd.revents && (poll_fd.revents & POLLIN)) {
                memset(buf, 0, MAX_SINGLE_BUFFER_SIZE);
                ret = read(c_fd, buf, sizeof(struct ql_fwd_pdu));
                if (ret <= 0) {
                    LOGE("read pdu error on client fd, ret = %d, errno = %d(%s)\n", ret, errno, strerror(errno));
                    if ((err_count > READ_RETRY) && (0 == ql_fwd_queue->watchdog_on)) { //client may exit without close
                        close(c_fd);
                        c_fd = -1;
                        ql_fwd_queue->client_fd = c_fd;
                        ql_fwd_queue->client_alive = 0;
                        ql_fwd_queue->heart_beat = 0;
                        break;
                    }
                    err_count++;
                    continue;
                }

                p_pdu = (struct ql_fwd_pdu *)(&buf[0]);
                if (strncmp(p_pdu->magic, PDU_MAGIC, MAGIC_SIZE)) {
                    LOGE("the unknown pdu magic will cause terriable error, disconnecting...\n");
                    close(c_fd);
                    c_fd = -1;
                    ql_fwd_queue->client_fd = c_fd;
                    ql_fwd_queue->client_alive = 0;
                    ql_fwd_queue->heart_beat = 0;
                    break;
                }

                switch (p_pdu->type) {
                case PDU_TYPE_HEART_BEAT:
                    ql_fwd_queue->heart_beat = time(&ql_fwd_queue->heart_beat);
                    break;
                case PDU_TYPE_BYE_BYE:
                    LOGD("client will disconnect...\n");
                    usleep(100); //wait for FIN
                    close(c_fd);
                    c_fd = -1;
                    ql_fwd_queue->client_fd = c_fd;
                    ql_fwd_queue->client_alive = 0;
                    ql_fwd_queue->heart_beat = 0;
                    break;
                case PDU_TYPE_DATA:
                    ret = read(c_fd, &(buf[sizeof(struct ql_fwd_pdu)]), p_pdu->size);
                    if (ret != p_pdu->size) {
                        LOGE("server read payload failed, this will cause terrible error, errno = %d(%s)\n", errno, strerror(errno));
                        close(c_fd);
                        c_fd = -1;
                        ql_fwd_queue->client_fd = c_fd;
                        ql_fwd_queue->client_alive = 0;
                        ql_fwd_queue->heart_beat = 0;
                        break;
                    } else {
                        q_data = ql_fwd_queue->alloc_buffer((size_t)ret);
                        if (NULL == q_data) {
                            LOGE("queue alloc buffer failed\n");
                            continue;
                        }
                        ql_fwd_queue->init_buffer(q_data);
                        memcpy(q_data->data, &(buf[sizeof(struct ql_fwd_pdu)]), p_pdu->size);
                        q_head = &(ql_fwd_queue->queue[QUEUE_TO_MODULE]);
                        if (q_head->enqueue(q_head, q_data) == NULL) {
                            LOGE("queue to module enqueue failed\n");
                            ql_fwd_queue->free_buffer(q_data);
                        }
                        q_head->kick_sender(q_head);
                        client_recv_count++;
                        LOGD("%d packages received, after kick_sender\n", client_recv_count);
                    }
                    LOGD("%d packages received\n", client_recv_count);
                    break;
                default:
                    LOGE("unsupported pdu type may cause terrible error, disconnecting...\n");
                    close(c_fd);
                    c_fd = -1;
                    ql_fwd_queue->client_fd = c_fd;
                    ql_fwd_queue->client_alive = 0;
                    ql_fwd_queue->heart_beat = 0;
                    break;
                } /*switch p_pdu->type */
            } /*if poll_fd.revents && (poll_fd.revents & POLLIN) */
        } /*while ql_fwd_queue->client_alive */
    } /*while ql_fwd_queue->server_alive */
    
err:
    if (s_fd >= 0) {
        close(s_fd);
	    s_fd = -1;
    }

    if (c_fd >= 0) {
        close(c_fd);
        c_fd = -1;
    }

    ql_fwd_queue->server_fd = -1;
    ql_fwd_queue->client_fd = -1;

err_create_socket:
    LOGD("kick to module queue sender\n");
    ql_fwd_queue->queue[QUEUE_TO_MODULE].kick_sender(&(ql_fwd_queue->queue[QUEUE_TO_MODULE]));
    LOGD("kick to app queue sender\n");
    ql_fwd_queue->queue[QUEUE_TO_APP].kick_sender(&(ql_fwd_queue->queue[QUEUE_TO_APP]));
    LOGD("waiting for to_app_thread\n");
    if (0 != to_app_thread) {
        pthread_join(to_app_thread, NULL);
    }
    LOGD("waiting for to_module_thread\n");
    if (0 != to_module_thread) {
        pthread_join(to_module_thread, NULL);
    }
    ql_data_fwd_svc_destroy_queue(ql_fwd_queue);

err_init_queue:
    LOGD("server will exit ^_^\n");
    return NULL;
}

void * send_to_app_thread(void *param)
{
    struct ql_data_buffer_head *queue = NULL;

    if (NULL == param) {
        LOGE("to_app_thread got a null param -_-!\n");
        return NULL;
    }
    queue = (struct ql_data_buffer_head *)param;
    while (queue->father->server_alive) {
        queue->father->send_to_app(queue->father); //start is also end
        pthread_mutex_lock(&(queue->fwd_cond_mutex));
        pthread_cond_wait(&(queue->fwd_cond), &(queue->fwd_cond_mutex));
        pthread_mutex_unlock(&(queue->fwd_cond_mutex));
        if (!queue->father->server_alive) {
            LOGE("server has gone, to_app_thread will follow him...\n");
            break;
        }
        queue->father->send_to_app(queue->father);
    }
    LOGD("to_app_thread will exit ^_^\n");
    return NULL;
}

void * send_to_module_thread(void *param)
{
    struct ql_data_buffer_head *queue = NULL;

    if (NULL == param) {
        LOGE("to_module_thread got a null param -_-!\n");
        return NULL;
    }
    queue = (struct ql_data_buffer_head *)param;
    while (queue->father->server_alive) {

        if (0 == queue->father->client_alive) { // client has dead nobody will kick me
            queue->father->send_to_module(queue->father);
        }

        pthread_mutex_lock(&(queue->fwd_cond_mutex));
        pthread_cond_wait(&(queue->fwd_cond), &(queue->fwd_cond_mutex));
        pthread_mutex_unlock(&(queue->fwd_cond_mutex));
        if (!queue->father->server_alive) {
            LOGE("server has gone, to_module_thread will follow him...\n");
            break;
        }
        queue->father->send_to_module(queue->father);
    }
    LOGD("to_module_thread will exit ^_^\n");
    return NULL;
}

static pthread_t ql_fwd_thread = 0;
static struct ql_data_buffer_queue ql_datafwd_queue;
void ql_fwdsvc_init(void) {
    if (0 == ql_fwd_thread) {
        pthread_create(&ql_fwd_thread, NULL, FwdSvcMainLoop, &ql_datafwd_queue);
    }
}

void ql_fwdsvc_recv_data(char *fwd_data) {
    if ((strlen(fwd_data) > 2*MAX_SINGLE_BUFFER_SIZE) || (strlen(fwd_data)%2 != 0)) {
        LOGE("invalid fwd_data len\n");
        return;
    }

    if (QUEUE_INITIALIZED == ql_datafwd_queue.state) {
        pthread_mutex_lock(&ql_datafwd_queue.state_mutex);
        if (QUEUE_INITIALIZED == ql_datafwd_queue.state) {
            struct ql_data_buffer *q_data = NULL;
            struct ql_data_buffer_head *q_head = NULL;
            q_head = &(ql_datafwd_queue.queue[QUEUE_TO_APP]);
            q_head->kick_sender(q_head); //empty fwd queue
            q_data = ql_datafwd_queue.alloc_buffer(strlen(fwd_data)/2);
            if (NULL == q_data) {
                LOGE("queue to app alloc buffer failed\n");
            } else {
                ql_datafwd_queue.init_buffer(q_data);
                //TODO copy data
                ql_datafwd_queue.toHex(fwd_data, q_data->data);
                if (q_head->enqueue(q_head, q_data) == NULL) {
                    LOGE("queue to app enqueue failed\n");
                    ql_datafwd_queue.free_buffer(q_data);
                } else {
                    q_head->kick_sender(q_head);
                }
            }
        }
        pthread_mutex_unlock(&ql_datafwd_queue.state_mutex);
    }
}
