#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>

#include "atchannel.h"
#include "at_tok.h"
#include "ql-datafwd.h"
#define LOG_NDEBUG 0
#define LOG_TAG "DATAFWD"
#include "ql-log.h"

static char *ql_hex_to_string(const char *src, char *dst, size_t len)
{
    const unsigned char *p = NULL;
    unsigned char *q = NULL;
    int i = 0;
    int j = 0;
    unsigned char tmp = 0;

    if (NULL == src) {
        LOGE("null pointer -> src\n");
        return NULL;
    }

    if (NULL == dst) {
        LOGE("null pointer -> dst\n");
        return NULL;
    }

    for (i = 0, j = 0, p = (unsigned char *)src, q = (unsigned char *)dst; i < len; i++, j+=2) {
        q[j] &= 0x0;
        q[j+1] &= 0x0;
        tmp = (p[i] >> 4) & 0x0f;
        q[j] = ((tmp < 10) ? (tmp + '0') : (tmp - 10 + 'A')); //high
        tmp = (p[i] & 0x0f);
        q[j+1] = ((tmp < 10) ? (tmp + '0') : (tmp - 10 + 'A')); //low
    }
    dst[(len << 1) + 1] = 0;
    return dst;
}

static char * ql_string_to_hex(const char *src, char *dst)
{
    const char *p = NULL;
    char *q = NULL;

    if (NULL == src) {
        LOGE("null pointer -> src\n");
        return NULL;
    }

    if (NULL == dst) {
        LOGE("null pointer -> dst\n");
        return NULL;
    }

    if (0 != strlen(src)%2) {
        LOGE("invalid src string len\n");
        return NULL;
    }

    for (p = src, q = dst; p && *p && q; p+=2, q++) {
        *q &= 0x0;
        if ((*p <= '9') && (*p >= '0')) {
            *q |= ((((unsigned char)(*p - '0')) << 4) & 0xf0);
        } else if ((*p <= 'f') && (*p >= 'a')) {
            *q |= ((((unsigned char)(*p - 'a' + 10)) << 4) & 0xf0);
        } else if ((*p <= 'F') && (*p >= 'A')) {
            *q |= ((((unsigned char)(*p - 'A' + 10)) << 4) & 0xf0);
        } else {
            LOGE("unsupport char : 0x%02x\n", *p);
            return NULL;
        }

        if ((*(p + 1) <= '9') && (*(p + 1) >= '0')) {
            *q |= (((unsigned char)(*(p + 1) - '0')) & 0x0f);
        } else if ((*(p + 1) <= 'f') && (*(p + 1) >= 'a')) {
            *q |= (((unsigned char)(*(p + 1) - 'a' + 10)) & 0x0f);
        } else if ((*(p + 1) <= 'F') && (*(p + 1) >= 'A')) {
            *q |= (((unsigned char)(*(p + 1) - 'A' + 10)) & 0x0f);
        } else {
            LOGE("unsupport char : 0x%02x\n", *(p + 1));
            return NULL;
        }
    }
	return dst;
}

static void ql_data_fwd_svc_kick_sender(struct ql_data_buffer_head *queue)
{
    if (NULL == queue) {
        LOGE("null pointer -> queue\n");
        return;
    }
    pthread_mutex_lock(&(queue->fwd_cond_mutex));
    pthread_cond_broadcast(&(queue->fwd_cond));
    pthread_mutex_unlock(&(queue->fwd_cond_mutex));
}

static int ql_data_fwd_svc_send_to_app(struct ql_data_buffer_queue *queue)
{
    struct ql_data_buffer_head *phead = NULL;
    struct ql_data_buffer *p = NULL;
    struct ql_data_buffer *q = NULL;
    char tmp_buf[MAX_SINGLE_BUFFER_SIZE + sizeof(struct ql_fwd_pdu)] = {0};
    struct ql_fwd_pdu *p_pdu = NULL;
    int ret = 0;
    size_t len = 0;
#define RETRY_COUNT 30
    int count = 0;
    struct pollfd poll_fd;
    phead = &(queue->queue[QUEUE_TO_APP]);

again:
    phead->lock(phead);
    if (!phead->is_empty(phead)) {
        phead->head->prev->next = NULL;
        p = phead->head->next;
        queue->init_buffer(phead->head);
        phead->total_size = 0;
    } else {
        phead->unlock(phead);
        goto out;
    }
    phead->unlock(phead);

    while (p) {
        q = p->next;
        //TODO send to app
        if (queue->client_alive && (queue->client_fd >= 0)) {
            memset(&(tmp_buf[0]), 0, sizeof(tmp_buf));
            p_pdu = (struct ql_fwd_pdu *)(tmp_buf);
            memcpy(&(p_pdu->magic[0]), PDU_MAGIC, MAGIC_SIZE);
            p_pdu->type = PDU_TYPE_DATA;
            p_pdu->size = p->size;
            memcpy(&(tmp_buf[sizeof(struct ql_fwd_pdu)]), p->data, p->size);
            len = 0;
            ret = write(queue->client_fd, tmp_buf, (sizeof(struct ql_fwd_pdu) + p->size));
            len += ((ret < 0) ? 0 : ret);
            if (ret != (sizeof(struct ql_fwd_pdu) + p->size)) {
                LOGE("packet send to app failed, errno = %d(%s), ret = %d\n", errno, strerror(errno), ret);
                count = 0;
                while (count < RETRY_COUNT) {
                    if (len == (sizeof(struct ql_fwd_pdu) + p->size)) {
                        break;
                    }
                    memset(&poll_fd, 0, sizeof(poll_fd));
                    poll_fd.fd = queue->client_fd;
                    poll_fd.events = POLLOUT;
                    poll_fd.revents = 0;
                    if ((ret = poll(&poll_fd, 1, 500)) <= 0) {
                        if ((0 == ret) || (EINTR == errno)) {
                            continue;
                        } else {
                            LOGE("send to app poll error, errno = %d(%s)\n", errno, strerror(errno));
                            break;
                        }
                    }
                    if (poll_fd.revents | POLLOUT) {
                        ret = write(queue->client_fd, ((char *)&(tmp_buf[0]) + len), sizeof(struct ql_fwd_pdu) + p->size - len);
                        len += ((ret < 0) ? 0 : ret);
                    }
                    if (len == (sizeof(struct ql_fwd_pdu) + p->size)) {
                        break;
                    }
                    count++;
                }
                if (RETRY_COUNT == count) {
                    LOGE("terrible error may happen, should send %zd bytes, sent %zd bytes\n", sizeof(struct ql_fwd_pdu) + p->size, len);
                }
            }
        }
        queue->free_buffer(p);
        p = q;
    }
    goto again;
out:
    return 0;
}

static int ql_data_fwd_svc_send_to_module(struct ql_data_buffer_queue *queue)
{
    struct ql_data_buffer_head *phead = NULL;
    struct ql_data_buffer *p = NULL;
    struct ql_data_buffer *q = NULL;
    char HEX_STRING[2*MAX_SINGLE_BUFFER_SIZE + 1] = {0};
    int ret = 0;
#define RETRY_COUNT 30
    int count = 0;
    char *at_cmd = NULL;
#define SRC_PORT 1
#define DST_PORT 0

    phead = &(queue->queue[QUEUE_TO_MODULE]);

again:
    phead->lock(phead);
    if (!phead->is_empty(phead)) {
        phead->head->prev->next = NULL;
        p = phead->head->next;
        queue->init_buffer(phead->head);
        phead->total_size = 0;
    } else {
        phead->unlock(phead);
        goto out;
    }
    phead->unlock(phead);

    while (p) {
        q = p->next;
        //TODO send to module
        //AT+QDATAFWD=2,0,length,data,0
        memset(HEX_STRING, 0, sizeof(HEX_STRING));
        queue->toString(p->data, HEX_STRING, p->size);
        asprintf(&at_cmd, "AT+QDATAFWD=%d,%d,%zd,\"%s\",0", SRC_PORT, DST_PORT, (p->size) << 1, HEX_STRING);
        ret = at_send_command(at_cmd, NULL);
        if (ret < 0) {
            LOGE("send command failed\n");
            while (count < RETRY_COUNT) {
                ret = at_send_command(at_cmd, NULL);
                if (0 == ret) {
                    break;
                }
                usleep(20);
                count++;
            }
        }
        queue->free_buffer(p);
        if (NULL != at_cmd) {
            free(at_cmd);
            at_cmd = NULL;
        }
        p = q;
    }
    goto again;
out:
    return 0;
}

static int ql_data_fwd_svc_is_queue_empty(struct ql_data_buffer_head *queue)
{
    if (NULL == queue) {
        LOGE("null pointer -> queue\n");
        return 0;
    }

    return ((NULL != queue->head) && (queue->head->prev == queue->head) && (queue->head->next == queue->head));
}

static void ql_data_fwd_svc_lock_queue(struct ql_data_buffer_head *queue)
{
    if (NULL == queue) {
        LOGE("null pointer -> queue\n");
        return;
    }
    pthread_mutex_lock(&queue->mutex);
}

static void ql_data_fwd_svc_unlock_queue(struct ql_data_buffer_head *queue)
{
    if (NULL == queue) {
        LOGE("null pointer -> queue\n");
        return;
    }
    pthread_mutex_unlock(&queue->mutex);
}

static struct ql_data_buffer * ql_data_fwd_svc_alloc_buffer(size_t data_size)
{
    struct ql_data_buffer *ret = NULL;

    if ((0 == data_size) || (data_size > MAX_SINGLE_BUFFER_SIZE)) {
        LOGE("invalid data_size, data_size = %zd\n", data_size);
        return ret;
    }

    ret = (struct ql_data_buffer *)malloc(sizeof(struct ql_data_buffer) + data_size);
    memset(ret, 0, sizeof(struct ql_data_buffer) + data_size);
    ret->size = data_size;

    return ret;
}

static void ql_data_fwd_svc_init_buffer(struct ql_data_buffer *buffer)
{
    if (NULL == buffer) {
        LOGE("null pointer -> buffer\n");
        return;
    }
    buffer->prev = buffer;
    buffer->next = buffer;
}

static void ql_data_fwd_svc_free_buffer(struct ql_data_buffer *buffer)
{
    if (NULL == buffer) {
        LOGE("null pointer -> buffer\n");
        return;
    }

    buffer->prev = buffer;
    buffer->next = buffer;
    free(buffer);
    buffer = NULL;
}

static struct ql_data_buffer * ql_data_fwd_svc_enqueue(struct ql_data_buffer_head *queue, struct ql_data_buffer *buffer)
{
    if (NULL == queue) {
        LOGE("null pointer -> queue\n");
        return NULL;
    }

    if (NULL == buffer) {
        LOGE("null pointer -> buffer\n");
        return NULL;
    }

    if (buffer->size > MAX_SINGLE_BUFFER_SIZE) {
        LOGE("invalid buffer size, buffer->size = %zd\n", buffer->size);
        return NULL;
    }

    queue->lock(queue);
    if ((buffer->size + queue->total_size) > MAX_TOTAL_BUFFER_SZ) {
        queue->unlock(queue);
        LOGE("total size too big\n");
        return NULL;
    }
    buffer->prev = queue->head->prev; //current queue tail
    buffer->next = queue->head; //queue head
    buffer->prev->next = buffer;
    buffer->next->prev = buffer;
    queue->unlock(queue);

    return buffer;
}

static struct ql_data_buffer * ql_data_fwd_svc_dequeue(struct ql_data_buffer_head *queue)
{
    struct ql_data_buffer *ret = NULL;

    if (NULL == queue) {
        LOGE("null pointer -> queue\n");
        return ret;
    }

    if (queue->is_empty(queue)) {
        return ret;
    } else {
        queue->lock(queue);
        ret = queue->head->next;
		queue->head->next = ret->next;
        ret->next->prev = queue->head;
        queue->total_size -= ret->size;
        queue->unlock(queue);
        queue->father->init_buffer(ret);
    }

    return ret;
}

int ql_data_fwd_svc_init_queue(struct ql_data_buffer_queue *queue)
{
    int ret = 0;
    int i = 0;
    int j = 0;
    struct ql_data_buffer_head *phead = NULL;

    LOGD("%s begin\n", __func__);
    if (NULL == queue) {
        LOGE("null pointer -> queue\n");
        ret = -1;
        goto out;
    }

    memset(queue, 0, sizeof(struct ql_data_buffer_queue));
    queue->state = QUEUE_INITING;
    queue->alloc_buffer = ql_data_fwd_svc_alloc_buffer;
    queue->init_buffer = ql_data_fwd_svc_init_buffer;
    queue->free_buffer = ql_data_fwd_svc_free_buffer;
    queue->send_to_app = ql_data_fwd_svc_send_to_app;
    queue->send_to_module = ql_data_fwd_svc_send_to_module;
    queue->toHex = ql_string_to_hex;
    queue->toString = ql_hex_to_string;
    queue->server_fd = -1;
    queue->client_fd = -1;
    //queue->watchdog_on = 1;
    queue->heart_beat_timeout = HEART_BEAT_TIMEOUT_SECONDS;
    pthread_mutex_init(&queue->state_mutex, NULL);

    for (i = 0; i < MAX_QUEUE; i++) {
        phead = &(queue->queue[i]);
        memset(phead, 0, sizeof(struct ql_data_buffer_head));
        phead->head = (struct ql_data_buffer *)malloc(sizeof(struct ql_data_buffer_head));
        if (NULL == phead->head) {
            LOGE("no memory!\n");
            for (j = 0; j < i; j++) {
                free(queue->queue[j].head);
            }
            ret = -1;
            goto out;
        }
        queue->init_buffer(phead->head);
        pthread_mutex_init(&phead->mutex, NULL);
        pthread_mutex_init(&phead->fwd_cond_mutex, NULL);
        pthread_cond_init(&phead->fwd_cond, NULL);
        phead->father = queue;
        phead->kick_sender = ql_data_fwd_svc_kick_sender;
        phead->lock = ql_data_fwd_svc_lock_queue; 
        phead->unlock = ql_data_fwd_svc_unlock_queue; 
        phead->enqueue = ql_data_fwd_svc_enqueue;
        phead->dequeue = ql_data_fwd_svc_dequeue;
        phead->is_empty = ql_data_fwd_svc_is_queue_empty;
    }
    queue->state = QUEUE_INITIALIZED;

out:
    LOGD("%s end, ret = %d\n", __func__, ret);
    return ret;
}

int ql_data_fwd_svc_destroy_queue(struct ql_data_buffer_queue *queue)
{
    int ret = 0;
    int i = 0;
    struct ql_data_buffer *buffer = NULL;
    struct ql_data_buffer_head *phead = NULL;

    LOGD("%s begin\n", __func__);
    if (NULL == queue) {
        LOGE("null pointer -> queue\n");
        ret = -1;
        goto out;
    }

    pthread_mutex_lock(&queue->state_mutex);
    for (i = 0; i < MAX_QUEUE; i++) {
        phead = &(queue->queue[i]);
		if (NULL == phead->head) {
            LOGE("cant get queue head, i = %d\n", i);
            continue;
        }
        while (!(phead->is_empty(phead))) {
            LOGD("queue not empty while destroy\n");
            buffer = phead->dequeue(phead);
            queue->free_buffer(buffer);
        }
        queue->free_buffer(phead->head);
    }

    queue->state = QUEUE_UNINIT;
    pthread_mutex_unlock(&queue->state_mutex);

out:
    LOGD("%s end, ret =  %d\n", __func__, ret);
    return ret;
}
