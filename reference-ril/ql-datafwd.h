#ifndef __QL_DATA_FWD_H__
#define __QL_DATA_FWD_H__

#include <pthread.h>
#include <time.h>

#define MAX_TOTAL_BUFFER_SZ (1024*1024)
#define MAX_SINGLE_BUFFER_SIZE (499)
#define HEART_BEAT_TIMEOUT_SECONDS (5)

typedef enum {
    QUEUE_TO_APP,
    QUEUE_TO_MODULE,
    MAX_QUEUE,
} fwd_queue_t;

typedef enum {
    QUEUE_UNINIT,
    QUEUE_INITING,
    QUEUE_INITIALIZED,
} queue_state_t;

struct ql_data_buffer {
    struct ql_data_buffer *prev;
    struct ql_data_buffer *next;
    size_t size;
    char data[0];
};

struct ql_data_buffer_queue;
struct ql_data_buffer_head {
    struct ql_data_buffer *head;
    struct ql_data_buffer_queue *father;
    pthread_mutex_t mutex;
    pthread_cond_t fwd_cond;
    pthread_mutex_t fwd_cond_mutex;
    pthread_t sender_thread;
    size_t total_size;
    fwd_queue_t type;
    int sent_count;
    int enqueue_count;
    void (*kick_sender)(struct ql_data_buffer_head *);
    void (*lock)(struct ql_data_buffer_head *);
    void (*unlock)(struct ql_data_buffer_head *);
    int (*is_empty)(struct ql_data_buffer_head *);
    struct ql_data_buffer * (*enqueue)(struct ql_data_buffer_head *, struct ql_data_buffer *);
    struct ql_data_buffer * (*dequeue)(struct ql_data_buffer_head *);
};

struct ql_data_buffer_queue {
    struct ql_data_buffer_head queue[MAX_QUEUE];
    queue_state_t state;
    pthread_mutex_t state_mutex;
    int server_fd;
    int client_fd;
    int server_alive;
    int client_alive;
    int watchdog_on;
    time_t heart_beat;
    time_t heart_beat_timeout;
    char *(*toHex)(const char *src, char *dst);
    char *(*toString)(const char *src, char *dst, size_t len);
    int (*send_to_app)(struct ql_data_buffer_queue *);
    int (*send_to_module)(struct ql_data_buffer_queue *);
    struct ql_data_buffer * (*alloc_buffer)(size_t data_size);
    void (*init_buffer)(struct ql_data_buffer *);
    void (*free_buffer)(struct ql_data_buffer *);
};

#define PDU_MAGIC "RILFWD"
#define MAGIC_SIZE 6 //RILFWD
enum {
    PDU_TYPE_CONTROL,
    PDU_TYPE_HEART_BEAT,
    PDU_TYPE_BYE_BYE,
    PDU_TYPE_DATA,
};
struct ql_fwd_pdu {
    char magic[MAGIC_SIZE + 1];
    int type;
    size_t size;
} __attribute__((packed));

int ql_data_fwd_svc_init_queue(struct ql_data_buffer_queue *queue);
int ql_data_fwd_svc_destroy_queue(struct ql_data_buffer_queue *queue);

#endif
