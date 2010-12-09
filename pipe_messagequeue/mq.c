#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <poll.h>
#include <pthread.h>
#include <sys/wait.h>

inline void release_cpu(void)
{
    usleep(1);
}

#define MQ_MAX_RESPONSE_LIFE_TIME_MS 5000
#define MQ_MAX_POLL_TIME_PER_HANDLER_MS 5
#define MQ_MAX_POLL_PKT_PER_HANDLER 50

enum mq_event {
    MQ_EVENT_REQUEST            = (1 << 0),
    MQ_EVENT_REQUEST_NO_ACK     = (1 << 1),
    MQ_EVENT_RESPONSE           = (1 << 2),
    MQ_EVENT_ACK                = (1 << 3),
    MQ_EVENT_EXIT               = (1 << 4),
};

enum mq_state {
    MQ_STATE_STARTING,
    MQ_STATE_RUNNING,
    MQ_STATE_STOPPING,
    MQ_STATE_STOPPED
};

struct mq_list {
    struct mq_list *next;
    struct mq_list *prev;
};

struct mq_data {
    unsigned long len;
    char *data;
} __attribute__((packed));

struct mq_request {
    unsigned char event;
    unsigned long long id;
    unsigned long time;
    struct mq_data data;
} __attribute__((packed));

struct mq_response {
    unsigned char event;
    unsigned long long req_id;
    unsigned long long rsp_id;
    unsigned long time;
    struct mq_data data;
} __attribute__((packed));

struct mq_arrived_response {
    struct mq_list list;
    struct mq_response rsp;
    unsigned long arrived;
};

struct mq_lock {
    pthread_mutex_t lock;

    int users: 31, // usage counter
        available: 1; // whether could be obtained or not
};

struct mq_handler {
    struct mq_list list;
    struct mq_lock lock;

    int pipein[2]; // 0-> read end for obtaining request, 1-> write end for issueing request
    int pipeout[2]; // 0-> read end for obtaining response, 1-> write end for issueing response
    int process; // handler PID

    unsigned long pushed, // amount of pushed requests
        popped; // amount of popped responses
    unsigned nacked; // not acked packets
};

struct mq {
    struct mq_list handlers;
    struct mq_lock lock;

    short state;
    pthread_t rsp_manager;

    struct mq_list rsp_list;
    pthread_mutex_t rsp_lock;
};

typedef unsigned long long mq_cookie;

#define container_of(ptr, type, member)         \
    (type *)((char *)ptr - (unsigned int)(&((type *)0)->member))

#define mq_lock_init(l)                         \
    do {                                        \
        pthread_mutex_init(&(l)->lock, NULL);   \
        (l)->available = (l)->users = 0;        \
    } while (0)

#define mq_lock_deinit(l)                         \
    do {                                          \
        pthread_mutex_destroy(&(l)->lock);        \
    } while (0)


#define mq_lock_lock(l)                         \
    do {                                        \
        pthread_mutex_lock(&(l)->lock);         \
    } while (0)

#define mq_lock_unlock(l)                       \
    do {                                        \
        pthread_mutex_unlock(&(l)->lock);       \
    } while (0)

#define mq_get_users(l)                                          \
    ({                                                           \
        unsigned int v = 0;                                      \
        mq_lock_lock(l);                                         \
        v = (l)->users;                                          \
        mq_lock_unlock(l);                                       \
        v;                                                       \
    })

#define mq_get_available(l)                                      \
    ({                                                           \
        unsigned int v = 0;                                      \
        mq_lock_lock(l);                                         \
        v = (l)->available;                                      \
        mq_lock_unlock(l);                                       \
        v;                                                       \
    })

#define mq_set_available(l, v)                                   \
    ({                                                           \
        mq_lock_lock(l);                                         \
        (l)->available = v;                                      \
        mq_lock_unlock(l);                                       \
    })

#define mq_get(l, type, member)                                  \
    ({                                                           \
            type *_e = container_of(l, type, member),            \
                *__e;                                            \
            mq_lock_lock(l);                                     \
            __e = (!(l)->available)?NULL:(++(l)->users, (_e));   \
            mq_lock_unlock(l);                                   \
            __e;                                                 \
    })

#define mq_put(l)                                            \
    ({                                                       \
        mq_lock_lock(l);                                     \
        --(l)->users;                                        \
        mq_lock_unlock(l);                                   \
    })

#define mq_request(rq, _event_, _id_, _time_, _data_, _len_)            \
    ({                                                                  \
        (rq)->id = (_id_);                                              \
        (rq)->time = (_time_);                                          \
        (rq)->event = (_event_);                                        \
        (rq)->data.len = (_len_);                                       \
        (rq)->data.data = (void *)(_data_);                             \
        (rq);                                                           \
    })

#define mq_request_no_ack(rq, _event_, _id_, _time_, _data_, _len_)     \
    mq_request((rq), (_event_) | MQ_EVENT_REQUEST_NO_ACK, (_id_), (_time_), (_data_), (_len_))


#define mq_response(rsp, rq, _id_, _time_, _data_, _len_)               \
    ({                                                                  \
        (rsp)->event = MQ_EVENT_RESPONSE;                               \
        (rsp)->req_id = (rq)->id;                                       \
        (rsp)->rsp_id = (_id_);                                         \
        (rsp)->time = (_time_);                                         \
        (rsp)->data.len = (_len_);                                      \
        (rsp)->data.data = (void *)(_data_);                            \
        (rsp);                                                          \
    })

#define mq_ack(rsp, rq, _time_)                                         \
    ({                                                                  \
        (rsp)->event = MQ_EVENT_ACK;                                    \
        (rsp)->req_id = (rq)->id;                                       \
        (rsp)->time = (_time_);                                         \
        (rsp)->data.len = 0;                                            \
        (rsp);                                                          \
    })

#define mq_list_empy(head) ((head)->next == (head) && (head)->prev == (head))

#define mq_list_for_each(head, e)                                \
    for ((e)=(head)->next;                                       \
         (e)!=(head);                                            \
         (e)=(e)->next)

#define mq_list_for_each_safe(head, e, t)                        \
    for ((t)=(head)->next->next, (e)=(t)->prev;                  \
         (e)!=(head);                                            \
         (t)=(t)->next, (e)=(t)->prev)

#define mq_list_init(list)                                              \
    do {                                                                \
        (list)->next = (list)->prev = (list);                           \
    } while (0)

#define mq_list_detach(list)                                            \
    do {                                                                \
        (list)->prev->next = (list)->next;                              \
        (list)->next->prev = (list)->prev;                              \
    } while (0)

#define mq_list_add_tail(head, list)                                    \
    do {                                                                \
        (head)->prev->next = (list);                                    \
        (list)->prev = (head)->prev;                                    \
        (head)->prev = (list);                                          \
        (list)->next = (head);                                          \
    } while (0)


#define mq_release_arrived_response(rsp)                                \
    do {                                                                \
        mq_list_detach(&rsp->list);                                     \
        free(rsp);                                                      \
    } while (0)

#define mq_release_response(rsp)                                        \
    do {                                                                \
        struct mq_arrived_response *r;                                  \
        r = container_of(rsp, struct mq_arrived_response, rsp);         \
        free(r);                                                        \
    } while (0)

#define timems()                                \
    ({                                          \
        struct timeval tv;                      \
        gettimeofday(&tv, NULL);                \
        tv.tv_sec*1000 + tv.tv_sec/1000;        \
    })

void
mq_cleanup_response_queue(struct mq *mq,
                          unsigned long now)
{
    struct mq_list *e, *t;
    struct mq_arrived_response *r;
    unsigned int unhandled = 0, total = 0;

    now -= MQ_MAX_RESPONSE_LIFE_TIME_MS;

    if (mq_get(&mq->lock, struct mq, lock)) {
        pthread_mutex_lock(&mq->rsp_lock);
        mq_list_for_each_safe(&mq->rsp_list, e, t) {
            r = container_of(e, struct mq_arrived_response, list);

            ++total;
            if (now > r->arrived) {
                mq_release_arrived_response(r);
                ++unhandled;
            }
        }
        pthread_mutex_unlock(&mq->rsp_lock);

        if (unhandled)
            printf("%-10lu: ## WARN ##  %u unhandled request(%u total in queue)\n",
                   now + MQ_MAX_RESPONSE_LIFE_TIME_MS, unhandled, total), fflush(stdout);

        mq_put(&mq->lock);
    }
}

void
mq_poll(struct mq *mq)
{
    struct mq_arrived_response *r;
    struct pollfd p = {-1, POLLIN, };

    struct mq_list *e;
    struct mq_handler *handler;

    if (mq_get(&mq->lock, struct mq, lock)) {
        mq_lock_lock(&mq->lock);
        mq_list_for_each(&mq->handlers, e) {
            handler = container_of(e, struct mq_handler, list);
            if (mq_get(&handler->lock, struct mq_handler, lock)) {
                unsigned long now = timems();
                int batch = MQ_MAX_POLL_PKT_PER_HANDLER;

                mq_lock_unlock(&mq->lock);

                p.fd = handler->pipeout[0];

                while (batch && (now + MQ_MAX_POLL_TIME_PER_HANDLER_MS) >= timems()) {
                    if (!mq_get_available(&handler->lock))
                        break;

                    switch (poll(&p, 1, MQ_MAX_POLL_TIME_PER_HANDLER_MS/MQ_MAX_POLL_PKT_PER_HANDLER/2)) {
                        case 1:
                            if (p.revents == POLLIN) {
                                struct mq_response rsp;
                                read(handler->pipeout[0], &rsp, sizeof(struct mq_response));
                                if (rsp.event & MQ_EVENT_ACK) {
                                    mq_lock_lock(&handler->lock);
                                    --handler->nacked;
                                    mq_lock_unlock(&handler->lock);
                                }
                                if (rsp.event & ~MQ_EVENT_ACK) {
                                    r = malloc(sizeof(struct mq_arrived_response) +
                                               rsp.data.len);
                                    if (!r) {
                                        printf("mq_poll: not enough memory(%lu bytes)\n",
                                               sizeof(struct mq_arrived_response) +
                                               rsp.data.len); ///< FIXME: handle pending data

                                        break;
                                    }
                                    r->rsp = rsp;

                                    if (rsp.data.len) {
                                        r->rsp.data.data = (char *)r +
                                            sizeof(struct mq_arrived_response);
                                        read(handler->pipeout[0], r->rsp.data.data, rsp.data.len);
                                    } else {
                                        r->rsp.data.data = NULL;
                                    }
                                    r->arrived = timems();

                                    pthread_mutex_lock(&mq->rsp_lock);
                                    mq_list_add_tail(&mq->rsp_list, &r->list);
                                    pthread_mutex_unlock(&mq->rsp_lock);

                                    mq_lock_lock(&handler->lock);
                                    ++handler->popped;
                                    mq_lock_unlock(&handler->lock);
                                }
                                --batch;
                            }
                            break;
                    }
                }

                mq_put(&handler->lock);
                mq_lock_lock(&mq->lock);
            }
        }
        mq_lock_unlock(&mq->lock);

        mq_put(&mq->lock);
    }
}

void *
mq_poll_wrapper(void *data)
{
    struct mq *mq = (struct mq *)data;

    unsigned int last_cleaned = timems(), now;

    for (;;) {
        mq_lock_lock(&mq->lock);
        if (mq->state == MQ_STATE_STOPPING) {
            mq_lock_unlock(&mq->lock);

            return NULL;
        } else if (mq->state == MQ_STATE_STARTING) {
            mq_lock_unlock(&mq->lock);

            release_cpu();

            continue;
        }

        mq_lock_unlock(&mq->lock);

        mq_poll(mq);

        now = timems();
        if (now - last_cleaned > MQ_MAX_RESPONSE_LIFE_TIME_MS) {
            last_cleaned = now;

            mq_cleanup_response_queue(mq, now);
        }
    }

    return NULL;
}

void
mq_join_handler(struct mq_handler *handler)
{
    waitpid(handler->process, NULL, 0);

    mq_list_detach(&handler->list);

    close(handler->pipeout[0]);
    close(handler->pipeout[1]);
    close(handler->pipein[0]);
    close(handler->pipein[1]);

    printf("handler %d: %lu pushed requests, %lu popped responses\n",
           handler->process, handler->pushed, handler->popped), fflush(stdout);

    mq_lock_deinit(&handler->lock);
}

void
mq_init(struct mq *mq)
{
    mq_list_init(&mq->handlers);
    mq_list_init(&mq->rsp_list);

    mq_lock_init(&mq->lock);

    pthread_mutex_init(&mq->rsp_lock, NULL);

    mq->state = MQ_STATE_STARTING;

    pthread_create(&mq->rsp_manager, NULL, mq_poll_wrapper, mq);

    mq->state = MQ_STATE_RUNNING;
    mq_set_available(&mq->lock, 1);
}

void
mq_deinit(struct mq *mq)
{
    struct mq_list *e, *t;
    struct mq_handler *handler;
    struct mq_arrived_response *r;
    unsigned int unhandled = 0;

    mq_set_available(&mq->lock, 0);

    mq_lock_lock(&mq->lock);
    mq_list_for_each_safe(&mq->handlers, e, t) {
        handler = container_of(e, struct mq_handler, list);

        mq_set_available(&handler->lock, 0);

        while (mq_get_users(&handler->lock)) { // FIXME: don't busy loop
            mq_lock_unlock(&mq->lock);
            release_cpu();
            mq_lock_lock(&mq->lock);
        }

        mq_join_handler(handler);
    }
    mq->state = MQ_STATE_STOPPING;

    mq_lock_unlock(&mq->lock);
    while (mq_get_users(&mq->lock)) { // FIXME: don't busy loop
        release_cpu();
    }
    mq_lock_lock(&mq->lock);

    pthread_mutex_lock(&mq->rsp_lock);
    mq_list_for_each_safe(&mq->rsp_list, e, t) {
        r = container_of(e, struct mq_arrived_response, list);
        mq_release_arrived_response(r);
        ++unhandled;
    }
    pthread_mutex_unlock(&mq->rsp_lock);

    if (unhandled)
        printf("## WARN ## %u unhandled responses in handler\n", unhandled), fflush(stdout);

    mq_lock_unlock(&mq->lock);

    pthread_join(mq->rsp_manager, (void **)NULL);

    pthread_mutex_destroy(&mq->rsp_lock);

    mq->state = MQ_STATE_STOPPED;
}

int
launch_process(void (*f)(int endpoints[2]),
               int endpoints[2])
{
    int pid;

    switch (pid = fork()) {
        case 0:
            f(endpoints);
            break;

        case -1:
            perror("fork");

        default:
            return pid;
    }

    exit(0);
}

int
mq_launch_handler(struct mq *mq,
                  struct mq_handler *handler,
                  void (*f)(int endpoints[2]))
{
    int endpoints[2];

    if (pipe(handler->pipein) == -1) {
        perror("pipe");

        goto fail_pipein;
    }
    if (pipe(handler->pipeout) == -1) {
        perror("pipe");

        goto fail_pipeout;
    }

    endpoints[0] = handler->pipein[0];
    endpoints[1] = handler->pipeout[1];

    if ((handler->process = launch_process(f, endpoints)) == -1)
        goto fail_launch;

    mq_lock_init(&handler->lock);

    handler->nacked = handler->popped = handler->pushed = 0;

    mq_lock_lock(&mq->lock);
    mq_list_add_tail(&mq->handlers, &handler->list);
    mq_lock_unlock(&mq->lock);

    mq_set_available(&handler->lock, 1);

    return 0;

  fail_launch:
    close(handler->pipeout[0]);
    close(handler->pipeout[1]);
  fail_pipeout:
    close(handler->pipein[0]);
    close(handler->pipein[1]);
  fail_pipein:

    return -1;
}

struct mq_response *
mq_get_response(struct mq *mq,
                mq_cookie cookie)
{
    struct mq_list *e, *t;
    struct mq_arrived_response *r;
    struct mq_response *rsp = NULL;

    if (mq_get(&mq->lock, struct mq, lock)) {
        pthread_mutex_lock(&mq->rsp_lock);
        mq_list_for_each_safe(&mq->rsp_list, e, t) {
            r = container_of(e, struct mq_arrived_response, list);

            if (r->rsp.req_id == cookie) {
                mq_list_detach(&r->list);

                rsp = &r->rsp;

                break;
            }
        }
        pthread_mutex_unlock(&mq->rsp_lock);

        mq_put(&mq->lock);
    }

    return rsp;
}

mq_cookie
mq_enqueue_request(struct mq *mq,
                   struct mq_request *req,
                   int broadcast)
{
    struct mq_list *e;
    struct mq_handler *handler;
    mq_cookie cookie = req->id;
    struct pollfd p = {-1, POLLOUT, };

    if (broadcast) {
        mq_lock_lock(&mq->lock);
        mq_list_for_each(&mq->handlers, e) {
            handler = container_of(e, struct mq_handler, list);

            if (mq_get(&handler->lock, struct mq_handler, lock)) {
                mq_lock_unlock(&mq->lock);

                p.fd = handler->pipein[1];

              retry:
                switch (poll(&p, 1, 0)) {
                    case 1:
                        if (p.revents == POLLOUT) {
                            write(handler->pipein[1], req, sizeof(struct mq_request));
                            if (req->data.len)
                                write(handler->pipein[1], req->data.data, req->data.len);

                            mq_lock_lock(&handler->lock);
                            ++handler->pushed;
                            if (!(req->event & MQ_EVENT_REQUEST_NO_ACK)) {
                                ++handler->nacked;
                            }
                            mq_lock_unlock(&handler->lock);

                            break;
                        } // else => fallthrough

                    default:
                        goto retry;
                }

                mq_lock_lock(&mq->lock);
                mq_put(&handler->lock);
            }
        }
        mq_lock_unlock(&mq->lock);
    } else {
        struct mq_handler *h;
      find_handler:
        h = NULL;

        mq_lock_lock(&mq->lock);
        mq_list_for_each(&mq->handlers, e) {
            handler = container_of(e, struct mq_handler, list);

            if (mq_get(&handler->lock, struct mq_handler, lock)) {
                mq_lock_lock(&handler->lock);

                if (h) {
                    if (handler->nacked < h->nacked)
                        h = handler;
                } else {
                    h = handler;
                }

                mq_lock_unlock(&handler->lock);
                mq_put(&handler->lock);
            }
        }
        mq_lock_unlock(&mq->lock);

        if (mq_get(&h->lock, struct mq_handler, lock)) {
            p.fd = h->pipein[1];
            switch (poll(&p, 1, 0)) {
                case 1:
                    if (p.revents == POLLOUT) {
                        write(h->pipein[1], req, sizeof(struct mq_request));
                        if (req->data.len)
                            write(h->pipein[1], req->data.data, req->data.len);

                        mq_lock_lock(&h->lock);
                        ++h->pushed;
                        if (!(req->event & MQ_EVENT_REQUEST_NO_ACK)) {
                            ++h->nacked;
                        }
                        mq_lock_unlock(&h->lock);

                        break;
                    } // else => fallthrough

                default:
                    mq_put(&h->lock);
                    goto find_handler;
            }
            mq_put(&h->lock);
        }
    }

    return cookie;
}

void
mq_send_response(struct mq_response *rsp,
                 int endpoints[2])
{
    write(endpoints[1], rsp, sizeof(struct mq_response));
    if (rsp->data.len)
        write(endpoints[1], rsp->data.data, rsp->data.len);
}

unsigned long
mq_get_request(struct mq_request *req,
               int endpoints[2])
{
    read(endpoints[0], req, sizeof(struct mq_request));

    if (req->data.len) {
        req->data.data = malloc(req->data.len);
        if (!req->data.data) {
            printf("not enough memory"); /// FIXME: handle pending data

            return 0;
        }
        read(endpoints[0], req->data.data, req->data.len);
    } else {
        req->data.data = NULL;
    }

    return req->data.len;
}

void
mq_send_response_free_request(struct mq_request *req,
                              struct mq_response *rsp,
                              int endpoints[2])
{
    if (req->data.data)
        free(req->data.data);

    if (!(req->event & MQ_EVENT_REQUEST_NO_ACK))
        rsp->event |= MQ_EVENT_ACK;

    mq_send_response(rsp, endpoints);
}

void
mq_free_request(struct mq_request *req,
                int endpoints[2])
{
    if (req->data.data)
        free(req->data.data);

    if (!(req->event & MQ_EVENT_REQUEST_NO_ACK)) {
        struct mq_response rsp;
        mq_send_response(mq_ack(&rsp,
                                req,
                                timems()),
                         endpoints);
    }
}

void
handler(int endpoints[2])
{
    struct mq_request req;
    struct mq_response rsp;
    unsigned int served = 0, id = 0;
    unsigned int pid = getpid();

    printf("Event Handler %u\n", pid);

    for (;;) {
        mq_get_request(&req, endpoints);

        ++served;

        if (req.event & MQ_EVENT_EXIT) {
                printf("Event Handler %u: exiting, request %u:%u, served %u\n", pid, (unsigned int)(req.id >> 32), (unsigned int)(req.id & 0xffffffff), served);
                mq_free_request(&req, endpoints);
                return;
        } else if (req.event & MQ_EVENT_REQUEST) {
            if (req.data.len) {
                printf("Event Handler %u: request %u:%u, %s\n", pid, (unsigned int)(req.id >> 32), (unsigned int)(req.id & 0xffffffff), (char *)req.data.data);
            }

            mq_send_response_free_request(&req,
                                          mq_response(&rsp,
                                                      &req,
                                                      ((unsigned long long)pid << 32) | id++,
                                                      timems(),
                                                      &pid,
                                                      4),
                                          endpoints);
        } else {
            printf("Event Handler %u: unknown event: %d", pid, (int)req.event);
            mq_free_request(&req, endpoints);
        }
    }
}

#define HANDLERS 3
struct mq mq;
struct mq_handler handlers[HANDLERS];

int main(int argc, char **argv)
{
    int i;

    unsigned int pid = getpid();
    unsigned int id = 0;

    struct mq_request req;
    struct mq_response *rsp;

    struct mq_cookie_list {
        struct mq_list list;
        mq_cookie cookie;
    } cookies;

    mq_init(&mq);

    mq_list_init(&cookies.list);

    for (i=0;i<HANDLERS;++i)
        if (mq_launch_handler(&mq, &handlers[i], handler) != 0) {
            fprintf(stderr, "Failed to launch handler\n");
            goto out;
        }

    const char *data = "CHECK";
    mq_cookie cookie = mq_enqueue_request(&mq,
                                          mq_request(&req,
                                                     MQ_EVENT_REQUEST,
                                                     ((unsigned long long)pid << 32) | id,
                                                     timems(),
                                                     data,
                                                     strlen(data)),
                                          1); /// broadcast

    for (i=0;i<HANDLERS;++i) {
        struct mq_cookie_list *entry = malloc(sizeof(struct mq_cookie_list));
        entry->cookie = cookie;
        mq_list_add_tail(&cookies.list, &entry->list);
    }

    for (;id<10000;++id) {
        struct mq_list *e, *t;
        struct mq_cookie_list *entry;
        mq_cookie cookie = mq_enqueue_request(&mq,
                                              mq_request(&req,
                                                         MQ_EVENT_REQUEST,
                                                         ((unsigned long long)pid << 32) | id,
                                                         timems(),
                                                         "",
                                                         0),
                                              0);

        mq_list_for_each_safe(&cookies.list, e, t) {
            entry = container_of(e, struct mq_cookie_list, list);

            if ((rsp = mq_get_response(&mq, entry->cookie))) {
                mq_release_response(rsp);
                mq_list_detach(&entry->list);
                free(entry);
            }
        }

        if ((rsp = mq_get_response(&mq, cookie))) {
            mq_release_response(rsp);
        } else {
            struct mq_cookie_list *entry = malloc(sizeof(struct mq_cookie_list));
            entry->cookie = cookie;
            mq_list_add_tail(&cookies.list, &entry->list);
        }
    }

    while (!mq_list_empy(&cookies.list)) {
        struct mq_list *e, *t;
        struct mq_cookie_list *entry;

        mq_list_for_each_safe(&cookies.list, e, t) {
            entry = container_of(e, struct mq_cookie_list, list);

            if ((rsp = mq_get_response(&mq, entry->cookie))) {
                mq_release_response(rsp);
                mq_list_detach(&entry->list);
                free(entry);
            }
        }
    }

  out:
    mq_enqueue_request(&mq,
                      mq_request_no_ack(&req,
                                        MQ_EVENT_EXIT,
                                        ((unsigned long long)pid << 32),
                                        timems(),
                                        "",
                                        0),
                      1);

    mq_deinit(&mq);

    return 0;
}
