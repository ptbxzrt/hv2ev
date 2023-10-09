#ifndef HV_2_EV_H_
#define HV_2_EV_H_

#include "hv/hbase.h"
#include "hv/hbuf.h"
#include "hv/hexport.h"
#include "hv/hloop.h"
#include "hv/hsocket.h"
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

#define evutil_socket_t int
#define EV_READ HV_READ
#define EV_WRITE HV_WRITE
#define EV_SIGNAL 0x08
#define EV_PERSIST 0x0010
#define EV_TIMEOUT 0x0020
#define evutil_make_socket_nonblocking(s) nonblocking((s))
#define evutil_closesocket(s) SAFE_CLOSESOCKET((s))
#define evutil_socketpair(family, type, protocol, pair)                        \
  Socketpair((family), (type), (protocol), (pair))
#define EVUTIL_SHUT_WR SHUT_WR
#define EVUTIL_SHUT_RD SHUT_RD
#define evutil_gettimeofday(tv, tz) gettimeofday((tv), (tz))
#define evtimer_add(ev, tv) event_add((ev), (tv))
#define evtimer_del(ev) event_del(ev)
#define evtimer_new(b, cb, arg) event_new((b), -1, 0, (cb), (arg))
#define evtimer_assign(ev, b, cb, arg)                                         \
  event_assign((ev), (b), -1, 0, (cb), (arg))
#define evtimer_pending(ev, tv) event_pending((ev), EV_TIMEOUT, (tv))
#define evutil_timerclear(tvp) timerclear(tvp)
#define evutil_socket_geterror(sock) (errno)
#define EVUTIL_ERR_CONNECT_RETRIABLE(e) ((e) == EINTR || (e) == EINPROGRESS)
#define EVUTIL_ERR_CONNECT_REFUSED(e) ((e) == ECONNREFUSED)
#define EVUTIL_ERR_RW_RETRIABLE(e) ((e) == EINTR || EVUTIL_ERR_IS_EAGAIN(e))
#define EVUTIL_SET_SOCKET_ERROR(errcode)                                       \
  do {                                                                         \
    errno = (errcode);                                                         \
  } while (0)
#define EVUTIL_ERR_IS_EAGAIN(e) ((e) == EAGAIN)
#define EVUTIL_ERR_ACCEPT_RETRIABLE(e)                                         \
  ((e) == EINTR || EVUTIL_ERR_IS_EAGAIN(e) || (e) == ECONNABORTED)
#define BEV_EVENT_READING 0x01   /**< error encountered while reading */
#define BEV_EVENT_WRITING 0x02   /**< error encountered while writing */
#define BEV_EVENT_EOF 0x10       /**< eof file reached */
#define BEV_EVENT_ERROR 0x20     /**< unrecoverable error encountered */
#define BEV_EVENT_TIMEOUT 0x40   /**< user-specified timeout reached */
#define BEV_EVENT_CONNECTED 0x80 /**< connect operation finished. */
#define EVUTIL_SOCK_CLOEXEC SOCK_CLOEXEC
#define EVUTIL_SOCK_NONBLOCK SOCK_NONBLOCK
#define ev_socklen_t socklen_t
#define MAX_TO_REALIGN_IN_EXPAND 2048
#define evutil_socket_error_to_string(errcode) (strerror(errcode))
#define BEV_OPT_CLOSE_ON_FREE (1 << 0)
#define BEV_OPT_DEFER_CALLBACKS (1 << 2)
#define EVBUFFER_MAX_READ 4096
#define EVBUFFER_REFERENCE 0x0004
#define EVBUFFER_IMMUTABLE 0x0008
#define LEV_OPT_LEAVE_SOCKETS_BLOCKING (1u << 0)
#define LEV_OPT_CLOSE_ON_FREE (1u << 1)
#define LEV_OPT_CLOSE_ON_EXEC (1u << 2)
#define LEV_OPT_REUSEABLE (1u << 3)
#define LEV_OPT_DISABLED (1u << 5)
#define LEV_OPT_DEFERRED_ACCEPT (1u << 6)
#define LEV_OPT_REUSEABLE_PORT (1u << 7)
#define LEV_OPT_BIND_IPV6ONLY (1u << 8)
#define evbuffer_iovec iovec
#define EV_RATE_LIMIT_MAX INT64_MAX
#define COMMON_TIMEOUT_MICROSECONDS_MASK 0x000fffff

struct evconnlistener;
struct bufferevent;
typedef void (*event_callback_fn)(evutil_socket_t fd, short events,
                                  void *callback_arg);
typedef void (*evbuffer_ref_cleanup_cb)(const void *data, size_t datalen,
                                        void *extra);
typedef void (*evconnlistener_cb)(struct evconnlistener *, evutil_socket_t,
                                  struct sockaddr *, int socklen, void *);
typedef void (*evconnlistener_errorcb)(struct evconnlistener *, void *);
typedef void (*bufferevent_data_cb)(struct bufferevent *bev, void *ctx);
typedef void (*bufferevent_event_cb)(struct bufferevent *bev, short what,
                                     void *ctx);

struct queue_node {
  struct queue_node *pre;
  struct queue_node *next;
};

struct event {
  struct event_base *base;

  hio_t *io;
  int fd;
  short events;
  short events_pending;

  event_callback_fn callback;
  void *callback_arg;

  htimer_t *timer;
  int timeout;

  int num_calls;
  struct queue_node self_signal_node;
  struct queue_node self_awaken_signal_node;
};

struct event_base {
  hloop_t *loop;
  htimer_t *timer;
  int timeout;

  int enable_signal;
  struct event signal_monitor;
  int pair[2];
  struct queue_node signal_events_head[NSIG];
  struct queue_node awaken_signal_events_head;
};

struct evbuffer_chain {
  hbuf_t buf;
  size_t misalign;
  size_t off;
  struct evbuffer_chain *next;
  unsigned flags;
  evbuffer_ref_cleanup_cb cleanupfn;
  void *args;
};

struct evbuffer {
  struct evbuffer_chain *first;
  struct evbuffer_chain *last;
  struct evbuffer_chain *last_with_datap;
  size_t total_len;
};

struct evdns_base {
  char useless;
};

struct evconnlistener {
  struct evconnlistener_event *lev_e;
  evconnlistener_cb cb;
  evconnlistener_errorcb errorcb;
  void *user_data;
  unsigned flags;
  int accept4_flags;
  unsigned enabled : 1;
};

struct evconnlistener_event {
  struct evconnlistener base;
  struct event listener;
};

struct bufferevent {
  struct event_base *ev_base;
  struct event ev_read;
  struct event ev_write;
  struct event ev_err;
  struct evbuffer *input;
  struct evbuffer *output;
  bufferevent_data_cb readcb;
  bufferevent_data_cb writecb;
  bufferevent_event_cb errorcb;
  void *cbarg;
  struct timeval timeout_read;
  struct timeval timeout_write;
  short enabled;
  unsigned connecting;
  unsigned connection_refused;
  int options;
};

struct ev_token_bucket_cfg {
  size_t read_rate;
  size_t read_maximum;
  size_t write_rate;
  size_t write_maximum;
  struct timeval tick_timeout;
  unsigned msec_per_tick;
};

int evutil_make_socket_closeonexec(evutil_socket_t fd);

int evutil_inet_pton(int af, const char *src, void *dst);

const char *evutil_inet_ntop(int af, const void *src, char *dst, size_t len);

struct evbuffer *evbuffer_new(void);

void evbuffer_free(struct evbuffer *buffer);

size_t evbuffer_get_length(const struct evbuffer *buffer);

struct evbuffer_chain *evbuffer_chain_new(size_t size);

void evbuffer_chain_free(struct evbuffer_chain *chain);

void evbuffer_chain_insert(struct evbuffer *buf, struct evbuffer_chain *chain);

int evbuffer_add(struct evbuffer *buf, const void *data_in, size_t datalen);

int evbuffer_expand(struct evbuffer *buf, size_t datalen);

int evbuffer_prepend(struct evbuffer *buf, const void *data, size_t datalen);

int evbuffer_drain(struct evbuffer *buf, size_t len);

int evbuffer_add_printf(struct evbuffer *buf, const char *fmt, ...);

int evbuffer_add_buffer(struct evbuffer *dst, struct evbuffer *src);

size_t evbuffer_add_iovec(struct evbuffer *buf, struct evbuffer_iovec *vec,
                          int n_vec);

unsigned char *evbuffer_pullup(struct evbuffer *buf, ssize_t size);

int evbuffer_add_reference(struct evbuffer *buf, const void *data,
                           size_t datalen, evbuffer_ref_cleanup_cb cleanupfn,
                           void *args);

int evbuffer_remove(struct evbuffer *buf, void *data_out, size_t datalen);

static void bufferevent_readcb(evutil_socket_t fd, short event, void *arg);

static void bufferevent_writecb(evutil_socket_t fd, short event, void *arg);

static void bufferevent_errcb(evutil_socket_t fd, short what, void *arg);

struct bufferevent *bufferevent_socket_new(struct event_base *base,
                                           evutil_socket_t fd, int options);

void bufferevent_free(struct bufferevent *bufev);

int bufferevent_write_buffer(struct bufferevent *bufev, struct evbuffer *buf);

int bufferevent_write(struct bufferevent *bufev, const void *data, size_t size);

struct evbuffer *bufferevent_get_input(struct bufferevent *bufev);

struct evbuffer *bufferevent_get_output(struct bufferevent *bufev);

int bufferevent_enable(struct bufferevent *bufev, short event);

int bufferevent_disable(struct bufferevent *bufev, short event);

short bufferevent_get_enabled(struct bufferevent *bufev);

void bufferevent_setcb(struct bufferevent *bufev, bufferevent_data_cb readcb,
                       bufferevent_data_cb writecb,
                       bufferevent_event_cb eventcb, void *cbarg);

int bufferevent_set_timeouts(struct bufferevent *bufev,
                             const struct timeval *tv_read,
                             const struct timeval *tv_write);

int evutil_socket_connect(evutil_socket_t *fd_ptr, const struct sockaddr *sa,
                          int socklen);

int bufferevent_socket_connect(struct bufferevent *bufev,
                               const struct sockaddr *sa, int socklen);
int bufferevent_socket_connect_hostname(struct bufferevent *bev,
                                        struct evdns_base *evdns_base,
                                        int family, const char *hostname,
                                        int port);

struct evconnlistener *evconnlistener_new(struct event_base *base,
                                          evconnlistener_cb cb, void *ptr,
                                          unsigned flags, int backlog,
                                          evutil_socket_t fd);

void evconnlistener_free(struct evconnlistener *lev);

struct evconnlistener *evconnlistener_new_bind(struct event_base *base,
                                               evconnlistener_cb cb, void *ptr,
                                               unsigned flags, int backlog,
                                               const struct sockaddr *sa,
                                               int socklen);

size_t bufferevent_read(struct bufferevent *bufev, void *data, size_t size);

int evconnlistener_enable(struct evconnlistener *lev);

struct event_base *event_base_new(void);

void event_base_free(struct event_base *base);

int event_base_loop(struct event_base *base, int flags);

int event_base_dispatch(struct event_base *base);

int event_base_loopbreak(struct event_base *base);

int event_base_loopexit(struct event_base *base, const struct timeval *tv);

int event_assign(struct event *ev, struct event_base *base, evutil_socket_t fd,
                 short events, event_callback_fn callback, void *callback_arg);

struct event *event_new(struct event_base *base, evutil_socket_t fd,
                        short events, event_callback_fn callback,
                        void *callback_arg);

int event_add(struct event *ev, const struct timeval *tv);

int event_del(struct event *ev);

void event_active(struct event *ev, int res, short ncalls);

int event_pending(const struct event *ev, short events, struct timeval *tv);

void event_free(struct event *ev);

void event_set_mem_functions(void *(*malloc_fn)(size_t sz),
                             void *(*realloc_fn)(void *ptr, size_t sz),
                             void (*free_fn)(void *ptr));

int evbuffer_prepend_buffer(struct evbuffer *dst, struct evbuffer *src);

evutil_socket_t evconnlistener_get_fd(struct evconnlistener *lev);

void ev_token_bucket_cfg_free(struct ev_token_bucket_cfg *cfg);

struct ev_token_bucket_cfg *
ev_token_bucket_cfg_new(size_t read_rate, size_t read_burst, size_t write_rate,
                        size_t write_burst, const struct timeval *tick_len);

#define evsignal_new(b, x, cb, arg)                                            \
  event_new((b), (x), EV_SIGNAL | EV_PERSIST, (cb), (arg))
#define evsignal_add(ev, tv) event_add((ev), (tv))
int event_base_gettimeofday_cached(struct event_base *base, struct timeval *tv);

// TODO_Lists
int bufferevent_set_rate_limit(struct bufferevent *bev,
                               struct ev_token_bucket_cfg *cfg);

#ifdef __cplusplus
}
#endif
#endif