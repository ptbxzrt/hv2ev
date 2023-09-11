#ifndef HEADR_H_
#define HEADR_H_

#include "hv/hbase.h"
#include "hv/hbuf.h"
#include "hv/hexport.h"
#include "hv/hloop.h"
#include "hv/hsocket.h"
#include <sys/ioctl.h>

#define EV_READ HV_READ
#define EV_WRITE HV_WRITE
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

typedef int evutil_socket_t;
typedef void (*event_callback_fn)(evutil_socket_t fd, short events,
                                  void *callback_arg);

#define BEV_OPT_CLOSE_ON_FREE (1 << 0)
#define BEV_OPT_THREADSAFE (1 << 1)
#define BEV_OPT_DEFER_CALLBACKS (1 << 2)
#define BEV_OPT_UNLOCK_CALLBACKS (1 << 3)

struct event {
  struct event_base *base;

  hio_t *io;
  int fd;
  short events;

  event_callback_fn callback;
  void *callback_arg;

  htimer_t *timer;
  int timeout;
};

struct event_base {
  hloop_t *loop;
  htimer_t *timer;
  int timeout;
};

#define EVBUFFER_REFERENCE 0x0004
#define EVBUFFER_IMMUTABLE 0x0008
typedef void (*evbuffer_ref_cleanup_cb)(const void *data, size_t datalen,
                                        void *extra);
struct evbuffer_chain {
  hbuf_t buf;
  size_t misalign;
  size_t off;
  evbuffer_chain *next;
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

typedef void (*evconnlistener_cb)(struct evconnlistener *, evutil_socket_t,
                                  struct sockaddr *, int socklen, void *);
typedef void (*evconnlistener_errorcb)(struct evconnlistener *, void *);

struct evconnlistener_event;

struct evconnlistener {
  evconnlistener_event *lev_e;
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

#define LEV_OPT_LEAVE_SOCKETS_BLOCKING (1u << 0)
#define LEV_OPT_CLOSE_ON_FREE (1u << 1)
#define LEV_OPT_CLOSE_ON_EXEC (1u << 2)
#define LEV_OPT_REUSEABLE (1u << 3)
#define LEV_OPT_THREADSAFE (1u << 4)
#define LEV_OPT_DISABLED (1u << 5)
#define LEV_OPT_DEFERRED_ACCEPT (1u << 6)
#define LEV_OPT_REUSEABLE_PORT (1u << 7)
#define LEV_OPT_BIND_IPV6ONLY (1u << 8)

void event_active(struct event *ev, int res, short ncalls);
int bufferevent_disable(struct bufferevent *bufev, short event);
void evbuffer_chain_free(struct evbuffer_chain *chain);

#endif