#ifndef HV_2_EV_H_
#define HV_2_EV_H_

#include "hv/hbase.h"
#include "hv/hbuf.h"
#include "hv/hexport.h"
#include "hv/hloop.h"
#include "hv/hsocket.h"

#define EV_READ HV_READ
#define EV_WRITE HV_WRITE
#define EV_PERSIST 0x0010
#define EV_TIMEOUT 0x0020

typedef int evutil_socket_t;
typedef void (*event_callback_fn)(evutil_socket_t fd, short events,
                                  void *callback_arg);

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

struct evbuffer_chain {
  hbuf_t buf;
  size_t misalign;
  size_t off;
  evbuffer_chain *next;
};

struct evbuffer {
  struct evbuffer_chain *first;
  struct evbuffer_chain *last;
  struct evbuffer_chain *last_with_datap;
  size_t total_len;
};

struct evbuffer *evbuffer_new(void) {
  struct evbuffer *buffer = NULL;
  HV_ALLOC(buffer, sizeof(struct evbuffer));
  buffer->total_len = 0;
  buffer->first = NULL;
  buffer->last = NULL;
  buffer->last_with_datap = buffer->first;
  return buffer;
}

void evbuffer_free(struct evbuffer *buffer) {
  if (buffer == NULL) {
    return;
  }
  struct evbuffer_chain *p = buffer->first;
  while (p != NULL) {
    struct evbuffer_chain *next = p->next;
    HV_FREE(p->buf.base);
    HV_FREE(p);
    p = next;
  }
  HV_FREE(buffer);
}

size_t evbuffer_get_length(const struct evbuffer *buffer) {
  return buffer->total_len;
}

struct evbuffer_chain *evbuffer_chain_new(size_t size) {
  size_t to_alloc = 1024;
  while (to_alloc < size) {
    to_alloc <<= 1;
  }
  to_alloc <<= 1;
  struct evbuffer_chain *chain = NULL;
  HV_ALLOC(chain, sizeof(struct evbuffer_chain));
  HV_ALLOC(chain->buf.base, to_alloc);
  chain->buf.len = to_alloc;
  chain->misalign = 0;
  chain->off = 0;
  chain->next = NULL;
  return chain;
}

void evbuffer_chain_free(struct evbuffer_chain *chain) {
  HV_FREE(chain->buf.base);
  HV_FREE(chain);
}

void evbuffer_chain_insert(struct evbuffer *buf, struct evbuffer_chain *chain) {
  if (buf->last == NULL) {
    buf->first = chain;
    buf->last = chain;
  } else {
    buf->last->next = chain;
    buf->last = chain;
  }
}

int evbuffer_add(struct evbuffer *buf, const void *data_in, size_t datalen) {
  struct evbuffer_chain *chain = buf->last_with_datap;

  if (chain == NULL) {
    chain = evbuffer_chain_new(datalen);
    if (chain == NULL) {
      return -1;
    }
    evbuffer_chain_insert(buf, chain);
    memcpy(chain->buf.base + chain->misalign + chain->off, data_in, datalen);
    chain->off += datalen;
    buf->last_with_datap = chain;
  } else {
    size_t free_space = chain->buf.len - chain->misalign - chain->off;
    if (free_space >= datalen) {
      memcpy(chain->buf.base + chain->misalign + chain->off, data_in, datalen);
      chain->off += datalen;
    } else {
      size_t left_datalen = datalen - free_space;
      char *left_data = (char *)data_in + free_space;
      struct evbuffer_chain *new_chain = evbuffer_chain_new(left_datalen);
      if (new_chain == NULL) {
        return -1;
      }
      memcpy(chain->buf.base + chain->misalign + chain->off, data_in,
             free_space);
      chain->off += free_space;
      evbuffer_chain_insert(buf, new_chain);
      memcpy(new_chain->buf.base + new_chain->misalign + new_chain->off,
             left_data, left_datalen);
      new_chain->off += left_datalen;
      buf->last_with_datap = new_chain;
    }
  }
  buf->total_len += datalen;
  return 0;
}

int evbuffer_expand(struct evbuffer *buf, size_t datalen) {
  struct evbuffer_chain *chain = buf->last_with_datap;

  if (chain == NULL) {
    chain = evbuffer_chain_new(datalen);
    if (chain == NULL) {
      return -1;
    }
    evbuffer_chain_insert(buf, chain);
    // 注意：如果有chain，但没有数据，last_with_datap也应该指向first
    buf->last_with_datap = chain;
  } else {
    int total_free_space = 0;
    struct evbuffer_chain *p = chain;
    while (p != NULL) {
      total_free_space += (p->buf.len - p->misalign - p->off);
      p = p->next;
    }
    if (total_free_space < datalen) {
      struct evbuffer_chain *new_chain =
          evbuffer_chain_new(datalen - total_free_space);
      if (new_chain == NULL) {
        return -1;
      }
      evbuffer_chain_insert(buf, new_chain);
    }
  }
  return 0;
}

int evbuffer_prepend(struct evbuffer *buf, const void *data, size_t datalen) {
  struct evbuffer_chain *chain = buf->first;

  if (chain == NULL) {
    chain = evbuffer_chain_new(datalen);
    if (chain == NULL) {
      return -1;
    }
    evbuffer_chain_insert(buf, chain);
    // 注意：如果有chain，但没有数据，last_with_datap也应该指向first
    buf->last_with_datap = chain;
  }

  if (chain->off == 0) {
    chain->misalign = chain->buf.len;
  }
  if (chain->misalign >= datalen) {
    memcpy(chain->buf.base + chain->misalign - datalen, data, datalen);
    chain->misalign -= datalen;
    chain->off += datalen;
  } else {
    size_t free_space = chain->misalign;
    memcpy(chain->buf.base, (char *)data + datalen - free_space, free_space);
    chain->misalign -= free_space;
    chain->off += free_space;

    size_t left_datalen = datalen - free_space;
    struct evbuffer_chain *new_chain = evbuffer_chain_new(left_datalen);
    if (new_chain == NULL) {
      return -1;
    }
    buf->first = new_chain;
    new_chain->next = chain;
    new_chain->misalign = new_chain->buf.len - left_datalen;
    new_chain->off = left_datalen;
    memcpy(new_chain->buf.base + new_chain->misalign, data, left_datalen);
  }
  buf->total_len += datalen;
  return 0;
}

int evbuffer_drain(struct evbuffer *buf, size_t len) {
  int buf_data_len = buf->total_len;
  struct evbuffer_chain *chain, *next;
  if (buf_data_len <= len) {
    for (chain = buf->first; chain != NULL; chain = next) {
      next = chain->next;
      evbuffer_chain_free(chain);
    }
    buf->total_len = 0;
    buf->first = NULL;
    buf->last = NULL;
    buf->last_with_datap = buf->first;
  } else {
    buf->total_len -= len;
    size_t remain_to_delete = len;
    for (chain = buf->first; remain_to_delete >= chain->off; chain = next) {
      next = chain->next;
      remain_to_delete -= chain->off;
      evbuffer_chain_free(chain);
    }
    buf->first = chain;
    chain->misalign += remain_to_delete;
    chain->off -= remain_to_delete;
  }
  return 0;
}

int evbuffer_add_printf(struct evbuffer *buf, const char *fmt, ...) {
  char str[1024];

  va_list args;
  va_start(args, fmt);
  sprintf(str, fmt, args);
  va_end(args);

  evbuffer_add(buf, str, strlen(str));
  return 0;
}

int evbuffer_add_buffer(struct evbuffer *dst, struct evbuffer *src) {
  if (dst == src || src->total_len == 0) {
    return 0;
  }
  struct evbuffer_chain *dst_last_datap = dst->last_with_datap;
  struct evbuffer_chain *src_last_datap = src->last_with_datap;

  struct evbuffer_chain *dst_first_no_datap = dst_last_datap->next;
  struct evbuffer_chain *src_first_no_datap = src_last_datap->next;

  dst_last_datap->next = src->first;
  src_last_datap->next = dst_first_no_datap;
  dst->last_with_datap = src_last_datap;

  src->first = src_first_no_datap;
  src->last_with_datap = src_first_no_datap;

  dst->total_len += src->total_len;
  src->total_len = 0;
  return 0;
}

#define evbuffer_iovec iovec

size_t evbuffer_add_iovec(struct evbuffer *buf, struct evbuffer_iovec *vec,
                          int n_vec) {
  int n;
  size_t res = 0;
  size_t to_alloc = 0;
  for (n = 0; n < n_vec; n++) {
    to_alloc += vec[n].iov_len;
  }
  evbuffer_expand(buf, to_alloc);
  for (n = 0; n < n_vec; n++) {

    if (evbuffer_add(buf, vec[n].iov_base, vec[n].iov_len) < 0) {
      return res;
    }

    res += vec[n].iov_len;
  }
  return res;
}

HV_INLINE struct event_base *event_base_new(void) {
  struct event_base *base = NULL;
  HV_ALLOC(base, sizeof(struct event_base));
  base->loop = hloop_new(HLOOP_FLAG_QUIT_WHEN_NO_ACTIVE_EVENTS);
  base->timer = NULL;
  return base;
}

HV_INLINE void event_base_free(struct event_base *base) {
  if (base->timer != NULL) {
    htimer_del(base->timer);
    base->timer = NULL;
  }
  if (base->loop != NULL) {
    hloop_free(&(base->loop));
    base->loop = NULL;
  }
  HV_FREE(base);
}

HV_INLINE int event_base_loop(struct event_base *base, int flags) {
  return hloop_run(base->loop);
}

HV_INLINE int event_base_dispatch(struct event_base *base) {
  return event_base_loop(base, 0);
}

HV_INLINE int event_base_loopbreak(struct event_base *base) {
  return hloop_stop(base->loop);
}

HV_INLINE int timeval_to_ms(const struct timeval *tv) {
  return (tv->tv_sec * 1000) + (tv->tv_usec / 1000);
}

HV_INLINE void on_loopexit_timeout(htimer_t *timer) {
  hloop_stop(hevent_loop(timer));
}

HV_INLINE void on_loopexit_directly(hevent_t *hevent) {
  hloop_stop(hevent_loop(hevent));
}

HV_INLINE int event_base_loopexit(struct event_base *base,
                                  const struct timeval *tv) {
  if (tv != NULL) {
    int timeout = timeval_to_ms(tv);
    base->timer =
        htimer_add(base->loop, on_loopexit_timeout, timeout, INFINITE);
    if (base->timer == NULL) {
      return -1;
    }
    base->timeout = timeout;
  } else {
    hevent_t hev;
    memset(&hev, 0, sizeof(hev));
    hev.cb = on_loopexit_directly;
    hloop_post_event(base->loop, &hev);
  }
  return 0;
}

HV_INLINE void on_readable(hio_t *io) {
  struct event *ev = (struct event *)hevent_userdata(io);
  int fd = hio_fd(io);
  short events = ev->events;

  if (!(events & EV_PERSIST)) {
    hio_del(io, EV_READ);
    if (ev->timer != NULL) {
      htimer_del(ev->timer);
    }
  }

  event_callback_fn callback = ev->callback;
  void *callback_arg = ev->callback_arg;
  if (callback) {
    callback(fd, EV_READ, callback_arg);
  }

  if ((ev->timer != NULL) && (events & EV_PERSIST)) {
    htimer_reset(ev->timer, ev->timeout);
  }
}

HV_INLINE void on_writable(hio_t *io) {
  struct event *ev = (struct event *)hevent_userdata(io);
  int fd = hio_fd(io);
  short events = ev->events;

  if (!(events & EV_PERSIST)) {
    hio_del(io, EV_WRITE);
    if (ev->timer != NULL) {
      htimer_del(ev->timer);
    }
  }

  event_callback_fn callback = ev->callback;
  void *callback_arg = ev->callback_arg;
  if (callback) {
    callback(fd, EV_WRITE, callback_arg);
  }

  if ((ev->timer != NULL) && (events & EV_PERSIST)) {
    htimer_reset(ev->timer, ev->timeout);
  }
}

int event_del(struct event *ev);

HV_INLINE void on_timeout(htimer_t *timer) {
  struct event *ev = (struct event *)hevent_userdata(timer);
  short events = ev->events;

  if (!(events & EV_PERSIST)) {
    event_del(ev);
    if (ev->timer != NULL) {
      htimer_del(ev->timer);
    }
  }

  event_callback_fn callback = ev->callback;
  void *callback_arg = ev->callback_arg;
  if (callback) {
    callback(ev->fd, EV_TIMEOUT, callback_arg);
  }

  if ((ev->timer != NULL) && (events & EV_PERSIST)) {
    htimer_reset(ev->timer, ev->timeout);
  }
}

HV_INLINE void on_active(hevent_t *hev) {
  struct event *ev = (struct event *)hevent_userdata(hev);
  int active_events = (intptr_t)hev->privdata;
  event_callback_fn callback = ev->callback;
  void *callback_arg = ev->callback_arg;
  if (callback) {
    callback(ev->fd, active_events, callback_arg);
  }

  if (ev->timer != NULL) {
    htimer_reset(ev->timer, ev->timeout);
  }
}

int event_assign(struct event *ev, struct event_base *base, evutil_socket_t fd,
                 short events, event_callback_fn callback, void *callback_arg) {
  if (ev == NULL) {
    return -1;
  }
  ev->io = NULL;
  ev->timer = NULL;
  ev->base = base;
  ev->fd = fd;
  ev->events = events;
  ev->callback = callback;
  ev->callback_arg = callback_arg;
  return 0;
}

HV_INLINE struct event *event_new(struct event_base *base, evutil_socket_t fd,
                                  short events, event_callback_fn callback,
                                  void *callback_arg) {
  struct event *ev = NULL;
  HV_ALLOC(ev, sizeof(struct event));
  ev->io = NULL;
  ev->timer = NULL;
  ev->base = base;
  ev->fd = fd;
  ev->events = events;
  ev->callback = callback;
  ev->callback_arg = callback_arg;
  return ev;
}

int event_add(struct event *ev, const struct timeval *tv) {
  int fd = ev->fd;
  struct event_base *base = ev->base;
  short events = ev->events;
  if (fd >= 0) {
    ev->io = hio_get(base->loop, fd);
    hevent_set_userdata(ev->io, ev);
    if (events & EV_READ) {
      hio_add(ev->io, on_readable, HV_READ);
    }
    if (events & EV_WRITE) {
      hio_add(ev->io, on_writable, EV_WRITE);
    }
  }
  if (tv != NULL) {
    ev->timeout = timeval_to_ms(tv);
    ev->timer = htimer_add(base->loop, on_timeout, ev->timeout, INFINITE);
    hevent_set_userdata(ev->timer, ev);
  }
  return 0;
}

void event_active(struct event *ev, int res, short ncalls) {
  hidle_add(ev->base->loop, NULL, 1);

  hevent_t hev;
  memset(&hev, 0, sizeof(hev));
  hev.cb = on_active;
  hev.userdata = ev;
  hev.privdata = (void *)res;
  hloop_post_event(ev->base->loop, &hev);
}

int event_del(struct event *ev) {
  if (ev->io != NULL) {
    short hv_events = hio_events(ev->io);
    if (hv_events & EV_READ) {
      hio_del(ev->io, EV_READ);
    }
    if (hv_events & EV_WRITE) {
      hio_del(ev->io, EV_WRITE);
    }
  }
  if (ev->timer != NULL) {
    htimer_del(ev->timer);
  }
  return 0;
}

HV_INLINE void event_free(struct event *ev) {
  event_del(ev);
  if (ev->io != NULL) {
    hio_close(ev->io);
    ev->io = NULL;
  }
  HV_FREE(ev);
}

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

#endif