#include "hv2ev.h"

int evutil_make_socket_closeonexec(evutil_socket_t fd) {
  int flags;
  if ((flags = fcntl(fd, F_GETFD, NULL)) < 0) {
    return -1;
  }
  if (!(flags & FD_CLOEXEC)) {
    if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1) {
      return -1;
    }
  }
  return 0;
}

int evutil_inet_pton(int af, const char *src, void *dst) {
  return inet_pton(af, src, dst);
}

const char *evutil_inet_ntop(int af, const void *src, char *dst, size_t len) {
  return inet_ntop(af, src, dst, len);
}

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
    evbuffer_chain_free(p);
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
  chain->flags = 0;
  chain->cleanupfn = NULL;
  chain->args = NULL;
  return chain;
}

void evbuffer_chain_free(struct evbuffer_chain *chain) {
  if (chain->flags & EVBUFFER_REFERENCE) {
    evbuffer_ref_cleanup_cb cleanupfn = chain->cleanupfn;
    if (cleanupfn != NULL) {
      cleanupfn(chain->buf.base, chain->buf.len, chain->args);
    }
    return;
  } else {
    HV_FREE(chain->buf.base);
  }
  HV_FREE(chain);
}

static void clear_free_chains_list(struct evbuffer_chain *chain) {
  struct evbuffer_chain *next;
  for (; chain; chain = next) {
    next = chain->next;
    evbuffer_chain_free(chain);
  }
}

void evbuffer_chain_insert(struct evbuffer *buf, struct evbuffer_chain *chain) {
  if (buf->last == NULL) {
    buf->first = chain;
    buf->last = chain;
    buf->last_with_datap = chain;
  } else {
    if (buf->total_len == 0) {
      clear_free_chains_list(buf->first);
      buf->first = chain;
      buf->last = chain;
      buf->last_with_datap = chain;
    } else {
      clear_free_chains_list(buf->last_with_datap->next);
      buf->last_with_datap->next = chain;
      buf->last = chain;
      if (chain->off > 0) {
        buf->last_with_datap = chain;
      }
    }
  }
  buf->total_len += chain->off;
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
    // 注意：如果有chain，但没有数据，last_with_datap也应该指向first
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

/** Helper: return true iff we should realign chain to fit datalen bytes of
    data in it. */
static int evbuffer_chain_should_realign(struct evbuffer_chain *chain,
                                         size_t datlen) {
  return chain->buf.len - chain->off >= datlen &&
         (chain->off < chain->buf.len / 2) &&
         (chain->off <= MAX_TO_REALIGN_IN_EXPAND);
}

/** Helper: realigns the memory in chain->buffer so that misalign is 0. */
static void evbuffer_chain_align(struct evbuffer_chain *chain) {
  memmove(chain->buf.base, chain->buf.base + chain->misalign, chain->off);
  chain->misalign = 0;
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
    if (evbuffer_chain_should_realign(chain, datalen)) {
      evbuffer_chain_align(chain);
      return 0;
    }

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
    if (chain != NULL) {
      chain->misalign += remain_to_delete;
      chain->off -= remain_to_delete;
    }
  }
  return 0;
}

int evbuffer_add_printf(struct evbuffer *buf, const char *fmt, ...) {
  char str[1024];
  memset(str, 0, sizeof(str));

  va_list args;
  va_start(args, fmt);
  vsprintf(str, fmt, args);
  va_end(args);

  evbuffer_add(buf, str, strlen(str));
  return 0;
}

int evbuffer_add_buffer(struct evbuffer *dst, struct evbuffer *src) {
  if (dst == src || src->total_len == 0) {
    return 0;
  }

  if (dst->total_len == 0) {
    struct evbuffer_chain *chain = dst->first, *next = NULL;
    while (chain != NULL) {
      next = chain->next;
      evbuffer_chain_free(chain);
      chain = next;
    }
    dst->first = NULL;
    dst->last = NULL;
    dst->last_with_datap = NULL;
  }

  if (dst->first == NULL) {
    dst->first = src->first;
    dst->last = src->last;
    dst->last_with_datap = src->last_with_datap;
  } else {
    struct evbuffer_chain *dst_last_datap = dst->last_with_datap;
    struct evbuffer_chain *src_last = src->last;
    struct evbuffer_chain *dst_first_no_datap = dst_last_datap->next;
    dst_last_datap->next = src->first;
    src_last->next = dst_first_no_datap;
    dst->last_with_datap = src->last_with_datap;
  }
  dst->total_len += src->total_len;

  src->first = NULL;
  src->last = NULL;
  src->last_with_datap = NULL;
  src->total_len = 0;

  struct evbuffer_chain *chain = dst->last_with_datap->next, *next = NULL;
  dst->last_with_datap->next = NULL;
  dst->last = dst->last_with_datap;
  while (chain != NULL) {
    next = chain->next;
    evbuffer_chain_free(chain);
    chain = next;
  }

  return 0;
}

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

unsigned char *evbuffer_pullup(struct evbuffer *buf, ssize_t size) {
  if (size < 0) {
    size = buf->total_len;
  } else if (size == 0 || size > buf->total_len) {
    return NULL;
  }

  struct evbuffer_chain *first_chain = buf->first;
  if (first_chain->off >= size) {
    return (unsigned char *)(first_chain->buf.base + first_chain->misalign);
  }

  char *buffer = NULL;
  struct evbuffer_chain *chain_contiguous = NULL, *chain = NULL;
  int remaining_to_copy = size;

  if (first_chain->buf.len - first_chain->misalign >= remaining_to_copy) {
    chain_contiguous = first_chain;
    remaining_to_copy -= first_chain->off;
    size_t old_off = first_chain->off;
    chain_contiguous->off = size;
    buffer = first_chain->buf.base + first_chain->misalign + old_off;
    chain = first_chain->next;
  } else {
    chain_contiguous = evbuffer_chain_new(remaining_to_copy);
    if (chain_contiguous == NULL) {
      return NULL;
    }
    chain_contiguous->off = size;
    buffer = chain_contiguous->buf.base + chain_contiguous->misalign;
    chain = first_chain;
  }

  while (remaining_to_copy > 0 && chain != NULL &&
         chain->off <= remaining_to_copy) {
    struct evbuffer_chain *next = chain->next;
    memcpy(buffer, chain->buf.base + chain->misalign, chain->off);
    buffer += chain->off;
    remaining_to_copy -= chain->off;
    evbuffer_chain_free(chain);
    chain = next;
  }

  if (remaining_to_copy > 0) {
    memcpy(buffer, chain->buf.base + chain->misalign, remaining_to_copy);
    chain->misalign += remaining_to_copy;
    chain->off -= remaining_to_copy;
    remaining_to_copy = 0;
  }

  buf->first = chain_contiguous;
  if (chain == NULL) {
    buf->last = chain_contiguous;
  }
  if (size == buf->total_len) {
    buf->last_with_datap = chain_contiguous;
  }

  chain_contiguous->next = chain;

  return (unsigned char *)(chain_contiguous->buf.base +
                           chain_contiguous->misalign);
}

int evbuffer_add_reference(struct evbuffer *buf, const void *data,
                           size_t datalen, evbuffer_ref_cleanup_cb cleanupfn,
                           void *args) {
  struct evbuffer_chain *chain = evbuffer_chain_new(datalen);
  chain->flags |= (EVBUFFER_REFERENCE | EVBUFFER_IMMUTABLE);
  chain->cleanupfn = cleanupfn;
  chain->args = args;
  chain->buf.base = (char *)data;
  chain->buf.len = datalen;
  chain->off = datalen;
  evbuffer_chain_insert(buf, chain);

  return 0;
}

int evbuffer_remove(struct evbuffer *buf, void *data_out, size_t datalen) {
  struct evbuffer_chain *chain;
  char *data = (char *)data_out;
  size_t nread;
  ssize_t result = 0;

  chain = buf->first;
  if (datalen > buf->total_len)
    datalen = buf->total_len;
  if (datalen == 0) {
    return result;
  }

  nread = datalen;

  while (datalen && datalen >= chain->off) {
    size_t copylen = chain->off;
    memcpy(data, chain->buf.base + chain->misalign, copylen);
    data += copylen;
    datalen -= copylen;
    chain = chain->next;
  }
  if (datalen) {
    memcpy(data, chain->buf.base + chain->misalign, datalen);
  }

  result = nread;
  if (result > 0) {
    evbuffer_drain(buf, result);
  }
  return result;
}

static void bufferevent_readcb(evutil_socket_t fd, short event, void *arg) {
  struct bufferevent *bufev = (struct bufferevent *)arg;

  short what = BEV_EVENT_READING;
  if (event == EV_TIMEOUT) {
    what |= BEV_EVENT_TIMEOUT;
    bufferevent_disable(bufev, EV_READ);
    bufev->errorcb(bufev, what, bufev->cbarg);
    return;
  }

  size_t n = EVBUFFER_MAX_READ;
  ioctl(fd, FIONREAD, &n);
  if (n <= 0) {
    n = 1;
  }

  char *new_buf = NULL;
  HV_ALLOC(new_buf, n);
  ssize_t nread = read(fd, new_buf, n);
  if (nread <= 0) {
    if (nread == 0) {
      what |= BEV_EVENT_EOF;
    } else {
      int err = evutil_socket_geterror(fd);
      if (EVUTIL_ERR_RW_RETRIABLE(err))
        return;
      if (EVUTIL_ERR_CONNECT_REFUSED(err)) {
        bufev->connection_refused = 1;
        return;
      }
      what |= BEV_EVENT_ERROR;
    }
    bufferevent_disable(bufev, EV_READ);
    bufev->errorcb(bufev, what, bufev->cbarg);
    return;
  }
  struct evbuffer *buffer = bufev->input;
  evbuffer_add(buffer, new_buf, nread);
  buffer->first->off += nread;
  HV_FREE(new_buf);

  if (bufev->readcb) {
    bufev->readcb(bufev, bufev->cbarg);
  }
}

int evutil_socket_finished_connecting(evutil_socket_t fd) {
  int e;
  ev_socklen_t elen = sizeof(e);

  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *)&e, &elen) < 0)
    return -1;

  if (e) {
    if (EVUTIL_ERR_CONNECT_RETRIABLE(e))
      return 0;
    EVUTIL_SET_SOCKET_ERROR(e);
    return -1;
  }

  return 1;
}

static void bufferevent_writecb(evutil_socket_t fd, short event, void *arg) {
  printf("进入bufferevent_writecb fd: %d\n", fd);
  struct bufferevent *bufev = (struct bufferevent *)arg;
  printf("ev_write pending: %d\n", bufev->ev_write.events_pending);
  short what = BEV_EVENT_WRITING;

  if (event == EV_TIMEOUT) {
    /* Note that we only check for event==EV_TIMEOUT. If
     * event==EV_TIMEOUT|EV_WRITE, we can safely ignore the
     * timeout, since a read has occurred */
    what |= BEV_EVENT_TIMEOUT;
    bufferevent_disable(bufev, EV_WRITE);
    bufev->errorcb(bufev, what, bufev->cbarg);
    return;
  }

  if (bufev->connecting) {
    int c = evutil_socket_finished_connecting(fd);
    if (bufev->connection_refused) {
      bufev->connection_refused = 0;
      c = -1;
    }
    if (c == 0)
      return;
    bufev->connecting = 0;
    if (c < 0) {
      event_del(&bufev->ev_write);
      event_del(&bufev->ev_read);
      bufev->errorcb(bufev, BEV_EVENT_ERROR, bufev->cbarg);
      return;
    } else {
      // connected = 1;
      bufev->errorcb(bufev, BEV_EVENT_CONNECTED, bufev->cbarg);
      if (!(bufev->enabled & EV_WRITE)) {
        event_del(&bufev->ev_write);
        return;
      }
    }
  }

  struct evbuffer *buffer = bufev->output;
  size_t n = evbuffer_get_length(buffer);
  if (n) {
    unsigned char *buf = evbuffer_pullup(buffer, n);
    ssize_t nwrite = write(fd, buf, n);
    if (nwrite <= 0) {
      if (nwrite == 0) {
        what |= BEV_EVENT_EOF;
      } else {
        int err = evutil_socket_geterror(fd);
        if (EVUTIL_ERR_RW_RETRIABLE(err)) {
          if (evbuffer_get_length(bufev->output) == 0) {
            event_del(&bufev->ev_write);
          }
          return;
        }
        what |= BEV_EVENT_ERROR;
      }
      bufferevent_disable(bufev, EV_WRITE);
      bufev->errorcb(bufev, what, bufev->cbarg);
      return;
    }
    evbuffer_drain(buffer, nwrite);
  }

  if (evbuffer_get_length(buffer) == 0) {
    event_del(&(bufev->ev_write));
    if (bufev->writecb) {
      bufev->writecb(bufev, bufev->cbarg);
    }
  }
  printf("退出bufferevent_writecb\n");
}

static void bufferevent_errcb(evutil_socket_t fd, short what, void *arg) {
  struct bufferevent *bufev = (struct bufferevent *)arg;
  bufev->errorcb(bufev, what, bufev->cbarg);
}

struct bufferevent *bufferevent_socket_new(struct event_base *base,
                                           evutil_socket_t fd, int options) {
  struct bufferevent *bufev;
  HV_ALLOC(bufev, sizeof(struct bufferevent));

  bufev->ev_base = base;
  if (!bufev->input) {
    bufev->input = evbuffer_new();
  }
  if (!bufev->output) {
    bufev->output = evbuffer_new();
  }

  event_assign(&(bufev->ev_read), bufev->ev_base, fd, EV_READ | EV_PERSIST,
               bufferevent_readcb, bufev);
  event_assign(&(bufev->ev_write), bufev->ev_base, fd, EV_WRITE | EV_PERSIST,
               bufferevent_writecb, bufev);
  event_assign(&(bufev->ev_err), bufev->ev_base, fd, 0, bufferevent_errcb,
               bufev);

  bufev->readcb = NULL;
  bufev->writecb = NULL;
  bufev->errorcb = NULL;
  bufev->cbarg = NULL;
  timerclear(&(bufev->timeout_read));
  timerclear(&(bufev->timeout_write));
  bufev->enabled = EV_WRITE;
  bufev->connecting = 0;
  bufev->connection_refused = 0;
  bufev->options = options;

  return bufev;
}

void bufferevent_free(struct bufferevent *bufev) {
  int fd = bufev->ev_read.fd;

  event_del(&bufev->ev_read);
  event_del(&bufev->ev_write);
  event_del(&bufev->ev_err);
  if ((bufev->options & BEV_OPT_CLOSE_ON_FREE) && fd >= 0)
    close(fd);
  if (bufev->input) {
    evbuffer_free(bufev->input);
  }
  if (bufev->output) {
    evbuffer_free(bufev->output);
  }
  HV_FREE(bufev);
}

int bufferevent_write_buffer(struct bufferevent *bufev, struct evbuffer *buf) {
  evbuffer_add_buffer(bufev->output, buf);
  if (evbuffer_get_length(bufev->output) > 0) {
    printf("bufferevent_write_buffer\n");
    event_add(&(bufev->ev_write), &(bufev->timeout_write));
  }
  // bufev->enabled |= EV_WRITE;
  return 0;
}

int bufferevent_write(struct bufferevent *bufev, const void *data,
                      size_t size) {
  evbuffer_add(bufev->output, data, size);
  if (size > 0) {
    event_add(&(bufev->ev_write), &(bufev->timeout_write));
  }
  return 0;
}

struct evbuffer *bufferevent_get_input(struct bufferevent *bufev) {
  return bufev->input;
}

struct evbuffer *bufferevent_get_output(struct bufferevent *bufev) {
  return bufev->output;
}

int bufferevent_enable(struct bufferevent *bufev, short event) {
  if (event & EV_READ) {
    event_add(&(bufev->ev_read), &(bufev->timeout_read));
    bufev->enabled |= EV_READ;
  }
  if (event & EV_WRITE) {
    event_add(&(bufev->ev_write), &(bufev->timeout_write));
    bufev->enabled |= EV_WRITE;
  }
  return 0;
}

int bufferevent_disable(struct bufferevent *bufev, short event) {
  if (event & EV_READ) {
    event_del(&(bufev->ev_read));
    bufev->enabled &= (~EV_READ);
  }
  if (event & EV_WRITE) {
    event_del(&(bufev->ev_write));
    bufev->enabled &= (~EV_WRITE);
  }
  return 0;
}

short bufferevent_get_enabled(struct bufferevent *bufev) {
  return bufev->enabled;
}

void bufferevent_setcb(struct bufferevent *bufev, bufferevent_data_cb readcb,
                       bufferevent_data_cb writecb,
                       bufferevent_event_cb eventcb, void *cbarg) {

  bufev->readcb = readcb;
  bufev->writecb = writecb;
  bufev->errorcb = eventcb;

  bufev->cbarg = cbarg;
}

int is_monitored(struct event *ev, short events) {
  hio_t *io = hio_get(ev->base->loop, ev->fd);

  short hv_events = hio_events(io);
  if (hv_events & events) {
    return 1;
  }

  return 0;
}

int adj_timeouts(struct bufferevent *bev) {
  int r = 0;
  if (is_monitored(&bev->ev_read, EV_READ)) {
    if (timerisset(&bev->timeout_read)) {
      if (event_add(&bev->ev_read, &bev->timeout_read) < 0)
        r = -1;
    } else {
      htimer_del((&(bev->ev_read))->timer);
      (&(bev->ev_read))->timer = NULL;
    }
  }
  if (is_monitored(&bev->ev_write, EV_WRITE)) {
    if (timerisset(&bev->timeout_write)) {
      if (event_add(&bev->ev_write, &bev->timeout_write) < 0)
        r = -1;
    } else {
      htimer_del((&(bev->ev_write))->timer);
      (&(bev->ev_write))->timer = NULL;
    }
  }
  return r;
}

int bufferevent_set_timeouts(struct bufferevent *bufev,
                             const struct timeval *tv_read,
                             const struct timeval *tv_write) {
  int r = 0;
  if (tv_read) {
    bufev->timeout_read = *tv_read;
  } else {
    timerclear(&(bufev->timeout_read));
  }
  if (tv_write) {
    bufev->timeout_write = *tv_write;
  } else {
    timerclear(&(bufev->timeout_write));
  }

  r = adj_timeouts(bufev);

  return r;
}

int evutil_socket_connect(evutil_socket_t *fd_ptr, const struct sockaddr *sa,
                          int socklen) {
  int made_fd = 0;

  if (*fd_ptr < 0) {
    if ((*fd_ptr = socket(sa->sa_family, SOCK_STREAM, 0)) < 0)
      goto err;
    made_fd = 1;
    if (evutil_make_socket_nonblocking(*fd_ptr) < 0) {
      goto err;
    }
  }

  if (connect(*fd_ptr, sa, socklen) < 0) {
    int e = evutil_socket_geterror(*fd_ptr);
    if (EVUTIL_ERR_CONNECT_RETRIABLE(e))
      return 0;
    if (EVUTIL_ERR_CONNECT_REFUSED(e))
      return 2;
    goto err;
  } else {
    return 1;
  }

err:
  if (made_fd) {
    evutil_closesocket(*fd_ptr);
    *fd_ptr = -1;
  }
  return -1;
}

int bufferevent_socket_connect(struct bufferevent *bufev,
                               const struct sockaddr *sa, int socklen) {
  int result = -1, ownfd = 0, r;

  evutil_socket_t fd = bufev->ev_read.fd;
  if (fd < 0) {
    if (!sa)
      goto done;
    fd = socket(sa->sa_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0)
      goto freesock;
    ownfd = 1;
  }

  if (sa) {
    r = evutil_socket_connect(&fd, sa, socklen);
    if (r < 0)
      goto freesock;
  }

  // bufferevent_setfd(bufev, fd);
  {
    event_del(&bufev->ev_read);
    event_del(&bufev->ev_write);
    event_assign(&bufev->ev_read, bufev->ev_base, fd, EV_READ | EV_PERSIST,
                 bufferevent_readcb, bufev);
    event_assign(&bufev->ev_write, bufev->ev_base, fd, EV_WRITE | EV_PERSIST,
                 bufferevent_writecb, bufev);

    if (fd >= 0)
      bufferevent_enable(bufev, bufev->enabled);
  }

  printf("bufferevent_socket_connect, r: %d\n", r);
  if (r == 0) {
    event_add(&bufev->ev_write, &bufev->timeout_write);
    bufev->connecting = 1;
    result = 0;
    goto done;
  } else if (r == 1) {
    /* The connect succeeded already. */
    result = 0;
    bufev->connecting = 1;
    event_active(&(bufev->ev_write), EV_WRITE, 1);
  } else {
    /* The connect failed already. */
    result = 0;
    event_active(&(bufev->ev_err), BEV_EVENT_ERROR, 1);
    bufferevent_disable(bufev, EV_WRITE | EV_READ);
  }
  goto done;

freesock:
  if (ownfd)
    evutil_closesocket(fd);

done:
  return result;
}

int bufferevent_socket_connect_hostname(struct bufferevent *bev,
                                        struct evdns_base *evdns_base,
                                        int family, const char *hostname,
                                        int port) {
  int ret = 0;
  sockaddr_u addr;
  memset(&addr, 0, sizeof(addr));
  ret = sockaddr_set_ipport((sockaddr_u *)&addr, hostname, port);
  if (ret < 0) {
    return -1;
  }
  ret = bufferevent_socket_connect(bev, (struct sockaddr *)(&(addr.sin)),
                                   sizeof(addr.sin));
  return ret;
}

evutil_socket_t accept4(evutil_socket_t sockfd, struct sockaddr *addr,
                        ev_socklen_t *addrlen, int flags) {
  evutil_socket_t result;
  result = accept(sockfd, addr, addrlen);
  if (result < 0)
    return result;

  if (flags & EVUTIL_SOCK_CLOEXEC) {
    if (evutil_make_socket_closeonexec(result) < 0) {
      evutil_closesocket(result);
      return -1;
    }
  }
  if (flags & EVUTIL_SOCK_NONBLOCK) {
    if (evutil_make_socket_nonblocking(result) < 0) {
      evutil_closesocket(result);
      return -1;
    }
  }
  return result;
}

static void listener_read_cb(evutil_socket_t fd, short what, void *p) {
  struct evconnlistener *lev = (struct evconnlistener *)p;
  int err;
  evconnlistener_cb cb;
  evconnlistener_errorcb errorcb;
  void *user_data;
  while (1) {
    struct sockaddr_storage ss;
    ev_socklen_t socklen = sizeof(ss);
    evutil_socket_t new_fd =
        accept4(fd, (struct sockaddr *)&ss, &socklen, lev->accept4_flags);
    if (new_fd < 0)
      break;
    if (socklen == 0) {
      /* This can happen with some older linux kernels in
       * response to nmap. */
      evutil_closesocket(new_fd);
      continue;
    }

    if (lev->cb == NULL) {
      evutil_closesocket(new_fd);
      return;
    }
    cb = lev->cb;
    user_data = lev->user_data;
    cb(lev, new_fd, (struct sockaddr *)&ss, (int)socklen, user_data);

    if (!lev->enabled) {
      /* the callback could have disabled the listener */
      return;
    }
  }
  err = evutil_socket_geterror(fd);
  if (EVUTIL_ERR_ACCEPT_RETRIABLE(err)) {
    return;
  }
  if (lev->errorcb != NULL) {
    errorcb = lev->errorcb;
    user_data = lev->user_data;
    errorcb(lev, user_data);
  } else {
    return;
  }
}

struct evconnlistener *evconnlistener_new(struct event_base *base,
                                          evconnlistener_cb cb, void *ptr,
                                          unsigned flags, int backlog,
                                          evutil_socket_t fd) {
  struct evconnlistener_event *lev;
  if (backlog > 0) {
    if (listen(fd, backlog) < 0)
      return NULL;
  } else if (backlog < 0) {
    if (listen(fd, 128) < 0)
      return NULL;
  }
  HV_ALLOC(lev, sizeof(struct evconnlistener_event));
  if (!lev)
    return NULL;

  lev->base.cb = cb;
  lev->base.user_data = ptr;
  lev->base.flags = flags;
  lev->base.lev_e = lev;

  lev->base.accept4_flags = 0;
  if (!(flags & LEV_OPT_LEAVE_SOCKETS_BLOCKING))
    lev->base.accept4_flags |= EVUTIL_SOCK_NONBLOCK;
  if (flags & LEV_OPT_CLOSE_ON_EXEC)
    lev->base.accept4_flags |= EVUTIL_SOCK_CLOEXEC;

  event_assign(&lev->listener, base, fd, EV_READ | EV_PERSIST, listener_read_cb,
               lev);

  // evconnlistener_enable(&lev->base);
  if (!(flags & LEV_OPT_DISABLED)) {
    lev->base.enabled = 1;
    if (lev->base.cb) {
      event_add(&(lev->listener), NULL);
    }
  }

  return &lev->base;
}

void evconnlistener_free(struct evconnlistener *lev) {
  struct evconnlistener_event *lev_e = lev->lev_e;
  event_del(&lev_e->listener);
  if (lev->flags & LEV_OPT_CLOSE_ON_FREE) {
    close(lev_e->listener.fd);
  }
  HV_FREE(lev);
}

struct evconnlistener *evconnlistener_new_bind(struct event_base *base,
                                               evconnlistener_cb cb, void *ptr,
                                               unsigned flags, int backlog,
                                               const struct sockaddr *sa,
                                               int socklen) {
  struct evconnlistener *listener;
  evutil_socket_t fd;
  int on = 1;
  int family = sa ? sa->sa_family : AF_UNSPEC;
  int socktype = SOCK_STREAM | EVUTIL_SOCK_NONBLOCK;

  if (backlog == 0)
    return NULL;

  if (flags & LEV_OPT_CLOSE_ON_EXEC)
    socktype |= EVUTIL_SOCK_CLOEXEC;

  fd = socket(family, socktype, 0);
  if (fd == -1)
    return NULL;

  if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&on, sizeof(on)) < 0)
    goto err;

  if (flags & LEV_OPT_REUSEABLE) {
    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&one,
                   (ev_socklen_t)sizeof(one)) < 0)
      goto err;
  }

  if (flags & LEV_OPT_REUSEABLE_PORT) {
    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (void *)&one,
                   (ev_socklen_t)sizeof(one)) < 0)
      goto err;
  }

  if (flags & LEV_OPT_DEFERRED_ACCEPT) {
    int one = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &one,
                   (ev_socklen_t)sizeof(one)) < 0)
      goto err;
  }

  if (flags & LEV_OPT_BIND_IPV6ONLY) {
    int one = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &one,
                   (ev_socklen_t)sizeof(one)) < 0)
      goto err;
  }

  if (sa) {
    if (bind(fd, sa, socklen) < 0)
      goto err;
  }

  listener = evconnlistener_new(base, cb, ptr, flags, backlog, fd);
  if (!listener)
    goto err;

  return listener;
err:
  evutil_closesocket(fd);
  return NULL;
}

size_t bufferevent_read(struct bufferevent *bufev, void *data, size_t size) {
  return (evbuffer_remove(bufev->input, data, size));
}

int evconnlistener_enable(struct evconnlistener *lev) {
  int r;
  lev->enabled = 1;
  if (lev->cb)
    r = event_add(&lev->lev_e->listener, NULL);
  else
    r = 0;
  return r;
}

#define queue_data(ptr, type, field)                                           \
  ((type *)((char *)(ptr)-offsetof(type, field)))

void queue_node_reset(struct queue_node *queue_node) {
  queue_node->next = queue_node;
  queue_node->pre = queue_node;
}

int queue_node_empty(struct queue_node *queue_node) {
  return queue_node->next == queue_node;
}

void queue_node_insert_tail(struct queue_node *head, struct queue_node *node) {
  node->next = head;
  node->pre = head->pre;
  node->pre->next = node;
  head->pre = node;
}

void queue_node_remove(struct queue_node *node) {
  node->pre->next = node->next;
  node->next->pre = node->pre;
}

void run_signal_cb(hevent_t *hevent) {
  printf("进入run_signal_cb\n");
  struct event_base *base = (struct event_base *)hevent->userdata;
  struct queue_node *head = &(base->awaken_signal_events_head);
  if (base->enable_signal && !queue_node_empty(head)) {
    struct queue_node *ev_node = head->next;
    while (ev_node != head) {
      struct event *ev =
          queue_data(ev_node, struct event, self_awaken_signal_node);
      for (int i = 0; i < ev->num_calls; i++) {
        ev->callback(ev->fd, EV_SIGNAL, ev->callback_arg);
      }
      struct queue_node *next = ev_node->next;
      queue_node_remove(ev_node);
      ev_node = next;
    }
  }
  printf("退出run_signal_cb\n");
}

static void sig_event_cb(int fd, short awakened_events_on_epoll, void *arg) {
  printf("进入sig_event_cb\n");
  char signals[1024];
  int n = 0;
  int ncaught[NSIG];
  memset(signals, 0, sizeof(signals));
  memset(ncaught, 0, sizeof(ncaught));

  struct event_base *base = (struct event_base *)arg;

  if (base == NULL) {
    return;
  }

  while (true) {
    n = read(fd, signals, sizeof(signals));
    if (n <= 0) {
      break;
    }
    for (int i = 0; i < n; ++i) {
      char sig = signals[i];
      if (sig < NSIG)
        ncaught[sig]++;
    }
  }

  for (int i = 0; i < NSIG; i++) {
    if (ncaught[i] > 0) {
      struct queue_node *events_at_sig = &(base->signal_events_head[i]);
      if (!queue_node_empty(events_at_sig)) {
        struct queue_node *ev_node = events_at_sig->next;
        while (ev_node != events_at_sig) {
          struct event *ev =
              queue_data(ev_node, struct event, self_signal_node);
          // ev->awakened_events_ |= EV_SIGNAL;
          ev->num_calls = ncaught[i];
          queue_node_insert_tail(&(base->awaken_signal_events_head),
                                 &(ev->self_awaken_signal_node));
          ev_node = ev_node->next;
        }
      }
    }
  }

  hevent_t hev;
  memset(&hev, 0, sizeof(hev));
  hev.cb = run_signal_cb;
  hev.userdata = base;
  hloop_post_event(base->loop, &hev);

  printf("退出sig_event_cb\n");
}

struct event_base *event_base_new(void) {
  struct event_base *base = NULL;
  HV_ALLOC(base, sizeof(struct event_base));
  base->loop = hloop_new(HLOOP_FLAG_QUIT_WHEN_NO_ACTIVE_EVENTS);
  base->timer = NULL;
  base->enable_signal = 0;

  return base;
}

void event_base_free(struct event_base *base) {
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

int event_base_loop(struct event_base *base, int flags) {
  return hloop_run(base->loop);
}

int event_base_dispatch(struct event_base *base) {
  return event_base_loop(base, 0);
}

int event_base_loopbreak(struct event_base *base) {
  return hloop_stop(base->loop);
}

int timeval_to_ms(const struct timeval *tv) {
  return (tv->tv_sec * 1000) + (tv->tv_usec / 1000);
}

void on_loopexit_timeout(htimer_t *timer) { hloop_stop(hevent_loop(timer)); }

void on_loopexit_directly(hevent_t *hevent) { hloop_stop(hevent_loop(hevent)); }

int event_base_loopexit(struct event_base *base, const struct timeval *tv) {
  if (tv != NULL) {
    if (base->timer != NULL) {
      htimer_del(base->timer);
      base->timer = NULL;
    }
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
  struct event *ev = (struct event *)hio_getcb_read(io);
  if (ev == NULL) {
    return;
  }
  int fd = hio_fd(io);
  short events = ev->events;
  short revents = hio_revents(io);
  if (!((events & EV_READ) && (revents & EV_READ))) {
    return;
  }

  if (!(events & EV_PERSIST)) {
    hio_del(io, HV_READ);
    if (ev->timer != NULL) {
      htimer_del(ev->timer);
      ev->timer = NULL;
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
  struct event *ev = (struct event *)hio_getcb_write(io);
  if (ev == NULL) {
    return;
  }
  int fd = hio_fd(io);
  short events = ev->events;
  short revents = hio_revents(io);
  if (!((events & EV_WRITE) && (revents & EV_WRITE))) {
    return;
  }

  if (!(events & EV_PERSIST)) {
    hio_del(io, HV_WRITE);
    if (ev->timer != NULL) {
      htimer_del(ev->timer);
      ev->timer = NULL;
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

void on_netio(hio_t *io) {
  printf("on_netio\n");
  short revents = hio_revents(io);
  if (revents & EV_WRITE) {
    on_writable(io);
  }
  if (revents & EV_READ) {
    on_readable(io);
  }
}

void on_timeout(htimer_t *timer) {
  struct event *ev = (struct event *)hevent_userdata(timer);
  short events = ev->events;

  if (!((events & EV_PERSIST))) {
    event_del(ev);
    if (ev->timer != NULL) {
      htimer_del(ev->timer);
      ev->timer = NULL;
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

void on_active(hevent_t *hev) {
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

struct event *event_new(struct event_base *base, evutil_socket_t fd,
                        short events, event_callback_fn callback,
                        void *callback_arg) {
  struct event *ev = NULL;
  HV_ALLOC(ev, sizeof(struct event));
  ev->io = NULL;
  ev->timer = NULL;
  ev->base = base;
  ev->fd = fd;
  ev->events = events;
  ev->events_pending = 0;
  ev->callback = callback;
  ev->callback_arg = callback_arg;
  ev->num_calls = 0;
  queue_node_reset(&(ev->self_signal_node));
  queue_node_reset(&(ev->self_awaken_signal_node));
  return ev;
}

static int sig_write_fd = -1;

static void sig_handler(int sig) {
  printf("进入sig_handler\n");
  int save_errno = errno;

  char signum = (char)sig;
  int n = write(sig_write_fd, &signum, 1);
  printf("写入%d个信号\n", n);

  errno = save_errno;
  printf("退出sig_handler\n");
}

int event_add(struct event *ev, const struct timeval *tv) {
  printf("进入event_add, events: %d\n", ev->events);
  int fd = ev->fd;
  struct event_base *base = ev->base;
  short events = ev->events;
  if (ev->events & EV_SIGNAL) {
    printf("添加信号事件\n");
    if (base->enable_signal == 0) {
      printf("启动信号\n");
      base->enable_signal = 1;
      for (int i = 0; i < NSIG; i++) {
        queue_node_reset(&(base->signal_events_head[i]));
      }
      queue_node_reset(&(base->awaken_signal_events_head));
      socketpair(AF_UNIX, SOCK_STREAM, 0, base->pair);
      fcntl(base->pair[0], F_SETFL, O_NONBLOCK);
      fcntl(base->pair[1], F_SETFL, O_NONBLOCK);
      fcntl(base->pair[0], F_SETFD, FD_CLOEXEC);
      fcntl(base->pair[1], F_SETFD, FD_CLOEXEC);
      event_assign(&(base->signal_monitor), base, base->pair[0],
                   EV_READ | EV_PERSIST, sig_event_cb, base);
      event_add(&(base->signal_monitor), NULL);
    }
    assert(fd >= 0 && fd < NSIG);
    struct queue_node *events_at_sig = &(base->signal_events_head[fd]);
    if (queue_node_empty(events_at_sig)) {
      struct sigaction sa;
      memset(&sa, 0, sizeof(sa));
      sa.sa_handler = sig_handler;
      sa.sa_flags |= SA_RESTART;
      sigfillset(&sa.sa_mask);
      sig_write_fd = base->pair[1];
      sigaction(fd, &sa, NULL);
    }
    queue_node_insert_tail(&(base->signal_events_head[fd]),
                           &(ev->self_signal_node));
    return 0;
  }
  ev->events_pending |= events;
  if (fd >= 0) {
    ev->io = hio_get(base->loop, fd);
    // hevent_set_userdata(ev->io, ev);
    if (events & EV_READ) {
      printf("监听读端%d\n", ev->fd);
      printf("监视的事件%d\n", ev->events);
      hio_setcb_read(ev->io, (hread_cb)ev);
      hio_add(ev->io, on_netio, HV_READ);
    }
    if (events & EV_WRITE) {
      hio_setcb_write(ev->io, (hwrite_cb)ev);
      hio_add(ev->io, on_netio, HV_WRITE);
    }
  }
  if (tv != NULL) {
    printf("添加定时器\n");
    if (ev->timer != NULL) {
      htimer_del(ev->timer);
      ev->timer = NULL;
    }
    ev->timeout = timeval_to_ms(tv);
    ev->timer = htimer_add(base->loop, on_timeout, ev->timeout, INFINITE);
    if (ev->timer != NULL) {
      hevent_set_userdata(ev->timer, ev);
    }
  }
  printf("退出event_add\n");
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
  printf("进入event_del, events: %d\n", ev->events);
  ev->events_pending &= (~ev->events);
  if (ev->io != NULL) {
    short events = ev->events;
    if (events & EV_READ) {
      hio_del(ev->io, HV_READ);
      hio_setcb_read(ev->io, NULL);
    }
    if (events & EV_WRITE) {
      hio_del(ev->io, HV_WRITE);
      hio_setcb_write(ev->io, NULL);
    }
  }
  if (ev->timer != NULL) {
    printf("删除定时器\n");
    htimer_del(ev->timer);
    ev->timer = NULL;
  }
  printf("退出event_del\n");
  return 0;
}

void event_free(struct event *ev) {
  event_del(ev);
  if (ev->io != NULL) {
    hio_close(ev->io);
    ev->io = NULL;
  }
  HV_FREE(ev);
}

void event_set_mem_functions(void *(*malloc_fn)(size_t sz),
                             void *(*realloc_fn)(void *ptr, size_t sz),
                             void (*free_fn)(void *ptr)) {
  return;
}

int evbuffer_prepend_buffer(struct evbuffer *dst, struct evbuffer *src) {
  size_t dst_total_len = dst->total_len;
  size_t src_total_len = src->total_len;

  if (dst == src || src_total_len == 0) {
    return 0;
  }

  if (dst_total_len == 0) {
    clear_free_chains_list(dst->first);
    dst->first = src->first;
    dst->last = src->last;
    dst->last_with_datap = src->last_with_datap;
    dst->total_len = src->total_len;
  } else {
    src->last->next = dst->first;
    dst->first = src->first;
    dst->total_len += src->total_len;
  }
  src->first = src->last = src->last_with_datap = NULL;
  src->total_len = 0;

  return 0;
}

int event_pending(const struct event *ev, short events, struct timeval *tv) {
  return ev->events_pending & events;
}

evutil_socket_t evconnlistener_get_fd(struct evconnlistener *lev) {
  return lev->lev_e->listener.fd;
}

void ev_token_bucket_cfg_free(struct ev_token_bucket_cfg *cfg) { free(cfg); }

struct ev_token_bucket_cfg *
ev_token_bucket_cfg_new(size_t read_rate, size_t read_burst, size_t write_rate,
                        size_t write_burst, const struct timeval *tick_len) {
  struct ev_token_bucket_cfg *r;
  struct timeval g;
  if (!tick_len) {
    g.tv_sec = 1;
    g.tv_usec = 0;
    tick_len = &g;
  }
  if (read_rate > read_burst || write_rate > write_burst || read_rate < 1 ||
      write_rate < 1)
    return NULL;
  if (read_rate > EV_RATE_LIMIT_MAX || write_rate > EV_RATE_LIMIT_MAX ||
      read_burst > EV_RATE_LIMIT_MAX || write_burst > EV_RATE_LIMIT_MAX)
    return NULL;
  HV_ALLOC(r, sizeof(struct ev_token_bucket_cfg));
  if (!r)
    return NULL;
  r->read_rate = read_rate;
  r->write_rate = write_rate;
  r->read_maximum = read_burst;
  r->write_maximum = write_burst;
  memcpy(&r->tick_timeout, tick_len, sizeof(struct timeval));
  r->msec_per_tick =
      (tick_len->tv_sec * 1000) +
      (tick_len->tv_usec & COMMON_TIMEOUT_MICROSECONDS_MASK) / 1000;
  return r;
}

int event_base_gettimeofday_cached(struct event_base *base,
                                   struct timeval *tv) {
  gettimeofday(tv, NULL);
}