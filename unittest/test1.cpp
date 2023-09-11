#include "../hv2ev.h"
#include "doctest/doctest.h"
#include <iostream>

static void many_event_cb(evutil_socket_t fd, short event, void *arg) {
  int *calledp = (int *)arg;
  *calledp += 1;
}

TEST_CASE("test_many_events") {
#define MANY 70

  // event_base_new()
  struct event_base *base = event_base_new();

  evutil_socket_t sock[MANY];
  struct event *ev[MANY];
  int called[MANY];
  int i;

  for (i = 0; i < MANY; ++i) {
    sock[i] = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(sock[i] >= 0);
    CHECK(!evutil_make_socket_nonblocking(sock[i]));
    called[i] = 0;
    ev[i] = event_new(base, sock[i], EV_WRITE, many_event_cb, &called[i]);
    event_add(ev[i], NULL);
  }

  event_base_loop(base, 0);

  for (i = 0; i < MANY; ++i) {
    CHECK_EQ(called[i], 1);
  }

  for (i = 0; i < MANY; ++i) {
    if (ev[i])
      event_free(ev[i]);
    if (sock[i] >= 0)
      evutil_closesocket(sock[i]);
  }
  event_base_free(base);

#undef MANY
}

TEST_CASE("test_many_events: one at a time") {
#define MANY 70

  // event_base_new()
  struct event_base *base = NULL;
  HV_ALLOC(base, sizeof(struct event_base));
  base->loop =
      hloop_new(HLOOP_FLAG_QUIT_WHEN_NO_ACTIVE_EVENTS | HLOOP_FLAG_RUN_ONCE);
  base->timer = NULL;

  evutil_socket_t sock[MANY];
  struct event *ev[MANY];
  int called[MANY];
  int i;
  int evflags = EV_PERSIST;

  for (i = 0; i < MANY; ++i) {
    sock[i] = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(sock[i] >= 0);
    CHECK(!evutil_make_socket_nonblocking(sock[i]));
    called[i] = 0;
    ev[i] =
        event_new(base, sock[i], EV_WRITE | evflags, many_event_cb, &called[i]);
    event_add(ev[i], NULL);
    event_base_loop(base, 0);
  }

  event_base_loop(base, 0);

  for (i = 0; i < MANY; ++i) {
    CHECK_EQ(called[i], MANY - i + 1);
  }

  for (i = 0; i < MANY; ++i) {
    if (ev[i])
      event_free(ev[i]);
    if (sock[i] >= 0)
      evutil_closesocket(sock[i]);
  }
  event_base_free(base);

#undef MANY
}

#define TEST1 "this is a test"

struct basic_cb_args {
  struct event_base *eb;
  struct event *ev;
  unsigned int callcount;
};

static void basic_read_cb(evutil_socket_t fd, short event, void *data) {
  char buf[256];
  int len;
  struct basic_cb_args *arg = (struct basic_cb_args *)data;

  len = read(fd, buf, sizeof(buf));

  CHECK_FALSE(len < 0);

  switch (arg->callcount++) {
  case 0: /* first call: expect to read data; cycle */
    if (len > 0)
      return;
    FAIL("EOF before data read");
    break;

  case 1: /* second call: expect EOF; stop */
    if (len > 0)
      FAIL("not all data read on first cycle");
    break;

  default: /* third call: should not happen */
    FAIL("too many cycles");
  }

  event_del(arg->ev);
  hio_close(arg->ev->io);
  event_base_loopexit(arg->eb, NULL);
}

TEST_CASE("test_event_base_new") {
  evutil_socket_t spair[2] = {-1, -1};
  evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, spair);
  evutil_make_socket_nonblocking(spair[0]);
  evutil_make_socket_nonblocking(spair[1]);
  int towrite = (int)strlen(TEST1) + 1;
  int len = write(spair[0], TEST1, towrite);
  shutdown(spair[0], EVUTIL_SHUT_WR);

  struct event_base *base = event_base_new();
  struct event ev1;
  struct basic_cb_args args;
  args.eb = base;
  args.ev = &ev1;
  args.callcount = 0;

  event_assign(&ev1, base, spair[1], EV_READ | EV_PERSIST, basic_read_cb,
               &args);
  event_add(&ev1, NULL);
  event_base_loop(base, 0);

  event_base_free(base);
}

char wbuf[4096];
char rbuf[4096];
int roff, woff;
int usepersist;

static void multiple_read_cb(evutil_socket_t fd, short event, void *arg) {
  struct event *ev = (struct event *)arg;
  int len;

  len = read(fd, rbuf + roff, sizeof(rbuf) - roff);
  if (len == -1)
    fprintf(stderr, "%s: read\n", __func__);
  if (len <= 0) {
    if (usepersist)
      event_del(ev);
    hio_close(ev->io);
    return;
  }

  roff += len;
  if (!usepersist) {
    event_add(ev, NULL);
  }
}

static void multiple_write_cb(evutil_socket_t fd, short event, void *arg) {
  struct event *ev = (struct event *)arg;
  int len;

  len = 128;
  if (woff + len >= (int)sizeof(wbuf))
    len = sizeof(wbuf) - woff;

  len = write(fd, wbuf + woff, len);
  if (len == -1) {
    fprintf(stderr, "%s: write\n", __func__);
    if (usepersist)
      event_del(ev);
    hio_close(ev->io);
    return;
  }

  woff += len;

  if (woff >= (int)sizeof(wbuf)) {
    shutdown(fd, EVUTIL_SHUT_WR);
    if (usepersist)
      event_del(ev);
    hio_close(ev->io);
    return;
  }

  if (!usepersist) {
    event_add(ev, NULL);
  }
}

TEST_CASE("test_persistent") {
  struct event ev, ev2;
  int i;
  evutil_socket_t spair[2] = {-1, -1};
  evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, spair);
  evutil_make_socket_nonblocking(spair[0]);
  evutil_make_socket_nonblocking(spair[1]);

  /* Multiple read and write test with persist */
  memset(rbuf, 0, sizeof(rbuf));
  for (i = 0; i < (int)sizeof(wbuf); i++)
    wbuf[i] = i;
  roff = woff = 0;
  usepersist = 1;

  struct event_base *base = event_base_new();

  event_assign(&ev, base, spair[0], EV_WRITE | EV_PERSIST, multiple_write_cb,
               &ev);
  event_add(&ev, NULL);
  event_assign(&ev2, base, spair[1], EV_READ | EV_PERSIST, multiple_read_cb,
               &ev2);
  event_add(&ev2, NULL);
  event_base_dispatch(base);
  event_base_free(base);

  CHECK_EQ(roff, woff);
  CHECK_EQ(memcmp(rbuf, wbuf, sizeof(wbuf)), 0);
}

TEST_CASE("test_multiple") {
  struct event ev, ev2;
  int i;
  evutil_socket_t spair[2] = {-1, -1};
  evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, spair);
  evutil_make_socket_nonblocking(spair[0]);
  evutil_make_socket_nonblocking(spair[1]);

  /* Multiple read and write test */
  memset(rbuf, 0, sizeof(rbuf));
  for (i = 0; i < (int)sizeof(wbuf); i++)
    wbuf[i] = i;

  roff = woff = 0;
  usepersist = 0;

  struct event_base *base = event_base_new();

  event_assign(&ev, base, spair[0], EV_WRITE, multiple_write_cb, &ev);
  event_add(&ev, NULL);
  event_assign(&ev2, base, spair[1], EV_READ, multiple_read_cb, &ev2);
  event_add(&ev2, NULL);
  event_base_dispatch(base);
  event_base_free(base);

  CHECK_EQ(roff, woff);
  CHECK_EQ(memcmp(rbuf, wbuf, sizeof(wbuf)), 0);
}

struct timeval tset;
struct timeval tcalled;

long timeval_msec_diff(const struct timeval *start, const struct timeval *end) {
  long ms = end->tv_sec - start->tv_sec;
  ms *= 1000;
  ms += ((end->tv_usec - start->tv_usec) + 500) / 1000;
  // // printf("time duration(ms): %ld\n", ms);
  return ms;
}

static void timeout_cb(evutil_socket_t fd, short event, void *arg) {
  evutil_gettimeofday(&tcalled, NULL);
}

#define CHECK_TIME(start, end, diff)                                           \
  CHECK_LE(labs(timeval_msec_diff((start), (end)) - (diff)), 50);

TEST_CASE("test_loopexit") {
  struct event_base *base = event_base_new();
  struct timeval tv, tv_start, tv_end;
  struct event ev;

  tv.tv_usec = 0;
  tv.tv_sec = 60 * 60 * 24;
  event_assign(&ev, base, -1, 0, timeout_cb, NULL);
  evtimer_add(&ev, &tv);

  tv.tv_usec = 300 * 1000;
  tv.tv_sec = 0;
  event_base_loopexit(base, &tv);

  evutil_gettimeofday(&tv_start, NULL);
  event_base_dispatch(base);
  evutil_gettimeofday(&tv_end, NULL);

  evtimer_del(&ev);

  event_base_free(base);

  CHECK_TIME(&tv_start, &tv_end, 300);
}

struct persist_active_timeout_called {
  int n;
  short events[16];
  struct timeval tvs[16];
};

static void persist_active_timeout_cb(evutil_socket_t fd, short event,
                                      void *arg) {
  struct persist_active_timeout_called *c =
      (struct persist_active_timeout_called *)arg;
  if (c->n < 15) {
    c->events[c->n] = event;
    evutil_gettimeofday(&c->tvs[c->n], NULL);
    ++c->n;
  }
}

static void activate_cb(evutil_socket_t fd, short event, void *arg) {
  struct event *ev = (struct event *)arg;
  event_active(ev, EV_READ, 1);
}

TEST_CASE("test_persistent_active_timeout") {
  struct timeval tv, tv2, tv_exit, start;
  struct event ev;
  struct persist_active_timeout_called res;

  struct event_base *base = event_base_new();

  memset(&res, 0, sizeof(res));

  tv.tv_sec = 0;
  tv.tv_usec = 200 * 1000;
  event_assign(&ev, base, -1, EV_TIMEOUT | EV_PERSIST,
               persist_active_timeout_cb, &res);
  event_add(&ev, &tv);

  tv2.tv_sec = 0;
  tv2.tv_usec = 100 * 1000;
  struct event *once_event = event_new(base, -1, EV_TIMEOUT, activate_cb, &ev);
  event_add(once_event, &tv2);

  tv_exit.tv_sec = 0;
  tv_exit.tv_usec = 600 * 1000;
  event_base_loopexit(base, &tv_exit);

  evutil_gettimeofday(&start, NULL);
  event_base_dispatch(base);
  CHECK(res.n == 3);
  CHECK(res.events[0] == EV_READ);
  CHECK(res.events[1] == EV_TIMEOUT);
  CHECK(res.events[2] == EV_TIMEOUT);
  CHECK_TIME(&start, &res.tvs[0], 100);
  CHECK_TIME(&start, &res.tvs[1], 300);
  CHECK_TIME(&start, &res.tvs[2], 500);

  event_del(&ev);
  event_free(once_event);
  event_base_free(base);
}

struct read_not_timeout_param {
  struct event **ev;
  int events;
  int count;
};

static void read_not_timeout_cb(evutil_socket_t fd, short what, void *arg) {
  struct read_not_timeout_param *rntp = (struct read_not_timeout_param *)arg;
  char c;
  int n;
  (void)fd;
  (void)what;
  n = read(fd, &c, 1);
  CHECK_EQ(n, 1);
  rntp->events |= what;
  ++rntp->count;
  if (2 == rntp->count)
    event_del(rntp->ev[0]);
}

static void incr_arg_cb(evutil_socket_t fd, short what, void *arg) {
  int *intptr = (int *)arg;
  (void)fd;
  (void)what;
  ++*intptr;
}

static void remove_timers_cb(evutil_socket_t fd, short what, void *arg) {
  struct event **ep = (struct event **)arg;
  (void)fd;
  (void)what;
  // event_remove_timer(ep[0]);
  // event_remove_timer(ep[1]);
  htimer_del(ep[0]->timer);
  htimer_del(ep[1]->timer);
}

static void send_a_byte_cb(evutil_socket_t fd, short what, void *arg) {
  evutil_socket_t *sockp = (evutil_socket_t *)arg;
  (void)fd;
  (void)what;
  if (write(*sockp, "A", 1) < 0)
    FAIL("write");
}

TEST_CASE("test_event_remove_timeout") {
  struct event_base *base = event_base_new();
  struct event *ev[5];
  int ev1_fired = 0;
  struct timeval ms25 = {0, 25 * 1000}, ms40 = {0, 40 * 1000},
                 ms75 = {0, 75 * 1000}, ms125 = {0, 125 * 1000};
  struct read_not_timeout_param rntp = {ev, 0, 0};
  evutil_socket_t spair[2] = {-1, -1};
  evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, spair);
  evutil_make_socket_nonblocking(spair[0]);
  evutil_make_socket_nonblocking(spair[1]);

  ev[0] = event_new(base, spair[0], EV_READ | EV_PERSIST, read_not_timeout_cb,
                    &rntp);
  ev[1] = evtimer_new(base, incr_arg_cb, &ev1_fired);
  ev[2] = evtimer_new(base, remove_timers_cb, ev);
  ev[3] = evtimer_new(base, send_a_byte_cb, &spair[1]);
  ev[4] = evtimer_new(base, send_a_byte_cb, &spair[1]);
  event_add(ev[2], &ms25);  /* remove timers */
  event_add(ev[4], &ms40);  /* write to test if timer re-activates */
  event_add(ev[0], &ms75);  /* read */
  event_add(ev[1], &ms75);  /* timer */
  event_add(ev[3], &ms125); /* timeout. */

  event_base_dispatch(base);

  CHECK_EQ(ev1_fired, 0);
  CHECK_EQ(rntp.events, EV_READ);

end:
  event_free(ev[0]);
  event_free(ev[1]);
  event_free(ev[2]);
  event_free(ev[3]);
  event_free(ev[4]);
  event_base_free(base);
}

TEST_CASE("test_simpletimeout") {
  struct event_base *base = event_base_new();
  struct timeval tv;
  struct event ev;

  tv.tv_usec = 200 * 1000;
  tv.tv_sec = 0;
  evutil_timerclear(&tcalled);
  event_assign(&ev, base, -1, 0, timeout_cb, NULL);
  evtimer_add(&ev, &tv);

  evutil_gettimeofday(&tset, NULL);
  event_base_dispatch(base);
  CHECK_TIME(&tset, &tcalled, 200);

  event_base_free(base);
}

struct event_base *global_base = NULL;

static void periodic_timeout_cb(evutil_socket_t fd, short event, void *arg) {
  int *count = (int *)arg;

  (*count)++;
  if (*count == 6) {
    /* call loopexit only once - on slow machines(?), it is
     * apparently possible for this to get called twice. */
    event_base_loopexit(global_base, NULL);
  }
}

TEST_CASE("test_persistent_timeout") {
  struct event_base *base = event_base_new();
  global_base = base;
  struct timeval tv;
  struct event ev;
  int count = 0;

  evutil_timerclear(&tv);
  tv.tv_usec = 10000;

  event_assign(&ev, base, -1, EV_TIMEOUT | EV_PERSIST, periodic_timeout_cb,
               &count);
  event_add(&ev, &tv);

  event_base_dispatch(base);

  CHECK_EQ(count, 6);

  event_del(&ev);
  global_base = NULL;
  event_base_free(base);
}

TEST_CASE("test_persistent_timeout_jump") {
  struct event_base *base = event_base_new();
  struct event ev;
  int count = 0;
  struct timeval msec100 = {0, 100 * 1000};
  struct timeval msec50 = {0, 50 * 1000};

  event_assign(&ev, base, -1, EV_PERSIST, periodic_timeout_cb, &count);
  event_add(&ev, &msec100);
  /* Wait for a bit */
  hv_msleep(300);
  event_base_loopexit(base, &msec50);
  event_base_dispatch(base);
  CHECK_EQ(count, 1);

  event_del(&ev);
  event_base_free(base);
}

#define EVBUFFER_DATA(x) evbuffer_pullup((x), -1)

static int evbuffer_validate(struct evbuffer *buf) {
  struct evbuffer_chain *chain;
  size_t sum = 0;

  if (buf->first == NULL) {
    CHECK(buf->last == NULL);
    CHECK(buf->total_len == 0);
  }

  chain = buf->first;

  while (chain != NULL) {
    sum += chain->off;
    if (chain->next == NULL) {
      CHECK(buf->last == chain);
    }
    CHECK(chain->buf.len >= chain->misalign + chain->off);
    chain = chain->next;
  }

  if (buf->first)
    CHECK(buf->last_with_datap);

  if (buf->last_with_datap) {
    chain = buf->last_with_datap;
    if (chain->off == 0) {
      CHECK(buf->total_len == 0);
      CHECK(chain == buf->first);
    }
    chain = chain->next;
    while (chain != NULL) {
      CHECK(chain->off == 0);
      chain = chain->next;
    }
  } else {
    CHECK(buf->first == NULL);
    CHECK(buf->last == NULL);
    CHECK(buf->last_with_datap == NULL);
    CHECK(buf->total_len == 0);
  }

  CHECK(sum == buf->total_len);
  return 1;
}

TEST_CASE("test_evbuffer") {
  static char buffer[512], *tmp;
  struct evbuffer *evb = evbuffer_new();
  struct evbuffer *evb_two = evbuffer_new();
  size_t sz_tmp;
  int i;

  evbuffer_validate(evb);
  evbuffer_add_printf(evb, "%s/%d", "hello", 1);
  evbuffer_validate(evb);

  CHECK(evbuffer_get_length(evb) == 7);
  CHECK(!memcmp((char *)EVBUFFER_DATA(evb), "hello/1", strlen("hello/1")));

  evbuffer_add_buffer(evb, evb_two);
  evbuffer_validate(evb);

  evbuffer_drain(evb, strlen("hello/"));
  evbuffer_validate(evb);
  CHECK(evbuffer_get_length(evb) == 1);
  CHECK(!memcmp((char *)EVBUFFER_DATA(evb), "1", 1));

  evbuffer_add_printf(evb_two, "%s", "/hello");
  CHECK(evbuffer_get_length(evb_two) == strlen("/hello"));
  evbuffer_validate(evb);
  evbuffer_add_buffer(evb, evb_two);
  evbuffer_validate(evb);

  CHECK(evbuffer_get_length(evb_two) == 0);
  CHECK(evbuffer_get_length(evb) == 7);
  unsigned char *fuck = evbuffer_pullup((evb), -1);
  CHECK(!memcmp((char *)EVBUFFER_DATA(evb), "1/hello", strlen("1/hello")));

  memset(buffer, 0, sizeof(buffer));
  evbuffer_add(evb, buffer, sizeof(buffer));
  evbuffer_validate(evb);
  CHECK(evbuffer_get_length(evb) == 7 + 512);

  tmp = (char *)evbuffer_pullup(evb, 7 + 512);
  CHECK(tmp);
  CHECK(!strncmp(tmp, "1/hello", 7));
  CHECK(!memcmp(tmp + 7, buffer, sizeof(buffer)));
  evbuffer_validate(evb);

  evbuffer_prepend(evb, "something", 9);
  evbuffer_validate(evb);
  evbuffer_prepend(evb, "else", 4);
  evbuffer_validate(evb);

  tmp = (char *)evbuffer_pullup(evb, 4 + 9 + 7);
  CHECK(!strncmp(tmp, "elsesomething1/hello", 4 + 9 + 7));
  evbuffer_validate(evb);

  evbuffer_drain(evb, -1);
  evbuffer_validate(evb);
  evbuffer_drain(evb_two, -1);
  evbuffer_validate(evb);

  for (i = 0; i < 3; ++i) {
    evbuffer_add(evb_two, buffer, sizeof(buffer));
    evbuffer_validate(evb_two);
    evbuffer_add_buffer(evb, evb_two);
    evbuffer_validate(evb);
    evbuffer_validate(evb_two);
  }

  CHECK(evbuffer_get_length(evb_two) == 0);
  CHECK(evbuffer_get_length(evb) == i * sizeof(buffer));

end:
  evbuffer_free(evb);
  evbuffer_free(evb_two);
}

static void evbuffer_get_waste(struct evbuffer *buf, size_t *allocatedp,
                               size_t *wastedp, size_t *usedp) {
  struct evbuffer_chain *chain;
  size_t a, w, u;
  int n = 0;
  u = a = w = 0;

  chain = buf->first;
  /* skip empty at start */
  while (chain && chain->off == 0) {
    ++n;
    a += chain->buf.len;
    chain = chain->next;
  }
  /* first nonempty chain: stuff at the end only is wasted. */
  if (chain) {
    ++n;
    a += chain->buf.len;
    u += chain->off;
    if (chain->next && chain->next->off)
      w += (size_t)(chain->buf.len - (chain->misalign + chain->off));
    chain = chain->next;
  }
  /* subsequent nonempty chains */
  while (chain && chain->off) {
    ++n;
    a += chain->buf.len;
    w += (size_t)chain->misalign;
    u += chain->off;
    if (chain->next && chain->next->off)
      w += (size_t)(chain->buf.len - (chain->misalign + chain->off));
    chain = chain->next;
  }
  /* subsequent empty chains */
  while (chain) {
    ++n;
    a += chain->buf.len;
  }
  *allocatedp = a;
  *wastedp = w;
  *usedp = u;
}

TEST_CASE("test_evbuffer_expand") {
  char data[4096];
  struct evbuffer *buf;
  size_t a, w, u;
  void *buffer;

  memset(data, 'X', sizeof(data));

  /* Make sure that expand() works on an empty buffer */
  buf = evbuffer_new();
  CHECK_EQ(evbuffer_expand(buf, 20000), 0);
  evbuffer_validate(buf);
  a = w = u = 0;
  evbuffer_get_waste(buf, &a, &w, &u);
  CHECK(w == 0);
  CHECK(u == 0);
  CHECK(a >= 20000);
  CHECK(buf->first);
  CHECK(buf->first == buf->last);
  CHECK(buf->first->off == 0);
  CHECK(buf->first->buf.len >= 20000);

  /* Make sure that expand() works as a no-op when there's enough
   * contiguous space already. */
  buffer = buf->first->buf.base;
  evbuffer_add(buf, data, 1024);
  CHECK_EQ(evbuffer_expand(buf, 1024), 0);
  CHECK(buf->first->buf.base == buffer);
  evbuffer_validate(buf);
  evbuffer_free(buf);

  /* Make sure that expand() can work by moving misaligned data
   * when it makes sense to do so. */
  buf = evbuffer_new();
  evbuffer_add(buf, data, 400);
  {
    int n = (int)(buf->first->buf.len - buf->first->off - 1);
    CHECK(n < (int)sizeof(data));
    evbuffer_add(buf, data, n);
  }
  CHECK(buf->first == buf->last);
  CHECK(buf->first->off == buf->first->buf.len - 1);
  evbuffer_drain(buf, buf->first->off - 1);
  CHECK(1 == evbuffer_get_length(buf));
  CHECK(buf->first->misalign > 0);
  CHECK(buf->first->off == 1);
  buffer = buf->first->buf.base;
  CHECK(evbuffer_expand(buf, 40) == 0);
  CHECK(buf->first == buf->last);
  CHECK(buf->first->off == 1);
  CHECK(buf->first->buf.base == buffer);
  CHECK(buf->first->misalign == 0);
  evbuffer_validate(buf);
  evbuffer_free(buf);

  /* add, expand, pull-up: This used to crash libevent. */
  buf = evbuffer_new();

  evbuffer_add(buf, data, sizeof(data));
  evbuffer_add(buf, data, sizeof(data));
  evbuffer_add(buf, data, sizeof(data));

  evbuffer_validate(buf);
  evbuffer_expand(buf, 1024);
  evbuffer_validate(buf);
  evbuffer_pullup(buf, -1);
  evbuffer_validate(buf);

end:
  evbuffer_free(buf);
}

static void no_cleanup(const void *data, size_t datalen, void *extra) {}

TEST_CASE("test_evbuffer_remove_buffer_with_empty") {
  struct evbuffer *src = evbuffer_new();
  struct evbuffer *dst = evbuffer_new();
  char buf[2] = {'A', 'A'};

  evbuffer_validate(src);
  evbuffer_validate(dst);

  /* setup the buffers */
  /* we need more data in src than we will move later */
  evbuffer_add_reference(src, buf, sizeof(buf), no_cleanup, NULL);
  evbuffer_add_reference(src, buf, sizeof(buf), no_cleanup, NULL);
  /* we need one buffer in dst and one empty buffer at the end */
  evbuffer_add(dst, buf, sizeof(buf));
  evbuffer_add_reference(dst, buf, 0, no_cleanup, NULL);

  evbuffer_validate(src);
  evbuffer_validate(dst);
  CHECK_EQ(memcmp(evbuffer_pullup(src, -1), "AAAA", 4), 0);
  CHECK_EQ(memcmp(evbuffer_pullup(dst, -1), "AA", 2), 0);

end:
  evbuffer_free(src);
  evbuffer_free(dst);
}

TEST_CASE("test_evbuffer_remove_buffer_with_empty2") {
  struct evbuffer *src = evbuffer_new();
  struct evbuffer *dst = evbuffer_new();
  struct evbuffer *buf = evbuffer_new();

  evbuffer_add(buf, "foo", 3);
  evbuffer_add_reference(buf, "foo", 3, NULL, NULL);

  evbuffer_add_reference(src, "foo", 3, NULL, NULL);
  evbuffer_add_reference(src, NULL, 0, NULL, NULL);
  evbuffer_add_buffer(src, buf);

  evbuffer_add(buf, "foo", 3);
  evbuffer_add_reference(buf, "foo", 3, NULL, NULL);

  evbuffer_add_reference(dst, "foo", 3, NULL, NULL);
  evbuffer_add_reference(dst, NULL, 0, NULL, NULL);
  evbuffer_add_buffer(dst, buf);

  CHECK(evbuffer_get_length(src) == 9);
  CHECK(evbuffer_get_length(dst) == 9);

  evbuffer_validate(src);
  evbuffer_validate(dst);

  CHECK_EQ(memcmp(evbuffer_pullup(src, -1), "foofoofoo", 9), 0);
  CHECK_EQ(memcmp(evbuffer_pullup(dst, -1), "foofoofoo", 9), 0);

end:
  evbuffer_free(src);
  evbuffer_free(dst);
  evbuffer_free(buf);
}

#define TEST_STR                                                               \
  "Now is the time for all good events to signal for "                         \
  "the good of their protocol"

static int n_strings_read = 0;
static int n_reads_invoked = 0;
static int bufferevent_connect_test_flags = 0;
static int bufferevent_trigger_test_flags = 0;

static void sender_writecb(struct bufferevent *bev, void *ctx) {
  // // printf("sender_writecb\n");
  if (evbuffer_get_length(bufferevent_get_output(bev)) == 0) {
    bufferevent_disable(bev, EV_READ | EV_WRITE);
    bufferevent_free(bev);
  }
}

static void sender_errorcb(struct bufferevent *bev, short what, void *ctx) {
  FAIL(("Got sender error %d", (int)what));
}

static void listen_cb(struct evconnlistener *listener, evutil_socket_t fd,
                      struct sockaddr *sa, int socklen, void *arg) {
  // // printf("listen_cb\n");
  struct event_base *base = (struct event_base *)arg;
  struct bufferevent *bev;
  const char s[] = TEST_STR;
  bev = bufferevent_socket_new(base, fd, bufferevent_connect_test_flags);
  CHECK(bev);
  bufferevent_setcb(bev, NULL, sender_writecb, sender_errorcb, NULL);
  bufferevent_write(bev, s, sizeof(s));
end:;
}

static void reader_readcb(struct bufferevent *bev, void *ctx) {
  // printf("reader_readcb\n");
  n_reads_invoked++;
}

static void reader_eventcb(struct bufferevent *bev, short what, void *ctx) {
  // printf("reader_eventcb\n");
  struct event_base *base = (struct event_base *)ctx;
  if (what & BEV_EVENT_ERROR) {
    // printf("BEV_EVENT_ERROR\n");
    perror("foobar");
    FAIL(("got connector error %d", (int)what));
    return;
  }
  if (what & BEV_EVENT_CONNECTED) {
    // printf("BEV_EVENT_CONNECTED\n");
    bufferevent_enable(bev, EV_READ);
  }
  if (what & BEV_EVENT_EOF) {
    // printf("BEV_EVENT_EOF\n");
    char buf[512];
    size_t n;
    n = bufferevent_read(bev, buf, sizeof(buf) - 1);
    CHECK(n >= 0);
    buf[n] = '\0';
    CHECK(strcmp(buf, TEST_STR) == 0);
    if (++n_strings_read == 2)
      event_base_loopexit(base, NULL);
  }
end:;
}

TEST_CASE("test_bufferevent_connect") {
  n_strings_read = 0;
  n_reads_invoked = 0;
  bufferevent_connect_test_flags = 0;

  struct event_base *base = event_base_new();
  struct evconnlistener *lev = NULL;
  struct bufferevent *bev1 = NULL, *bev2 = NULL;
  struct sockaddr_in localhost;
  struct sockaddr_storage ss;
  struct sockaddr *sa;
  ev_socklen_t slen;

  int be_flags = BEV_OPT_CLOSE_ON_FREE;
  bufferevent_connect_test_flags = be_flags;

  memset(&localhost, 0, sizeof(localhost));

  localhost.sin_port = 0; /* pick-a-port */
  localhost.sin_addr.s_addr = htonl(0x7f000001L);
  localhost.sin_family = AF_INET;
  sa = (struct sockaddr *)&localhost;
  lev = evconnlistener_new_bind(base, listen_cb, base,
                                LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, 16,
                                sa, sizeof(localhost));
  CHECK(lev);

  sa = (struct sockaddr *)&ss;
  slen = sizeof(ss);
  if (getsockname(lev->lev_e->listener.fd, sa, &slen) < 0) {
    FAIL("getsockname");
  }

  CHECK(!evconnlistener_enable(lev));
  bev1 = bufferevent_socket_new(base, -1, be_flags);
  bev2 = bufferevent_socket_new(base, -1, be_flags);
  CHECK(bev1);
  CHECK(bev2);
  bufferevent_setcb(bev1, reader_readcb, NULL, reader_eventcb, base);
  bufferevent_setcb(bev2, reader_readcb, NULL, reader_eventcb, base);

  bufferevent_enable(bev1, EV_READ);
  bufferevent_enable(bev2, EV_READ);

  CHECK(!bufferevent_socket_connect(bev1, sa, sizeof(localhost)));
  CHECK(!bufferevent_socket_connect(bev2, sa, sizeof(localhost)));

  event_base_dispatch(base);

  CHECK(n_strings_read == 2);
  CHECK(n_reads_invoked >= 2);
end:
  if (lev)
    evconnlistener_free(lev);

  if (bev1)
    bufferevent_free(bev1);

  if (bev2)
    bufferevent_free(bev2);
  event_base_free(base);
}

static int n_events_invoked = 0;

static evutil_socket_t fake_listener_create(struct sockaddr_in *localhost) {
  struct sockaddr *sa = (struct sockaddr *)localhost;
  evutil_socket_t fd = -1;
  ev_socklen_t slen = sizeof(*localhost);

  memset(localhost, 0, sizeof(*localhost));
  localhost->sin_port = 0; /* have the kernel pick a port */
  localhost->sin_addr.s_addr = htonl(0x7f000001L);
  localhost->sin_family = AF_INET;

  /* bind, but don't listen or accept. should trigger
     "Connection refused" reliably on most platforms. */
  fd = socket(localhost->sin_family, SOCK_STREAM, 0);
  CHECK(fd >= 0);
  CHECK(bind(fd, sa, slen) == 0);
  CHECK(getsockname(fd, sa, &slen) == 0);

  return fd;

end:
  return -1;
}

static void reader_eventcb_simple(struct bufferevent *bev, short what,
                                  void *ctx) {
  n_events_invoked++;
}

static void close_socket_cb(evutil_socket_t fd, short what, void *arg) {
  evutil_socket_t *fdp = (evutil_socket_t *)arg;
  if (*fdp >= 0) {
    evutil_closesocket(*fdp);
    *fdp = -1;
  }
}

TEST_CASE("test_bufferevent_connect_fail_eventcb") {
  n_strings_read = 0;
  n_reads_invoked = 0;
  bufferevent_connect_test_flags = 0;
  n_events_invoked = 0;

  struct event_base *base = event_base_new();
  int flags = BEV_OPT_CLOSE_ON_FREE;
  struct event close_listener_event;
  struct bufferevent *bev = NULL;
  struct evconnlistener *lev = NULL;
  struct sockaddr_in localhost;
  struct timeval close_timeout = {0, 300000};
  ev_socklen_t slen = sizeof(localhost);
  evutil_socket_t fake_listener = -1;
  int r;

  fake_listener = fake_listener_create(&localhost);

  CHECK(n_events_invoked == 0);

  bev = bufferevent_socket_new(base, -1, flags);
  CHECK(bev);
  bufferevent_setcb(bev, reader_readcb, reader_readcb, reader_eventcb_simple,
                    base);
  bufferevent_enable(bev, EV_READ | EV_WRITE);
  CHECK(n_events_invoked == 0);
  CHECK(n_reads_invoked == 0);

  /** @see also test_bufferevent_connect_fail() */
  r = bufferevent_socket_connect(bev, (struct sockaddr *)&localhost, slen);
  /* XXXX we'd like to test the '0' case everywhere, but FreeBSD tells
   * detects the error immediately, which is not really wrong of it. */
  short temp = (r == 0 /*|| r == -1*/);
  CHECK(temp);

  CHECK(n_events_invoked == 0);
  CHECK(n_reads_invoked == 0);

  /* Close the listener socket after a delay. This should trigger
     "connection refused" on some other platforms, including OSX. */
  evtimer_assign(&close_listener_event, base, close_socket_cb, &fake_listener);
  event_add(&close_listener_event, &close_timeout);

  event_base_dispatch(base);
  CHECK(n_events_invoked == 1);
  CHECK(n_reads_invoked == 0);

end:
  if (lev)
    evconnlistener_free(lev);
  if (bev)
    bufferevent_free(bev);
  if (fake_listener >= 0)
    evutil_closesocket(fake_listener);
  event_base_free(base);
}

static int test_ok = 0;

static void want_fail_eventcb(struct bufferevent *bev, short what, void *ctx) {
  struct event_base *base = (struct event_base *)ctx;
  const char *err;
  evutil_socket_t s;

  if (what & BEV_EVENT_ERROR) {
    s = bev->ev_read.fd;
    err = evutil_socket_error_to_string(evutil_socket_geterror(s));
    test_ok = 1;
  } else {
    FAIL(("didn't fail? what %hd", what));
  }

  event_base_loopexit(base, NULL);
}

TEST_CASE("test_bufferevent_connect_fail") {
  struct event_base *base = event_base_new();
  struct bufferevent *bev = NULL;
  struct event close_listener_event;
  int close_listener_event_added = 0;
  struct timeval close_timeout = {0, 300000};
  struct sockaddr_in localhost;
  ev_socklen_t slen = sizeof(localhost);
  evutil_socket_t fake_listener = -1;
  int r;

  test_ok = 0;

  fake_listener = fake_listener_create(&localhost);
  bev = bufferevent_socket_new(base, -1,
                               BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
  CHECK(bev);
  bufferevent_setcb(bev, NULL, NULL, want_fail_eventcb, base);

  r = bufferevent_socket_connect(bev, (struct sockaddr *)&localhost, slen);
  /* XXXX we'd like to test the '0' case everywhere, but FreeBSD tells
   * detects the error immediately, which is not really wrong of it. */
  short temp = (r == 0 /*|| r == -1*/);
  CHECK(temp);

  /* Close the listener socket after a delay. This should trigger
     "connection refused" on some other platforms, including OSX. */
  evtimer_assign(&close_listener_event, base, close_socket_cb, &fake_listener);
  event_add(&close_listener_event, &close_timeout);
  close_listener_event_added = 1;

  event_base_dispatch(base);

  CHECK(test_ok == 1);

end:
  if (fake_listener >= 0)
    evutil_closesocket(fake_listener);

  if (bev)
    bufferevent_free(bev);

  if (close_listener_event_added)
    event_del(&close_listener_event);
  event_base_free(base);
}

struct timeout_cb_result {
  struct timeval read_timeout_at;
  struct timeval write_timeout_at;
  struct timeval last_wrote_at;
  struct timeval last_read_at;
  int n_read_timeouts;
  int n_write_timeouts;
  int total_calls;
};

static void bev_timeout_read_cb(struct bufferevent *bev, void *arg) {
  struct timeout_cb_result *res = (struct timeout_cb_result *)arg;
  evutil_gettimeofday(&res->last_read_at, NULL);
}

static void bev_timeout_write_cb(struct bufferevent *bev, void *arg) {
  struct timeout_cb_result *res = (struct timeout_cb_result *)arg;
  evutil_gettimeofday(&res->last_wrote_at, NULL);
}

static void bev_timeout_event_cb(struct bufferevent *bev, short what,
                                 void *arg) {
  struct timeout_cb_result *res = (struct timeout_cb_result *)arg;
  ++res->total_calls;

  if ((what & (BEV_EVENT_READING | BEV_EVENT_TIMEOUT)) ==
      (BEV_EVENT_READING | BEV_EVENT_TIMEOUT)) {
    evutil_gettimeofday(&res->read_timeout_at, NULL);
    ++res->n_read_timeouts;
  }
  if ((what & (BEV_EVENT_WRITING | BEV_EVENT_TIMEOUT)) ==
      (BEV_EVENT_WRITING | BEV_EVENT_TIMEOUT)) {
    evutil_gettimeofday(&res->write_timeout_at, NULL);
    ++res->n_write_timeouts;
  }
}

TEST_CASE("test_bufferevent_timeouts") {
  /* "arg" is a string containing "pair" and/or "filter". */
  struct event_base *base = event_base_new();
  struct bufferevent *bev1 = NULL, *bev2 = NULL;
  int use_pair = 0, use_filter = 0;
  struct timeval tv_w, tv_r, started_at;
  struct timeout_cb_result res1, res2;

  memset(&res1, 0, sizeof(res1));
  memset(&res2, 0, sizeof(res2));

  evutil_socket_t spair[2] = {-1, -1};
  evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, spair);
  evutil_make_socket_nonblocking(spair[0]);
  evutil_make_socket_nonblocking(spair[1]);
  bev1 = bufferevent_socket_new(base, spair[0], 0);
  bev2 = bufferevent_socket_new(base, spair[1], 0);
  CHECK(bev1);
  CHECK(bev2);

  /* Do this nice and early. */
  bufferevent_disable(bev2, EV_READ);

  /* bev1 will try to write and read.  Both will time out. */
  evutil_gettimeofday(&started_at, NULL);
  tv_w.tv_sec = tv_r.tv_sec = 0;
  tv_w.tv_usec = 100 * 1000;
  tv_r.tv_usec = 150 * 1000;
  bufferevent_setcb(bev1, bev_timeout_read_cb, bev_timeout_write_cb,
                    bev_timeout_event_cb, &res1);
  bufferevent_set_timeouts(bev1, &tv_r, &tv_w);
  bufferevent_write(bev1, "ABCDEFG", 7);
  bufferevent_enable(bev1, EV_READ | EV_WRITE);

  /* bev2 has nothing to say, and isn't listening. */
  bufferevent_setcb(bev2, bev_timeout_read_cb, bev_timeout_write_cb,
                    bev_timeout_event_cb, &res2);
  tv_w.tv_sec = tv_r.tv_sec = 0;
  tv_w.tv_usec = 200 * 1000;
  tv_r.tv_usec = 100 * 1000;
  bufferevent_set_timeouts(bev2, &tv_r, &tv_w);
  bufferevent_enable(bev2, EV_WRITE);

  tv_r.tv_sec = 0;
  tv_r.tv_usec = 350 * 1000;

  event_base_loopexit(base, &tv_r);
  event_base_dispatch(base);

  /* XXXX Test that actually reading or writing a little resets the
   * timeouts. */

  // CHECK(res1.total_calls == 2);
  // CHECK(res1.n_read_timeouts == 1);
  // CHECK(res1.n_write_timeouts == 1);
  // CHECK(res2.total_calls == !(use_pair && !use_filter));
  // CHECK(res2.n_write_timeouts == !(use_pair && !use_filter));
  // CHECK(!res2.n_read_timeouts);

  // printf("res1.total_calls: %d\n", res1.total_calls);
  // printf("res1.n_read_timeouts: %d\n", res1.n_read_timeouts);
  // printf("res1.n_write_timeouts: %d\n", res1.n_write_timeouts);
  // printf("res2.total_calls: %d\n", res2.total_calls);
  // printf("res2.n_write_timeouts: %d\n", res2.n_write_timeouts);
  // printf("!res2.n_read_timeouts: %d\n", !res2.n_read_timeouts);

  CHECK_TIME(&started_at, &res1.read_timeout_at, 150);
  // CHECK_TIME(&started_at, &res1.write_timeout_at, 100);

  // #define tt_assert_timeval_empty(tv)                                            \
//   do {                                                                         \
//     CHECK((tv).tv_sec == 0);                                                   \
//     CHECK((tv).tv_usec == 0);                                                  \
//   } while (0)
  //   tt_assert_timeval_empty(res1.last_read_at);
  //   tt_assert_timeval_empty(res2.last_read_at);
  //   tt_assert_timeval_empty(res2.last_wrote_at);
  //   tt_assert_timeval_empty(res2.last_wrote_at);
  // #undef tt_assert_timeval_empty

end:
  if (bev1)
    bufferevent_free(bev1);
  if (bev2)
    bufferevent_free(bev2);
  event_base_free(base);
}

static int regress_get_listener_addr(struct evconnlistener *lev,
                                     struct sockaddr *sa,
                                     ev_socklen_t *socklen) {
  evutil_socket_t s = lev->lev_e->listener.fd;
  if (s <= 0)
    return -1;
  return getsockname(s, sa, socklen);
}

static void trigger_failure_cb(evutil_socket_t fd, short what, void *ctx) {
  FAIL(("The triggered callback did not fire or the machine is really slow "
        "(try increasing timeout)."));
}

static void trigger_eventcb(struct bufferevent *bev, short what, void *ctx) {
  struct event_base *base = (struct event_base *)ctx;
  if (what == ~0) {
    event_base_loopexit(base, NULL);
    return;
  }
  reader_eventcb(bev, what, ctx);
}

static void trigger_readcb_triggered(struct bufferevent *bev, void *ctx) {
  n_reads_invoked++;
  // bufferevent_trigger_event(bev, ~0, bufferevent_trigger_test_flags);
  bev->errorcb(bev, ~0, bev->cbarg);
}

static void trigger_readcb(struct bufferevent *bev, void *ctx) {
  struct timeval timeout = {30, 0};
  struct event_base *base = (struct event_base *)ctx;
  size_t low, high, len;
  int expected_reads;

  expected_reads = ++n_reads_invoked;
  bufferevent_setcb(bev, trigger_readcb_triggered, NULL, trigger_eventcb, ctx);
  len = evbuffer_get_length(bufferevent_get_input(bev));
  // bev->readcb(bev, bev->cbarg);
  /* no callback expected */
  CHECK(n_reads_invoked == expected_reads);
  expected_reads++;

  bev->readcb(bev, bev->cbarg);
  CHECK(n_reads_invoked == expected_reads);

end:;
}

TEST_CASE("test_bufferevent_trigger") {
  struct event_base *base = event_base_new();
  struct evconnlistener *lev = NULL;
  struct bufferevent *bev = NULL;
  struct sockaddr_in localhost;
  struct sockaddr_storage ss;
  struct sockaddr *sa;
  ev_socklen_t slen;

  int be_flags = BEV_OPT_CLOSE_ON_FREE;
  int trig_flags = 0;

  bufferevent_connect_test_flags = be_flags;
  bufferevent_trigger_test_flags = trig_flags;

  memset(&localhost, 0, sizeof(localhost));

  localhost.sin_port = 0; /* pick-a-port */
  localhost.sin_addr.s_addr = htonl(0x7f000001L);
  localhost.sin_family = AF_INET;
  sa = (struct sockaddr *)&localhost;
  lev = evconnlistener_new_bind(base, listen_cb, base,
                                LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, 16,
                                sa, sizeof(localhost));
  CHECK(lev);

  sa = (struct sockaddr *)&ss;
  slen = sizeof(ss);
  if (regress_get_listener_addr(lev, sa, &slen) < 0) {
    FAIL("getsockname");
  }

  CHECK(!evconnlistener_enable(lev));
  bev = bufferevent_socket_new(base, -1, be_flags);
  CHECK(bev);
  bufferevent_setcb(bev, trigger_readcb, NULL, trigger_eventcb, base);

  bufferevent_enable(bev, EV_READ);

  CHECK(!bufferevent_socket_connect(bev, sa, sizeof(localhost)));

  event_base_dispatch(base);

  CHECK(n_reads_invoked == 2);
end:
  if (lev)
    evconnlistener_free(lev);

  if (bev)
    bufferevent_free(bev);
  event_base_free(base);
}