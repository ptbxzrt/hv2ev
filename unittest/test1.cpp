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
  printf("time duration(ms): %ld\n", ms);
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