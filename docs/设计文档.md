<a name="BBShF"></a>
## 一、项目标题
libevhtp使用libhv替代libevent
<a name="p0UC4"></a>
## 二、项目目标

- 将libevhtp中使用到libevent中至少80%接口替代为使用libhv的接口，并且保持原有软件功能正常 。
- 代码以patch的形式合入libevhtp仓库的master分支。
- 替代的接口占原有使用接口的比例50%以上，并且覆盖80%的不同接口，对于无法替代的接口继续使用libevent，并提供对应的材料说明。
- 替代之后unbound的测试用例以及功能同原有一致。
- 注释/文档详尽。
<a name="APhLx"></a>
## 三、软件逻辑视图
![image.png](https://cdn.nlark.com/yuque/0/2023/png/26055455/1690006209627-bc57dc5c-3fdf-4738-9c1c-f7d1576377f0.png#averageHue=%23dedede&clientId=uaf4eb09c-2e58-4&from=paste&id=ub9d5778c&originHeight=307&originWidth=315&originalType=binary&ratio=2&rotation=0&showTitle=false&size=43521&status=done&style=none&taskId=u71ac971d-072f-41e1-b174-efce3ad3042&title=)
<a name="cBoUq"></a>
## 四、软件实现方案设计
:::info
总体思路：

- 使用libhv实现libevent的API，从而在无需修改libevhtp源码的情况下将底层的libevent替换为libhv。
:::
具体做法：

- 新增一个hv2ev.h文件。
- 在该文件中，基于libhv的API实现libevent的API，例如基于hloop_new实现event_base_new。
```c
HV_INLINE struct event_base *event_base_new(void) {
    struct event_base *base = NULL;
    HV_ALLOC(base, sizeof(struct event_base));
    base->loop = hloop_new(HLOOP_FLAG_QUIT_WHEN_NO_ACTIVE_EVENTS);
    base->timer = NULL;
    return base;
}
```

- hv2ev.h可以直接作为libevhtp的头文件之一，也可以尝试合入libhv的仓库。
- libevhtp只需include合适的头文件、链接到libhv库即可，最终目标如下图所示。

![image.png](https://cdn.nlark.com/yuque/0/2023/png/26055455/1690007860234-d7b5f369-89fa-47a7-b79d-0b3fc228e4c2.png#averageHue=%23dedede&clientId=uaf4eb09c-2e58-4&from=paste&id=u5bdc34c2&originHeight=307&originWidth=315&originalType=binary&ratio=2&rotation=0&showTitle=false&size=42613&status=done&style=none&taskId=ua45c0aff-5791-467d-afbc-89307cce439&title=)
> 注意事项：
> - 以libevent-2.1.12-stable的API为标准。
> - libevhtp自行设计了线程池模型，没有采用libevent的多线程接口和锁接口，因此基于libhv实现libevent API时，无需考虑接口的线程安全问题。
> - openEuler操作系统的内核是Linux，因此当遇到无法解决的跨平台问题时，以Linux为准。
> - libevent某些接口的功能复杂、参数众多，本项目优先实现libevhtp所涉及的部分。

<a name="VG9so"></a>
## 五、软件实现功能范围（替代类）
红色表示libevent中的结构体或接口<br />蓝色表示libhv中的结构体或接口

| **libevent结构体** | **描述** | **实现思路** |
| --- | --- | --- |
| event_base | 持有事件循环的信息和状态 | 与libhv中hloop_t结构体类似，可在hloop_t上进行一定扩展 |
| event | 持有事件的信息和状态 | 与libhv中的hio_t、htimer_t等结构体类似 |
| evconnlistener_event | 用于监听tcp连接的结构体<br />**注意**：准确来说，evconnlistener和event共同组成了evconnlistener_event。evconnlistener用于保存监听器的一些元数据和状态信息，event用于监听读事件。 | evconnlistener_event本质上来说就是一个用于监听某端口读事件的结构体，可以通过hio_t外加一些必要的信息实现 |
| evbuffer | 一块读写缓冲区，其内部其实是由多块非连续缓冲区组成的链表结构 | hbuf_t是一块连续缓冲区，可以基于它实现类似evbuffer的结构 |
| bufferevent | 用于处理IO事件且带有读写缓冲区的结构体 | 根据之前的设计，我们基于hio_t、htimer_t实现了event，基于hbuf_t实现了evbuffer，在这两个结构体的基础上进行一定扩展，可以实现类似bufferevent的结构体 |

| **libevent接口** | **描述** | **实现思路** |
| --- | --- | --- |
| event_base_new() | 创建并返回一个event_base结构体 | 创建并返回一个由hloop_t及其它必要信息构成的结构体 |
| event_base_free() | 销毁event_base结构体 | 释放相应内存空间并调用hloop_free() |
| event_base_loop() | 开启事件循环 | 可以用hloop_run()开启事件循环 |
| event_base_loopbreak() | 退出事件循环 | hloop_stop()通过设置某个标志位，使得事件循环停止 |
| event_base_loopexit() | 在超时时退出事件循环，若没有指定超时时间，即刻退出循环 | 用hloop_t和htimer_t共同构成event_base，以实现超时退出的功能 |
| event_base_gettimeofday_cached() | 获取当前时间，如果可能的话，从event_base中获取缓存的时间，以减少系统调用 | libhv中使用gettimeofday()来获取当前时间 |
| event_set_mem_functions() | 用于设置自定义的内存管理策略，默认使用mallock、free、realloc等glibc的接口 | libhv没有自定义内存管理策略的功能，不过这不影响主体功能，可以暂时忽略 |
| **----------------------------------------------------------------------------------------------------------------------------------------** |  |  |
| event_new() | 创建并返回一个event结构体 | event结构体可以同时处理io事件、定时器事件和信号事件。可以创建并返回一个由hio_t和htimer_t及其它必要信息构成的结构体 |
| event_free() | 销毁event结构体 | 释放相应内存空间并调用hio_del()、htimer_del()、hio_close()等 |
| event_add() | 添加event到event_base中，并开启监听相应事件 | 使用hio_add()和htimer_add()将需要监听的事件加入hloop_t即可 |
| event_active() | 激活event<br />**注意**：激活效果是一次性，不会受event_base已有事件的影响，也不会影响event_base的已有事件 | hloop_post_event()可以实现类似功能 |
| **----------------------------------------------------------------------------------------------------------------------------------------** |  |  |
| evconnlistener_new() | 监听指定文件描述符的tcp连接，创建一个evconnlistener_event结构体，并返回其中的evconnlistener部分 | 使用系统调用listen()来开启监听，创建一个由hio_t和其它必要信息构成的结构体，并返回合适的部分 |
| evutil_make_socket_nonblocking() | 设置某文件描述符为non-blocking模式 | 可以直接用宏nonblocking替代 |
| evutil_make_socket_closeonexec() | 设置某文件描述符为close-on-exe模式 | 没有可以直接替代的接口或宏，但由于其功能简单，可以直接用fcntl()系统调用实现 |
| evutil_closesocket() | 关闭套接字 | 可以直接用宏SAFE_CLOSESOCKET替代 |
| evutil_socketpair() | 创建一对关联套接字 | 可以直接用Socketpair()替代 |
| evutil_inet_pton() | 解析一个ip地址 | ResolveAddr()实现了类似功能，但需要一定额外封装 |
| evutil_inet_ntop() | 网络地址转换为可读的字符串表示形式 | sockaddr_ip()具有类似的功能 |
| **----------------------------------------------------------------------------------------------------------------------------------------** |  |  |
| evbuffer_new() | 创建并返回一个evbuffer结构体 | 可以使用多个hbuf_t结构体形成链表的结构，构造一种新的并且类似evbuffer结构体 |
| evbuffer_free() | 销毁evbuffer结构体 | 使用宏HV_FREE释放相应内存空间 |
| evbuffer_get_length() | 返回evbuffer中存储的总字节数 | 在新结构体中额外增加一个变量来记录即可 |
| evbuffer_add() | 将数据附加到evbuffer的末尾 | 创建一块新的hbuf_t，并将数据复制进该hbuf_t，然后将该hbuf_t插入链表结尾 |
| evbuffer_add_printf() | 将格式化的数据附加到evbuffer的末尾 | 可以借助库函数sprintf()生成合适的格式化字符串，然后执行类似evbuffer_add()的逻辑 |
| evbuffer_add_buffer() | 将所有数据从一个evbuffer移至另一个evbuffer | 将必要的hbuf_t从一个链表上取下并挂载到另外一个链表 |
| evbuffer_add_iovec() | 一次性将多个iovec所包含的数据添加到evbuffer末尾 | 将所有数据拷贝到一个hbuf_t中，然后将该hbuf_t添加到相应链表 |
| evbuffer_drain() | 从evbuffer的开头删除指定数量的字节数据 | 删除链表中合适的hbuf_t节点 |
| evbuffer_pullup() | 使evbuffer从头开始指定长度的内存空间是连续的 | 合并链表头部的若干hbuf_t节点 |
| evbuffer_expand() | 扩展evbuffer的可用空间 | 创建适当大小的hbuf_t节点挂载到链表即可 |
| evbuffer_prepend() | 将数据添加到evbuffer的开头 | 创建一块新的hbuf_t，并将数据复制进该hbuf_t，然后将该hbuf_t插入链表头部 |
| evbuffer_add_reference() | 引用一块内存到evbuffer中，且没有复制操作 | 创建一块新的hbuf_t，让该hbuf_t指向需要引用的内存，然后将该hbuf_t插入链表头部 |
| **----------------------------------------------------------------------------------------------------------------------------------------** |  |  |
| bufferevent_socket_new() | 在现有套接字上创建并返回一个新的bufferevent | 基于hio_t、htimer_t和hbuf_t可以创建并返回一个功能和bufferevent相同的结构体，其中的hio_t需要与给定的套接字绑定 |
| bufferevent_free() | 释放与bufferevent结构体关联的内存空间 | 同理，释放相应内存并关闭IO |
| bufferevent_get_input() | 返回bufferevent中的输入缓冲区 | 基于hio_t、htimer_t和hbuf_t实现的类似bufferevent的结构体中，可以基于hbuf_t分别实现两个缓冲区，分别用于输入和输出。此时返回相应的输入缓冲区即可 |
| bufferevent_get_output() | 返回bufferevent中的输出缓冲区 | 返回相应的输出缓冲区即可 |
| bufferevent_enable() | 激活bufferevent的某个事件监听 | hio_read具有类似功能 |
| bufferevent_disable() | 关闭bufferevent的某个事件监听 | hio_write具有类似功能 |
| bufferevent_get_enabled() | 返回给定bufferevent上启用监听的事件 | 在基于hio_t、htimer_t和hbuf_t实现的类似bufferevent的结构体中增加一个short类型的变量，用于记录被激活的事件 |
| bufferevent_setcb() | 设置bufferevent的各种回调函数 | 在”类似bufferevent的结构体“中增加用于记录各种回调函数的成员变量（函数指针）。此时修改这些函数指针的值即可 |
| bufferevent_write_buffer() | 将某个evbuffer的数据写入bufferevent的输出缓冲区，且 evbuffer中的数据会被清除 | 调用evbuffer_add_buffer()即可，而evbuffer_add_buffer()在前面已经有了设计 |
| bufferevent_flush() | 强制bufferevent从底层IO读取或写入尽可能多的字节，忽略其他可能阻止写入的限制<br />**注意**：该函数对于socket-base的bufferevent没有任何作用，但libevhtp仍然使用了它，按理说可以直接忽略 | 该函数对于socket-base的bufferevent没有任何作用，但libevhtp仍然使用了它，按理说可以直接忽略 |
| bufferevent_set_timeouts() | 设置bufferevent所监听的读写事件的超时时间 | 在前面，已经基于hio_t、htimer_t设计了event结构体和event_add()。可以通过event_add()来调整读写事件的超时时间 |
| bufferevent_socket_connect() | 如果bufferevent尚未设置套接字，则为其分配一个新的流套接字，并使其为非阻塞模式 | Connect()提供了建立tcp连接的功能，可以用它为bufferevent建立连接进而设置相应的套接字 |
| bufferevent_socket_connect_hostname() | 比bufferevent_socket_connect()多了一个地址解析的动作 | ResolveAddr()可以用于实现地址解析 |
| bufferevent_shutdown() | 该接口在libevent-2.1.12-stable中已被废弃 | bufferevent_shutdown()不是libevhtp必须使用的接口，libevhtp会通过宏LIBEVENT_HAS_SHUTDOWN来判断当前链接的libevent库中是否有bufferevent_shutdown()，如果没有，则不会使用该接口 |
|  |  |  |
|  |  |  |
|  |  |  |
| bufferevent_get_openssl_error() |  | 待定 |
| bufferevent_openssl_socket_new() |  | 待定 |

<a name="hV6xJ"></a>
## 六、测试方法及测试用例
3个方面的测试

1. 语义一致性测试：
   1. 测试目的：测试基于libhv实现的libevent API与原生API的语义是否一致。
   2. 测试用例：libevent仓库的test目录下有大量的单元测试，可以直接挪用或仿写。
2. 功能正确性测试：
   1. 测试目的：验证替换后libevhtp的功能是否保持正常。
   2. 测试用例：libevhtp仓库的examples目录下有大量示例程序和测试程序，可以用于功能正确性的验证。



