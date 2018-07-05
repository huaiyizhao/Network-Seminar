cmake_minimum_required(VERSION 3.10)
project(code)

set(CMAKE_CXX_STANDARD 11)

include_directories(include)

add_executable(code
        include/arp.h
        include/arpcache.h
        include/async_wait.h
        include/base.h
        include/checksum.h
        include/ether.h
        include/hash.h
        include/icmp.h
        include/ip.h
        include/list.h
        include/log.h
        include/packet.h
        include/ring_buffer.h
        include/rtable.h
        include/synch_wait.h
        include/tcp.h
        include/tcp_apps.h
        include/tcp_hash.h
        include/tcp_sock.h
        include/tcp_timer.h
        include/types.h
        arp.c
        arpcache.c
        client.py
        icmp.c
        ip.c
        main.c
        Makefile
        packet.c
        rtable.c
        rtable_internal.c
        server.py
        tcp.c
        tcp_apps.c
        tcp_in.c
        tcp_out.c
        tcp_sock.c
        tcp_timer.c
        tcp_topo_loss.py)
