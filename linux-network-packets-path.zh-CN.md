---
layout: post
title: Linux 网络数据包路径
categories: [Linux, Network, Kernel]
---

## 简介

本文介绍 Linux 5.10 及更高版本内核中的 **TCP/IP** 和 **UDP/IP** 路径，并配有交互式图表。

目录：

- [交互式图表](#交互式图表)
- [出站路径（TX）](#出站路径tx)
- [入站路径（RX）](#入站路径rx)
- [参考资料](#参考资料)

## 交互式图表

下方图表追踪出站（**TX**）和入站（**RX**）路径中的主要内核函数，同时展示 `sk_buff` 缓冲区布局以及 **netfilter/eBPF** hook 点。

<p style="text-align:right; margin-bottom:6px;">
  <a href="./linux-packet-path-diagram.html" target="_blank" rel="noopener" style="font-size:13px;">
    ↗ 在新标签页中打开完整图表
  </a>
</p>
<iframe
  src="./linux-packet-path-diagram.html"
  style="width:100%; height:85vh; border:1px solid #2a3545; border-radius:8px; background:#0a0e14;"
  loading="lazy"
  allowfullscreen>
</iframe>
<noscript>
  <p><a href="./linux-packet-path-diagram.html">打开交互式图表</a>（需要 JavaScript）。</p>
</noscript>

---

## 出站路径（TX）

### 1. 用户态 → Socket 层

进程在 socket **fd** 上调用 `write()`、`send()` 或 `sendto()`。**VFS** 通过 `sock_sendmsg()` 分发请求；该函数从 **fd** 中获取 `struct sock`，附加来自 `task_struct` 的凭据（_PID/UID/GID_），执行 **LSM hook**（_SELinux/AppArmor_），然后通过 `sk_prot->sendmsg` 函数指针将请求分发给传输层协议。

`INDIRECT_CALL_INET` 宏通过对最常见的两种协议（_TCP/UDP_）进行硬编码检查，避免间接分支预测的开销；其他协议则回退到通用的间接调用。

### 2. 传输层 —— TCP

`tcp_sendmsg()` 首先检查连接是否处于 **ESTABLISHED** 状态，然后遍历用户缓冲区，按照 **MSS** 大小分配 `sk_buff` 结构。

数据通过 `skb_add_data_nocache()` 从用户态复制到内核态（写入已有的尾部空间），或者通过分配新页面来保存。

数据段会加入 socket 写队列（`sk->sk_write_queue`）。随后，`tcp_push()` → `tcp_write_xmit()` 遍历队列，应用拥塞窗口（`cwnd`）和接收窗口（`rwnd`）限制，设置重传定时器，构造 TCP 头部（_seq/ack/flags/window/options_），计算校验和（也可以通过 `CHECKSUM_PARTIAL` 延迟到硬件计算），最后通过 `icsk_af_ops->queue_xmit` 函数指针调用 `ip_queue_xmit()`。

### 传输层 —— UDP

`udp_sendmsg()` 的处理更简单：它通过 `ip_route_output_flow()` 解析路由，处理 **corking**（`UDP_CORK`，将多次 `sendmsg()` 调用合并为一个 IP 数据报）或 **non-corking**（立即发送），构造 UDP 头部并计算校验和，随后调用 `ip_make_skb()` + `udp_send_skb()` 将数据交给 IP 层。

### 3. IP 层

`__ip_queue_xmit()`（**TCP** 路径）或 `ip_push_pending_frames()`（**UDP** 路径）通过 **FIB**（_Forwarding Information Base，已编译的路由表）执行路由查找。

如果路由已经缓存在 `skb->_skb_refdst` 中，则会跳过查找。

随后构造 IP 头部（版本、IHL、TOS、TTL、协议、源/目的地址），并执行以下步骤：

- 触发 `NF_INET_LOCAL_OUT` netfilter hook；iptables/nftables 的 **OUTPUT** 链规则在此执行，连接跟踪也从这里开始。
- `ip_output()` 触发 `NF_INET_POST_ROUTING`；**POSTROUTING** 链在此执行（**SNAT/masquerade** 在此发生）。
- `ip_finish_output()` 检查 **MTU**，必要时通过 `ip_fragment()` 进行分片。如果设置了 **DF** 位（**PMTUD**），则不会进行分片。
- 邻居子系统解析 **L2** 地址：`neigh_resolve_output()` 执行 **ARP** 查找，或使用邻居缓存。如果没有 ARP 响应，`skb` 会暂存在邻居的 `arp_queue` 中，等待解析完成。
- 将以太网头部压入 `skb`。

### 4. Qdisc / 设备层

`dev_queue_xmit()` 设置 `skb->mac_header`，然后进入排队规则（**qdisc**）。默认排队规则是 `pfifo_fast`（现代发行版通常是 `fq_codel`）。`__qdisc_run()` 取出 `skb`，执行 `validate_xmit_skb()`（插入 VLAN 标签、在硬件支持时执行 GSO/TSO 分段、完成校验和），然后调用驱动的 `ndo_start_xmit()`。

`skb` 被放入 TX 环形缓冲区，通常对应 DMA 映射的环形描述符。驱动写入描述符，并通过 **MMIO** 写入敲响网卡的 doorbell 寄存器，触发发送。

**绕过路径：**

- `dev_direct_xmit()` 供 **XDP** 和 **AF_XDP** 使用，可以完全跳过 qdisc。
- `XDP_TX` 在驱动层反射数据包，不会进入更高层协议栈。
- TC 出站处理（`tc_egress()` / `tcf_classify()`）在 qdisc 入队和驱动之间运行 **tc-BPF** 或 **u32/flower** 分类器。

---

## 入站路径（RX）

### 1. 网卡 → 驱动

网卡通过 **DMA** 将数据包写入预先分配的环形缓冲区（**RX ring**），并在描述符中写入元数据（长度、校验和状态、RSS 哈希等），随后触发硬件中断（或 **MSI-X** 向量）。

驱动的 **ISR** 调用 `napi_schedule()` 安排 **NAPI** 轮询，然后屏蔽中断。中断合并非常关键：没有 NAPI 的话，每个数据包触发一次中断会严重损害吞吐量。

### 2. NAPI 轮询 / 驱动 → netdev

在 **softirq** 上下文（`NET_RX_SOFTIRQ`）中，`napi_poll()` 调用驱动的轮询函数。该函数遍历 RX ring，分配 `sk_buff` 结构，填充元数据（通过 `eth_type_trans()` 设置协议、设备和接收哈希等），然后调用 `napi_gro_receive()`。

**GRO（Generic Receive Offload，通用接收卸载）** 会将多个 TCP 段合并为一个较大的 `skb`，再向上传递，从而降低逐包处理的开销。

### 3. `netif_receive_skb()`

- 设置 `skb->mac_header`，并取出以太网头部。
- **af_packet** socket（_tcpdump/libpcap_）在此通过 `deliver_skb()` 获得数据包副本，副本会发送给所有注册的 `ptype_all` 处理器。
- 如果挂载了 clsact/ingress qdisc，则运行 `tc_ingress()`；这是一个重要的 **eBPF** hook 点（`BPF_PROG_TYPE_SCHED_CLS`）。
- 带 VLAN 标签的帧会被分发到对应的 VLAN 子接口。
- 如果接口被加入网桥，或注册了 `rx_handler`，`rx_handler()` 可以截获数据包。
- 根据 `skb->protocol`（`ETH_P_IP`）进行协议分发，调用 `ip_rcv()`。

### 4. IP 层

`ip_rcv()` 校验 IP 头部（_version == 4、IHL >= 5、总长度一致、头部校验和），设置 `skb->transport_header`，并触发 `NF_INET_PRE_ROUTING`（**PREROUTING** 链、**DNAT** 和连接跟踪）。

`ip_rcv_finish()` 通过 `ip_route_input_noref()` 执行路由查找，即 **FIB** 查找。

路由结果会将 `skb->dst->input` 设置为以下函数之一：

- `ip_local_deliver()` —— 数据包发往本机。
- `ip_forward()` —— 数据包需要转发（递减 TTL，并触发 `NF_INET_FORWARD` hook）。
- `ip_mr_input()` —— 多播路由。

对于本地交付：`ip_defrag()` 重新组装分片，随后触发 `NF_INET_LOCAL_IN`（**INPUT** 链），最后 `ip_local_deliver_finish()` 移除 IP 头部，并将数据包分发给传输层协议处理器。

### 5. 传输层 —— TCP

`tcp_v4_rcv()` 校验 TCP 头部和校验和，并通过 `__inet_lookup_skb()` 查找 socket（先查已建立连接哈希表，再查监听表）。

对于已建立的连接：调用 `tcp_v4_do_rcv()` → `tcp_rcv_established()`。

- **快速路径**：头部预测成功（预测的下一个 seq/ack、没有特殊标志、窗口未变化）时，数据会直接复制到用户态，或加入 `sk->sk_receive_queue`。
- **慢速路径**：处理乱序段、SACK、ECN、紧急数据等情况，并执行完整的状态机逻辑。

对于监听 socket 上的 SYN 数据包，会调用 `tcp_v4_cookie_check()`（SYN 洪水攻击时使用 SYN cookies）和 `tcp_check_req()` 完成 **三次握手（3WHS）**。

### 传输层 —— UDP

`udp_rcv()` → `__udp4_lib_rcv()`：根据目的端口查找 socket，校验和验证后，由 `udp_queue_rcv_skb()` 将数据包加入 `sk->sk_receive_queue`，再由 `sk->sk_data_ready()` 唤醒读取者。

### 6. Socket 层 / 用户态读取

`read()` → `sock_recvmsg()` → `inet_recvmsg()` → `tcp_recvmsg()` / `udp_recvmsg()`。

数据从接收队列中的 `skb` 复制到用户态缓冲区，读取完成后释放这些 `skb`。

## 参考资料

### 主要资料

- Stephan 与 Wüstrich，《数据包在 Linux 内核中的路径》（TUM，2024）：https://www.net.in.tum.de/fileadmin/TUM/NET/NET-2024-04-1/NET-2024-04-1_16.pdf
- PackageCloud，《Linux 网络栈监控与调优：接收数据》：https://blog.packagecloud.io/monitoring-tuning-linux-networking-stack-receiving-data/
- PackageCloud，《Linux 网络栈监控与调优：发送数据》：https://blog.packagecloud.io/monitoring-tuning-linux-networking-stack-sending-data/
- PackageCloud，《Linux 网络栈监控与调优图解：接收数据》：https://blog.packagecloud.io/illustrated-guide-monitoring-tuning-linux-networking-stack-receiving-data/

### 官方内核文档

- [Networking subsystem index](https://docs.kernel.org/networking/index.html)
- [NAPI documentation](https://docs.kernel.org/networking/napi.html)
- [sk_buff documentation](https://docs.kernel.org/networking/skbuff.html)
- [Kernel networking API](https://www.kernel.org/doc/html/v4.14/networking/kapi.html)
- [`/proc/sys/net/` tuning parameters](https://docs.kernel.org/admin-guide/sysctl/net.html)
- [Kernel source browser (v5.10.8)](https://elixir.bootlin.com/linux/v5.10.8/source)

### Linux Foundation Wiki

- [Kernel Flow — full packet path diagram](https://wiki.linuxfoundation.org/networking/kernel_flow)
- [NAPI driver implementation guide](https://wiki.linuxfoundation.org/networking/napi)

### 学术论文

- Høiland-Jørgensen 等，《The eXpress Data Path: Fast Programmable Packet Processing in the Operating System Kernel》（ACM CoNEXT 2018）：https://dl.acm.org/doi/10.1145/3281411.3281443
- Cai 等，《Understanding Host Network Stack Overheads》（ACM SIGCOMM 2021）：https://dl.acm.org/doi/10.1145/3452296.3472888；[PDF](https://www.cs.cornell.edu/~ragarwal/pubs/network-stack.pdf)
- Chimata，《Path of a Packet in the Linux Kernel Stack》（2005，kernel 2.6.11）：https://www.cs.dartmouth.edu/~sergey/netreads/path-of-packet/Network_stack.pdf

### 社区资料

- [Linux Network Performance Ultimate Guide](https://ntk148v.github.io/posts/linux-network-performance-ultimate-guide/)
- [Path of a Received Packet in the Kernel — Overview](https://www.sheharyaar.in/blog/packet-path-overview/)（Sheharyaar，2024）
- [DaveM's Linux Networking Blog](http://vger.kernel.org/~davem/cgi-bin/X_blog.cgi) —— GRO 内部机制

### eBPF / XDP

- [Cilium BPF and XDP Reference Guide](https://docs.cilium.io/en/latest/bpf/)
- [XDP paper source + benchmarks](https://github.com/xdp-project/xdp-paper)
- [SIGCOMM '21 network stack profiling tools](https://github.com/Terabit-Ethernet/Understanding-network-stack-overheads-SIGCOMM-2021)
