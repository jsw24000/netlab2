# Lab2 — RTP 报文封装 + 三次握手（阶段一）

本代码基于官方 2026 Lab2 RTP 模板。这里只实现报文打包、CRC32 校验、UDP 通信与三次握手；还未实现文件传输、GBN/SR、FIN。原始 `src/rtp.h`、`src/util.c`、`src/util.h` 保持不变。

## 覆盖文件

请将压缩包中的以下文件复制到你的 Lab2 仓库相同路径：
- `src/rtp_packet.h`：新增
- `src/rtp_packet.c`：新增
- `src/sender.c`：替换原始空模板
- `src/receiver.c`：替换原始空模板
- `CMakeLists.txt`：替换（相对官方模板只增加 `src/rtp_packet.c`）

**注意**：压缩包不是完整仓库；不要删除仓库已有的其他文件和 `third_party`、`test` 目录。

## 在容器中编译

```bash
cd ~/workspace/code
cmake -S . -B build
cmake --build build -j
```

## 在两个终端验证握手

先启动 Receiver（终端 A）：

```bash
./build/receiver 45678 /tmp/rtp_recv.bin 16 1
```

再启动 Sender（终端 B）：

```bash
./build/sender 127.0.0.1 45678 /etc/hosts 16 1
```

预期两侧输出 `RTP three-way handshake completed`。Sender 完成第三次 ACK 后还会停留大约 2 秒，处理可能出现的重复 SYNACK。

这里的 `file path`、`window size`、`mode` 只解析（或保留）参数，尚未进行文件收发。测试后不会生成接收的文件，属于当前阶段的正常情况。

完整 Lab2 测试现在还不能通过，需要实现后续数据传输和连接关闭功能。

## 报文处理重点

- 头部按官方 `rtp.h` 使用小端序布局，长度为 11 字节；没有额外转换字节序。
- CRC 计算前将 `checksum=0`；校验范围为 `sizeof(rtp_header_t)+length`。
- 数据包 `flags=0`，控制包 `flags` 为 SYN、ACK、SYNACK、FIN、FINACK 且 `length=0`。
- 合法的 `seq_num` 在 `[0, 2^30-1]`，递增时取模。
- Sender 发送 SYN，Receiver 发送 SYNACK，Sender 回复 ACK；两个方向的首次控制重传间隔为 100 ms、重试 50 次。
- Receiver 最多等待初次 SYN 5 秒；Sender 发送最后 ACK 后保留约 2 秒响应重复 SYNACK。
- 所用 `connect()` 是 UDP Socket 的 `connect()`，只记录目的地并过滤来源，不是 TCP 握手。

## 当前实现不自动写入 GitHub

本 ZIP 包是本地实现。将文件复制进容器后，通过 `git diff` 检查，再决定何时提交与推送 GitHub。
