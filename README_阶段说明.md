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

# Lab2 第二阶段：无差错文件传输 + Go-Back-N (GBN) + FIN

## 本次修改的文件

- `src/sender.c`：在上一阶段已经成功的三次握手基础上，实现二进制文件读取、按 RTP DATA 分包、GBN 发送窗口与累计 ACK、100 ms 窗口超时重传、FIN/FINACK 关闭。
- `src/receiver.c`：保留三次握手，实现 GBN 按序接收与文件写入、累计 ACK、乱序/重复包丢弃、FINACK 发送及其丢失后的补发。

**其他文件无需修改。** 继续使用上一阶段已有的 `src/rtp.h`、`src/rtp_packet.h`、`src/rtp_packet.c`、`src/util.[ch]` 和已经包含 `src/rtp_packet.c` 的 `CMakeLists.txt`。

## 什么是“无差错传输”和 GBN 的差异？

无差错文件传输只要求在没有丢包或乱序时，按 `PAYLOAD_MAX=1461` 字节分包发送，接收端依次写入，最后完成关闭。GBN 还需要定义发送窗口、累计 ACK、超时重传和重复包/乱序包处理。这里直接实现完整的 GBN 模式，因此无差错传输也由它涵盖，不另写一套停等协议。

GBN Receiver 不缓存乱序 DATA；例如期待 12 却收到 13，会丢弃 13 并回复 ACK(12)。GBN Sender 收到 ACK(15)，意味着 15 之前所有数据包已经连续确认，而不只是第 15 包。

## 代码说明

### Sender

`sender_transfer_gbn()` 维护两个单调递增的**包下标**：

- `base`：最早尚未累积确认的 DATA 下标。
- `next`：下一份待发送的 DATA 下标。

始终保证 `next - base <= window_size`。RTP 的实际 `seq_num` 用 `data_seq_at()` 转换，并按 2^30 回绕。`ACK.seq_num` 减去第一个 DATA 的序号后取得累计确认的包数；只有该值落在 `(base, next]` 才能推动窗口。

如果 `base` 在 100 ms 内没有前进，就重传 `[base, next)` 的所有已发送、未确认 DATA。代码每 32 个包分批检查 ACK，重传大窗口时短暂限速，减少 UDP 缓冲区被突发报文挤满的概率。

数据全被确认后发送 `FIN(seq=first_data_seq+packet_count)`；FIN 每 100 ms 重传一次，直到收到相同序号的 FINACK，或达到上限 50 次。

### Receiver

`receiver_transfer_gbn()` 只接受 `seq_num == expected_seq` 的 DATA，并按字节写入文件。每个有效 DATA（包括重复或乱序数据）之后，回复 `ACK(expected_seq)`。对于意外收到的更靠后的 DATA，不缓存、不写入，只重复 ACK 当前期待的序号。

收到符合预期序号的 FIN 后，先关闭文件，再发送 FINACK；再保持 socket 约 2 秒，以便重发被丢失的 FINACK。此阶段不再处理 DATA，防止重复写入。

## 在 CLab 容器中更新代码

将 ZIP 上传到远程容器中的 `~/workspace/code/`，在该目录运行：

```bash
unzip -o Lab2_GBN_文件传输与关闭.zip
cmake -S . -B build
cmake --build build -j
```

### 测试 A：小文件端到端传输

终端 1：

```bash
cd ~/workspace/code
./build/receiver 45678 /tmp/rtp_recv.bin 16 0
```

终端 2：

```bash
cd ~/workspace/code
./build/sender 127.0.0.1 45678 /etc/hosts 16 0
```

传输结束后任一终端：

```bash
cmp /etc/hosts /tmp/rtp_recv.bin && echo 'PASS: 两文件完全一致'
sha256sum /etc/hosts /tmp/rtp_recv.bin
```

**注意：** 这次 `mode` 必须用 `0`，即 GBN；原来的 `1` 是 SR 模式，本阶段尚未实现。

### 测试 B：2 MiB 随机二进制文件

先创建输入：

```bash
dd if=/dev/urandom of=/tmp/rtp_input.bin bs=1M count=2 status=none
```

终端 1：

```bash
./build/receiver 45679 /tmp/rtp_output.bin 16 0
```

终端 2：

```bash
./build/sender 127.0.0.1 45679 /tmp/rtp_input.bin 16 0
```

检查：

```bash
cmp /tmp/rtp_input.bin /tmp/rtp_output.bin && echo 'PASS: 2 MiB 二进制文件完全一致'
```

也可以将两侧窗口同时设置为 `1` 或 `32`，但每次必须使用不同端口或确保上一次进程已经退出。

### 测试 C：课程自带标准 Sender/Receiver

从仓库根目录运行：

```bash
bash test/runtest.sh NORMAL
bash test/runtest.sh NORMAL_SMALL_WINDOW
```

这些测试会分别将自己的 Sender 与标准 Receiver、自己的 Receiver 与标准 Sender 对接。完成后进一步运行（含模拟错误信道）：

```bash
bash test/runtest.sh SENDER_SINGLE_1
bash test/runtest.sh RECEIVER_SINGLE_1
bash test/runtest.sh SENDER_SINGLE_2
bash test/runtest.sh RECEIVER_SINGLE_2
```

**关于官方测试脚本：** 第一次运行 `test/runtest.sh` 会复制 `test/src/test.cpp` 到 `src/test.cpp` 并重新构建；随后根目录如果已经有 `.built`，脚本将**跳过自动构建**。以后每次修改代码后先运行 `cmake --build build -j`，或者明确删除 `.built` 后再运行脚本。注意 `src/test.cpp` 可能在本地变成未提交的修改，可通过 `git status` 检查。

`RTP.NORMAL_OPT` 等 SR（mode=1）测试在本阶段预期不能通过，下一阶段再实现 SR。

## 本地验证范围

在独立 Linux 环境下，已成功编译，并通过：空文件、1 字节、1461/1462 字节边界、100 KB、2 MiB、10 MiB、窗口 1/16/32/20000 的端到端比对；2^30 序号回绕；模拟 DATA 丢失、ACK 丢失、数据损坏、重复、乱序及第一次 FINACK 丢失。以上不是 CLab 内官方测试程序的实际评分结果，仍请执行测试 C 核实与标准程序的互操作。

## 仍待完成

- `mode=1` 的 SR（选择重传），包括独立 ACK、接收缓存、仅重传未确认包。
- 官方全部测试与隐藏测试的兼容性/性能检查。


# Lab2 第三阶段：SR（Selective Repeat，选择重传）

## 1. 与已有代码的关系

本版本在已经完成且通过 GBN 官方正常测试的代码上增量实现 SR。

- **仅覆盖** `src/sender.c`、`src/receiver.c` 两个文件。
- 保留原 `src/rtp.h`、`src/rtp_packet.h`、`src/rtp_packet.c`、`src/util.c`、`src/util.h`、`CMakeLists.txt` 和 `src/test.cpp`，它们不需要改动。
- `mode=0` 仍运行原 GBN 实现；`mode=1` 运行新增 SR 实现。
- UDP 三次握手、CRC32、FIN/FINACK 关闭逻辑由原实现复用。
- 本包**没有修改 GitHub 仓库**，需自行复制文件到 CLab 容器并编译。

## 2. SR Sender 的设计

新增 `sender_transfer_sr()`：

- 读取文件和分包仍沿用原先的 `read_all_file()`、`sender_send_data()`，每 DATA 最多 1461 字节。
- `base` 表示最左侧尚未连续确认的 DATA 下标；`next` 表示下一个尚未初次发送的 DATA 下标。
- 新增 `acked[i]` 位图。SR 中 `ACK(seq_num)` **只确认 `seq_num` 对应的单个 DATA**，与 GBN 累积 ACK 完全不同。
- 收到 ACK 时，先用 `(seq_num - first_seq) & (2^30-1)` 计算相对数据包下标；更新 `acked[index]`，只有 `base` 起连续确认时，发送窗口才能滑动。
- 若窗口在 100 ms 内没有前进，只重传 `[base,next)` 中 `acked[i]==0` 的报文。只维护一个窗口计时器，符合官方 SR 的简化定时要求。
- `GBN_SEND_BURST=32` 限制每轮新增发送的数据包数，避免窗口很大时一次发送过多 UDP 数据报。
- 所有数据包独立确认后，复用原代码发送 `FIN(last_data_seq+1)`，等待 `FINACK`。

## 3. SR Receiver 的设计

新增 `receiver_transfer_sr()` 和 `receiver_send_sr_ack()`：

- 使用长度为 `window_size` 的**环形缓存**，每个槽保存 `ready`、`length` 和 `payload`。无需随窗口推进整体复制缓存。
- `expected_seq` 为下一个可按序交付的数据包序号；`head` 为其对应的环形槽位。
- 对接收窗口内的合法 DATA，即使乱序，也缓存并发送 `ACK(该 DATA 的 seq_num)`。
- `expected_seq` 对应的数据到达后，顺序写入该数据包以及后面已经缓存的连续数据，推进接收窗口。
- 对刚刚交付过、落在窗口左侧一个窗口跨度内的重复 DATA，补发该包的独立 ACK；其他窗口外报文直接丢弃。
- 只有 `FIN.seq_num == expected_seq` 才接受关闭，之后复用原 `FINACK` 补发逻辑，不再写入其他 DATA。

## 4. 更新代码（在容器项目根目录）

```bash
cd ~/workspace/code

# 先把 Lab2_SR_选择重传.zip 上传到这个目录
unzip -o Lab2_SR_选择重传.zip

# 仍保留原有 CMake 文件：src/rtp_packet.c 已在 rtp_all 中
cmake -S . -B build
cmake --build build -j
```

### 手动 SR 端到端测试（mode=1）

终端 A：

```bash
./build/receiver 45678 /tmp/rtp_sr_out.bin 16 1
```

终端 B：

```bash
./build/sender 127.0.0.1 45678 /etc/hosts 16 1
```

等待双方退出，然后校验：

```bash
cmp /etc/hosts /tmp/rtp_sr_out.bin && echo 'PASS: SR 文件完全一致'
```

### 2 MiB 二进制文件测试

```bash
dd if=/dev/urandom of=/tmp/rtp_sr_input.bin bs=1M count=2 status=none
```

终端 A：

```bash
./build/receiver 45679 /tmp/rtp_sr_result.bin 32 1
```

终端 B：

```bash
./build/sender 127.0.0.1 45679 /tmp/rtp_sr_input.bin 32 1
```

校验：

```bash
cmp /tmp/rtp_sr_input.bin /tmp/rtp_sr_result.bin && echo 'PASS: 2MiB SR'
```

### 官方自动测试

在项目根目录先确认标准程序可执行（你此前已经修复过这个问题）：

```bash
chmod +x test/bin/test_sender test/bin/test_receiver
cmake --build build -j
```

先跑无错误 SR：

```bash
./build/rtp_test_all --gtest_filter='RTP.NORMAL_OPT:RTP.NORMAL_OPT_SMALL_WINDOW'
```

再跑官方公开的 8 个 SR 故障测试：

```bash
./build/rtp_test_all --gtest_filter='RTP.OPT_SENDER_*:RTP.OPT_RECEIVER_*'
```

最后回归 GBN：

```bash
./build/rtp_test_all --gtest_filter='RTP.NORMAL:RTP.NORMAL_SMALL_WINDOW:RTP.SENDER_*:RTP.RECEIVER_*'
```

也可以运行全部公开测试：

```bash
./build/rtp_test_all
```

**注意：** 如果使用 `bash test/runtest.sh NORMAL_OPT`，该脚本的 `.built` 标志可能跳过重新编译；因此建议先手动 `cmake --build build -j`。`test/runtest.sh` 首次运行还会复制 `test/src/test.cpp` 到 `src/test.cpp`，属于官方提供的本地测试流程。当前版本没有修改测试框架。

## 5. 本地验证范围和注意事项

已在独立 Linux 环境编译两端程序，验证空文件、分片边界、2 MiB/10 MiB 文件、窗口 1/16/32/20000、SR 丢失 ACK/数据、损坏、重复、乱序、FINACK 丢失和混合错误，另通过固定初始序号模拟了 2^30 回绕。GBN 正常传输及部分故障恢复回归也已运行。

**这些均为本地独立测试，不是 CLab 容器的官方标准程序互操作测试。** 最终是否通过官方 20 个公开测试点及隐藏测试，需要你在课程环境中运行上述指令确认。故障测试存在随机性，建议对失败点多次运行并保存调试日志。

## 6. AI 使用记录

官方 Lab2 允许 Vibe Coding，但要求提交时附上完整 Session 记录，并以教学网的正式提交说明为准。请保留本次聊天记录及后续修改/调试记录。
