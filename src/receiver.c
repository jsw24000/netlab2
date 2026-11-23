#define _POSIX_C_SOURCE 200809L

#include "rtp.h"
#include "rtp_packet.h"
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

static int parse_int(const char *text, long minimum, long maximum, int *value) {
    char *end = NULL;
    errno = 0;
    long parsed = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' ||
        parsed < minimum || parsed > maximum) {
        return -1;
    }
    *value = (int)parsed;
    return 0;
}

// 握手成功时返回 0，并把 Sender 的第一个 DATA 序号写入 *data_seq。
static int receiver_handshake(int sockfd, uint32_t *data_seq) {
    rtp_packet_t request, synack;
    struct sockaddr_in sender_addr;

    // 首次握手：最多等待 5 秒，只有合法 SYN 才能建立会话。
    const int64_t first_deadline = rtp_now_ms() + RTP_SYN_WAIT_MS;
    uint32_t initial_seq = 0;
    while (1) {
        const int64_t remaining = first_deadline - rtp_now_ms();
        if (remaining <= 0) {
            LOG_DEBUG("Receiver: initial SYN timed out\n");
            return -1;
        }
        const int state = rtp_recv_packet(sockfd, &request, &sender_addr,
                                          (int)remaining);
        if (state < 0) {
            perror("receive SYN");
            return -1;
        }
        if (state == 0) {
            return -1;
        }
        if (request.rtp.flags == RTP_SYN) {
            initial_seq = request.rtp.seq_num;
            break;
        }
    }
    *data_seq = rtp_next_seq(initial_seq);
    LOG_DEBUG("Receiver: got SYN seq=%u\n", initial_seq);

    // 本实验只有一个 Sender；锁定首次合法 SYN 的源地址。
    // 后续使用 send()/recv() 进行 UDP 通信即可。
    if (connect(sockfd, (struct sockaddr *)&sender_addr, sizeof(sender_addr)) < 0) {
        perror("UDP connect to Sender");
        return -1;
    }
    if (!rtp_make_packet(&synack, *data_seq, RTP_SYN | RTP_ACK, NULL, 0)) {
        return -1;
    }

    for (int attempt = 1; attempt <= RTP_MAX_RETRIES; ++attempt) {
        // 第二次握手：发送 SYNACK；100 ms 内没有正确 ACK 就重传。
        if (rtp_send_packet(sockfd, &synack) != 0) {
            perror("send SYNACK");
            return -1;
        }
        LOG_DEBUG("Receiver: SYNACK seq=%u, attempt=%d\n", *data_seq, attempt);

        const int64_t deadline = rtp_now_ms() + RTP_RTO_MS;
        while (1) {
            const int64_t remaining = deadline - rtp_now_ms();
            if (remaining <= 0) {
                break;
            }
            const int state = rtp_recv_packet(sockfd, &request, NULL, (int)remaining);
            if (state < 0) {
                perror("receive final ACK");
                return -1;
            }
            if (state == 0) {
                break;
            }
            if (request.rtp.flags == RTP_ACK &&
                request.rtp.seq_num == *data_seq) {
                // 第三次握手 ACK 不占用新数据序号，首个 DATA 仍从 x+1 开始。
                LOG_DEBUG("Receiver: final ACK received, seq=%u\n", *data_seq);
                return 0;
            }
            if (request.rtp.flags == RTP_SYN &&
                request.rtp.seq_num == initial_seq) {
                // Sender 没有收到上一次 SYNACK 时可能重传原 SYN。
                if (rtp_send_packet(sockfd, &synack) != 0) {
                    perror("reply to duplicate SYN");
                    return -1;
                }
            }
        }
    }
    LOG_DEBUG("Receiver: handshake failed after %d SYNACK attempts\n",
              RTP_MAX_RETRIES);
    return -1;
}


// GBN 只有一个可以按序交付的数据包位置 expected_seq。
// 收到更靠后的包时不缓存；发回累积 ACK(expected_seq)，表示仍然在等待该序号。
static int receiver_send_ack(int sockfd, uint32_t next_expected_seq) {
    rtp_packet_t ack;
    if (rtp_make_packet(&ack, next_expected_seq, RTP_ACK, NULL, 0) == 0) {
        return -1;
    }
    if (rtp_send_packet(sockfd, &ack) != 0) {
        perror("Receiver: send GBN ACK");
        return -1;
    }
    return 0;
}

// FINACK 可能在 UDP 网络中丢失：关闭前短暂保留 socket，响应对端重传的 FIN。
// 收到 FIN 后不再接受 DATA，避免结束阶段重复写入文件。
static int receiver_linger_after_fin(int sockfd, uint32_t fin_seq) {
    rtp_packet_t finack, request;
    if (rtp_make_packet(&finack, fin_seq, RTP_FIN | RTP_ACK, NULL, 0) == 0) {
        return -1;
    }
    if (rtp_send_packet(sockfd, &finack) != 0) {
        perror("Receiver: send FINACK");
        return -1;
    }
    LOG_DEBUG("Receiver: FINACK seq=%u sent\n", fin_seq);

    const int64_t deadline = rtp_now_ms() + RTP_FINAL_ACK_WAIT_MS;
    while (1) {
        const int64_t remaining = deadline - rtp_now_ms();
        if (remaining <= 0) {
            return 0;
        }
        const int state = rtp_recv_packet(sockfd, &request, NULL,
                                          (int)remaining);
        if (state < 0) {
            perror("Receiver: wait duplicate FIN");
            return -1;
        }
        if (state == 0) {
            return 0;
        }
        if (request.rtp.flags == RTP_FIN &&
            request.rtp.seq_num == fin_seq) {
            // Sender 没收到之前的 FINACK，会在 100 ms 后重发同一份 FIN。
            if (rtp_send_packet(sockfd, &finack) != 0) {
                perror("Receiver: resend FINACK");
                return -1;
            }
            LOG_DEBUG("Receiver: duplicate FIN; resent FINACK seq=%u\n",
                      fin_seq);
        }
    }
}

// 从第一个 DATA 开始连续接收，直到收到恰好位于 expected_seq 的 FIN。
// 每接收一个合法、按序 DATA：先写文件，再移动 expected_seq 并回复累积 ACK。
static int receiver_transfer_gbn(int sockfd, const char *output_path,
                                 uint32_t first_data_seq) {
    FILE *output = fopen(output_path, "wb");
    if (output == NULL) {
        perror("Receiver: fopen output file");
        return -1;
    }
    uint32_t expected_seq = first_data_seq;
    size_t received_bytes = 0;
    size_t accepted_packets = 0;
    rtp_packet_t packet;

    while (1) {
        // 实验规定 Receiver 在连续 5 秒收不到合法报文时可以退出。
        const int state = rtp_recv_packet(sockfd, &packet, NULL, RTP_SYN_WAIT_MS);
        if (state < 0) {
            perror("Receiver: receive DATA/FIN");
            break;
        }
        if (state == 0) {
            LOG_DEBUG("Receiver: no valid RTP packet for 5 seconds\n");
            break;
        }
        if (packet.rtp.flags == 0) {
            if (packet.rtp.seq_num == expected_seq) {
                // 只有期望的下一包才能交付；其余乱序 DATA 在 GBN 中直接丢弃。
                const size_t bytes = (size_t)packet.rtp.length;
                if (fwrite(packet.payload, 1, bytes, output) != bytes) {
                    perror("Receiver: fwrite output file");
                    break;
                }
                received_bytes += bytes;
                ++accepted_packets;
                expected_seq = rtp_next_seq(expected_seq);
            }
            // 收到的是新包、重复包还是乱序包，都回复「下一期望序号」。
            // 比如 expected_seq=103，ACK(103) 表示 103 之前的包已连续收到。
            if (receiver_send_ack(sockfd, expected_seq) != 0) {
                break;
            }
            continue;
        }
        if (packet.rtp.flags == RTP_FIN) {
            if (packet.rtp.seq_num != expected_seq) {
                // FIN 只允许在所有 DATA 都已经按序到达后被接受。
                // 若它提前到达，仍用累积 ACK 告知缺少的包。
                if (receiver_send_ack(sockfd, expected_seq) != 0) {
                    break;
                }
                continue;
            }
            // 确保数据已经成功写入目标文件，之后再发送 FINACK。
            if (fclose(output) != 0) {
                perror("Receiver: fclose output file");
                return -1;
            }
            LOG_MSG("Receiver: GBN wrote %zu bytes in %zu DATA packets\n",
                    received_bytes, accepted_packets);
            if (receiver_linger_after_fin(sockfd, expected_seq) != 0) {
                return -1;
            }
            LOG_MSG("Receiver: RTP transfer completed\n");
            return 0;
        }
        // 重复的握手 ACK 等其他控制报文不改变文件和接收窗口状态。
    }

    fclose(output);
    return -1;
}


// SR 接收窗口中的一个槽位：未收到的数据 ready=0；收到乱序数据后 ready=1。
// 使用环形数组，而不是每次窗口移动就整体移动 payload，窗口可达 20000。
typedef struct SrSlot {
    uint16_t length;
    unsigned char ready;
    char payload[PAYLOAD_MAX];
} sr_slot_t;

// 选择重传的 ACK(seq) 只表示「我已经收到 seq 号 DATA」，不是下一个期望号。
static int receiver_send_sr_ack(int sockfd, uint32_t received_seq) {
    rtp_packet_t ack;
    if (rtp_make_packet(&ack, received_seq, RTP_ACK, NULL, 0) == 0) {
        return -1;
    }
    if (rtp_send_packet(sockfd, &ack) != 0) {
        perror("Receiver: send SR ACK");
        return -1;
    }
    return 0;
}

// SR 允许乱序接收和独立 ACK，但文件仍必须按 DATA 序号连续写入。
static int receiver_transfer_sr(int sockfd, const char *output_path,
                                uint32_t first_data_seq, size_t window_size) {
    FILE *output = fopen(output_path, "wb");
    if (output == NULL) {
        perror("Receiver: fopen SR output file");
        return -1;
    }
    if (window_size > SIZE_MAX / sizeof(sr_slot_t)) {
        fclose(output);
        return -1;
    }
    sr_slot_t *slots = calloc(window_size, sizeof(*slots));
    if (slots == NULL) {
        perror("Receiver: calloc SR receive window");
        fclose(output);
        return -1;
    }

    uint32_t expected_seq = first_data_seq;  // 最早尚未交付文件的数据包序号。
    size_t head = 0;                        // 环形缓存中 expected_seq 对应的槽位。
    size_t received_bytes = 0;
    size_t accepted_packets = 0;
    rtp_packet_t packet;
    int result = -1;
    int output_open = 1;

    LOG_MSG("Receiver: SR receive window=%zu, starting seq=%u\n",
            window_size, first_data_seq);

    while (1) {
        const int state = rtp_recv_packet(sockfd, &packet, NULL, RTP_SYN_WAIT_MS);
        if (state < 0) {
            perror("Receiver: receive SR DATA/FIN");
            break;
        }
        if (state == 0) {
            LOG_DEBUG("Receiver: SR timed out waiting for DATA/FIN\n");
            break;
        }

        if (packet.rtp.flags == 0) {
            // 将 30-bit 序号转换为相对于窗口左边界的距离。
            // 对于 [expected_seq, expected_seq+W) 内的包：offset < W。
            const uint32_t offset =
                (packet.rtp.seq_num - expected_seq) & (RTP_SEQ_MOD - 1U);
            if ((size_t)offset < window_size) {
                const size_t pos = (head + (size_t)offset) % window_size;
                sr_slot_t *slot = &slots[pos];
                if (!slot->ready) {
                    // 乱序包也先缓存；同一个 slot 不重复写，防止重复包覆盖数据。
                    slot->length = packet.rtp.length;
                    memcpy(slot->payload, packet.payload, slot->length);
                    slot->ready = 1;
                }

                // 只要包落在接收窗口内且 CRC/字段合法，就回复它自己的序号。
                // 即使前面的包尚未到达，也必须发送 ACK，不使用 GBN 的累积 ACK。
                if (receiver_send_sr_ack(sockfd, packet.rtp.seq_num) != 0) {
                    break;
                }

                // 只将从窗口最左端起「连续已收到」的数据交付文件。
                // 例如缓存 3、4 等待 2；一旦 2 到达，按序写入 2、3、4。
                while (slots[head].ready) {
                    sr_slot_t *front = &slots[head];
                    if (fwrite(front->payload, 1, front->length, output) !=
                        front->length) {
                        perror("Receiver: fwrite SR output file");
                        goto cleanup;
                    }
                    received_bytes += front->length;
                    ++accepted_packets;
                    front->ready = 0;
                    expected_seq = rtp_next_seq(expected_seq);
                    head = (head + 1) % window_size;
                }
            } else {
                // 已被交付的旧 DATA 的 ACK 也可能在网络里丢失。
                // 对落在当前窗口左侧一个窗口跨度内的重复包，重发独立 ACK；
                // 对更远的未来包或明显超出窗口的报文，不接收也不确认。
                const uint32_t behind =
                    (expected_seq - packet.rtp.seq_num) & (RTP_SEQ_MOD - 1U);
                if (behind > 0 && (size_t)behind <= window_size) {
                    if (receiver_send_sr_ack(sockfd, packet.rtp.seq_num) != 0) {
                        break;
                    }
                }
            }
            continue;
        }

        if (packet.rtp.flags == RTP_FIN) {
            // 只有所有 DATA 都已按序交付，FIN 才能被接受。
            // 提前到达的 FIN 不产生 SR DATA ACK；Sender 会按超时规则重发 FIN。
            if (packet.rtp.seq_num != expected_seq) {
                continue;
            }
            if (fclose(output) != 0) {
                perror("Receiver: fclose SR output file");
                output_open = 0;
                break;
            }
            output_open = 0;
            LOG_MSG("Receiver: SR wrote %zu bytes in %zu DATA packets\n",
                    received_bytes, accepted_packets);
            result = receiver_linger_after_fin(sockfd, expected_seq);
            if (result == 0) {
                LOG_MSG("Receiver: RTP transfer completed\n");
            }
            break;
        }
        // 其他控制报文（例如第三次握手 ACK 的重复包）不改变 SR 数据状态。
    }

cleanup:
    if (output_open) {
        fclose(output);
    }
    free(slots);
    return result;
}

int main(int argc, char **argv) {
    if (argc != 5) {
        LOG_FATAL("Usage: ./receiver [listen port] [file path] [window size] "
                  "[mode]\n");
    }
    int port, window_size, mode;
    if (parse_int(argv[1], 1, 65535, &port) != 0 ||
        parse_int(argv[3], 1, 1000000, &window_size) != 0 ||
        parse_int(argv[4], 0, 1, &mode) != 0) {
        LOG_FATAL("Receiver: invalid port/window size/mode\n");
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        LOG_FATAL("Receiver: socket() failed\n");
    }
    struct sockaddr_in local_addr = {0};
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = htons((uint16_t)port);
    if (bind(sockfd, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0) {
        close(sockfd);
        LOG_FATAL("Receiver: bind() failed; is the port already in use?\n");
    }

    uint32_t first_data_seq = 0;
    if (receiver_handshake(sockfd, &first_data_seq) < 0) {
        close(sockfd);
        LOG_FATAL("Receiver: handshake failed or timed out\n");
    }
    LOG_MSG("Receiver: RTP three-way handshake completed, expect DATA seq=%u\n",
            first_data_seq);

    // 根据 mode 选择 GBN 或 SR；复用已验证的三次握手和 FIN 关闭处理。
    const int transfer_ok = (mode == 0)
        ? receiver_transfer_gbn(sockfd, argv[2], first_data_seq)
        : receiver_transfer_sr(sockfd, argv[2], first_data_seq,
                               (size_t)window_size);
    close(sockfd);
    if (transfer_ok != 0) {
        LOG_FATAL("Receiver: %s data transfer failed\n", mode == 0 ? "GBN" : "SR");
    }
    return 0;
}
