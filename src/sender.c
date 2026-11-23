#define _POSIX_C_SOURCE 200809L

#include "rtp.h"
#include "rtp_packet.h"
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
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

static int sender_handshake(int sockfd, uint32_t initial_seq) {
    const uint32_t next_seq = rtp_next_seq(initial_seq);
    rtp_packet_t syn, ack, response;
    if (!rtp_make_packet(&syn, initial_seq, RTP_SYN, NULL, 0) ||
        !rtp_make_packet(&ack, next_seq, RTP_ACK, NULL, 0)) {
        return -1;
    }

    for (int attempt = 1; attempt <= RTP_MAX_RETRIES; ++attempt) {
        // 第一握手：发送 SYN；未收到正确 SYNACK 时每隔 100 ms 重传。
        if (rtp_send_packet(sockfd, &syn) != 0) {
            perror("send SYN");
            return -1;
        }
        LOG_DEBUG("Sender: SYN seq=%u, attempt=%d\n", initial_seq, attempt);

        const int64_t deadline = rtp_now_ms() + RTP_RTO_MS;
        while (1) {
            const int64_t remaining = deadline - rtp_now_ms();
            if (remaining <= 0) {
                break;
            }
            const int state = rtp_recv_packet(sockfd, &response, NULL, (int)remaining);
            if (state < 0) {
                perror("receive SYNACK");
                return -1;
            }
            if (state == 0) {
                break;
            }
            // 只有同时满足 SYN|ACK 标志和期望序号，才能进入第三次握手。
            if (response.rtp.flags != (RTP_SYN | RTP_ACK) ||
                response.rtp.seq_num != next_seq) {
                continue;
            }

            if (rtp_send_packet(sockfd, &ack) != 0) {
                perror("send final ACK");
                return -1;
            }
            LOG_DEBUG("Sender: SYNACK received; ACK seq=%u sent\n", next_seq);

            // 第三次 ACK 没有独立的确认报文，因此停留约 2 秒。
            // 若 Receiver 没收到 ACK，它会重传 SYNACK；此时必须补发 ACK。
            const int64_t grace_deadline = rtp_now_ms() + RTP_FINAL_ACK_WAIT_MS;
            while (1) {
                const int64_t grace_left = grace_deadline - rtp_now_ms();
                if (grace_left <= 0) {
                    break;
                }
                const int grace_state = rtp_recv_packet(sockfd, &response, NULL,
                                                        (int)grace_left);
                if (grace_state < 0) {
                    perror("wait for duplicate SYNACK");
                    return -1;
                }
                if (grace_state == 0) {
                    break;
                }
                if (response.rtp.flags == (RTP_SYN | RTP_ACK) &&
                    response.rtp.seq_num == next_seq) {
                    if (rtp_send_packet(sockfd, &ack) != 0) {
                        perror("resend final ACK");
                        return -1;
                    }
                    LOG_DEBUG("Sender: duplicate SYNACK; resent final ACK\n");
                }
            }
            return 0;
        }
    }
    LOG_DEBUG("Sender: handshake failed after %d SYN attempts\n", RTP_MAX_RETRIES);
    return -1;
}


// 这是一个 GBN 发送端，而不是停等协议：窗口内允许多个 DATA 同时处于未确认状态。
// 每轮最多突发发送 32 个包，随后检查 ACK，避免窗口很大时一次性向 UDP 缓冲区灌入数千个包。
#define GBN_SEND_BURST 32U
#define GBN_MAX_STALL_ROUNDS 200

// 把连续的数据包下标转换为 30-bit RTP 序号，处理 2^30 的回绕。
// 本实验文件最多约 10 MB，包数远小于整个序号空间。
static uint32_t data_seq_at(uint32_t first_seq, size_t packet_index) {
    return (uint32_t)(((uint64_t)first_seq + packet_index) % RTP_SEQ_MOD);
}

// 一次性读入二进制文件，便于 GBN 超时后重发窗口内的任意数据包。
// 10 MB 以内的实验文件可以直接保存在内存中，不需要反复磁盘 seek。
static int read_all_file(const char *path, unsigned char **out_data,
                         size_t *out_length) {
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        perror("Sender: fopen input file");
        return -1;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        perror("Sender: fseek input file");
        fclose(fp);
        return -1;
    }
    long file_length = ftell(fp);
    if (file_length < 0 || fseek(fp, 0, SEEK_SET) != 0) {
        perror("Sender: ftell/rewind input file");
        fclose(fp);
        return -1;
    }
    const size_t length = (size_t)file_length;
    unsigned char *data = malloc(length == 0 ? 1 : length);
    if (data == NULL) {
        perror("Sender: malloc input buffer");
        fclose(fp);
        return -1;
    }
    if (length != 0 && fread(data, 1, length, fp) != length) {
        perror("Sender: fread input file");
        free(data);
        fclose(fp);
        return -1;
    }
    if (fclose(fp) != 0) {
        perror("Sender: fclose input file");
        free(data);
        return -1;
    }
    *out_data = data;
    *out_length = length;
    return 0;
}

// 发送指定下标的数据包；重传时仍使用完全相同的序号与文件字节。
static int sender_send_data(int sockfd, const unsigned char *file_data,
                            size_t file_length, uint32_t first_seq,
                            size_t packet_index) {
    const size_t offset = packet_index * PAYLOAD_MAX;
    const size_t remaining = file_length - offset;
    const uint16_t payload_length =
        (uint16_t)(remaining < PAYLOAD_MAX ? remaining : PAYLOAD_MAX);
    rtp_packet_t packet;
    if (rtp_make_packet(&packet, data_seq_at(first_seq, packet_index),
                        0, file_data + offset, payload_length) == 0) {
        return -1;
    }
    if (rtp_send_packet(sockfd, &packet) != 0) {
        perror("Sender: send DATA");
        return -1;
    }
    return 0;
}

// GBN 核心逻辑：
// base = 最早尚未确认的数据包下标；next = 下一个待发送的数据包下标。
// 保证 0 <= base <= next <= packet_count 且 next-base <= window_size。
// GBN ACK 的 seq_num 表示「接收方期望的下一包」；它是累积确认。
static int sender_transfer_gbn(int sockfd, const unsigned char *file_data,
                               size_t file_length, uint32_t first_seq,
                               size_t window_size) {
    const size_t packet_count =
        file_length / PAYLOAD_MAX + (file_length % PAYLOAD_MAX != 0);
    size_t base = 0;
    size_t next = 0;
    int stall_rounds = 0;
    int64_t last_progress_ms = rtp_now_ms();
    rtp_packet_t response;
    if (last_progress_ms < 0) {
        return -1;
    }

    LOG_MSG("Sender: GBN transferring %zu bytes in %zu DATA packets, window=%zu\n",
            file_length, packet_count, window_size);

    while (base < packet_count) {
        // 尽量把可用窗口填满，但分批检查 ACK，给接收端处理数据的机会。
        unsigned int burst = 0;
        while (next < packet_count && next - base < window_size &&
               burst < GBN_SEND_BURST) {
            if (sender_send_data(sockfd, file_data, file_length,
                                 first_seq, next) != 0) {
                return -1;
            }
            ++next;
            ++burst;
        }

        const int64_t now = rtp_now_ms();
        if (now < 0) {
            return -1;
        }
        int64_t until_timeout = RTP_RTO_MS - (now - last_progress_ms);
        if (until_timeout <= 0) {
            // 窗口左边界 100 ms 未前进：回退 N，重传所有已发送但未累积确认的数据包。
            if (++stall_rounds > GBN_MAX_STALL_ROUNDS) {
                LOG_DEBUG("Sender: GBN window stalled too long\n");
                return -1;
            }
            LOG_DEBUG("Sender: GBN timeout, retransmit [%zu, %zu)\n", base, next);
            for (size_t i = base; i < next; ++i) {
                if (sender_send_data(sockfd, file_data, file_length,
                                     first_seq, i) != 0) {
                    return -1;
                }
                // 大窗口重传时轻微限速，减少本机 UDP 接收缓冲区溢出。
                if ((i - base + 1) % GBN_SEND_BURST == 0) {
                    struct timespec pause_time = {.tv_sec = 0, .tv_nsec = 1000000};
                    nanosleep(&pause_time, NULL);
                }
            }
            last_progress_ms = rtp_now_ms();
            if (last_progress_ms < 0) {
                return -1;
            }
            continue;
        }

        // 如果窗口还有空间，最多等待 1 ms 就继续填充；窗口满了则等待 ACK 或超时。
        int wait_ms = (next < packet_count && next - base < window_size)
                          ? 1 : (int)until_timeout;
        if (wait_ms < 1) {
            wait_ms = 1;
        }
        const int state = rtp_recv_packet(sockfd, &response, NULL, wait_ms);
        if (state < 0) {
            perror("Sender: receive GBN ACK");
            return -1;
        }
        if (state != 1 || response.rtp.flags != RTP_ACK) {
            continue;
        }

        // 模 2^30 的差值，是从首个 DATA 序号到 ACK 所表示的「下一期望序号」的距离。
        // 例如首包 seq=100、ACK seq=103，就表示前 3 个 DATA 已连续收到。
        // 用差值而不是直接比较 seq 大小，避免序号回绕时的比较错误。
        const size_t acked_count =
            (size_t)((response.rtp.seq_num - first_seq) & (RTP_SEQ_MOD - 1U));
        if (acked_count > base && acked_count <= next) {
            base = acked_count;          // 累积确认：整体推进窗口左边界。
            last_progress_ms = rtp_now_ms();
            stall_rounds = 0;
            if (last_progress_ms < 0) {
                return -1;
            }
        }
        // 重复 ACK、过期 ACK、指向尚未发送数据的 ACK 都忽略。
    }
    LOG_MSG("Sender: all %zu DATA packets cumulatively acknowledged\n",
            packet_count);
    return 0;
}

// 只有全部 DATA 得到累积确认后才能发送 FIN。
// 本实验 FINACK 的 seq_num 与 FIN 相同，不是 TCP 的 FIN+1 规则。
static int sender_close_connection(int sockfd, uint32_t fin_seq) {
    rtp_packet_t fin, response;
    if (rtp_make_packet(&fin, fin_seq, RTP_FIN, NULL, 0) == 0) {
        return -1;
    }
    for (int attempt = 1; attempt <= RTP_MAX_RETRIES; ++attempt) {
        if (rtp_send_packet(sockfd, &fin) != 0) {
            perror("Sender: send FIN");
            return -1;
        }
        LOG_DEBUG("Sender: FIN seq=%u, attempt=%d\n", fin_seq, attempt);
        const int64_t deadline = rtp_now_ms() + RTP_RTO_MS;
        while (1) {
            const int64_t remaining = deadline - rtp_now_ms();
            if (remaining <= 0) {
                break;
            }
            const int state = rtp_recv_packet(sockfd, &response, NULL,
                                              (int)remaining);
            if (state < 0) {
                perror("Sender: receive FINACK");
                return -1;
            }
            if (state == 0) {
                break;
            }
            if (response.rtp.flags == (RTP_FIN | RTP_ACK) &&
                response.rtp.seq_num == fin_seq) {
                LOG_MSG("Sender: FINACK received, RTP transfer completed\n");
                return 0;
            }
        }
    }
    LOG_DEBUG("Sender: FINACK timed out\n");
    return -1;
}

int main(int argc, char **argv) {
    if (argc != 6) {
        LOG_FATAL("Usage: ./sender [receiver ip] [receiver port] [file path] "
                  "[window size] [mode]\n");
    }

    int port, window_size, mode;
    if (parse_int(argv[2], 1, 65535, &port) != 0 ||
        parse_int(argv[4], 1, 1000000, &window_size) != 0 ||
        parse_int(argv[5], 0, 1, &mode) != 0) {
        LOG_FATAL("Sender: invalid port/window size/mode\n");
    }
    // 本阶段实现 GBN（mode=0），SR（mode=1）留待下一阶段。
    if (mode != 0) {
        LOG_FATAL("Sender: SR (mode=1) is not implemented yet; use mode=0 for GBN\n");
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        LOG_FATAL("Sender: socket() failed\n");
    }
    struct sockaddr_in receiver = {0};
    receiver.sin_family = AF_INET;
    receiver.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, argv[1], &receiver.sin_addr) != 1) {
        close(sockfd);
        LOG_FATAL("Sender: invalid IPv4 address\n");
    }
    // UDP 的 connect() 只绑定默认通信地址和过滤其他来源；不会建立 TCP 连接。
    if (connect(sockfd, (struct sockaddr *)&receiver, sizeof(receiver)) < 0) {
        close(sockfd);
        LOG_FATAL("Sender: UDP connect() failed\n");
    }

    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        close(sockfd);
        LOG_FATAL("Sender: clock_gettime() failed\n");
    }
    srand((unsigned)(ts.tv_sec ^ ts.tv_nsec ^ getpid()));
    const uint32_t initial_seq = (uint32_t)rand() % RTP_SEQ_MOD;
    LOG_DEBUG("Sender: initial seq=%u\n", initial_seq);

    if (sender_handshake(sockfd, initial_seq) < 0) {
        close(sockfd);
        LOG_FATAL("Sender: handshake failed\n");
    }
    LOG_MSG("Sender: RTP three-way handshake completed, data seq starts at %u\n",
            rtp_next_seq(initial_seq));

    // 文件读取失败时不进入 DATA/FIN 阶段，避免把不完整文件传给 Receiver。
    unsigned char *file_data = NULL;
    size_t file_length = 0;
    if (read_all_file(argv[3], &file_data, &file_length) != 0) {
        close(sockfd);
        return 1;
    }
    const uint32_t first_data_seq = rtp_next_seq(initial_seq);
    const size_t packet_count =
        file_length / PAYLOAD_MAX + (file_length % PAYLOAD_MAX != 0);
    const uint32_t fin_seq = data_seq_at(first_data_seq, packet_count);

    const int transfer_ok =
        sender_transfer_gbn(sockfd, file_data, file_length,
                            first_data_seq, (size_t)window_size);
    free(file_data);
    if (transfer_ok != 0) {
        close(sockfd);
        LOG_FATAL("Sender: GBN data transfer failed\n");
    }
    if (sender_close_connection(sockfd, fin_seq) != 0) {
        close(sockfd);
        LOG_FATAL("Sender: failed to close RTP connection\n");
    }
    close(sockfd);
    return 0;
}
