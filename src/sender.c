#define _POSIX_C_SOURCE 200809L

#include "rtp.h"
#include "rtp_packet.h"
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
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
    // 本阶段仅实现握手；文件路径、窗口和模式参数在传输阶段使用。
    (void)argv[3];
    (void)window_size;
    (void)mode;

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

    // TODO（下一阶段）：从 argv[3] 读取文件，按 GBN/SR 窗口发送 DATA；结束后发送 FIN。
    close(sockfd);
    return 0;
}
