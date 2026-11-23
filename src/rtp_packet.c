#define _POSIX_C_SOURCE 200809L

#include "rtp_packet.h"
#include "util.h"

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

uint32_t rtp_next_seq(uint32_t seq_num) {
    return (seq_num + 1U) % RTP_SEQ_MOD;
}

// 仅允许本实验定义的数据报文、握手报文和结束报文。
static int flags_are_valid(uint8_t flags, uint16_t length) {
    if (flags == 0) {
        return length > 0;  // DATA 必须有负载。
    }
    if (length != 0) {
        return 0;  // 控制报文不允许携带数据。
    }
    return flags == RTP_SYN || flags == RTP_ACK ||
           flags == (RTP_SYN | RTP_ACK) || flags == RTP_FIN ||
           flags == (RTP_FIN | RTP_ACK);
}

size_t rtp_make_packet(rtp_packet_t *packet, uint32_t seq_num,
                       uint8_t flags, const void *payload, uint16_t length) {
    if (packet == NULL || seq_num >= RTP_SEQ_MOD ||
        length > PAYLOAD_MAX || !flags_are_valid(flags, length) ||
        (length > 0 && payload == NULL)) {
        return 0;
    }

    // 清零结构体，特别是校验字段，保证两端 CRC 的输入一致。
    memset(packet, 0, sizeof(*packet));
    packet->rtp.seq_num = seq_num;
    packet->rtp.length = length;
    packet->rtp.flags = flags;
    if (length > 0) {
        memcpy(packet->payload, payload, length);
    }

    // 注意：只校验 11 字节 RTP 首部 + 实际 payload，不校验尾部未使用的数组空间。
    const size_t packet_bytes = sizeof(rtp_header_t) + length;
    packet->rtp.checksum = compute_checksum(packet, packet_bytes);
    return packet_bytes;
}

int rtp_check_packet(const rtp_packet_t *packet, size_t received_bytes) {
    if (packet == NULL || received_bytes < sizeof(rtp_header_t)) {
        return 0;
    }

    const uint16_t length = packet->rtp.length;
    if (length > PAYLOAD_MAX ||
        received_bytes != sizeof(rtp_header_t) + (size_t)length ||
        packet->rtp.seq_num >= RTP_SEQ_MOD ||
        !flags_are_valid(packet->rtp.flags, length)) {
        return 0;
    }

    // 校验时保存对端给出的校验值，并在临时副本上把 checksum 置 0。
    // 这样不破坏原始报文，也避免计算过程中修改它。
    rtp_packet_t copy;
    memcpy(&copy, packet, received_bytes);
    const uint32_t received_checksum = copy.rtp.checksum;
    copy.rtp.checksum = 0;
    return compute_checksum(&copy, received_bytes) == received_checksum;
}

int rtp_send_packet(int sockfd, const rtp_packet_t *packet) {
    if (packet == NULL || packet->rtp.length > PAYLOAD_MAX) {
        errno = EINVAL;
        return -1;
    }
    const size_t bytes = sizeof(rtp_header_t) + packet->rtp.length;
    ssize_t result;
    do {
        result = send(sockfd, packet, bytes, 0);
    } while (result < 0 && errno == EINTR);
    // UDP 按数据报发送；发送成功应一次发完指定长度。
    return result == (ssize_t)bytes ? 0 : -1;
}

int64_t rtp_now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
        return -1;
    }
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int rtp_recv_packet(int sockfd, rtp_packet_t *packet,
                    struct sockaddr_in *from, int timeout_ms) {
    if (packet == NULL || timeout_ms < 0) {
        errno = EINVAL;
        return -1;
    }
    const int64_t started = rtp_now_ms();
    if (started < 0) {
        return -1;
    }
    const int64_t deadline = started + timeout_ms;

    while (1) {
        const int64_t now = rtp_now_ms();
        if (now < 0) {
            return -1;
        }
        const int64_t remaining = deadline - now;
        if (remaining <= 0) {
            return 0;
        }
        struct pollfd pfd = {.fd = sockfd, .events = POLLIN, .revents = 0};
        int ready = poll(&pfd, 1, (int)remaining);
        if (ready == 0) {
            return 0;
        }
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (pfd.revents & POLLNVAL) {
            errno = EBADF;
            return -1;
        }
        if (pfd.revents & POLLERR) {
            // Linux 上，连接型 UDP socket 发往暂未监听的端口时，
            // 可能收到 ICMP Port Unreachable（ECONNREFUSED）。
            // 这不代表握手需要立即失败：清除异步错误后继续等待，
            // 让上层按 100 ms 的重传定时器再次发送 SYN。
            int socket_error = 0;
            socklen_t error_length = sizeof(socket_error);
            if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR,
                           &socket_error, &error_length) < 0) {
                return -1;
            }
            if (socket_error == ECONNREFUSED || socket_error == EHOSTUNREACH ||
                socket_error == ENETUNREACH) {
                continue;
            }
            errno = socket_error != 0 ? socket_error : EIO;
            return -1;
        }
        if (!(pfd.revents & POLLIN)) {
            continue;
        }

        struct sockaddr_in peer = {0};
        socklen_t peer_size = sizeof(peer);
        // MSG_TRUNC 在 Linux 上可以返回原始数据报大小，从而识别过长报文。
        ssize_t received = recvfrom(sockfd, packet, sizeof(*packet), MSG_TRUNC,
                                    (struct sockaddr *)&peer, &peer_size);
        if (received < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ||
                errno == ECONNREFUSED) {
                continue;
            }
            return -1;
        }
        if ((size_t)received > sizeof(*packet) ||
            !rtp_check_packet(packet, (size_t)received)) {
            LOG_DEBUG("RTP: discard invalid/corrupted packet\n");
            continue;
        }
        if (from != NULL) {
            *from = peer;
        }
        return 1;
    }
}
