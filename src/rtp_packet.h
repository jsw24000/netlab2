#ifndef RTP_PACKET_H
#define RTP_PACKET_H

#include "rtp.h"

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

// RTP 的序号空间为 [0, 2^30 - 1]，超过最大值后回绕到 0。
#define RTP_SEQ_MOD (1U << 30)
#define RTP_RTO_MS 100
#define RTP_MAX_RETRIES 50
#define RTP_SYN_WAIT_MS 5000
#define RTP_FINAL_ACK_WAIT_MS 2000

// 生成一个完整的 RTP 报文，成功时返回实际报文长度，失败时返回 0。
// 控制报文（SYN/ACK/FIN）没有负载，调用时传入 payload=NULL、length=0。
size_t rtp_make_packet(rtp_packet_t *packet, uint32_t seq_num,
                       uint8_t flags, const void *payload, uint16_t length);

// 检查报文长度、字段合法性和 CRC32；成功返回 1，否则返回 0。
int rtp_check_packet(const rtp_packet_t *packet, size_t received_bytes);

// 序号 +1，并按 2^30 回绕。
uint32_t rtp_next_seq(uint32_t seq_num);

// 对已经 connect() 的 UDP socket 发送一份完整报文；成功返回 0。
int rtp_send_packet(int sockfd, const rtp_packet_t *packet);

// 在 timeout_ms 毫秒内等待一个有效的 RTP 报文。
// 返回 1=收到合法报文，0=超时，-1=发生系统错误。
// from 非 NULL 时，写入发送方地址；非法或损坏的报文会被直接丢弃。
int rtp_recv_packet(int sockfd, rtp_packet_t *packet,
                    struct sockaddr_in *from, int timeout_ms);

// 返回单调时钟毫秒数，用于计算剩余超时时间。
int64_t rtp_now_ms(void);

#ifdef __cplusplus
}
#endif

#endif // RTP_PACKET_H
