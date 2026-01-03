/*
 * Non-Commercial Share-Alike Software License (NCSL-1.0)
 * � 2025, Roman Gorkusha / Karroplan
 *
 * Permission is granted to use, copy, modify, and share this software
 * for non-commercial purposes only, provided that this notice and the
 * full license text are retained. Derivative works must be licensed
 * under the same terms (NCSL-1.0).
 *
 * Commercial use of this software requires a separate license agreement
 * with the author.
 *
 * SPDX-License-Identifier: NCSL-1.0
 * See the LICENSE file for full license text.
 *
 * This software uses OpenSSL 3.0, which is licensed separately under its own terms.
 * See https://www.openssl.org/source/license.html for details.
 */


#define _POSIX_C_SOURCE 200809L  //nanosleep requres it
#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <pthread.h>
#include <time.h>
#include <sys/timerfd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "wsp_sockets.h"
#include "wsp_websock.h"

//convert 8byte unsigned int from net byte order to host byte order
uint64_t ntohll(uint64_t val) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return (((uint64_t)ntohl((uint32_t)(val & 0x0FFFFFFFF))) << 32) | (uint64_t)ntohl((uint32_t)(val >> 32));
#else
    return val;
#endif
}

//convert 8byte unsigned int from host byte order to net byte order
uint64_t htonll(uint64_t value) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return (((uint64_t)htonl((uint32_t)(value & 0x0FFFFFFFF))) << 32) | htonl((uint32_t)(value >> 32));
#else
    return value;
#endif
}


int ws_recv_frame_header(const wsp_socket* sckt, ws_frame_header* pws_hdr, int _timeout) {

    uint8_t hdr[2];
    size_t rdbytes;

    if (sckt->fn_read_exact(sckt, hdr, 2, &rdbytes, _timeout) != -1) {
        pws_hdr->opcode = hdr[0] & 0x0F;
        pws_hdr->fin = (hdr[0] & 0x80) >> 7;
        pws_hdr->ismasked = (hdr[1] & 0x80) >> 7;
        uint8_t pldlen1 = hdr[1] & (unsigned char)0x7f;
        pws_hdr->len1 = pldlen1;

        if (pldlen1 == 0) pws_hdr->follows = FOLLOWS_NONE;
        if (pldlen1 <= 125 && pws_hdr->ismasked) {
            pws_hdr->follows = FOLLOWS_MASK;
        }
        else if (pldlen1 <= 125 && pldlen1 > 0) {
            pws_hdr->follows = FOLLOWS_BODY;
        }
        else if (pldlen1 == 126) {
            pws_hdr->follows = FOLLOWS_2B_LENGTH;
        }
        else if (pldlen1 == 127) {
            pws_hdr->follows = FOLLOWS_2B_LENGTH;
        }

        if (pldlen1 <= 125) pws_hdr->body_length = pldlen1;

        return 0;
    }
    else
        return -1;
}

int ws_recv_2b_length(const wsp_socket* sckt, ws_frame_header* pws_hdr, int _timeout) {
    uint8_t exln[2];
    uint16_t len16;
    size_t rdbytes;

    if (sckt->fn_read_exact(sckt, exln, 2, &rdbytes, _timeout) != -1) {
        memcpy(&len16, exln, 2);
        pws_hdr->body_length = ntohs(len16);

        if (pws_hdr->ismasked)
            pws_hdr->follows = FOLLOWS_MASK;
        else if (pws_hdr->body_length == 0)
            pws_hdr->follows = FOLLOWS_NONE;
        else
            pws_hdr->follows = FOLLOWS_BODY;

        return 0;
    }

    return -1;
}

int ws_recv_8b_length(const wsp_socket* sckt, ws_frame_header* pws_hdr, int _timeout) {
    uint8_t exln8b[8];
    uint64_t len64;
    size_t rdbytes;

    if (sckt->fn_read_exact(sckt, exln8b, 8, &rdbytes, _timeout) != -1) {
        memcpy(&len64, exln8b, 8);
        pws_hdr->body_length = ntohll(len64);

        if (pws_hdr->ismasked)
            pws_hdr->follows = FOLLOWS_MASK;
        else if (pws_hdr->body_length == 0)
            pws_hdr->follows = FOLLOWS_NONE;
        else
            pws_hdr->follows = FOLLOWS_BODY;

        return 0;
    }

    return -1;

}

int ws_recv_mask(const wsp_socket* sckt, ws_frame_header* pws_hdr, int _timeout) {
    uint8_t mask[4];
    size_t rdbytes;

    if (sckt->fn_read_exact(sckt, mask, 4, &rdbytes, _timeout) != -1) {
        memcpy(&pws_hdr->mask, mask, 4);

        if (pws_hdr->body_length == 0)
            pws_hdr->follows = FOLLOWS_NONE;
        else
            pws_hdr->follows = FOLLOWS_BODY;

        return 0;

    }

    return -1;
}

int ws_recv_body(const wsp_socket* sckt, ws_frame_header* pws_hdr, ws_frame_body* pws_bdy, int _timeout) {

    pws_hdr->follows = FOLLOWS_NONE;

    if (pws_hdr->body_length == 0)
        return 0;

    pws_bdy->body_length = pws_hdr->body_length;
    pws_bdy->bytes = malloc(pws_bdy->body_length + 1);

    if (!pws_bdy->bytes)
        return -1;

    size_t rdbytes;
    if (sckt->fn_read_exact(sckt, pws_bdy->bytes, pws_bdy->body_length, &rdbytes, _timeout) == -1)
        return -1;

    if (rdbytes != pws_bdy->body_length)
        return -1;

    ((char*)pws_bdy->bytes)[pws_bdy->body_length] = '\0';

    return 0;
}

int ws_free_body(ws_frame_body* pws_bdy) {
    if (pws_bdy->bytes) {
        free(pws_bdy->bytes);
        pws_bdy->body_length = 0;
    }

    return 0;
}

ssize_t ws_send_close(const wsp_socket* sckt, int _timeout) {

    uint8_t close_frame_hdr[2];
    close_frame_hdr[0] = 0x88; //FIN is SET and opcode = 0x8
    close_frame_hdr[1] = 0;

    close_frame_hdr[1] |= 0x80; //mask bit is set

    size_t bts;

    //send header
    if (sckt->fn_write_exact(sckt, close_frame_hdr, 2, &bts, _timeout) == -1)
        return -1;

    //generate mask
    uint8_t mask[4]; // keep it as-is

    //send mask
    if (sckt->fn_write_exact(sckt, mask, 4, &bts, _timeout) == -1) return -1;

    return 0;
}

int ws_mask_buffer(uint8_t* buf, size_t buf_sz, const uint8_t* mask) {
    if (!buf || !mask || buf_sz == 0) return -1;

    for (size_t i = 0; i < buf_sz; ++i) {
        buf[i] ^= mask[i % 4];
    }

    return 0;
}

ssize_t ws_send_message(const wsp_socket* sckt, void* buf, size_t buf_sz, size_t* bts_sent, int _timeout) {

    if (!sckt) return -1;

    size_t bytes_written = 0;
    uint8_t msg_frame_hdr[2];
    msg_frame_hdr[0] = 0x81; //FIN is SET and opcode = 0x1
    msg_frame_hdr[1] = 0;

    bool need2b_length = false;
    uint16_t msg_body_length_2b = 0;
    bool need8b_length = false;
    uint64_t msg_body_length_8b = 0;

    //check length
    if (buf_sz <= 125) {
        msg_frame_hdr[1] |= (uint8_t)buf_sz;
    }
    else if (buf_sz <= 65535) {
        msg_frame_hdr[1] |= 126; //2b length
        need2b_length = true;

        msg_body_length_2b = htons((uint16_t)buf_sz);
    }
    else {
        msg_frame_hdr[1] |= 127; //8b length
        need8b_length = true;
        need2b_length = true;

        msg_body_length_2b = 0;
        msg_body_length_8b = htonll(buf_sz);
    }

    msg_frame_hdr[1] |= 0x80; //mask bit is set

    size_t btssent = 0;

    //send frame header
    sckt->fn_write_exact(sckt, msg_frame_hdr, 2, &btssent, _timeout);

    //send 2b length if needed
    if (need2b_length) {
        if (sckt->fn_write_exact(sckt, &msg_body_length_2b, 2, &bytes_written, _timeout) == -1) return -1;
    }

    //send 8b length if needed
    if (need8b_length) {
        if (sckt->fn_write_exact(sckt, &msg_body_length_8b, 8, &bytes_written, _timeout) == -1) return -1;
    }

    //generate mask
    uint8_t mask[4];
    for (int i = 0; i < 4; ++i) {
        mask[i] = (uint8_t)(rand() % 256);
    }

    //send mask
    if (sckt->fn_write_exact(sckt, mask, 4, &bytes_written, _timeout) == -1) {
        *bts_sent = bytes_written;
        return -1;
    }

    //Mask the message body
    if (ws_mask_buffer((uint8_t*)buf, buf_sz, mask) == -1) {
        *bts_sent = bytes_written;
        return -1;
    }

    //send message body
    ssize_t sndret = sckt->fn_write_exact(sckt, buf, buf_sz, &bytes_written, _timeout);
	*bts_sent = bytes_written;

	return sndret;
}

int ws_send_pong(const wsp_socket* sckt, ws_frame_body* ping_body, int _timeout) {
    uint8_t pong_frame_hdr[2];
    pong_frame_hdr[0] = 0x8A; //FIN is set and opcode = 0xA
    pong_frame_hdr[1] = 0;

    pong_frame_hdr[1] |= 0x80; //mask bit is set

    bool need2b_length = false;
    uint16_t pong_body_length_2b = 0;
    bool need8b_length = false;
    uint64_t pong_body_length_8b = 0;

    //check length
    if (ping_body->body_length <= 125) {
        pong_frame_hdr[1] |= (uint8_t)ping_body->body_length;
    }
    else if (ping_body->body_length <= 65535) {
        pong_frame_hdr[1] |= 126; //2b length
        need2b_length = true;

        pong_body_length_2b = htons((uint16_t)ping_body->body_length);
    }
    else {
        pong_frame_hdr[1] |= 127; //8b length
        need8b_length = true;
        need2b_length = true;

        pong_body_length_2b = 0;
        pong_body_length_8b = htonll(ping_body->body_length);
    }

    size_t btssent = 0;
    sckt->fn_write_exact(sckt, pong_frame_hdr, 2, &btssent, _timeout);
    if (need2b_length) {
        sckt->fn_write_exact(sckt, &pong_body_length_2b, 2, &btssent, _timeout);
    }
    if (need8b_length) {
        sckt->fn_write_exact(sckt, &pong_body_length_8b, 8, &btssent, _timeout);
    }

    //generate mask
    uint8_t mask[4];
    for (int i = 0; i < 4; ++i) {
        mask[i] = (uint8_t)(rand() % 256);
    }

    //send mask
    if (sckt->fn_write_exact(sckt, mask, 4, &btssent, _timeout) == -1) return -1;

    //Mask the message body
    if (ping_body->body_length > 0) {
        if (ws_mask_buffer((uint8_t*)ping_body->bytes, ping_body->body_length, mask) == -1) {
            return -1;
        }
    }

    // send pong body
    if(ping_body->body_length >0)
        sckt->fn_write_exact(sckt, ping_body->bytes, ping_body->body_length, &btssent, _timeout);

    return 0;
}

int ws_send_ping(const wsp_socket* sckt, char* msg, ssize_t msg_size, int _timeout) {
    uint8_t ping_frame_hdr[2];
    ping_frame_hdr[0] = 0x89; //FIN is set and opcode = 0x9
    ping_frame_hdr[1] = 0;
    bool need2b_length = false;
    uint16_t ping_body_length_2b = 0;
    bool need8b_length = false;
    uint64_t ping_body_length_8b = 0;

    ping_frame_hdr[1] |= 0x80; //mask bit is set

    //check length
    if (msg_size <= 125) {
        ping_frame_hdr[1] |= (uint8_t)msg_size;
    }
    else if (msg_size <= 65535) {
        ping_frame_hdr[1] |= 126; //2b length
        need2b_length = true;
        ping_body_length_2b = htons((uint16_t)msg_size);
    }
    else {
        ping_frame_hdr[1] |= 127; //8b length
        need8b_length = true;
        need2b_length = true;
        ping_body_length_2b = 0;
        ping_body_length_8b = htonll((uint64_t)msg_size);
    }

    size_t btssent = 0;
    sckt->fn_write_exact(sckt, ping_frame_hdr, 2, &btssent, _timeout);
    if (need2b_length) {
        sckt->fn_write_exact(sckt, &ping_body_length_2b, 2, &btssent, _timeout);
    }
    if (need8b_length) {
        sckt->fn_write_exact(sckt, &ping_body_length_8b, 8, &btssent, _timeout);
    }

    //generate mask
    uint8_t mask[4];
    for (int i = 0; i < 4; ++i) {
        mask[i] = (uint8_t)(rand() % 256);
    }

    //send mask
    if (sckt->fn_write_exact(sckt, mask, 4, &btssent, _timeout) == -1) return -1;

    //Mask the message body
    if (msg_size > 0 && msg != NULL) {
        if (ws_mask_buffer((uint8_t*)msg, (size_t)msg_size, mask) == -1) {
            return -1;
        }
    }


    if (msg_size > 0)
        sckt->fn_write_exact(sckt, msg, (size_t)msg_size, &btssent, _timeout);

    return 0;
}

int ws_print_body(const char* prefix, const ws_frame_body* pws_bdy) {
    printf("%s %s\n", prefix, (char*)pws_bdy->bytes);
    return 0;
}
