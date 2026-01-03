/*
 * Non-Commercial Share-Alike Software License (NCSL-1.0)
 * © 2025, Roman Gorkusha / Karroplan
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


#pragma once
#ifndef WSP_WEBSOCK
#define WSP_WEBSOCK

//websocket opcodes
#define OC_CONT 0x00
#define OC_TEXT 0x01
#define OC_BIN 0x02
#define OC_CLOSE 0x08
#define OC_PING 0x09
#define OC_PONG 0x0A

//states of frame header parsing
#define FOLLOWS_NONE            0
#define FOLLOWS_2B_LENGTH       1
#define FOLLOWS_8B_LENGTH       2
#define FOLLOWS_MASK            3
#define FOLLOWS_BODY            4

typedef struct ws_frame_header_t {
    int fin;
    int ismasked;
    int opcode;
    int follows;
    uint8_t len1;
    uint64_t body_length;
    uint32_t mask;
} ws_frame_header;

typedef struct ws_frame_body_t {
    void* bytes;
    uint64_t body_length;
} ws_frame_body;

//convert 8byte unsigned int from net byte order to host byte order
uint64_t ntohll(uint64_t val);

//convert 8byte unsigned int from host byte order to net byte order
uint64_t htonll(uint64_t value);

// reads websocket frame header from socket
int ws_recv_frame_header(const wsp_socket* sckt, ws_frame_header* pws_hdr, int _timeout);

// reads 2-byte length from socket
int ws_recv_2b_length(const wsp_socket* sckt, ws_frame_header* pws_hdr, int _timeout);

// reads 8-byte length from socket
int ws_recv_8b_length(const wsp_socket* sckt, ws_frame_header* pws_hdr, int _timeout);

// reads mask from socket
int ws_recv_mask(const wsp_socket* sckt, ws_frame_header* pws_hdr, int _timeout);

// reads frame body from socket
int ws_recv_body(const wsp_socket* sckt, ws_frame_header* pws_hdr, ws_frame_body* pws_bdy, int _timeout);

// frees frame body
int ws_free_body(ws_frame_body* pws_bdy);

// sends close frame to socket
ssize_t ws_send_close(const wsp_socket* sckt, int _timeout);

// masks/unmasks buffer with given mask
int ws_mask_buffer(uint8_t* buf, size_t buf_sz, const uint8_t* mask);

// sends message to websocket
ssize_t ws_send_message(const wsp_socket* sckt, void* buf, size_t buf_sz, size_t* bts_sent, int _timeout);

// sends pong frame in response to ping
int ws_send_pong(const wsp_socket* sckt, ws_frame_body* ping_body, int _timeout);

// sends ping frame
int ws_send_ping(const wsp_socket* sckt, char* msg, ssize_t msg_size, int _timeout);

// prints frame body
int ws_print_body(const char* prefix, const ws_frame_body* pws_bdy);

#endif // !WSP_WEBSOCK

