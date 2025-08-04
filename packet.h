#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include "packet.c"

static uint16_t ip_checksum(void *vdata, size_t length);

int build_eth_ipv4_packet(const uint8_t *payload, size_t payload_len,
                          uint8_t **out_packet, size_t *out_len);