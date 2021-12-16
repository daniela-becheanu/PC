#include <stdio.h>
#include <stdlib.h>
#include <queue.h>
#include "skel.h"

#define BUFF_SIZE 80
#define MAX_SIZE_ADDR 20
#define MAX_LEN_TABLE 80000
#define IP_OFF (sizeof(struct ether_header))
#define ICMP_OFF (IP_OFF + sizeof(struct iphdr))
#define TYPE_ECHO_REPLY 0
#define ICMP_ECHO_CODE 0

/* Entries for arp table and route table */
struct route_table_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
} __attribute__((packed));
typedef struct route_table_entry route_table_entry; 

struct arp_entry {
	uint32_t ip;
	uint8_t mac[6];
};
typedef struct arp_entry arp_entry;

/* Function used to parse the route table given, returninfg the number of
 * elements in the route table */
int parse_rtable(char *file_name, route_table_entry *rtable){
	char buff[BUFF_SIZE];
	FILE *f = fopen(file_name, "r");
	DIE(f == NULL, "cannot open file!\n");

	int i = 0;

	while(fgets(buff, sizeof(buff), f)){
		char prefix[MAX_SIZE_ADDR];
		char next_hop[MAX_SIZE_ADDR];
		char mask[MAX_SIZE_ADDR];
		i++;
		sscanf(buff, "%s %s %s %d", prefix, next_hop, mask,
			&rtable[i - 1].interface);
       
		rtable[i - 1].prefix = inet_addr(prefix);
		rtable[i - 1].next_hop = inet_addr(next_hop);
		rtable[i - 1].mask = inet_addr(mask);
	}

	fclose(f);
	return i;
}

/* Function used to get the best route to a certain destination using binary
 * search */
route_table_entry* get_best_route(__uint32_t dest_ip,
	route_table_entry* rtable, int start, int end) {

	int mid;

	while (start <= end) {

		mid = (start + end) / 2;
		
		if ((rtable[mid].mask & dest_ip) == rtable[mid].prefix) {
			return &rtable[mid];
		}

		if ((rtable[mid].mask & dest_ip) < rtable[mid].prefix) {
			end = mid - 1;
		} else {
			start = mid + 1;
		}
	}

    return NULL;
}

/* Finds the correspondent ARP entry of an IP */
arp_entry *get_arp_entry(__uint32_t ip, arp_entry* arp_table,
	unsigned int arp_table_len) {
	for (int i = 0; i < arp_table_len; ++i) {
		if (arp_table[i].ip == ip) {
			return &arp_table[i];
		}
	}
	return NULL;
}

/* Function used for comparing two route table entries and sorting the
 * route table array */
int compare(const void *e1, const void *e2) {
	if ((*(route_table_entry *)e1).prefix >
		(*(route_table_entry *)e2).prefix) {
		return 1;
	}

	if ((*(route_table_entry *)e1).prefix <
		(*(route_table_entry *)e2).prefix) {
		return -1;
	}

    if ((*(route_table_entry *)e1).mask >
		(*(route_table_entry *)e2).mask) {
		return 1;
    }

	if ((*(route_table_entry *)e1).mask <
		(*(route_table_entry *)e2).mask) {
		return -1;
    }

	return 0;
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	init(argc - 2, argv + 2);

	/* Declaring and allocating memory for the route table and ARP table */
	route_table_entry *rtable;
	arp_entry *arp_table;

	rtable = calloc(MAX_LEN_TABLE, sizeof(route_table_entry));
	unsigned int rtable_len = parse_rtable(argv[1], rtable);

	/* Sorting the route table using the compare fucntion */
	qsort(rtable, rtable_len, sizeof(route_table_entry), compare);

	arp_table = calloc(MAX_LEN_TABLE, sizeof(arp_entry));
	int arp_table_len = 0;
	queue q = queue_create();

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		/* Extracting the headers of the packet */
		struct ether_header *eth_hdr;
		struct iphdr *ip_hdr;
		struct icmphdr *icmp_hdr;
		struct arp_header *arp_hdr;

		eth_hdr = (struct ether_header *)m.payload;
		ip_hdr = (struct iphdr *)(m.payload + IP_OFF);
		icmp_hdr = parse_icmp(m.payload);
		arp_hdr = parse_arp(m.payload);

		/* Checking if it is an IP packet */
		if (eth_hdr->ether_type == htons(ETHERTYPE_IP)) {
			/* If it is an IP packet for the router (ICMP ECHO REQUEST) */
			if (inet_addr(get_interface_ip(m.interface)) == ip_hdr->daddr
				&& icmp_hdr && icmp_hdr->code == ICMP_ECHO_CODE
				&& icmp_hdr->type == ICMP_ECHO) {
				send_icmp(ip_hdr->saddr, ip_hdr->daddr,
					eth_hdr->ether_dhost, eth_hdr->ether_shost, 
					ICMP_ECHOREPLY, ICMP_ECHO_CODE, m.interface,
					getppid(), 0);
				continue;
			}

			/* Checking the checksum */
			if (ip_checksum(ip_hdr, sizeof(struct iphdr))) {
				continue;
			}
			
			/* Checking the ttl */
			if (ip_hdr->ttl <= 1) {
				send_icmp_error(ip_hdr->saddr, ip_hdr->daddr,
					eth_hdr->ether_dhost, eth_hdr->ether_shost, 
					ICMP_TIME_EXCEEDED, ICMP_ECHO_CODE, m.interface);
				continue;
			}
			
			/* Getting the best route for the packet to be sent to */
			route_table_entry* best_route = get_best_route(ip_hdr->daddr,
				rtable, 0, rtable_len - 1);

			/* If best route is not found, send ICMP DEST UNREACH */
			if (!best_route) {
				send_icmp_error(ip_hdr->saddr, ip_hdr->daddr,
					eth_hdr->ether_dhost, eth_hdr->ether_shost, 
					ICMP_DEST_UNREACH, ICMP_ECHO_CODE, m.interface);
				continue;
			}

			/* If the best route is found, get the corresponding ARP entry */
			arp_entry *arp = get_arp_entry(best_route->next_hop, arp_table,
				arp_table_len);
			
			/* If there is no ARP entry in the ARP table, insert a copy of the
			 * packet in the queue and send an ARP REQUEST as broadcast*/
			if (!arp) {
				struct ether_header *eth_hdr_aux;
				packet *p;

				p = malloc(sizeof(packet));
				memcpy(p, &m, sizeof(packet));
                queue_enq(q, p);
                
				eth_hdr_aux = calloc(1, sizeof(struct ether_header));
                hwaddr_aton("ff:ff:ff:ff:ff:ff:ff", eth_hdr_aux->ether_dhost);
                eth_hdr_aux->ether_type = htons(ETHERTYPE_ARP);
                get_interface_mac(best_route->interface,
					eth_hdr_aux->ether_shost);
				
                send_arp(best_route->next_hop,
					inet_addr(get_interface_ip(best_route->interface)),
                	eth_hdr_aux, best_route->interface, htons(ARPOP_REQUEST));
				continue;
			}
			
			/* If the ARP entry is found, forward the packet with the updated
			 * ttl and checksum */
			get_interface_mac(best_route->interface, eth_hdr->ether_shost);
			memcpy(eth_hdr->ether_dhost, arp->mac, sizeof(arp->mac));

			--ip_hdr->ttl;
			ip_hdr->check = 0;
			ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));
			send_packet(best_route->interface, &m);
		}

		/* CHecking if it is an ARP packet */
		if (eth_hdr->ether_type == htons(ETHERTYPE_ARP)) {
			/* If it is an ARP REQUEST packet for the router, send an ARP
			 * REPLY */
			if (arp_hdr && arp_hdr->op == ntohs(ARPOP_REQUEST)) {
				if (inet_addr(get_interface_ip(m.interface)) == arp_hdr->tpa) {
					memcpy(eth_hdr->ether_dhost, arp_hdr->sha,
						sizeof(unsigned char) * 6);
					get_interface_mac(m.interface, eth_hdr->ether_shost);

					send_arp(arp_hdr->spa, inet_addr(get_interface_ip(m.interface)),
						eth_hdr, m.interface, htons(ARPOP_REPLY));
					continue;
				}
			}

			/* If it is an ARP REPLY, add the arp entry if it is necessary and
			 * send the packet in the queue */
			if (arp_hdr && arp_hdr->op == ntohs(ARPOP_REPLY) 
				&& inet_addr(get_interface_ip(m.interface)) == arp_hdr->tpa) {
				if (!get_arp_entry(arp_hdr->spa, arp_table, arp_table_len)) {
					// memcpy(arp_table[arp_table_len].mac, arp_hdr->sha,
					// 	sizeof(arp_hdr->sha));
					// arp_table[arp_table_len].ip = arp_hdr->spa;
					++arp_table_len;

					arp_table_len++;
                    arp_table[arp_table_len - 1].ip = arp_hdr->spa;
                    memcpy(arp_table[arp_table_len - 1].mac, arp_hdr->sha, 6);
				}

				if (!queue_empty(q)) {
					packet p = *((packet *)queue_deq(q));
					struct ether_header* eth_hdr_p =(struct ether_header *)p.payload; 
					struct iphdr* ip_hdr_p = (struct iphdr* )(p.payload + IP_OFF);
					/* Get the MAC address of the best route and copy it in the
					 * destination field */
					route_table_entry* best_route = get_best_route(ip_hdr_p->daddr,
						rtable, 0, rtable_len - 1);
					u_char *mac;
					mac = get_arp_entry(arp_hdr->spa, arp_table, arp_table_len)->mac;
					memcpy(eth_hdr_p->ether_dhost, mac, 6);
					get_interface_mac(best_route->interface, eth_hdr_p->ether_shost);
					--ip_hdr->ttl;
					ip_hdr->check = 0;
					ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));
					send_packet(best_route->interface, &p);
				}
			}
		}
	}
	free(rtable);
	free(arp_table);
}
