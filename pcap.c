#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <my_global.h>
#include <mysql.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <sys/time.h>
#include <time.h>
#include <math.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <linux/tcp.h>
#include <netdb.h>

#define SUPPORT_OUTPUT
#define ETHER_ADDR_LEN 6
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN];
    u_char ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
};
struct sniff_ip {
    u_char ip_vhl;
    u_char ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
#define IP_RF 0x8000    
#define IP_DF 0x4000    
#define IP_MF 0x2000    
#define IP_OFFMASK 0x1fff   
    u_char ip_ttl;
    u_char ip_p;
    u_short ip_sum;
    struct in_addr ip_src, ip_dst;
};
#define IP_HL(ip)      (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)      (((ip)->ip_vhl) >> 4)
typedef u_int tcp_seq;
struct sniff_tcp {
    u_short th_sport;
    u_short th_dport;
    tcp_seq th_seq;
    tcp_seq th_ack;
    u_char th_offx2;
#define TH_OFF(th)   (((th)->th_offx2 & 0xf0) > 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
};
struct pseudohdr {
    u_int32_t   saddr;
    u_int32_t   daddr;
    u_int8_t    useless;
    u_int8_t    protocol;
    u_int16_t   tcplength;
};
struct struct_domain_list {
    int id;
    char domain[256];
    char created_at[100];
    char comment[150];
};
MYSQL* mq;
//MYSQL* con;

struct struct_domain_list* domain_list;
int domain_list_cnt;
char if_bind_global[] = "lo";
int if_bind_global_len = 2;
int sendraw_mode = 1;

unsigned short in_cksum(u_short* addr, int len);

int sendraw(u_char* pre_packet, int mode);

void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet);

int main(int argc, char* argv[])
{
    pcap_t* handle;
    char* dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    char port_num[] = "dst port 80";

    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct pcap_pkthdr header;
    const u_char* packet;
    MYSQL_RES* res;
    MYSQL_ROW row;

    int ret;
    mq = mysql_init(NULL);

    if (mysql_real_connect
    (mq,
        "127.0.0.1",
        "linuxuser",
        "4321",
        "shopping_db",
        3306,
        NULL,
        0) == NULL) {
        printf("실패:\n");
    }
    ret = mysql_query(mq, "SELECT COUNT(*) FROM tb_domain_list;");
    if (ret != 0) {
        printf("오류!\n");
    }
    res = mysql_store_result(mq);
    row = mysql_fetch_row(res);
    domain_list_cnt = atoi(row[0]);

    ret = mysql_query(mq, "SELECT * FROM tb_domain_list;");
    if (ret != 0) {
        printf("오류!\n");
    }
    res = mysql_store_result(mq);

    domain_list = malloc(sizeof(struct struct_domain_list) * domain_list_cnt);

    if (domain_list == NULL) {
        printf("도메인 리스트 오류!\n");
    }
    else {
        printf("도메인 리스트:%d개\n", domain_list_cnt);
    }

    int j = 0;
    while (row = mysql_fetch_row(res))
    {
        printf("도메인 = %s\n", row[1]);
        printf(" 이름  = %s\n", row[3]);

        domain_list[j].id = atoi(row[0]);
        strcpy(domain_list[j].domain, row[1]);
        strcpy(domain_list[j].created_at, row[2]);
        strcpy(domain_list[j].comment, row[3]);
        j++;
    }


    dev = pcap_lookupdev(NULL);

    if (dev == NULL)
        printf("오류\n");

    if (pcap_lookupnet(dev, &net, &mask, NULL) == -1)
        printf("오류\n");

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, NULL);

    if (handle == NULL)
        printf("오류\n");

    if (pcap_compile(handle, &fp, port_num, 0, net) == -1)
        printf("오류\n");

    if (pcap_setfilter(handle, &fp) == -1)
        printf("오류\n");

    pcap_loop(handle, 0, got_packet, NULL);


    pcap_close(handle);

    if (mq != NULL)
        mysql_close(mq);
    //mq=0;
    return(0);
}

void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet)
{
#define SIZE_ETHERNET 14
    const struct sniff_ethernet* ethernet;
    const struct sniff_ip* ip;
    const struct sniff_tcp* tcp;
    const char* payload;
    u_int size_ip;
    u_int size_tcp;
    ethernet = (struct sniff_ethernet*)(packet);
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        printf("IP 오류: %u bytes\n", size_ip);
        return;
    }


    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = 20;
    if (size_tcp < 20) {
        printf("TCP 오류: %u bytes\n", size_tcp);
        return;
    }
    payload = (u_char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    char* ip_src_str;
    char* ip_dst_str;
    ip_src_str = malloc(16);
    ip_dst_str = malloc(16);
    strcpy(ip_src_str, inet_ntoa(ip->ip_src));
    ip_dst_str = inet_ntoa(ip->ip_dst);
    char* line;
    char* line_start;
    char* line_end;
    int line_len = 0;
    int while_con1 = 1;
    char domain[256];
    int result = 0;
    int ret = 0;
    line_start = payload;
    memset(line, 0x00, 256);
    line = malloc(1000);
    int sendraw_result = 0;
    int cnt = 0;




    while (while_con1 > 0) {
        line_end = strstr(line_start, "\x0d\x0a");
        if (line_end == NULL) {
            while_con1 = 0;
        }
        else {
            line_len = line_end - line_start;
            strncpy(line, line_start, line_len);
            printf("\tline: %s\n", line);
            if (strncmp(line, "host: ", 6) == 0) {
                memset(&domain, 0x00, 256);
                strcpy(domain, line + 6);
                printf(" 도메인 = %s .\n", domain);

                for (int i = 0; i < domain_list_cnt; i++)
                    if (strcmp(domain, domain_list[i].domain) == 0)
                        cnt++;

                if (cnt > 0) {
                    printf("도메인 일치\n");

                    sendraw_result = sendraw(packet, 1);
                    if (sendraw_result == 1) {
                        printf("sendraw 성공\n");
                    }
                    else {
                        printf("sendraw 실패\n");

                    }
                }


                else {
                    printf("실패\n");
                    result = 1;
                }
                char insert_query[10240];
                memset(&insert_query, 0x00, 10240);
                sprintf(&insert_query, "INSERT INTO tb_cpu_usage "
                    " ( domain , result ) "
                    " values ( '%s' , %d )",
                    domain, result);
                ret = mysql_query(mq, insert_query);

                if (ret != 0) {
                    printf("ERROR: mariadb query error (%s).\n",
                        mysql_error(mq)
                    );
                }
                else {
                    printf("INFO: mariadb query ok.\n");
                }

            }

            line_start = line_end + 2;
        }
    }

    free(line);
}

int sendraw(u_char* pre_packet, int mode)
{
    const struct sniff_ethernet* ethernet;

    u_char packet[1600];
    int raw_socket, recv_socket;
    int on = 1, len;
    char recv_packet[100], compare[100];
    struct iphdr* iphdr;
    struct tcphdr* tcphdr;
    struct in_addr source_address, dest_address;
    struct sockaddr_in address, target_addr;
    struct pseudohdr* pseudo_header;
    struct in_addr ip;
    struct hostent* target;
    int port = 80;
    int loop1 = 0;
    int loop2 = 0;
    int pre_payload_size = 0;
    u_char* payload = NULL;
    int size_vlan = 0;
    int size_vlan_apply = 0;
    int size_payload = 0;
    int post_payload_size = 0;
    int sendto_result = 0;
    int rc = 0;
    char* if_bind;
    int if_bind_len = 0;
    int setsockopt_result = 0;
    int prt_sendto_payload = 0;
    char* ipaddr_str_ptr;

    int warning_page = 1;
    int vlan_tag_disabled = 0;

    int ret = 0;


    for (port = 80; port < 81; port++) {
        raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (raw_socket < 0) {
            printf("에러\n");
            return -2;
        }

        setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, (char*)&on, sizeof(on));

        if (if_bind_global != NULL)
            setsockopt_result = setsockopt(raw_socket, SOL_SOCKET, SO_BINDTODEVICE, if_bind_global, if_bind_global_len);

        ethernet = (struct sniff_ethernet*)(pre_packet);
        if (ethernet->ether_type == (unsigned short)*(unsigned short*)&"\x81\x00") {
            printf("vlan packet\n");
            size_vlan = 4;
            memcpy(packet, pre_packet, size_vlan);
        }
        else if (ethernet->ether_type == (unsigned short)*(unsigned short*)&"\x08\x00") {
            printf("normal packet\n");
            size_vlan = 0;
        }
        else {
            fprintf(stderr, "NOTICE: ether_type diagnostics failed .......... \n");
        }

        vlan_tag_disabled = 1;
        if (vlan_tag_disabled == 1) {
            size_vlan_apply = 0;
            memset(packet, 0x00, 4);
        }
        else {
            size_vlan_apply = size_vlan;
        }
        iphdr = (struct iphdr*)(packet + size_vlan_apply);
        memset(iphdr, 0, 20);
        tcphdr = (struct tcphdr*)(packet + size_vlan_apply + 20);
        memset(tcphdr, 0, 20);

        tcphdr->source = htons(777);
        tcphdr->dest = htons(port);
        tcphdr->seq = htonl(92929292);
        tcphdr->ack_seq = htonl(12121212);

        source_address.s_addr =
            ((struct iphdr*)(pre_packet + size_vlan + 14))->daddr;
        dest_address.s_addr = ((struct iphdr*)(pre_packet + size_vlan + 14))->saddr;
        iphdr->id = ((struct iphdr*)(pre_packet + size_vlan + 14))->id;
        int pre_tcp_header_size = 0;
        char pre_tcp_header_size_char = 0x0;
        pre_tcp_header_size = ((struct tcphdr*)(pre_packet + size_vlan + 14 + 20))->doff;
        pre_payload_size = ntohs(((struct iphdr*)(pre_packet + size_vlan + 14))->tot_len) - (20 + pre_tcp_header_size * 4);

        tcphdr->source = ((struct tcphdr*)(pre_packet + size_vlan + 14 + 20))->dest;
        tcphdr->dest = ((struct tcphdr*)(pre_packet + size_vlan + 14 + 20))->source;
        tcphdr->seq = ((struct tcphdr*)(pre_packet + size_vlan + 14 + 20))->ack_seq;
        tcphdr->ack_seq = ((struct tcphdr*)(pre_packet + size_vlan + 14 + 20))->seq + htonl(pre_payload_size - 20);
        tcphdr->window = ((struct tcphdr*)(pre_packet + size_vlan + 14 + 20))->window;

        tcphdr->doff = 5;

        tcphdr->ack = 1;
        tcphdr->psh = 1;

        tcphdr->fin = 1;
        pseudo_header = (struct pseudohdr*)((char*)tcphdr - sizeof(struct pseudohdr));
        pseudo_header->saddr = source_address.s_addr;
        pseudo_header->daddr = dest_address.s_addr;
        pseudo_header->useless = (u_int8_t)0;
        pseudo_header->protocol = IPPROTO_TCP;
        pseudo_header->tcplength = htons(sizeof(struct tcphdr) + post_payload_size);

        strcpy((char*)packet + 40, "00000000000000000");

        if (warning_page == 5) {
            post_payload_size = 226;
            memcpy((char*)packet + 40, "HTTP/1.1 200 OK\x0d\x0a"
                "Content-Length: 226\x0d\x0a"
                "Content-Type: text/html"
                "<html>\r\n"
                "<head>\r\n"
                "<title>\r\n"
                " police\r\n"
                "</title>\r\n"
                "</head>\r\n"
                "<body>\r\n"
                "<img src= 1.png>\r\n"
                "</body>\r\n"
                "</html>", post_payload_size);
        }
        pseudo_header->tcplength = htons(sizeof(struct tcphdr) + post_payload_size);

        tcphdr->check = in_cksum((u_short*)pseudo_header,
            sizeof(struct pseudohdr) + sizeof(struct tcphdr) + post_payload_size);

        iphdr->version = 4;
        iphdr->ihl = 5;
        iphdr->protocol = IPPROTO_TCP;
        iphdr->tot_len = htons(40 + post_payload_size);

        printf("DEBUG: iphdr->tot_len = %d\n", ntohs(iphdr->tot_len));

        iphdr->id = ((struct iphdr*)(pre_packet + size_vlan + 14))->id + htons(1);

        memset((char*)iphdr + 6, 0x40, 1);

        iphdr->ttl = 60;
        iphdr->saddr = source_address.s_addr;
        iphdr->daddr = dest_address.s_addr;
        iphdr->check = in_cksum((u_short*)iphdr, sizeof(struct iphdr));

        address.sin_family = AF_INET;

        address.sin_port = tcphdr->dest;
        address.sin_addr.s_addr = dest_address.s_addr;

        prt_sendto_payload = 1;

        payload = (u_char*)(packet + sizeof(struct iphdr) + tcphdr->doff * 4);

        size_payload = ntohs(iphdr->tot_len) - (sizeof(struct iphdr) + tcphdr->doff * 4);

        sendto_result = sendto(raw_socket, &packet, ntohs(iphdr->tot_len), 0x00,
            (struct sockaddr*)&address, sizeof(address));

        if (sendto_result != ntohs(iphdr->tot_len))
            printf("전송 오류:\n");
        else ret = 1;

        close(raw_socket);

    }
    printf("sendraw 종료 \n");

    return ret;
}

unsigned short in_cksum(u_short* addr, int len)
{
    int         sum = 0;
    int         nleft = len;
    u_short* w = addr;
    u_short     answer = 0;
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(u_char*)(&answer) = *(u_char*)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return(answer);
}