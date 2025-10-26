#include "RTL8019AS.h"
#include <string.h>
#include <stdio.h>
#include <machine.h>
#ifndef ETH_HEADER
#define ETH_HEADER
#define printf ((int (*)(const char *,...))0x002b86 )

#define URG (1 << 5)
#define ACK (1 << 4)
#define PSH (1 << 3)
#define RST (1 << 2)
#define SYN (1 << 1)
#define FIN (1 << 0)

//static unsigned char myip[4] = {192,168,0,20};
static unsigned char myip[4] = {172,16,28,60};
const char *htmlreply = "HTTP/1.1 200 OK\r\n"
						 "Content-Length: 7\r\n"
						 "Content-Type: text/html\r\n"
						 "\r\n"
						 "HELLO\r\n";

typedef enum {
	CLOSED,
	LISTEN,
	SYN_RCVD,
	SYN_SENT,
	ESTABLISHED,
	FIN_WAIT1,
	FIN_WAIT2,
	CLOSING,
	TIME_WAIT,
	CLOSE_WAIT,
	LAST_ACK
} tcp_state;

 
typedef union{
	struct {
		unsigned char dst_mac[6];
		unsigned char src_mac[6];
		unsigned short type;
	} header;
	unsigned char data[14];
} ether_header; 

typedef union {
	struct {
		unsigned char version:4;
		unsigned char ihl:4;
		unsigned char tos;
		unsigned short total_length;
		unsigned short id;
		unsigned short flags:3;
		unsigned short f_offset:13;
		unsigned char ttl;
		unsigned char protocol;
		unsigned short chksum;
		
		unsigned char src_ip[4];
		unsigned char dst_ip[4];
	} header;
	unsigned char data[20];
	unsigned short data_s[10];
} ip_header;

typedef union {
	struct {
		unsigned short hardware;
		unsigned short protocol;
		unsigned char h_length;
		unsigned char p_length;
		unsigned short op;
		unsigned char src_mac[6];
		unsigned char src_ip[4];
		unsigned char dst_mac[6];
		unsigned char dst_ip[4];
	} header;
	unsigned char data[28];	
} arp_header;

typedef union {
	struct {
		unsigned char type;
		unsigned char code;
		unsigned short chksum;
		unsigned short id;
		unsigned short seq;
	} header;
	unsigned char data[4];
	//unsigned short data16[2];	
} icmp_header;

typedef union {
	struct {
		unsigned short src_port;
		unsigned short dst_port;
		unsigned short seq_number[2];
		unsigned short ack_number[2];
		unsigned short header_length:4;
		unsigned short reserved:6;
		unsigned short flag:6;
		unsigned short window_size;
		unsigned short chksum;
		unsigned short emg_pointer;
	} header;
} tcp_header;

typedef union {
	struct {
		unsigned short src_port;
		unsigned short dst_port;
		unsigned short length;
		unsigned short chksum;
	} header;
} udp_header;

typedef struct  {
		unsigned char src_ip[4];
		unsigned char dst_ip[4];
		unsigned char padding;
		unsigned char protocol;
		unsigned short packet_length;
		tcp_header tcp;	
} tcp_chksum_header;

typedef struct  {
		unsigned char src_ip[4];
		unsigned char dst_ip[4];
		unsigned char padding;
		unsigned char protocol;
		unsigned short packet_length;
		udp_header udp;	
} udp_chksum_header;

typedef struct {
	unsigned char li:2;
	unsigned char vm:3;
	unsigned char mode:3;
	unsigned char stratum;
	unsigned char poll;
	unsigned char precision;
	unsigned short root_delay[2];
	unsigned short root_dispersion[2];
	unsigned short refer_id[2];
	unsigned short refer_time[4];
	unsigned short org_time[4];
	unsigned short recv_time[4];
	unsigned short transmit_time[4];
	unsigned short key_id[2];
	unsigned short message[8];
	
	
} sntp_packet;

union {
	unsigned char buf[1514];
	unsigned short buf16[757];

} u_buf;

typedef struct {
	tcp_state state;
	unsigned char active_flag;
	unsigned char close_flag;
	unsigned char src_mac[6];
	unsigned char dst_mac[6];
	unsigned char src_ip[4];
	unsigned char dst_ip[4];
	unsigned short src_port;
	unsigned short dst_port;
	unsigned short seq[2];
	unsigned short ack[2];
} sockets;

sockets sock[16];

void eth_recv(ether_header *h,void *data,unsigned int size){
	unsigned char buf[1514];
	packet_receive(buf);
	memcpy(h->data,buf,14);
	memcpy(data,buf+14,size);
}

void eth_send(ether_header *h,void *data,unsigned int size){
	unsigned char buf[1514];
	memcpy(buf,h->data,14);
	memcpy(buf+14,data,size);
	packet_send(buf,size+14);
}

void arp_request(unsigned char *mymac,unsigned char *myip,unsigned char *dst_ip,unsigned char *dst_mac){
	ether_header eth;
	arp_header arp;
	//unsigned char buf[1514];
	unsigned int i;
	
	memset(eth.header.dst_mac,0xff,6);
	memcpy(eth.header.src_mac,mymac,6);
	eth.header.type=0x0806;
	arp.header.hardware=1;
	arp.header.protocol=0x0800;
	arp.header.h_length=6;
	arp.header.p_length=4;
	arp.header.op=1;//arp request
	memcpy(arp.header.src_mac,mymac,6);
	memcpy(arp.header.src_ip,myip,4);
	memcpy(arp.header.dst_ip,dst_ip,4);
	memset(arp.header.dst_mac,0,6);
	eth_send(&eth,arp.data,sizeof(arp)+18);
	memset(&arp,0,sizeof(arp));
	while(1){
		eth_recv(&eth,arp.data,sizeof(arp));
		if(!memcmp(eth.header.dst_mac,mymac,6)){
			if(eth.header.type == 0x0806){
				if(arp.header.op==2){
					if(!memcmp(arp.header.dst_ip,myip,4)){
						if(!memcmp(arp.header.src_ip,dst_ip,4)){
							memcpy(dst_mac,arp.header.src_mac,6);
							break;	
						}
					}
				}
			}
		}
	}	
}

unsigned char arp_reply(unsigned char *mymac,unsigned char *myip){
	struct header{
		ether_header eth;
		arp_header arp;
		unsigned char trailer[18];
	} *h;
	unsigned int i;
	unsigned char dst_mac[6];
	unsigned char dst_ip[4];
//	unsigned char broadcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};

	h=(struct header *)u_buf.buf;
//	if(!memcmp(h->eth.header.dst_mac,broadcast,6)){
		if(h->eth.header.type == 0x0806){//printf("%u.%u.%u.%u\n",h->arp.header.dst_ip[0],h->arp.header.dst_ip[1],h->arp.header.dst_ip[2],h->arp.header.dst_ip[3]);//printf("myip:%u.%u.%u.%u\n",myip[0],myip[1],myip[2],myip[3]);
			if(!memcmp(h->arp.header.dst_ip,myip,4)){
				if(h->arp.header.op==1){
					memcpy(dst_mac,h->arp.header.src_mac,6);
					memcpy(dst_ip,h->arp.header.src_ip,4);
					memcpy(h->eth.header.dst_mac,dst_mac,6);
					memcpy(h->eth.header.src_mac,mymac,6);
					h->eth.header.type=0x0806;
					h->arp.header.hardware=1;
					h->arp.header.protocol=0x0800;
					h->arp.header.h_length=6;
					h->arp.header.p_length=4;
					h->arp.header.op=2;//arp reply
					memcpy(h->arp.header.src_mac,mymac,6);
					memcpy(h->arp.header.src_ip,myip,4);
					memcpy(h->arp.header.dst_ip,dst_ip,4);
					memcpy(h->arp.header.dst_mac,dst_mac,6);
					h->trailer[14]=0xea;
					h->trailer[15]=0xd3;
					h->trailer[16]=0x42;
					h->trailer[17]=0x25;
					
					packet_send(u_buf.buf,60);
				}
			}
		}
	//}
	
	return 0;
}

void ping_reply(unsigned char *myip,unsigned char *mymac){
	unsigned int i;
	unsigned int chksum;
	unsigned short chksumtmp;
	unsigned char ret_ip[4],ret_mac[6];
	unsigned short *s;
	unsigned short id,seq;
//	unsigned char mymac[6],myip[4];
	
	typedef struct {
		ether_header eth;
		ip_header ip;
		icmp_header icmp;
		char pingdata[33];	
	} headers;
	
	headers *h;

//	memcpy(mymac,mymac,6);
//	memcpy(myip,myip,4);
//	//printf("%d.%d.%d.%d\n",myip[0],myip[1],myip[2],myip[3]);
//	memset(u_buf.buf,0,1514);
//	packet_receive(u_buf.buf);
	h=(headers *)u_buf.buf;
	if(!memcmp(mymac,h->eth.header.dst_mac,6)){
		if(h->eth.header.type==0x0800){
			////printf("chksum=%04x\n",h->ip.header.chksum);
			chksumtmp=h->ip.header.chksum;
			h->ip.header.chksum=0;
			chksum=0;
			s=(unsigned short *)&(h->ip);
			for(i=0;i<10;i++){
				if((0xffff-chksum)>=s[i]){
					chksum+=s[i];
				}
				else {
					chksum+=s[i]+1;	
				}
			}
			chksum=~chksum;
			h->ip.header.chksum=chksumtmp;
			//if(!chksum) return;
		/*	//printf("**************************");
			for(i=0;i<74;i++) //printf("%04x\n",h->ip.data[i]);
			//printf("**************************");*/
			////printf("%x\n",chksumtmp);
			////printf("%x\n",chksum);
			if(chksumtmp==chksum){ 
				if(h->ip.header.protocol==1){//icmp
					if(!memcmp(myip,h->ip.header.dst_ip,4)){
						if(h->icmp.header.type==0x08){
							id=h->icmp.header.id;
							seq=h->icmp.header.seq;
							chksumtmp=h->icmp.header.chksum;
							h->icmp.header.chksum=0;
							/*chksum=0;
							for(i=0;i<h->ip.header.total_length-20;i++){
								chksum+=u_buf.buf16[i+17];
								if(chksum&0x00010000) {
									chksum&=~0xffff0000;
									chksum++;
								}	
								chksum=~chksum;
							}*/
							chksum=0;
							s=(unsigned short *)&(h->icmp);
							for(i=0;i<(h->ip.header.total_length-20)/2;i++){
								if((0xffff-chksum)>=s[i]){
									chksum+=s[i];
								}
								else {
									chksum+=s[i]+1;	
								}
							}
							chksum=~chksum;
							////printf("%x\n",chksumtmp);
							////printf("%x\n",chksum);
							if(chksumtmp==chksum){
								memcpy(ret_ip,h->ip.header.src_ip,4);
								memcpy(ret_mac,h->eth.header.src_mac,6);
								//memset(u_buf.buf,0,1514);
								memcpy(h->eth.header.dst_mac,ret_mac,6);
								memcpy(h->eth.header.src_mac,mymac,6);
								h->eth.header.type=0x0800;
								h->ip.header.version=4;
								h->ip.header.ihl=5;
								h->ip.header.tos=0;
								h->ip.header.total_length=20+8+32;
								h->ip.header.id=0;
								h->ip.header.flags=0;
								h->ip.header.f_offset=0;
								h->ip.header.ttl=128;
								h->ip.header.protocol=1;
								h->ip.header.chksum=0;
								memcpy(h->ip.header.dst_ip,ret_ip,4);
								memcpy(h->ip.header.src_ip,myip,4);
								chksum=0;
								s=(unsigned short *)&(h->ip);
								for(i=0;i<10;i++){
									if((0xffff-chksum)>=s[i]){
										chksum+=s[i];
									}
									else {
										chksum+=s[i]+1;	
									}
								}
								chksum=~chksum;
								h->ip.header.chksum=chksum;
								
	
								h->icmp.header.type=0x00;
								h->icmp.header.code=0x00;
								h->icmp.header.chksum=0;
								h->icmp.header.id=id;
								h->icmp.header.seq=seq;
								strcpy(h->pingdata,"abcdefghijklmnopqrstuvwxyz012345");
								chksum=0;
								s=(unsigned short *)&(h->icmp);
								for(i=0;i<(h->ip.header.total_length-20)/2;i++){
									if((0xffff-chksum)>=s[i]){
										chksum+=s[i];
									}
									else {
										chksum+=s[i]+1;	
									}
								}
								chksum=~chksum;
								h->icmp.header.chksum=chksum;
								//for(i=0;i<14+20+8+10;i++)//printf("%x\n",u_buf.buf[i]);
							//	packet_send(u_buf.buf,59);
								packet_send(u_buf.buf,14+20+8+32);
							//	//printf("%d.%d.%d.%d\n",h->ip.header.dst_ip[0],h->ip.header.dst_ip[1],h->ip.header.dst_ip[2],h->ip.header.dst_ip[3]);
								////printf("*****\n");
							}
						}
					}
				}	
			}
		}
	}

	
}

void icmp_send(unsigned char *myip,unsigned char *mymac,unsigned char type,unsigned char code){
	unsigned int i;
	unsigned int chksum;
	unsigned short chksumtmp;
	unsigned char ret_ip[4],ret_mac[6];
	unsigned short *s;
	unsigned short id,seq;
//	unsigned char mymac[6],myip[4];
	
	typedef struct {
		ether_header eth;
		ip_header ip;
		icmp_header icmp;
		char pingdata[33];	
	} headers;
	
	headers *h;

//	memcpy(mymac,mymac,6);
//	memcpy(myip,myip,4);
//	//printf("%d.%d.%d.%d\n",myip[0],myip[1],myip[2],myip[3]);
//	memset(u_buf.buf,0,1514);
//	packet_receive(u_buf.buf);
	
								memcpy(ret_ip,h->ip.header.src_ip,4);
								memcpy(ret_mac,h->eth.header.src_mac,6);
								//memset(u_buf.buf,0,1514);
								memcpy(h->eth.header.dst_mac,ret_mac,6);
								memcpy(h->eth.header.src_mac,mymac,6);
								h->eth.header.type=0x0800;
								h->ip.header.version=4;
								h->ip.header.ihl=5;
								h->ip.header.tos=0;
								h->ip.header.total_length=20+8+32;
								h->ip.header.id=0;
								h->ip.header.flags=0;
								h->ip.header.f_offset=0;
								h->ip.header.ttl=128;
								h->ip.header.protocol=1;
								h->ip.header.chksum=0;
								memcpy(h->ip.header.dst_ip,ret_ip,4);
								memcpy(h->ip.header.src_ip,myip,4);
								chksum=0;
								s=(unsigned short *)&(h->ip);
								for(i=0;i<10;i++){
									if((0xffff-chksum)>=s[i]){
										chksum+=s[i];
									}
									else {
										chksum+=s[i]+1;	
									}
								}
								chksum=~chksum;
								h->ip.header.chksum=chksum;
								
	
								h->icmp.header.type=type;
								h->icmp.header.code=code;
								h->icmp.header.chksum=0;
								h->icmp.header.id=id;
								h->icmp.header.seq=seq;
								strcpy(h->pingdata,"abcdefghijklmnopqrstuvwxyz012345");
								chksum=0;
								s=(unsigned short *)&(h->icmp);
								for(i=0;i<(h->ip.header.total_length-20)/2;i++){
									if((0xffff-chksum)>=s[i]){
										chksum+=s[i];
									}
									else {
										chksum+=s[i]+1;	
									}
								}
								chksum=~chksum;
								h->icmp.header.chksum=chksum;
								//for(i=0;i<14+20+8+10;i++)//printf("%x\n",u_buf.buf[i]);
							//	packet_send(u_buf.buf,59);
								packet_send(u_buf.buf,14+20+8+32);
							//	//printf("%d.%d.%d.%d\n",h->ip.header.dst_ip[0],h->ip.header.dst_ip[1],h->ip.header.dst_ip[2],h->ip.header.dst_ip[3]);
				
				////printf("*****\n");
				
	
}

void tcp_datasend(unsigned short src_port,unsigned short dst_port,unsigned char flag,
						unsigned short *seq,unsigned short *ack,
						unsigned char *src_ip,unsigned char *dst_ip,
						unsigned char *src_mac,unsigned char *dst_mac,
						unsigned char *data,unsigned short data_size){
	static unsigned short *s;
	static unsigned short chksum;
	unsigned char i;
	void *dataptr,*option_ptr;
	unsigned short datalen;
	tcp_chksum_header tch;
	//unsigned char option[20]={0x02,0x04,0x05,0xb4,0x04,0x02,0x08,0x0a,0x00,0x22,0x10,0x9d,0x00,0x00,0x00,0x00,0x01,0x03,0x03,0x07};
	struct header{
		ether_header eth;
		ip_header ip;
		tcp_header tcp;	
	} *h;
	
	//printf("tcp_send0:%d.%d.%d.%d\n",myip[0],myip[1],myip[2],myip[3]);
	h=(struct header *)u_buf.buf;
	
	memcpy(h->eth.header.dst_mac,dst_mac,6);
	memcpy(h->eth.header.src_mac,src_mac,6);
	h->eth.header.type=0x0800;
	
	memcpy(h->ip.header.src_ip,src_ip,4);
	memcpy(h->ip.header.dst_ip,dst_ip,4);
	h->ip.header.version=4;
	h->ip.header.ihl=5;
	h->ip.header.tos=0;
	h->ip.header.total_length=20+20+data_size;
	h->ip.header.id=0;
	h->ip.header.flags=0;
	h->ip.header.f_offset=0;
	h->ip.header.ttl=128;
	h->ip.header.protocol=6;
	h->ip.header.chksum=0;
	chksum=0;
	s=(unsigned short *)&(h->ip);
	for(i=0;i<10;i++){
		if((0xffff-chksum)>=s[i]){
			chksum+=s[i];
		}
		else {
			chksum+=s[i]+1;	
		}
	}
	chksum=~chksum;
	h->ip.header.chksum=chksum;
	//printf("tcp_send1:%d.%d.%d.%d\n",myip[0],myip[1],myip[2],myip[3]);
	
	h->tcp.header.src_port=src_port;
	h->tcp.header.dst_port=dst_port;
	memcpy(h->tcp.header.seq_number,seq,4);
	memcpy(h->tcp.header.ack_number,ack,4);
	h->tcp.header.header_length=5;
	h->tcp.header.flag=flag;
	h->tcp.header.window_size=30080;
	h->tcp.header.chksum=0;
	h->tcp.header.emg_pointer;

	memcpy(tch.src_ip,src_ip,4);
	memcpy(tch.dst_ip,dst_ip,4);
	tch.padding=0;
	tch.protocol=6;
	tch.packet_length=h->ip.header.total_length-20;
	memcpy(&(tch.tcp),&(h->tcp),sizeof(tch.tcp));
	option_ptr=u_buf.buf+sizeof(*h);
//	memcpy(option_ptr,option,12);
//	memset(option_ptr,0,12);
	if(data!=NULL){
		dataptr=(unsigned char *)&(h->tcp)+((h->tcp.header.header_length)*4);
		memcpy(dataptr,data,data_size);
	}
	//	//printf("%x\n",datalen);
	tch.tcp.header.chksum=0;
	chksum=0;
	s=(unsigned short *)&tch;
	for(i=0;i<(sizeof(tch)/2);i++){
		////printf("%d:%04x\n",i,s[i]);
		if((0xffff-chksum)>=s[i]){
			chksum+=s[i];
		}
		else {
			chksum+=s[i]+1;	
		}
	}
	/*
	//printf("tcp_send2:%d.%d.%d.%d\n",myip[0],myip[1],myip[2],myip[3]);
	s=(unsigned short *)option_ptr;
	for(i=0;i<(tch.packet_length-sizeof(h->tcp))/2;i++){
		////printf("%d:%04x\n",i,s[i]);
		if((0xffff-chksum)>=s[i]){
			chksum+=s[i];
		}
		else {
			chksum+=s[i]+1;	
		}
	}
	*/
	if(data!=NULL){
		s=(unsigned short *)dataptr;
		for(i=0;i<data_size/2;i++){
			////printf("%d:%04x\n",i,s[i]);
			if((0xffff-chksum)>=s[i]){
				chksum+=s[i];
			}
			else {
				chksum+=s[i]+1;	
			}
		}
	}
	chksum=~chksum;
	h->tcp.header.chksum=chksum;
	//printf("tcp_send3:%d.%d.%d.%d\n",myip[0],myip[1],myip[2],myip[3]);
//	//printf("%d\n",14+20+20+data_size);
	packet_send(u_buf.buf,14+20+20+data_size);
	//printf("tcp_send4:%d.%d.%d.%d\n",myip[0],myip[1],myip[2],myip[3]);
}

void tcp_send(unsigned short src_port,unsigned short dst_port,unsigned char flag,
						unsigned short *seq,unsigned short *ack,
						unsigned char *src_ip,unsigned char *dst_ip,
						unsigned char *src_mac,unsigned char *dst_mac,
						unsigned char *data,unsigned short data_size){
	static unsigned short *s;
	static unsigned short chksum;
	unsigned char i;
	void *dataptr,*option_ptr;
	unsigned short datalen;
	tcp_chksum_header tch;
	unsigned char option[20]={0x02,0x04,0x05,0xb4,0x04,0x02,0x08,0x0a,0x00,0x22,0x10,0x9d,0x00,0x00,0x00,0x00,0x01,0x03,0x03,0x07};
	struct header{
		ether_header eth;
		ip_header ip;
		tcp_header tcp;	
	} *h;
	
	//printf("tcp_send0:%d.%d.%d.%d\n",myip[0],myip[1],myip[2],myip[3]);
	h=(struct header *)u_buf.buf;
	
	memcpy(h->eth.header.dst_mac,dst_mac,6);
	memcpy(h->eth.header.src_mac,src_mac,6);
	h->eth.header.type=0x0800;
	
	memcpy(h->ip.header.src_ip,src_ip,4);
	memcpy(h->ip.header.dst_ip,dst_ip,4);
	h->ip.header.version=4;
	h->ip.header.ihl=5;
	h->ip.header.tos=0;
	h->ip.header.total_length=20+20+12+data_size;
	h->ip.header.id=40445;
	h->ip.header.flags=2;
	h->ip.header.f_offset=0;
	h->ip.header.ttl=128;
	h->ip.header.protocol=6;
	h->ip.header.chksum=0;
	chksum=0;
	s=(unsigned short *)&(h->ip);
	for(i=0;i<10;i++){
		if((0xffff-chksum)>=s[i]){
			chksum+=s[i];
		}
		else {
			chksum+=s[i]+1;	
		}
	}
	chksum=~chksum;
	h->ip.header.chksum=chksum;
	//printf("tcp_send1:%d.%d.%d.%d\n",myip[0],myip[1],myip[2],myip[3]);
	
	h->tcp.header.src_port=src_port;
	h->tcp.header.dst_port=dst_port;
	memcpy(h->tcp.header.seq_number,seq,4);
	memcpy(h->tcp.header.ack_number,ack,4);
	h->tcp.header.header_length=8;
	h->tcp.header.flag=flag;
	h->tcp.header.window_size=65535;
	h->tcp.header.chksum=0;
	h->tcp.header.emg_pointer;

	memcpy(tch.src_ip,src_ip,4);
	memcpy(tch.dst_ip,dst_ip,4);
	tch.padding=0;
	tch.protocol=6;
	tch.packet_length=h->ip.header.total_length-20;
	memcpy(&(tch.tcp),&(h->tcp),sizeof(tch.tcp));
	option_ptr=u_buf.buf+sizeof(*h);
//	memcpy(option_ptr,option,12);
	memset(option_ptr,0,12);
	if(data!=NULL){
		dataptr=(unsigned char *)&(h->tcp)+((h->tcp.header.header_length)*4);
		memcpy(dataptr,data,data_size);
	}
	//	//printf("%x\n",datalen);
	tch.tcp.header.chksum=0;
	chksum=0;
	s=(unsigned short *)&tch;
	for(i=0;i<(sizeof(tch)/2);i++){
		////printf("%d:%04x\n",i,s[i]);
		if((0xffff-chksum)>=s[i]){
			chksum+=s[i];
		}
		else {
			chksum+=s[i]+1;	
		}
	}
	//printf("tcp_send2:%d.%d.%d.%d\n",myip[0],myip[1],myip[2],myip[3]);
	s=(unsigned short *)option_ptr;
	for(i=0;i<(tch.packet_length-sizeof(h->tcp))/2;i++){
		////printf("%d:%04x\n",i,s[i]);
		if((0xffff-chksum)>=s[i]){
			chksum+=s[i];
		}
		else {
			chksum+=s[i]+1;	
		}
	}
	
	if(data!=NULL){
		s=(unsigned short *)dataptr;
		for(i=0;i<data_size/2;i++){
			////printf("%d:%04x\n",i,s[i]);
			if((0xffff-chksum)>=s[i]){
				chksum+=s[i];
			}
			else {
				chksum+=s[i]+1;	
			}
		}
	}
	chksum=~chksum;
	h->tcp.header.chksum=chksum;
	//printf("tcp_send3:%d.%d.%d.%d\n",myip[0],myip[1],myip[2],myip[3]);
//	//printf("%d\n",14+20+20+data_size);
	packet_send(u_buf.buf,14+20+20+12+data_size);
	//printf("tcp_send4:%d.%d.%d.%d\n",myip[0],myip[1],myip[2],myip[3]);
}

char tcp_recv(unsigned short *src_port,unsigned short *dst_port,unsigned char *flag,
						unsigned short *seq,unsigned short *ack,
						unsigned char *src_ip,unsigned char *dst_ip,
						unsigned char *src_mac,unsigned char *dst_mac,
						unsigned char **data,unsigned short *data_size){

	static unsigned short *s;
	static unsigned short chksum,chksumtmp;
	unsigned char i;
	void *dataptr,*option_ptr;
	unsigned short datalen;
	tcp_chksum_header tch;
	static struct header{
		ether_header eth;
		ip_header ip;
		tcp_header tcp;	
	} *h;
	

	////printf("tcp_recv0:%d.%d.%d.%d\n",myip[0],myip[1],myip[2],myip[3]);
	h=(struct header *)u_buf.buf;
	
	if(!memcmp(h->eth.header.dst_mac,dst_mac,6) &&
	 	h->eth.header.type==0x0800){
		
		chksumtmp=h->ip.header.chksum;
		h->ip.header.chksum=0;
		chksum=0;
		s=(unsigned short *)&(h->ip);
		for(i=0;i<10;i++){
			if((0xffff-chksum)>=s[i]){
				chksum+=s[i];
			}
			else {
				chksum+=s[i]+1;	
			}
		}
		chksum=~chksum;
		h->ip.header.chksum=chksumtmp;
		//printf("0x%x,0x%x\n",chksum,chksumtmp);
		if((!memcmp(h->ip.header.dst_ip,dst_ip,4)) && 
			(chksumtmp == chksum) &&
			(h->ip.header.protocol == 6)){
			////printf("ip");
			
			memcpy(tch.src_ip,h->ip.header.src_ip,4);
			memcpy(tch.dst_ip,h->ip.header.dst_ip,4);
			tch.protocol=6;
			tch.packet_length=h->ip.header.total_length-20;
			memcpy(&(tch.tcp),&(h->tcp),sizeof(tch.tcp));
			option_ptr=u_buf.buf+sizeof(*h);
			dataptr=(unsigned char *)&(h->tcp)+((h->tcp.header.header_length)*4);
			datalen=h->ip.header.total_length-20-((h->tcp.header.header_length)*4);
			
		//	memcpy(dataptr,data,datalen);
		//	//printf("%x\n",datalen);
			//printf("tcp_recv1:%d.%d.%d.%d\n",myip[0],myip[1],myip[2],myip[3]);
			chksumtmp=h->tcp.header.chksum;
			tch.tcp.header.chksum=0;
			chksum=0;
			s=(unsigned short *)&tch;
			for(i=0;i<(sizeof(tch)/2);i++){
				////printf("%d:%04x\n",i,s[i]);
				if((0xffff-chksum)>=s[i]){
					chksum+=s[i];
				}
				else {
					chksum+=s[i]+1;	
				}
			}
			//printf("tcp_recv2:%d.%d.%d.%d\n",myip[0],myip[1],myip[2],myip[3]);
			s=(unsigned short *)option_ptr;
			for(i=0;i<(tch.packet_length-sizeof(h->tcp))/2;i++){
				////printf("%d:%04x\n",i,s[i]);
				if((0xffff-chksum)>=s[i]){
					chksum+=s[i];
				}
				else {
					chksum+=s[i]+1;	
				}
			}
			//printf("tcp_recv3:%d.%d.%d.%d\n",myip[0],myip[1],myip[2],myip[3]);
			s=(unsigned short *)dataptr;
			for(i=0;i<datalen/2;i++){
				////printf("%d:%04x\n",i,s[i]);
				if((0xffff-chksum)>=s[i]){
					chksum+=s[i];
				}
				else {
					chksum+=s[i]+1;	
				}
			}
			chksum=~chksum;
			h->tcp.header.chksum=chksumtmp;	
			//printf("0x%x,0x%x\n",chksum,chksumtmp);
		//	if(chksumtmp==chksum){
				memcpy(src_mac,h->eth.header.src_mac,6);
				memcpy(src_ip,h->ip.header.src_ip,4);
				*src_port=h->tcp.header.src_port;
				*dst_port=h->tcp.header.dst_port;
				*flag=h->tcp.header.flag;
				memcpy(seq,h->tcp.header.seq_number,4);
				memcpy(ack,h->tcp.header.ack_number,4);
				*data=dataptr;
				*data_size=datalen;
			//	memcpy(data,dataptr,datalen);
			//	memcpy(data_size,&datalen,2);
				////printf("size:%u,%s\n",data_size,data);
				
				return 0;
		//	}
		}
	}
	return -1;
}
	  

void udp_send(unsigned short src_port,unsigned short dst_port,
						unsigned char *src_ip,unsigned char *dst_ip,
						unsigned char *src_mac,unsigned char *dst_mac,
						unsigned char *data,unsigned short data_size){
	static unsigned short *s;
	static unsigned short chksum;
	unsigned char i;
	void *dataptr,*option_ptr;
	unsigned short datalen;
	udp_chksum_header uch;
	
	struct header{
		ether_header eth;
		ip_header ip;
		udp_header udp;	
	} *h;
	
	//printf("tcp_send0:%d.%d.%d.%d\n",myip[0],myip[1],myip[2],myip[3]);
	h=(struct header *)u_buf.buf;
	
	memcpy(h->eth.header.dst_mac,dst_mac,6);
	memcpy(h->eth.header.src_mac,src_mac,6);
	h->eth.header.type=0x0800;
	
	memcpy(h->ip.header.src_ip,src_ip,4);
	memcpy(h->ip.header.dst_ip,dst_ip,4);
	h->ip.header.version=4;
	h->ip.header.ihl=5;
	h->ip.header.tos=0;
	h->ip.header.total_length=20+8+data_size;
	h->ip.header.id=40445;
	h->ip.header.flags=2;
	h->ip.header.f_offset=0;
	h->ip.header.ttl=128;
	h->ip.header.protocol=17;
	h->ip.header.chksum=0;
	chksum=0;
	s=(unsigned short *)&(h->ip);
	for(i=0;i<10;i++){
		if((0xffff-chksum)>=s[i]){
			chksum+=s[i];
		}
		else {
			chksum+=s[i]+1;	
		}
	}
	chksum=~chksum;
	h->ip.header.chksum=chksum;
	//printf("tcp_send1:%d.%d.%d.%d\n",myip[0],myip[1],myip[2],myip[3]);
	
	h->udp.header.src_port=src_port;
	h->udp.header.dst_port=dst_port;
	h->udp.header.length=8+data_size;
	h->udp.header.chksum=0;

	memcpy(uch.src_ip,src_ip,4);
	memcpy(uch.dst_ip,dst_ip,4);
	uch.padding=0;
	uch.protocol=17;
	uch.packet_length=h->ip.header.total_length-20;
	memcpy(&(uch.udp),&(h->udp),sizeof(uch.udp));

	dataptr=(unsigned char *)&(h->udp)+8;
	memcpy(dataptr,data,data_size);
	//	//printf("%x\n",datalen);
	uch.udp.header.chksum=0;
	chksum=0;
	s=(unsigned short *)&uch;
	for(i=0;i<(sizeof(uch)/2);i++){
		////printf("%d:%04x\n",i,s[i]);
		if((0xffff-chksum)>=s[i]){
			chksum+=s[i];
		}
		else {
			chksum+=s[i]+1;	
		}
	}
	//printf("tcp_send2:%d.%d.%d.%d\n",myip[0],myip[1],myip[2],myip[3]);
	
	if(data!=NULL){
		s=(unsigned short *)dataptr;
		for(i=0;i<data_size/2;i++){
			////printf("%d:%04x\n",i,s[i]);
			if((0xffff-chksum)>=s[i]){
				chksum+=s[i];
			}
			else {
				chksum+=s[i]+1;	
			}
		}
	}
	chksum=~chksum;
	h->udp.header.chksum=chksum;
	//printf("tcp_send3:%d.%d.%d.%d\n",myip[0],myip[1],myip[2],myip[3]);
//	//printf("%d\n",14+20+20+data_size);
	packet_send(u_buf.buf,14+20+8+data_size);
	//printf("tcp_send4:%d.%d.%d.%d\n",myip[0],myip[1],myip[2],myip[3]);
}

char udp_recv(unsigned short *src_port,unsigned short *dst_port,
						unsigned char *src_ip,unsigned char *dst_ip,
						unsigned char *src_mac,unsigned char *dst_mac,
						unsigned char **data,unsigned short *data_size){

	static unsigned short *s;
	static unsigned short chksum,chksumtmp;
	unsigned char i;
	void *dataptr;
	unsigned short datalen;
	udp_chksum_header uch;
	static struct header{
		ether_header eth;
		ip_header ip;
		tcp_header udp;	
	} *h;
	

	////printf("tcp_recv0:%d.%d.%d.%d\n",myip[0],myip[1],myip[2],myip[3]);
	h=(struct header *)u_buf.buf;
	
	if(!memcmp(h->eth.header.dst_mac,dst_mac,6) &&
	 	h->eth.header.type==0x0800){
		
		chksumtmp=h->ip.header.chksum;
		h->ip.header.chksum=0;
		chksum=0;
		s=(unsigned short *)&(h->ip);
		for(i=0;i<10;i++){
			if((0xffff-chksum)>=s[i]){
				chksum+=s[i];
			}
			else {
				chksum+=s[i]+1;	
			}
		}
		chksum=~chksum;
		h->ip.header.chksum=chksumtmp;
		//printf("0x%x,0x%x\n",chksum,chksumtmp);
		if((!memcmp(h->ip.header.dst_ip,dst_ip,4)) && 
			(chksumtmp == chksum) &&
			(h->ip.header.protocol == 17)){
			////printf("ip");
			
			memcpy(uch.src_ip,h->ip.header.src_ip,4);
			memcpy(uch.dst_ip,h->ip.header.dst_ip,4);
			uch.protocol=6;
			uch.packet_length=h->ip.header.total_length-20;
			memcpy(&(uch.udp),&(h->udp),sizeof(uch.udp));
			dataptr=(unsigned char *)&(h->udp)+8;
			datalen=h->ip.header.total_length-20-8;
			
		//	memcpy(dataptr,data,datalen);
		//	//printf("%x\n",datalen);
			//printf("tcp_recv1:%d.%d.%d.%d\n",myip[0],myip[1],myip[2],myip[3]);
			chksumtmp=h->udp.header.chksum;
			uch.udp.header.chksum=0;
			chksum=0;
			s=(unsigned short *)&uch;
			for(i=0;i<(sizeof(uch)/2);i++){
				////printf("%d:%04x\n",i,s[i]);
				if((0xffff-chksum)>=s[i]){
					chksum+=s[i];
				}
				else {
					chksum+=s[i]+1;	
				}
			}

			s=(unsigned short *)dataptr;
			for(i=0;i<datalen/2;i++){
				////printf("%d:%04x\n",i,s[i]);
				if((0xffff-chksum)>=s[i]){
					chksum+=s[i];
				}
				else {
					chksum+=s[i]+1;	
				}
			}
			chksum=~chksum;
			h->udp.header.chksum=chksumtmp;	
			//printf("0x%x,0x%x\n",chksum,chksumtmp);
		//	if(chksumtmp==chksum){
				memcpy(src_mac,h->eth.header.src_mac,6);
				memcpy(src_ip,h->ip.header.src_ip,4);
				*src_port=h->udp.header.src_port;
				*dst_port=h->udp.header.dst_port;
				*data=dataptr;
				*data_size=datalen;
			//	memcpy(data,dataptr,datalen);
			//	memcpy(data_size,&datalen,2);
				////printf("size:%u,%s\n",data_size,data);
				
				return 0;
		//	}
		}
	}
	return -1;
}

unsigned short *long_inc(unsigned short *d,unsigned short n){
	if((0xffff-n)>=d[1]){
		d[1]+=n;
	}
	else{
		d[0]++;
		d[1]+=n;	
	}
	return d;
}

char tcp_write(sockets *s ,unsigned char *data,unsigned short n){
	unsigned char ret;
	unsigned char tcp_flag;
	if(s->state != ESTABLISHED){
		return -1;	
	}
	tcp_datasend(s->src_port,s->dst_port,PSH|ACK,s->seq,s->ack,s->src_ip,s->dst_ip,s->src_mac,s->dst_mac,data,n);
	
	return 0;
}

char tcp_read(sockets *s,unsigned char **data,unsigned short *n){
	unsigned char ret;
	unsigned char tcp_flag;
	if(s->state != ESTABLISHED){
		return -1;	
	}
	
	ret=tcp_recv(&(s->dst_port),&(s->src_port),&tcp_flag,s->ack,s->seq,s->dst_ip,s->src_ip,s->dst_mac,s->src_mac,data,n);
	
	if(ret!=-1){
	//	//printf("size%d\n",*n);
		long_inc(s->ack,*n);
		return ret;
	}
	return ret;
}


void tcp_connection(sockets *s){
	unsigned char tcp_flag;
	unsigned char **data;
	char ret;
	unsigned short data_len;
	unsigned short seq_tmp[2];
	unsigned short wait_count;
	sockets tmp;
	
	switch(s->state){
		case CLOSED:
		//	//printf("CLOSED\n");
		//	memset(s,0,sizeof(*s));
			memset(s->ack,0,4);
			if(s->active_flag) {
					tcp_send(s->src_port,s->dst_port,SYN,s->seq,s->ack,s->src_ip,s->dst_ip,s->src_mac,s->dst_mac,(unsigned char *)NULL,0/*"start",5*/);
					s->state=SYN_SENT;
			}
			else {
				if(!(s->close_flag)) s->state=LISTEN;
			}
		break;
		case LISTEN:
			////printf("LISTEN\n");
			if(!(s->active_flag)){
				ret=tcp_recv(&(tmp.dst_port),&(tmp.src_port),&tcp_flag,tmp.ack,tmp.seq,tmp.dst_ip,s->src_ip,tmp.dst_mac,s->src_mac,data,&data_len);
				////printf("%d\n",ret);
				if(ret==-1) return;
				
				if( tmp.src_port==s->src_port && tcp_flag == SYN ){
					
					memcpy(s->dst_mac,tmp.dst_mac,6);
					memcpy(s->dst_ip,tmp.dst_ip,4);
					s->dst_port=tmp.dst_port;//printf("%02x:%02x:%02x:%02x:%02x:%02x\n",s->dst_mac[0],s->dst_mac[1],s->dst_mac[2],s->dst_mac[3],s->dst_mac[4],s->dst_mac[5]);
					memcpy(s->seq,tmp.seq,4);//printf("dst:%u.%u.%u.%u\n",s->dst_ip[0],s->dst_ip[1],s->dst_ip[2],s->dst_ip[3]);
					memcpy(s->seq,tmp.seq,4);//printf("src:%u.%u.%u.%u\n",s->src_ip[0],s->src_ip[1],s->src_ip[2],s->src_ip[3]);
					printf("before_inc_ack:%d.%d.%d.%d\n",myip[0],myip[1],myip[2],myip[3]);
					memcpy(s->ack,long_inc(tmp.ack,1),4);
					printf("before_tcp_send:%d.%d.%d.%d\n",myip[0],myip[1],myip[2],myip[3]);
					tcp_send(s->src_port,s->dst_port,SYN|ACK,s->seq,s->ack,s->src_ip,s->dst_ip,s->src_mac,s->dst_mac,(unsigned char *)NULL,0/*"listen",6*/);
					s->state=SYN_RCVD;//printf("src=%u,dst=%u\n",tmp.src_port,tmp.dst_port);
				}
			}
		break;
		case SYN_RCVD:
			////printf("SYN_RCVD\n");
			ret=tcp_recv(&(tmp.dst_port),&(tmp.src_port),&tcp_flag,tmp.ack,tmp.seq,tmp.dst_ip,s->src_ip,tmp.dst_mac,s->src_mac,data,&data_len);
			////printf("%d\n",ret);
			if(ret==-1) return;
			//printf("src=%u,dst=%u\n",tmp.src_port,tmp.dst_port);
			if( tmp.src_port==s->src_port ){
				if( tcp_flag == RST)s->state=LISTEN;
				else s->state=ESTABLISHED;
			}
			
		break;
		case SYN_SENT:
			////printf("SYN_SENT\n");
			if(s->active_flag){
				ret=tcp_recv(&(tmp.dst_port),&(tmp.src_port),&tcp_flag,tmp.ack,tmp.seq,tmp.dst_ip,s->src_ip,tmp.dst_mac,s->src_mac,data,&data_len);
			
				if(ret==-1) return;
				if( tmp.src_port==s->src_port && tmp.dst_port==s->dst_port){
					if(tcp_flag == (SYN|ACK)){
						memcpy(s->seq,tmp.seq,4);
						memcpy(s->ack,long_inc(tmp.ack,1),4);
						tcp_send(s->src_port,s->dst_port,ACK,s->seq,s->ack,s->src_ip,s->dst_ip,s->src_mac,s->dst_mac,(unsigned char *)NULL,0/*"sent:synack",11*/);
						s->state=ESTABLISHED;
					}
					else if(tcp_flag==SYN){
						memcpy(s->seq,tmp.seq,4);
						memcpy(s->ack,long_inc(tmp.ack,1),4);
						tcp_send(s->src_port,s->dst_port,ACK,s->seq,s->ack,s->src_ip,s->dst_ip,s->src_mac,s->dst_mac,(unsigned char *)NULL,0/*"sent:syn",8*/);
						s->state=SYN_RCVD;	
					}
				}	
			}
		break;
		case ESTABLISHED:
			////printf("ESTABLISHED\n");
			if(s->close_flag){
				if(s->active_flag){
					memcpy(s->seq,tmp.seq,4);
					memset(s->ack,0,4);
				//	memcpy(s->ack,long_inc(tmp.ack,1),4);
					tcp_send(s->src_port,s->dst_port,FIN|ACK,s->seq,s->ack,s->src_ip,s->dst_ip,s->src_mac,s->dst_mac,(unsigned char *)NULL,0/*"est:fin_wait",12*/);
					s->state=FIN_WAIT1;
				}
					
			}
			else {
				ret=tcp_recv(&(tmp.dst_port),&(tmp.src_port),&tcp_flag,tmp.ack,tmp.seq,tmp.dst_ip,s->src_ip,tmp.dst_mac,s->src_mac,data,&data_len);
				if(ret==-1) return;
				if( tmp.src_port==s->src_port && tmp.dst_port==s->dst_port && (tcp_flag & (FIN)) ){
				
					memcpy(s->seq,tmp.seq,4);
					memcpy(s->ack,long_inc(tmp.ack,1),4);
					tcp_send(s->src_port,s->dst_port,ACK,s->seq,s->ack,s->src_ip,s->dst_ip,s->src_mac,s->dst_mac,(unsigned char *)NULL,0/*"est:close",9*/);
					s->state=CLOSE_WAIT;
				}
			}
		break;
		case FIN_WAIT1:
			//printf("FIN_WAIT1\n");
			//if(s->close_flag){
			//	if(s->active_flag){
					ret=tcp_recv(&(tmp.dst_port),&(tmp.src_port),&tcp_flag,tmp.ack,tmp.seq,tmp.dst_ip,s->src_ip,tmp.dst_mac,s->src_mac,data,&data_len);
					
					if(ret==-1) return;
					if( tmp.src_port==s->src_port && tmp.dst_port==s->dst_port){
						
						if(tcp_flag&(ACK)){
						//	ret=tcp_recv(&(tmp.dst_port),&(tmp.src_port),&tcp_flag,tmp.ack,tmp.seq,tmp.dst_ip,s->src_ip,tmp.dst_mac,s->src_mac,data,&data_len);
						//	if(ret==-1) return;
						//	if( tmp.src_port==s->src_port && tmp.dst_port==s->dst_port && (tcp_flag & (FIN|ACK)) ){
						//		memcpy(s->seq,tmp.seq,4);
						//		memcpy(s->ack,long_inc(tmp.ack,1),4);	
						//		tcp_send(s->src_port,s->dst_port,FIN|ACK,s->seq,s->ack,s->src_ip,s->dst_ip,s->src_mac,s->dst_mac,(unsigned char *)"abcdef",6);			
						//		printf("FIN_WAIT1\n");
								s->state=FIN_WAIT2;
						//	}
						}
						//else if(tcp_flag==FIN){
						//	memcpy(s->seq,tmp.seq,4);
						//	memcpy(s->ack,long_inc(tmp.ack,1),4);
						//	tcp_send(s->src_port,s->dst_port,ACK,s->seq,s->ack,s->src_ip,s->dst_ip,s->src_mac,s->dst_mac,(unsigned char *)NULL,0/*"fin_wait1:fin",13*/);
						//	s->state=CLOSING;
						//}
					//	else if(tcp_flag == FIN|ACK){
					//		printf("fin_wait1:finack\n");
					//		memcpy(s->seq,tmp.seq,4);
					//		memcpy(s->ack,long_inc(tmp.ack,1),4);
					//		tcp_send(s->src_port,s->dst_port,ACK,s->seq,s->ack,s->src_ip,s->dst_ip,s->src_mac,s->dst_mac,(unsigned char *)NULL,0/*"fin_wait1:finack",16*/);
					//		s->state=TIME_WAIT;
					//		wait_count=1200;
					//	}
					}
			//	}
			//}
		break;
		case FIN_WAIT2:
			////printf("FIN_WAIT2\n");
			ret=tcp_recv(&(tmp.dst_port),&(tmp.src_port),&tcp_flag,tmp.ack,tmp.seq,tmp.dst_ip,s->src_ip,tmp.dst_mac,s->src_mac,data,&data_len);
			if(ret==-1) return;
			if( tmp.src_port==s->src_port && tmp.dst_port==s->dst_port && (tcp_flag & (FIN|ACK)) ){
				printf("FIN_WAIT2\n");
				memcpy(s->seq,tmp.seq,4);
				memcpy(s->ack,long_inc(tmp.ack,1),4);	
				tcp_send(s->src_port,s->dst_port,ACK,s->seq,s->ack,s->src_ip,s->dst_ip,s->src_mac,s->dst_mac,(unsigned char *)NULL,0/*"fin_wait2:finack",16*/);
				s->state=TIME_WAIT;
				wait_count=1200;
			}
		break;
		case CLOSING:
			////printf("CLOSING\n");
			ret=tcp_recv(&(tmp.dst_port),&(tmp.src_port),&tcp_flag,tmp.ack,tmp.seq,tmp.dst_ip,s->src_ip,tmp.dst_mac,s->src_mac,data,&data_len);
			if(ret==-1) return;
			if( tmp.src_port==s->src_port && tmp.dst_port==s->dst_port && (tcp_flag & (ACK)) ){
				s->state=TIME_WAIT;
				wait_count=1200;
			}
		break;
		case TIME_WAIT:
			if(wait_count==1200)printf("TIME_WAIT\n");
			delay_ms(100);
			if((wait_count--)==0)s->state=CLOSED;
			s->active_flag=0;
			s->close_flag=0;
		break;
		case CLOSE_WAIT:
			////printf("CLOSE_WAIT\n");
			memcpy(s->seq,tmp.seq,4);
			memcpy(s->ack,long_inc(tmp.ack,1),4);
			tcp_send(s->src_port,s->dst_port,FIN|ACK,s->seq,s->ack,s->src_ip,s->dst_ip,s->src_mac,s->dst_mac,(unsigned char *)NULL,0/*"close_wait",10*/);
			s->state=LAST_ACK;
		break;
		case LAST_ACK:
			////printf("LAST_ACK\n");
			ret=tcp_recv(&(tmp.dst_port),&(tmp.src_port),&tcp_flag,tmp.ack,tmp.seq,tmp.dst_ip,s->src_ip,tmp.dst_mac,s->src_mac,data,&data_len);
			if(ret==-1) return;
			if( tmp.src_port==s->src_port && tmp.dst_port==s->dst_port && tcp_flag == (ACK) ){
				s->active_flag=0;
				s->close_flag=0;	
				s->state=CLOSED;
			}
		break;
		default:
		break;
	}
	//return data;
	
}

char http_reply(sockets *s){
	unsigned short length;
	static unsigned char *req;
	unsigned char tcp_flag;
	char ret;
//	static char get_flag;
	unsigned char i;
	ret=tcp_read(s,&req,&length);//printf("a\n");
	if(!strncmp((char *)req,"GET",3) && ret==0){
		//icmp_send(s->src_ip,s->src_mac,3,10);
		//
	//	get_flag=1;
		tcp_send(s->src_port,s->dst_port,ACK,s->seq,s->ack,s->src_ip,s->dst_ip,s->src_mac,s->dst_mac,(unsigned char *)NULL,0/*"http_ack",8*/);
	//	while(1){
			
			/*for(i=0;i<3;i++)*/tcp_write(s,(unsigned char *)htmlreply,strlen(htmlreply));
		//	tcp_write(s,(unsigned char *)htmlreply,strlen(htmlreply));
	//	while(1){
	//		packet_receive(u_buf.buf);
	//		tcp_recv(&(s->dst_port),&(s->src_port),&tcp_flag,s->ack,s->seq,s->dst_ip,s->src_ip,s->dst_mac,s->src_mac,&req,&length);
	//		printf("flag:%02x\n",tcp_flag);
	//		if(tcp_flag&ACK){
	//			long_inc(s->ack,1);
	//			delay_ms(100);
	//			s->active_flag=1;
	//			s->close_flag=1;
	//			break;
	//			get_flag=0;
	//		}
	//	}
		return 0;
	}
	return -1;
}

char sntp_get(sockets *s){
	unsigned short size;
	sntp_packet sntp,*sntpptr;
	memset(&sntp,0,sizeof(sntp_packet));
	sntp.li=0;
	sntp.vm=4;
	sntp.mode=3;
	
	size=sizeof(sntp_packet);
	
	printf("send:%d\n",size);
	udp_send(s->src_port,123,s->src_ip,s->dst_ip,s->src_mac,s->dst_mac,(unsigned char *)&sntp,size);
		
	packet_receive(u_buf.buf);
	udp_recv(&(s->dst_port),&(s->src_port),s->dst_ip,s->src_ip,s->dst_mac,s->src_mac,(unsigned char **)&sntpptr,&size);
	printf("recv:%d\n",size);
	 //refer_time[4];
	//org_time[4];
	//recv_time[4];
	//transmit_time[4];
	printf("0x%04x%04x%04x%04x\n",sntpptr->refer_time[0],sntpptr->refer_time[1],sntpptr->refer_time[2],sntpptr->refer_time[3]);
}


#endif