
#ifndef RTL8019AS
#define RTL8019AS
#include <machine.h>
#define CR (*(volatile unsigned char   *)0x0200000)
#define PSTART (*(volatile unsigned char   *)0x0200001)
#define PSTOP (*(volatile unsigned char   *)0x0200002)
#define BNRY (*(volatile unsigned char   *)0x0200003)
#define TPSR (*(volatile unsigned char   *)0x0200004)
#define TBCR0 (*(volatile unsigned char   *)0x0200005)
#define TBCR1 (*(volatile unsigned char   *)0x0200006)
#define ISR (*(volatile unsigned char   *)0x0200007)
#define RSAR0 (*(volatile unsigned char   *)0x0200008)
#define RSAR1 (*(volatile unsigned char   *)0x0200009)
#define RBCR0 (*(volatile unsigned char   *)0x020000a)
#define RBCR1 (*(volatile unsigned char   *)0x020000b)
#define RCR (*(volatile unsigned char   *)0x020000c)
#define TCR (*(volatile unsigned char   *)0x020000d)
#define DCR (*(volatile unsigned char   *)0x020000e)
#define IMR (*(volatile unsigned char   *)0x020000f)

#define PAR0 (*(volatile unsigned char   *)0x0200001)
#define PAR1 (*(volatile unsigned char   *)0x0200002)
#define PAR2 (*(volatile unsigned char   *)0x0200003)
#define PAR3 (*(volatile unsigned char   *)0x0200004)
#define PAR4 (*(volatile unsigned char   *)0x0200005)
#define PAR5 (*(volatile unsigned char   *)0x0200006)
#define CURR (*(volatile unsigned char   *)0x0200007)
#define MAR0 (*(volatile unsigned char   *)0x0200008)
#define MAR1 (*(volatile unsigned char   *)0x0200009)
#define MAR2 (*(volatile unsigned char   *)0x020000a)
#define MAR3 (*(volatile unsigned char   *)0x020000b)
#define MAR4 (*(volatile unsigned char   *)0x020000c)
#define MAR5 (*(volatile unsigned char   *)0x020000d)
#define MAR6 (*(volatile unsigned char   *)0x020000e)
#define MAR7 (*(volatile unsigned char   *)0x020000f)

#define RDMAP (*(volatile unsigned char   *)0x0200010)
#define RP (*(volatile unsigned char   *)0x0200018)

void NIC_init(unsigned char *src_mac){
	unsigned char data;
	int i;
	delay_ms(10);
	data=RP;
	RP=data;
	delay_ms(10);
	CR=0x21;
	DCR=0x4a;
	RBCR0=0x00;
	RBCR1=0x00;
	RCR=0x20;
	TCR=0x02;
	TPSR=0x40;
	PSTART=0x46;
	BNRY=0x46;
	PSTOP=0x60;
	IMR=0x00;
	ISR=0xff;
	RBCR0=12;
	RBCR1=0;
	RSAR0=0;
	RSAR1=0;
	CR=0x0a;
	for(i=0;i<6;i++){
		src_mac[i]=RDMAP;
		data=RDMAP;
	}
	while((ISR&0x40)==0x00);
	CR=0x61;
	PAR0=src_mac[0];
	PAR1=src_mac[1];
	PAR2=src_mac[2];
	PAR3=src_mac[3];
	PAR4=src_mac[4];
	PAR5=src_mac[5];
	
	CURR=0x47;
	
	MAR0=0;
	MAR1=0;
	MAR2=0;
	MAR3=0;
	MAR4=0;
	MAR5=0;
	MAR6=0;
	MAR7=0;
	
	CR=0x21;
	RCR=0x04;
	CR=0x22;
	TCR=0;
	IMR=0;
	
		
}

unsigned char packet_receive(unsigned char *packet){
		unsigned short i;
		unsigned short size;
		unsigned char data;
		unsigned char size_H,size_L;
		unsigned char boundary_page,start_page,current_page;
		unsigned char header[4];
		
		CR=0x22;
		boundary_page=BNRY;
		CR=0x62;
		current_page=CURR;
		
		if(current_page<boundary_page){
			current_page+=(0x60-0x46);	
		}
		if(current_page==boundary_page+1){
			return 1;	
		}
		start_page=boundary_page+1;
		if(start_page==0x60){
			start_page=0x46;	
		}
		
		CR=0x22;
		RBCR0=4;
		RBCR1=0;
		RSAR0=0;
		RSAR1=start_page;
		CR=0x0a;
		for(i=0;i<4;i++){
			header[i]=RDMAP;	
		}
		
		while((ISR&0x40)==0x00);
		
		CR=0x22;
		size_L=header[2];
		size_H=header[3];
		size=((unsigned short)size_H<<8)+((unsigned short)size_L);
		
		RBCR0=size_L;
		RBCR1=size_H;
		RSAR0=0;
		RSAR1=start_page;
		CR=0x0a;
		for(i=0;i<4;i++){
			data=RDMAP;	
		}
		for(i=0;i<(size-4);i++){
			packet[i]=RDMAP;
			if(i>=256){
				data=RDMAP;	
			}	
		}
		
		while((ISR&0x40)==0x00);
		CR=0x22;
		boundary_page=current_page-1;
		if(boundary_page>=0x60){
			boundary_page-=(0x60-0x46);
		}
		BNRY=boundary_page;
}

void packet_send(unsigned char *packet,unsigned short size){
   unsigned short i;
   unsigned char data;
   unsigned char size_H, size_L;

   size_L = (unsigned char)(size & 0x00FF); 
   size_H = (unsigned char)(size >> 8); 
   
   CR=0x22; 
   RBCR0=size_L; 
   RBCR1=size_H; 
   RSAR0=0x00; 
   RSAR1=0x40; 
   CR=0x12; 
   for (i = 0; i < size; i++)
   {
      RDMAP=packet[i]; 
   }
   do
   {
      data = ISR;
   } while ((data & 0x40) == 0x00); 
   
   CR=0x22;
   TBCR0=size_L;
   TBCR1=size_H;
   TPSR=0x40;
   CR=0x26; 
   do
   {
      data = CR;
   } while ((data & 0x04) == 0x04);
}

#endif