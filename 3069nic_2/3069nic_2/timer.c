
/********timer.c***********/
#include"iodefine.h"

void init_timer(void){
	ITU0.TCR.BIT.TPSC=0x01;
	ITU0.TCR.BIT.CCLR=0x01;
	ITU1.TCR.BIT.TPSC=0x03;
	ITU1.TCR.BIT.CCLR=0x01;
	ITU2.TCR.BIT.TPSC=0x03;
	ITU2.TCR.BIT.CCLR=0x01;
	ITU0.GRA=10;
	ITU1.GRA=2500;
	ITU2.GRA=25000;		
}

void delay_us(unsigned int us){
	unsigned int i;
	ITU.TSTR.BIT.STR0=1;
	for(i=0;i<us;i++){
		while(!ITU.TISRA.BIT.IMFA0);
		ITU.TISRA.BIT.IMFA0=0;
	}		
	ITU.TSTR.BIT.STR0=0;
}

void delay_ms(unsigned int ms){
	unsigned int i;
	ITU.TSTR.BIT.STR1=1;
	for(i=0;i<ms;i++){ 
		while(!ITU.TISRA.BIT.IMFA1);
		ITU.TISRA.BIT.IMFA1=0;
	}
	ITU.TSTR.BIT.STR1=0;
}