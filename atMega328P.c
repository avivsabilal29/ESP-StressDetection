/*******************************************************
This program was created by the
CodeWizardAVR V3.14 Advanced
Automatic Program Generator
© Copyright 1998-2014 Pavel Haiduc, HP InfoTech s.r.l.
http://www.hpinfotech.com

Project : 
Version : 
Date    : 18/05/2024
Author  : 
Company : 
Comments: 


Chip type               : ATmega328P
Program type            : Application
AVR Core Clock frequency: 12,000000 MHz
Memory model            : Small
External RAM size       : 0
Data Stack size         : 512
*******************************************************/

#include <mega328p.h>
#include <delay.h>
// Declare your global variables here

void main(void)
{
// Declare your local variables here

// Crystal Oscillator division factor: 1
#pragma optsize-
CLKPR=(1<<CLKPCE);
CLKPR=(0<<CLKPCE) | (0<<CLKPS3) | (0<<CLKPS2) | (0<<CLKPS1) | (0<<CLKPS0);
#ifdef _OPTIMIZE_SIZE_
#pragma optsize+
#endif

// Input/Output Ports initialization
// Port B initialization
// Function: Bit7=Out Bit6=Out Bit5=Out Bit4=Out Bit3=Out Bit2=Out Bit1=Out Bit0=Out 
DDRB=(1<<DDB7) | (1<<DDB6) | (1<<DDB5) | (1<<DDB4) | (1<<DDB3) | (1<<DDB2) | (1<<DDB1) | (1<<DDB0);
// State: Bit7=0 Bit6=0 Bit5=0 Bit4=0 Bit3=0 Bit2=0 Bit1=0 Bit0=0 
PORTB=(0<<PORTB7) | (0<<PORTB6) | (0<<PORTB5) | (0<<PORTB4) | (0<<PORTB3) | (0<<PORTB2) | (0<<PORTB1) | (0<<PORTB0);

// Port C initialization
// Function: Bit6=Out Bit5=Out Bit4=Out Bit3=Out Bit2=Out Bit1=Out Bit0=Out 
DDRC=(1<<DDC6) | (1<<DDC5) | (1<<DDC4) | (1<<DDC3) | (1<<DDC2) | (1<<DDC1) | (1<<DDC0);
// State: Bit6=0 Bit5=0 Bit4=0 Bit3=0 Bit2=0 Bit1=0 Bit0=0 
PORTC=(0<<PORTC6) | (0<<PORTC5) | (0<<PORTC4) | (0<<PORTC3) | (0<<PORTC2) | (0<<PORTC1) | (0<<PORTC0);

// Port D initialization
// Function: Bit7=In Bit6=In Bit5=In Bit4=In Bit3=In Bit2=In Bit1=In Bit0=In 
DDRD=(1<<DDD7) | (1<<DDD6) | (1<<DDD5) | (1<<DDD4) | (1<<DDD3) | (0<<DDD2) | (0<<DDD1) | (0<<DDD0);
// State: Bit7=T Bit6=T Bit5=T Bit4=T Bit3=T Bit2=T Bit1=P Bit0=P 
PORTD=(0<<PORTD7) | (0<<PORTD6) | (0<<PORTD5) | (0<<PORTD4) | (0<<PORTD3) | (1<<PORTD2) | (1<<PORTD1) | (1<<PORTD0);

// Timer/Counter 0 initialization
// Clock source: System Clock
// Clock value: Timer 0 Stopped
// Mode: Normal top=0xFF
// OC0A output: Disconnected
// OC0B output: Disconnected
TCCR0A=(0<<COM0A1) | (0<<COM0A0) | (0<<COM0B1) | (0<<COM0B0) | (0<<WGM01) | (0<<WGM00);
TCCR0B=(0<<WGM02) | (0<<CS02) | (0<<CS01) | (0<<CS00);
TCNT0=0x00;
OCR0A=0x00;
OCR0B=0x00;

// Timer/Counter 1 initialization
// Clock source: System Clock
// Clock value: Timer1 Stopped
// Mode: Normal top=0xFFFF
// OC1A output: Disconnected
// OC1B output: Disconnected
// Noise Canceler: Off
// Input Capture on Falling Edge
// Timer1 Overflow Interrupt: Off
// Input Capture Interrupt: Off
// Compare A Match Interrupt: Off
// Compare B Match Interrupt: Off
TCCR1A=(0<<COM1A1) | (0<<COM1A0) | (0<<COM1B1) | (0<<COM1B0) | (0<<WGM11) | (0<<WGM10);
TCCR1B=(0<<ICNC1) | (0<<ICES1) | (0<<WGM13) | (0<<WGM12) | (0<<CS12) | (0<<CS11) | (0<<CS10);
TCNT1H=0x00;
TCNT1L=0x00;
ICR1H=0x00;
ICR1L=0x00;
OCR1AH=0x00;
OCR1AL=0x00;
OCR1BH=0x00;
OCR1BL=0x00;

// Timer/Counter 2 initialization
// Clock source: System Clock
// Clock value: Timer2 Stopped
// Mode: Normal top=0xFF
// OC2A output: Disconnected
// OC2B output: Disconnected
ASSR=(0<<EXCLK) | (0<<AS2);
TCCR2A=(0<<COM2A1) | (0<<COM2A0) | (0<<COM2B1) | (0<<COM2B0) | (0<<WGM21) | (0<<WGM20);
TCCR2B=(0<<WGM22) | (0<<CS22) | (0<<CS21) | (0<<CS20);
TCNT2=0x00;
OCR2A=0x00;
OCR2B=0x00;

// Timer/Counter 0 Interrupt(s) initialization
TIMSK0=(0<<OCIE0B) | (0<<OCIE0A) | (0<<TOIE0);

// Timer/Counter 1 Interrupt(s) initialization
TIMSK1=(0<<ICIE1) | (0<<OCIE1B) | (0<<OCIE1A) | (0<<TOIE1);

// Timer/Counter 2 Interrupt(s) initialization
TIMSK2=(0<<OCIE2B) | (0<<OCIE2A) | (0<<TOIE2);

// External Interrupt(s) initialization
// INT0: Off
// INT1: Off
// Interrupt on any change on pins PCINT0-7: Off
// Interrupt on any change on pins PCINT8-14: Off
// Interrupt on any change on pins PCINT16-23: Off
EICRA=(0<<ISC11) | (0<<ISC10) | (0<<ISC01) | (0<<ISC00);
EIMSK=(0<<INT1) | (0<<INT0);
PCICR=(0<<PCIE2) | (0<<PCIE1) | (0<<PCIE0);

// USART initialization
// USART disabled
UCSR0B=(0<<RXCIE0) | (0<<TXCIE0) | (0<<UDRIE0) | (0<<RXEN0) | (0<<TXEN0) | (0<<UCSZ02) | (0<<RXB80) | (0<<TXB80);

// Analog Comparator initialization
// Analog Comparator: Off
// The Analog Comparator's positive input is
// connected to the AIN0 pin
// The Analog Comparator's negative input is
// connected to the AIN1 pin
ACSR=(1<<ACD) | (0<<ACBG) | (0<<ACO) | (0<<ACI) | (0<<ACIE) | (0<<ACIC) | (0<<ACIS1) | (0<<ACIS0);
ADCSRB=(0<<ACME);
// Digital input buffer on AIN0: On
// Digital input buffer on AIN1: On
DIDR1=(0<<AIN0D) | (0<<AIN1D);

// ADC initialization
// ADC disabled
ADCSRA=(0<<ADEN) | (0<<ADSC) | (0<<ADATE) | (0<<ADIF) | (0<<ADIE) | (0<<ADPS2) | (0<<ADPS1) | (0<<ADPS0);

// SPI initialization
// SPI disabled
SPCR=(0<<SPIE) | (0<<SPE) | (0<<DORD) | (0<<MSTR) | (0<<CPOL) | (0<<CPHA) | (0<<SPR1) | (0<<SPR0);

// TWI initialization
// TWI disabled
TWCR=(0<<TWEA) | (0<<TWSTA) | (0<<TWSTO) | (0<<TWEN) | (0<<TWIE);


// Pin:   7 6 5 4 3 2 1 0
// Bit:   7 6 5 4 3 2 1 0
// 0 nyala 1 mati 


// angka 1
// PORTC=0b00010011;
// PORTD=0b00111000;

// angka2 
// PORTC=0b00001001;
// PORTD=0b00010000;

// angka 3
// PORTC=0b00000001;
// PORTD=0b00011000;

// angka 4
// PORTC=0b00010011;
// PORTD=0b00001000;

// angka 5
// PORTC=0b00000101;
// PORTD=0b00001000;

// angka 6
// PORTC=0b00000101;
// PORTD=0b00000000;

// angka 7
// PORTC=0b00010001;
// PORTD=0b00111000;

// angka 8
// PORTC=0b00000001;
// PORTD=0b00000000;

// angka 9
// PORTC=0b00000001;
// PORTD=0b00001000;






while (1)
      {
        
        do
            { 
                // Bagian Traffict Light 1
                // PORTB=0b00001001;
                // PORTC=0b00010011; //1
                // PORTD=0b00111000;
                // delay_ms(1000);
                // PORTB=0b00010001;
                // PORTC=0b00001001; // 2
                // PORTD=0b00010000;
                // delay_ms(1000);
                // PORTB=0b00100001;
                // PORTC=0b00000001; // 3
                // PORTD=0b00011000;
                // delay_ms(1000);

                // Merah
                PORTB=0b00001001;
                PORTC=0b00000001;
                PORTD=0b00001000; // 9
                delay_ms(1000);
                PORTB=0b00001001;
                PORTC=0b00000001;
                PORTD=0b00000000; // 8
                delay_ms(1000);
                PORTB=0b00001001;
                PORTC=0b00010001;
                PORTD=0b00111000; // 7
                delay_ms(1000);

                // Kuning
                PORTB=0b00010001;
                PORTC=0b00000101; // 6
                PORTD=0b00000000;
                delay_ms(1000);
                PORTB=0b00010001;
                PORTC=0b00000101;//5
                PORTD=0b00001000;
                delay_ms(1000);
                PORTB=0b00010001;
                PORTC=0b00010011;
                PORTD=0b00001000; // 4
                delay_ms(1000);

                // Hijau
                PORTB=0b00100001;
                PORTC=0b00000001; // 3
                PORTD=0b00011000;
                delay_ms(1000);
                PORTB=0b00100001;
                PORTC=0b00001001; // 2
                PORTD=0b00010000;
                delay_ms(1000);
                PORTB=0b00100001;
                PORTC=0b00010011; //1
                PORTD=0b00111000;
                delay_ms(1000);

                // Bagian Traffict Light 2
                // PORTB=0b00001001;
                // PORTC=0b00010011;
                // PORTD=0b00001000; // 4
                // delay_ms(1000);
                // PORTB=0b00001010;
                // PORTC=0b00000101;//5
                // PORTD=0b00001000;
                // delay_ms(1000);
                // PORTB=0b00001100;
                // PORTC=0b00000101; // 6
                // PORTD=0b00000000;
                // delay_ms(1000);

                // Merah
                PORTB=0b00001001;
                PORTC=0b00000001;
                PORTD=0b00001000; // 9
                delay_ms(1000);
                PORTB=0b00001001;
                PORTC=0b00000001;
                PORTD=0b00000000; // 8
                delay_ms(1000);
                PORTB=0b00001001;
                PORTC=0b00010001;
                PORTD=0b00111000; // 7
                delay_ms(1000);

                // Kuning
                PORTB=0b00001010;
                PORTC=0b00000101; // 6
                PORTD=0b00000000;
                delay_ms(1000);
                PORTB=0b00001010;
                PORTC=0b00000101;//5
                PORTD=0b00001000;
                delay_ms(1000);
                PORTB=0b00001010;
                PORTC=0b00010011;
                PORTD=0b00001000; // 4
                delay_ms(1000);

                // Hijau
                PORTB=0b00001100;
                PORTC=0b00000001; // 3
                PORTD=0b00011000;
                delay_ms(1000);
                PORTB=0b00001100;
                PORTC=0b00001001; // 2
                PORTD=0b00010000;
                delay_ms(1000);
                PORTB=0b00001100;
                PORTC=0b00010011; //1
                PORTD=0b00111000;
                delay_ms(1000);


                // Bagian Traffict Light 3
                // PORTB=0b00001001;
                // PORTC=0b00010001;
                // PORTD=0b00111000; // 7
                // delay_ms(1000);
                // PORTB=0b10001000;
                // PORTC=0b00000000;
                // PORTD=0b00000000; // 8
                // delay_ms(1000);
                // PORTB=0b01001000;
                // PORTC=0b00000000;
                // PORTD=0b00001000; // 9
                // delay_ms(1000);

                // Merah
                PORTB=0b00001001;
                PORTC=0b00000001;
                PORTD=0b00001000; // 9
                delay_ms(1000);
                PORTB=0b00001001;
                PORTC=0b00000001;
                PORTD=0b00000000; // 8
                delay_ms(1000);
                PORTB=0b00001001;
                PORTC=0b00010001;
                PORTD=0b00111000; // 7
                delay_ms(1000);

                // Kuning
                PORTB=0b10001001;
                PORTC=0b00000100; // 6
                PORTD=0b00000000;
                delay_ms(1000);
                PORTB=0b10001001;
                PORTC=0b00000100;//5
                PORTD=0b00001000;
                delay_ms(1000);
                PORTB=0b10001001;
                PORTC=0b00010010;
                PORTD=0b00001000; // 4
                delay_ms(1000);

                // Hijau
                PORTB=0b01001001;
                PORTC=0b00000000; // 3
                PORTD=0b00011000;
                delay_ms(1000);
                PORTB=0b01001001;
                PORTC=0b00001000; // 2
                PORTD=0b00010000;
                delay_ms(1000);
                PORTB=0b01001001;
                PORTC=0b00010010; //1
                PORTD=0b00111000;
                delay_ms(1000);
            if(PIND.0==0){
                // Bagian Traffict Light 1
                // PORTB=0b00001001;
                // PORTC=0b00010011; //1
                // PORTD=0b00111000;
                // delay_ms(1000);
                // PORTB=0b00010001;
                // PORTC=0b00001001; // 2
                // PORTD=0b00010000;
                // delay_ms(1000);
                // PORTB=0b00100001;
                // PORTC=0b00000001; // 3
                // PORTD=0b00011000;
                // delay_ms(1000);

                // Merah
                PORTB=0b00001001;
                PORTC=0b00000001;
                PORTD=0b00001000; // 9
                delay_ms(1000);
                PORTB=0b00001001;
                PORTC=0b00000001;
                PORTD=0b00000000; // 8
                delay_ms(1000);
                PORTB=0b00001001;
                PORTC=0b00010001;
                PORTD=0b00111000; // 7
                delay_ms(1000);

                // Kuning
                PORTB=0b00010001;
                PORTC=0b00000101; // 6
                PORTD=0b00000000;
                delay_ms(1000);
                PORTB=0b00010001;
                PORTC=0b00000101;//5
                PORTD=0b00001000;
                delay_ms(1000);
                PORTB=0b00010001;
                PORTC=0b00010011;
                PORTD=0b00001000; // 4
                delay_ms(1000);

                // Hijau
                PORTB=0b00100001;
                PORTC=0b00000001; // 3
                PORTD=0b00011000;
                delay_ms(1000);
                PORTB=0b00100001;
                PORTC=0b00001001; // 2
                PORTD=0b00010000;
                delay_ms(1000);
                PORTB=0b00100001;
                PORTC=0b00010011; //1
                PORTD=0b00111000;
                delay_ms(1000);

                // Bagian Traffict Light 2
                // PORTB=0b00001001;
                // PORTC=0b00010011;
                // PORTD=0b00001000; // 4
                // delay_ms(1000);
                // PORTB=0b00001010;
                // PORTC=0b00000101;//5
                // PORTD=0b00001000;
                // delay_ms(1000);
                // PORTB=0b00001100;
                // PORTC=0b00000101; // 6
                // PORTD=0b00000000;
                // delay_ms(1000);

                // Merah
                PORTB=0b00001001;
                PORTC=0b00000001;
                PORTD=0b00001000; // 9
                delay_ms(1000);
                PORTB=0b00001001;
                PORTC=0b00000001;
                PORTD=0b00000000; // 8
                delay_ms(1000);
                PORTB=0b00001001;
                PORTC=0b00010001;
                PORTD=0b00111000; // 7
                delay_ms(1000);

                // Kuning
                PORTB=0b00001010;
                PORTC=0b00000101; // 6
                PORTD=0b00000000;
                delay_ms(1000);
                PORTB=0b00001010;
                PORTC=0b00000101;//5
                PORTD=0b00001000;
                delay_ms(1000);
                PORTB=0b00001010;
                PORTC=0b00010011;
                PORTD=0b00001000; // 4
                delay_ms(1000);

                // Hijau
                PORTB=0b00001100;
                PORTC=0b00000001; // 3
                PORTD=0b00011000;
                delay_ms(1000);
                PORTB=0b00001100;
                PORTC=0b00001001; // 2
                PORTD=0b00010000;
                delay_ms(1000);
                PORTB=0b00001100;
                PORTC=0b00010011; //1
                PORTD=0b00111000;
                delay_ms(1000);


                // Bagian Traffict Light 3
                // PORTB=0b00001001;
                // PORTC=0b00010001;
                // PORTD=0b00111000; // 7
                // delay_ms(1000);
                // PORTB=0b10001000;
                // PORTC=0b00000000;
                // PORTD=0b00000000; // 8
                // delay_ms(1000);
                // PORTB=0b01001000;
                // PORTC=0b00000000;
                // PORTD=0b00001000; // 9
                // delay_ms(1000);

                // Merah
                PORTB=0b00001001;
                PORTC=0b00000001;
                PORTD=0b00001000; // 9
                delay_ms(1000);
                PORTB=0b00001001;
                PORTC=0b00000001;
                PORTD=0b00000000; // 8
                delay_ms(1000);
                PORTB=0b00001001;
                PORTC=0b00010001;
                PORTD=0b00111000; // 7
                delay_ms(1000);

                // Kuning
                PORTB=0b10001001;
                PORTC=0b00000100; // 6
                PORTD=0b00000000;
                delay_ms(1000);
                PORTB=0b10001001;
                PORTC=0b00000100;//5
                PORTD=0b00001000;
                delay_ms(1000);
                PORTB=0b10001001;
                PORTC=0b00010010;
                PORTD=0b00001000; // 4
                delay_ms(1000);

                // Hijau
                PORTB=0b01001001;
                PORTC=0b00000000; // 3
                PORTD=0b00011000;
                delay_ms(1000);
                PORTB=0b01001001;
                PORTC=0b00001000; // 2
                PORTD=0b00010000;
                delay_ms(1000);
                PORTB=0b01001001;
                PORTC=0b00010010; //1
                PORTD=0b00111000;
                delay_ms(1000);
                }
                else if(PIND.1==0){

                // Bagian Traffict Light 1
                // PORTB=0b00001001;
                // PORTC=0b00010011;
                // PORTD=0b00001000; // 4
                // delay_ms(1000);
                // PORTB=0b00001010;
                // PORTC=0b00000101;//5
                // PORTD=0b00001000;
                // delay_ms(1000);
                // PORTB=0b00001100;
                // PORTC=0b00000101; // 6
                // PORTD=0b00000000;
                // delay_ms(1000);

                // Merah
                PORTB=0b00001001;
                PORTC=0b00000001;
                PORTD=0b00001000; // 9
                delay_ms(1000);
                PORTB=0b00001001;
                PORTC=0b00000001;
                PORTD=0b00000000; // 8
                delay_ms(1000);
                PORTB=0b00001001;
                PORTC=0b00010001;
                PORTD=0b00111000; // 7
                delay_ms(1000);

                // Kuning
                PORTB=0b00001010;
                PORTC=0b00000101; // 6
                PORTD=0b00000000;
                delay_ms(1000);
                PORTB=0b00001010;
                PORTC=0b00000101;//5
                PORTD=0b00001000;
                delay_ms(1000);
                PORTB=0b00001010;
                PORTC=0b00010011;
                PORTD=0b00001000; // 4
                delay_ms(1000);

                // Hijau
                PORTB=0b00001100;
                PORTC=0b00000001; // 3
                PORTD=0b00011000;
                delay_ms(1000);
                PORTB=0b00001100;
                PORTC=0b00001001; // 2
                PORTD=0b00010000;
                delay_ms(1000);
                PORTB=0b00001100;
                PORTC=0b00010011; //1
                PORTD=0b00111000;
                delay_ms(1000);

                    // Bagian Traffict Light 2
                // PORTB=0b00001001;
                // PORTC=0b00010011; //1
                // PORTD=0b00111000;
                // delay_ms(1000);
                // PORTB=0b00010001;
                // PORTC=0b00001001; // 2
                // PORTD=0b00010000;
                // delay_ms(1000);
                // PORTB=0b00100001;
                // PORTC=0b00000001; // 3
                // PORTD=0b00011000;
                // delay_ms(1000);

                // Merah
                PORTB=0b00001001;
                PORTC=0b00000001;
                PORTD=0b00001000; // 9
                delay_ms(1000);
                PORTB=0b00001001;
                PORTC=0b00000001;
                PORTD=0b00000000; // 8
                delay_ms(1000);
                PORTB=0b00001001;
                PORTC=0b00010001;
                PORTD=0b00111000; // 7
                delay_ms(1000);

                // Kuning
                PORTB=0b00010001;
                PORTC=0b00000101; // 6
                PORTD=0b00000000;
                delay_ms(1000);
                PORTB=0b00010001;
                PORTC=0b00000101;//5
                PORTD=0b00001000;
                delay_ms(1000);
                PORTB=0b00010001;
                PORTC=0b00010011;
                PORTD=0b00001000; // 4
                delay_ms(1000);

                // Hijau
                PORTB=0b00100001;
                PORTC=0b00000001; // 3
                PORTD=0b00011000;
                delay_ms(1000);
                PORTB=0b00100001;
                PORTC=0b00001001; // 2
                PORTD=0b00010000;
                delay_ms(1000);
                PORTB=0b00100001;
                PORTC=0b00010011; //1
                PORTD=0b00111000;
                delay_ms(1000);


                // Bagian Traffict Light 3
                // PORTB=0b00001001;
                // PORTC=0b00010001;
                // PORTD=0b00111000; // 7
                // delay_ms(1000);
                // PORTB=0b10001000;
                // PORTC=0b00000000;
                // PORTD=0b00000000; // 8
                // delay_ms(1000);
                // PORTB=0b01001000;
                // PORTC=0b00000000;
                // PORTD=0b00001000; // 9
                // delay_ms(1000);

                // Merah
                PORTB=0b00001001;
                PORTC=0b00000001;
                PORTD=0b00001000; // 9
                delay_ms(1000);
                PORTB=0b00001001;
                PORTC=0b00000001;
                PORTD=0b00000000; // 8
                delay_ms(1000);
                PORTB=0b00001001;
                PORTC=0b00010001;
                PORTD=0b00111000; // 7
                delay_ms(1000);

                // Kuning
                PORTB=0b10001001;
                PORTC=0b00000100; // 6
                PORTD=0b00000000;
                delay_ms(1000);
                PORTB=0b10001001;
                PORTC=0b00000100;//5
                PORTD=0b00001000;
                delay_ms(1000);
                PORTB=0b10001001;
                PORTC=0b00010010;
                PORTD=0b00001000; // 4
                delay_ms(1000);

                // Hijau
                PORTB=0b01001001;
                PORTC=0b00000000; // 3
                PORTD=0b00011000;
                delay_ms(1000);
                PORTB=0b01001001;
                PORTC=0b00001000; // 2
                PORTD=0b00010000;
                delay_ms(1000);
                PORTB=0b01001001;
                PORTC=0b00010010; //1
                PORTD=0b00111000;
                delay_ms(1000);
                }
                else if(PIND.2==0){


                // Bagian Traffict Light 1
                // PORTB=0b00001001;
                // PORTC=0b00010001;
                // PORTD=0b00111000; // 7
                // delay_ms(1000);
                // PORTB=0b10001000;
                // PORTC=0b00000000;
                // PORTD=0b00000000; // 8
                // delay_ms(1000);
                // PORTB=0b01001000;
                // PORTC=0b00000000;
                // PORTD=0b00001000; // 9
                // delay_ms(1000);

                // Merah
                PORTB=0b00001001;
                PORTC=0b00000001;
                PORTD=0b00001000; // 9
                delay_ms(1000);
                PORTB=0b00001001;
                PORTC=0b00000001;
                PORTD=0b00000000; // 8
                delay_ms(1000);
                PORTB=0b00001001;
                PORTC=0b00010001;
                PORTD=0b00111000; // 7
                delay_ms(1000);

                // Kuning
                PORTB=0b10001001;
                PORTC=0b00000100; // 6
                PORTD=0b00000000;
                delay_ms(1000);
                PORTB=0b10001001;
                PORTC=0b00000100;//5
                PORTD=0b00001000;
                delay_ms(1000);
                PORTB=0b10001001;
                PORTC=0b00010010;
                PORTD=0b00001000; // 4
                delay_ms(1000);

                // Hijau
                PORTB=0b01001001;
                PORTC=0b00000000; // 3
                PORTD=0b00011000;
                delay_ms(1000);
                PORTB=0b01001001;
                PORTC=0b00001000; // 2
                PORTD=0b00010000;
                delay_ms(1000);
                PORTB=0b01001001;
                PORTC=0b00010010; //1
                PORTD=0b00111000;
                delay_ms(1000);


                // Bagian Traffict Light 2
                // PORTB=0b00001001;
                // PORTC=0b00010011; //1
                // PORTD=0b00111000;
                // delay_ms(1000);
                // PORTB=0b00010001;
                // PORTC=0b00001001; // 2
                // PORTD=0b00010000;
                // delay_ms(1000);
                // PORTB=0b00100001;
                // PORTC=0b00000001; // 3
                // PORTD=0b00011000;
                // delay_ms(1000);

                // Merah
                PORTB=0b00001001;
                PORTC=0b00000001;
                PORTD=0b00001000; // 9
                delay_ms(1000);
                PORTB=0b00001001;
                PORTC=0b00000001;
                PORTD=0b00000000; // 8
                delay_ms(1000);
                PORTB=0b00001001;
                PORTC=0b00010001;
                PORTD=0b00111000; // 7
                delay_ms(1000);

                // Kuning
                PORTB=0b00010001;
                PORTC=0b00000101; // 6
                PORTD=0b00000000;
                delay_ms(1000);
                PORTB=0b00010001;
                PORTC=0b00000101;//5
                PORTD=0b00001000;
                delay_ms(1000);
                PORTB=0b00010001;
                PORTC=0b00010011;
                PORTD=0b00001000; // 4
                delay_ms(1000);

                // Hijau
                PORTB=0b00100001;
                PORTC=0b00000001; // 3
                PORTD=0b00011000;
                delay_ms(1000);
                PORTB=0b00100001;
                PORTC=0b00001001; // 2
                PORTD=0b00010000;
                delay_ms(1000);
                PORTB=0b00100001;
                PORTC=0b00010011; //1
                PORTD=0b00111000;
                delay_ms(1000);

                // Bagian Traffict Light 3
                // PORTB=0b00001001;
                // PORTC=0b00010011;
                // PORTD=0b00001000; // 4
                // delay_ms(1000);
                // PORTB=0b00001010;
                // PORTC=0b00000101;//5
                // PORTD=0b00001000;
                // delay_ms(1000);
                // PORTB=0b00001100;
                // PORTC=0b00000101; // 6
                // PORTD=0b00000000;
                // delay_ms(1000);

                // Merah
                PORTB=0b00001001;
                PORTC=0b00000001;
                PORTD=0b00001000; // 9
                delay_ms(1000);
                PORTB=0b00001001;
                PORTC=0b00000001;
                PORTD=0b00000000; // 8
                delay_ms(1000);
                PORTB=0b00001001;
                PORTC=0b00010001;
                PORTD=0b00111000; // 7
                delay_ms(1000);

                // Kuning
                PORTB=0b00001010;
                PORTC=0b00000101; // 6
                PORTD=0b00000000;
                delay_ms(1000);
                PORTB=0b00001010;
                PORTC=0b00000101;//5
                PORTD=0b00001000;
                delay_ms(1000);
                PORTB=0b00001010;
                PORTC=0b00010011;
                PORTD=0b00001000; // 4
                delay_ms(1000);

                // Hijau
                PORTB=0b00001100;
                PORTC=0b00000001; // 3
                PORTD=0b00011000;
                delay_ms(1000);
                PORTB=0b00001100;
                PORTC=0b00001001; // 2
                PORTD=0b00010000;
                delay_ms(1000);
                PORTB=0b00001100;
                PORTC=0b00010011; //1
                PORTD=0b00111000;
                delay_ms(1000);

                }
            } while (1);
            


      }
}

