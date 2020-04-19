// This is a C program to implement ping.
// Author: Chris Zachariah
// chriszachariah3@gmail.com

#include <stdio.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <netinet/ip.h>
#include <netdb.h> 
#include <unistd.h> 
#include <string.h> 
#include <stdlib.h> 
#include <netinet/ip_icmp.h> 
#include <time.h> 
#include <fcntl.h> 
#include <signal.h> 
#include <time.h> 
#include <stdbool.h>
#ifndef SOL_IP
#define SOL_IP IPPROTO_IP
#endif


// Default Port Number
#define PORT_NO 0

// Default Time-out
#define RECV_TIMEOUT 1

// Default Sleep rate
#define PING_SLEEP_RATE 1000000

// ping packet size 
#define PING_PKT_S 64 

// ping packet structure 
struct ping_pkt 
{ 
    struct icmp hdr; 
    char msg[PING_PKT_S-sizeof(struct icmp)]; 
};

// Calculating the Check Sum 
unsigned short checksum(void *b, int len) 
{    
  unsigned short *buf = b; 
  unsigned int sum=0; 
  unsigned short result; 
  
  for ( sum = 0; len > 1; len -= 2 ) 
    sum += *buf++; 
  if ( len == 1 ) 
    sum += *(unsigned char*)buf; 
  sum = (sum >> 16) + (sum & 0xFFFF); 
  sum += (sum >> 16); 
  result = ~sum; 
  return result; 
} 

// Keep loop running
int loopRunner = 1;

// method stops the loop
void loopStopper()
{
  loopRunner = 0;
} // loopStopper()

// Performs a DNS lookup  
char* LookUpDNS(char *addr_hostname, struct sockaddr_in *addr_connection) 
{ 
    struct hostent* host_entity; 
    char* ip=(char*)malloc(NI_MAXHOST*sizeof(char)); 
    int i; 
    // cannot resolve the hostname
    if ((host_entity = gethostbyname(addr_hostname)) == NULL) 
    {  
        return NULL; 
    } 
    // fill the address
    strcpy(ip,inet_ntoa(*(struct in_addr*) host_entity->h_addr)); 
    (*addr_connection).sin_family = host_entity->h_addrtype; 
    (*addr_connection).sin_port = htons(PORT_NO); 
    (*addr_connection).sin_addr.s_addr  = *(long*)host_entity->h_addr; 
    return ip; 
} // LookUpDNS()

// Resolves the reverse lookup of the hostname 
char* ReverseLookUpDNS(char *IP_addr) 
{ 
    struct sockaddr_in temporary_addr;     
    socklen_t length; 
    char buffer[NI_MAXHOST];
    char* return_buffer; 
  
    temporary_addr.sin_family = AF_INET; 
    temporary_addr.sin_addr.s_addr = inet_addr(IP_addr); 
    length = sizeof(struct sockaddr_in); 
  
    // check if the name can be resolved
    if (getnameinfo((struct sockaddr *) &temporary_addr, length, buffer,sizeof(buffer), NULL, 0, NI_NAMEREQD))  
    { 
        return NULL; 
    } 
    return_buffer = (char*)malloc((strlen(buffer)+1)*sizeof(char)); 
    strcpy(return_buffer, buffer); 
    return return_buffer; 
} // ReverseLookUpDNS()

void sendPing(int ping_sockfd, struct sockaddr_in *ping_addr,char *ping_dom, char *ping_ip, char *rev_host) 
{
  int ttl_val=64, msg_count=0, i,flag=1,msg_received_count=0; 
  socklen_t addr_len;
  struct ping_pkt pckt; 
  struct sockaddr_in r_addr; 
  struct timespec time_start, time_end, tfs, tfe; 
  long double rtt_msec=0, total_msec=0; 
  struct timeval tv_out; 
  tv_out.tv_sec = RECV_TIMEOUT; 
  tv_out.tv_usec = 0; 

  clock_gettime(CLOCK_MONOTONIC, &tfs);

  // set socket options at ip to TTL and value to 64, change to what you want by setting ttl_val 
  if (setsockopt(ping_sockfd, SOL_IP, IP_TTL,&ttl_val, sizeof(ttl_val)) != 0) 
  { 
    printf("Setting socket options to TTL failed!\n"); 
    return; 
  } 
  else
  { 
    printf("\nSocket set to TTL..\n"); 
  } 

  // setting timeout of recv setting 
  setsockopt(ping_sockfd, SOL_SOCKET, SO_RCVTIMEO,(const char*)&tv_out, sizeof tv_out);

  // send icmp packet in an infinite loop 
    while(loopRunner) 
    { 
      // flag is whether packet was sent or not 
      flag=1; 
     
      //filling packet 
      bzero(&pckt, sizeof(pckt)); 
          
      pckt.hdr.icmp_type = ICMP_ECHO; 
      pckt.hdr.icmp_code = getpid(); 
          
      for ( i = 0; i < sizeof(pckt.msg)-1; i++ ) 
      {
        pckt.msg[i] = i+'0';
      }   
      pckt.msg[i] = 0; 
      pckt.hdr.icmp_code = msg_count++; 
      pckt.hdr.icmp_cksum = checksum(&pckt, sizeof(pckt)); 

      usleep(PING_SLEEP_RATE); 
  
      //send packet 
      clock_gettime(CLOCK_MONOTONIC, &time_start); 
      if ( sendto(ping_sockfd, &pckt, sizeof(pckt), 0,(struct sockaddr*) ping_addr, sizeof(*ping_addr)) <= 0) 
      { 
        printf("\nPacket Sending Failed!\n"); 
        flag=0; 
      } 

      //receive packet 
      addr_len=sizeof(r_addr); 
  
      if ( recvfrom(ping_sockfd, &pckt, sizeof(pckt), 0,(struct sockaddr*)&r_addr, &addr_len) <= 0 && msg_count>1)  
      { 
        printf("\nPacket receive failed!\n"); 
      } 
      else
      { 
        clock_gettime(CLOCK_MONOTONIC, &time_end); 
              
        double timeElapsed = ((double)(time_end.tv_nsec - time_start.tv_nsec))/1000000.0; 
        rtt_msec = (time_end.tv_sec-time_start.tv_sec) * 1000.0 + timeElapsed; 
              
        // if packet was not sent, don't receive 
        if(flag) 
        { 
          if(!(pckt.hdr.icmp_type ==69 && pckt.hdr.icmp_code==0))  
          { 
            printf("Error..Packet received with ICMP type %d code %d\n",pckt.hdr.icmp_type, pckt.hdr.icmp_code); 
          } 
          else
          { 
            printf("%d bytes from %s (h: %s) (%s) msg_seq=%d ttl=%d rtt = %Lf ms.\n",PING_PKT_S, ping_dom, rev_host,ping_ip, msg_count, ttl_val, rtt_msec); 
            msg_received_count++; 
          } 
        } 
      }     
    } 
    clock_gettime(CLOCK_MONOTONIC, &tfe); 
    double timeElapsed = ((double)(tfe.tv_nsec - tfs.tv_nsec))/1000000.0; 
      
    total_msec = (tfe.tv_sec-tfs.tv_sec)*1000.0+timeElapsed;              
    printf("\n===%s ping statistics===\n", ping_ip); 
    printf("\n%d packets sent, %d packets received, %f percentp acket loss. Total time: %Lf ms.\n\n", msg_count, msg_received_count,((msg_count - msg_received_count)/msg_count) * 100.0,total_msec);
} // sendPing()

int main (int argc , char* argv[])
{
  char* IP;
  char* hostName;
  struct sockaddr_in addr_connection; 
  int sockfd;

  if (argc == 1)
  {
    printf("Please provide a hostname or an IP address as an argument.\n");
    return 0;
  }

  // resolve the IP
  IP = LookUpDNS(argv[1],&addr_connection);
  if (IP == NULL)
  {
    printf("Error: Could not resolve IP.\n");
    return 0;
  }
  printf("IP Resolved: %s\n",IP);

  // save the hostname
  hostName = ReverseLookUpDNS(IP);
  
  // want to make a socket to be able to sniff out ICMP packets
  sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sockfd < 0)
  {
     printf("Socket file descriptor not received.\n"); 
     return 0; 
  }

  // allows us to interupt the loop and stop it
  signal(SIGINT, loopStopper); 

  sendPing(sockfd, &addr_connection, hostName,IP,argv[1]); 
  return 0;
} // main()
