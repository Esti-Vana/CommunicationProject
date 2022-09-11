#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <json-c/json.h>
#include <limits.h>
#include <time.h>

#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN  6
#define MAX_BUFFER 1024
#define SIZE_HASH_TABLE 1000

//data structure- hash table
struct conn_data{
   int conn_id,protocol;
   char * server_ip,*client_ip;
   u_short server_port,client_port;
   int seconds_without_packets;
};
struct Transaction_data
{
   int Transaction_id,num_outbound_packets_in_range,num_inbound_packets_in_range;
   long Start_time;
   int max_packet_size_inbound,min_packet_size_inbound;
};

struct DataItem {
  
   struct conn_data * p_conn_data;
   struct Transaction_data * p_transaction_data;
   int key;
};
FILE * file;
struct DataItem* hashArray[SIZE_HASH_TABLE]; 
struct DataItem* dummyItem;
struct DataItem* item;
int connection_id_index=0;
int timer_id=0;
int five_tuple_key(char * server_ip,char*client_ip,int protocol, u_short server_port,u_short client_port)
{   
    int result= atof(server_ip)+atof(client_ip)+protocol+(int)server_port+(int)client_port;
    int key=result% SIZE_HASH_TABLE;
    return key;
}

void Statistics_and_print_transaction_data(struct Transaction_data* p_transaction_data,struct conn_data * p_conn_data){
    if(p_transaction_data->num_inbound_packets_in_range==1)
    fprintf(file,"%d, %d, %d, %d, %s, %hu, %s, %hu, %d, %d, 0, 0 \n",p_conn_data->conn_id,p_transaction_data->Transaction_id,p_transaction_data->Start_time,p_transaction_data->num_inbound_packets_in_range, p_conn_data->server_ip ,p_conn_data->server_port, p_conn_data->client_ip,p_conn_data->client_port, p_conn_data->protocol,p_transaction_data->num_outbound_packets_in_range);
    else
    fprintf(file,"%d, %d, %d, %d, %s, %hu, %s, %hu, %d, %d,   %d, %d \n",p_conn_data->conn_id,p_transaction_data->Transaction_id,p_transaction_data->Start_time,p_transaction_data->num_inbound_packets_in_range,p_conn_data->server_ip ,p_conn_data->server_port, p_conn_data->client_ip,p_conn_data->client_port, p_conn_data->protocol,p_transaction_data->num_outbound_packets_in_range,p_transaction_data->max_packet_size_inbound,p_transaction_data->min_packet_size_inbound);
}
int compare_five_tuples(struct conn_data * p1,struct conn_data * p2 ){
    if(strcmp(p1->client_ip,p2->client_ip)==0&&strcmp(p1->server_ip,p2->server_ip)==0&& p1->protocol==p2->protocol&& p1->server_port==p2->server_port&& p1->client_port==p2->client_port)
    {           
       return 1;
    }
    if(strcmp(p1->client_ip,p2->server_ip)==0&&strcmp(p1->server_ip,p2->client_ip)==0&& p1->protocol==p2->protocol&& p1->server_port==p2->client_port&& p1->client_port==p2->server_port)
            return 1;
    return 0;

}
void insert(struct conn_data *p_conn_data,int in_range,int is_server,int arrival_time,int size_packet)
{
   int hashIndex = five_tuple_key(p_conn_data->server_ip,p_conn_data->client_ip,p_conn_data->protocol,p_conn_data->server_port,p_conn_data->client_port);  
   
     display();
    time_t start, end;
    double elapsed;
   //get the hash
   //move in array until an empty or deleted cell
    if(in_range!=1||is_server!=0)
    {
        
        while(hashArray[hashIndex] != NULL && hashArray[hashIndex]->key != -1) {
            //go to next cell

            if(compare_five_tuples(hashArray[hashIndex]->p_conn_data,p_conn_data)==1)
            {
       
               

                if(in_range==0 &&is_server==0)
                        hashArray[hashIndex]->p_transaction_data->num_outbound_packets_in_range++;
                if(in_range==1 &&is_server==1)
                    {
                        if (size_packet >hashArray[hashIndex]->p_transaction_data->max_packet_size_inbound)
                        {
                            hashArray[hashIndex]->p_transaction_data->max_packet_size_inbound=size_packet;
                        }
                        if (size_packet <hashArray[hashIndex]->p_transaction_data->min_packet_size_inbound)
                        {
                            hashArray[hashIndex]->p_transaction_data->min_packet_size_inbound=size_packet;
                        }
                        hashArray[hashIndex]->p_transaction_data->num_inbound_packets_in_range++;
                    }
                free(p_conn_data);
                return;
            }
            ++hashIndex;
            //wrap around the table
            hashIndex %= SIZE_HASH_TABLE;
        }
        return;
    }
      //if request
    if(in_range==1&&is_server==0){

         while(hashArray[hashIndex] != NULL && hashArray[hashIndex]->key != -1) {
            //go to next cell
            if(compare_five_tuples(hashArray[hashIndex]->p_conn_data,p_conn_data)==1)
            {
                Statistics_and_print_transaction_data(hashArray[hashIndex]->p_transaction_data,hashArray[hashIndex]->p_conn_data);
                //init transaction data
                hashArray[hashIndex]->p_transaction_data->Start_time=arrival_time;
                hashArray[hashIndex]->p_transaction_data->Transaction_id++;
                hashArray[hashIndex]->p_transaction_data->num_outbound_packets_in_range=0;
                hashArray[hashIndex]->p_transaction_data->num_inbound_packets_in_range=1;
                hashArray[hashIndex]->p_transaction_data->max_packet_size_inbound=-1;
                hashArray[hashIndex]->p_transaction_data->min_packet_size_inbound=INT_MAX;
               // hashArray[hashIndex]->p_conn_data->seconds_without_packets=-1;
                               return;
            }
            ++hashIndex;
            //wrap around the table
            hashIndex %= SIZE_HASH_TABLE;
        }
        //init connection data
        struct DataItem *item = (struct DataItem*) malloc(sizeof(struct DataItem));
        item-> p_conn_data=p_conn_data;
        item->key=hashIndex;
        item->p_conn_data->conn_id=++connection_id_index;
        item->p_transaction_data=(struct Transaction_data*)malloc(sizeof(struct Transaction_data));
        item->p_transaction_data->Start_time=arrival_time;
        item->p_transaction_data->Transaction_id=1;
        item->p_transaction_data->num_outbound_packets_in_range=0;
        item->p_transaction_data->num_inbound_packets_in_range=1;
        item->p_transaction_data->max_packet_size_inbound=-1;
        item->p_transaction_data->min_packet_size_inbound=INT_MAX;
    //     int timer=++timer_id;
    //     item->p_conn_data->seconds_without_packets=timer;
       hashArray[hashIndex] = item;
    //     _sleep(20);
    //    if(hashArray[hashIndex]->p_conn_data->seconds_without_packets==timer)
    //     delete_connection();
    }
}

// struct DataItem* delete(struct DataItem* item) {
//    int key = item->key;

//    //get the hash 
//   // int hashIndex = hashCode(key);

//    //move in array until an empty
//    while(hashArray[hashIndex] != NULL) {
	
//       if(hashArray[hashIndex]->key == key) {
//          struct DataItem* temp = hashArray[hashIndex]; 
			
//          //assign a dummy item at deleted position
//          hashArray[hashIndex] = dummyItem; 
//          return temp;
//       }
		
//       //go to next cell
//       ++hashIndex;
		
//       //wrap around the table
//       hashIndex %= SIZE_HASH_TABLE;
//    }      
	
//    return NULL;        
// }

void display() {
   int i = 0;
	
   for(i = 0; i<SIZE_HASH_TABLE; i++) {
	
      if(hashArray[i] != NULL)
         printf(" (%d,%d,%d)",hashArray[i]->key,hashArray[i]->p_conn_data->conn_id,hashArray[i]->p_transaction_data->num_inbound_packets_in_range);
      else
         printf(" ~~ ");
   }
	
   printf("\n");
}

    struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
        u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
        u_short ether_type; /* IP? ARP? RARP? etc */
    };

    /* IP header */
struct sniff_ip {          
        u_char ip_vhl;      /* version << 4 | header length >> 2 */
        u_char ip_tos;      /* type of service */
        u_short ip_len;     /* total length */
        u_short ip_id;      /* identification */
        u_short ip_off;     /* fragment offset field */
    #define IP_RF 0x8000        /* reserved fragment flag */
    #define IP_DF 0x4000        /* dont fragment flag */
    #define IP_MF 0x2000        /* more fragments flag */
    #define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
        u_char ip_ttl;      /* time to live */
        u_char ip_p;        /* protocol */
        u_short ip_sum;     /* checksum */
        struct in_addr ip_src;
        struct in_addr ip_dst; /* source and dest address */
    };

    #define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
    #define IP_V(ip)        (((ip)->ip_vhl) >> 4)

/* packet header*/
typedef struct packet_header{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
}packet_header;

free_data(){

    for (size_t i = 0; i < SIZE_HASH_TABLE; i++)
    {
        free(hashArray[i]->p_conn_data->server_ip);
        free(hashArray[i]->p_conn_data->client_ip);
        free(hashArray[i]->p_conn_data);
        free(hashArray[i]->p_transaction_data);
        free(hashArray[i]);
    }
    
}

int main(int argc, char *argv[])
{
   
    //read data from config file.
    FILE * p_configFile;
    char buffer[MAX_BUFFER];
    struct json_object * parsed_json,* j_request_packet_threshold,* j_inbound_packets_in_range_min,*j_inbound_packets_in_range_max,*j_outbound_packets_in_range_min ;
    struct json_object *j_minimum_video_connection_size,* j_max_diff_time_inbound_threshold,*j_min_diff_time_inbound_threshold,*j_number_of_videos_to_output_statistics_per_video,*j_max_number_of_connections,*j_max_number_of_transaction_per_video,*j_video_connection_timeout;
    int minimum_video_connection_size,outbound_packets_in_range_min,outbound_packets_in_range_max;
    int request_packet_threshold,inbound_packets_in_range_min,inbound_packets_in_range_max;
    int max_diff_time_inbound_threshold,min_diff_time_inbound_threshold,number_of_videos_to_output_statistics_per_video,max_number_of_connections, max_number_of_transaction_per_video,video_connection_timeout;
    p_configFile=fopen("config.json","r");
    fread(buffer,MAX_BUFFER,1,p_configFile);
    fclose(p_configFile);
    parsed_json=json_tokener_parse(buffer);
    json_object_object_get_ex(parsed_json,"request_packet_threshold",&j_request_packet_threshold);
    json_object_object_get_ex(parsed_json,"inbound_packets_in_range_min",&j_inbound_packets_in_range_min);
    json_object_object_get_ex(parsed_json,"inbound_packets_in_range_max",&j_inbound_packets_in_range_max);
    json_object_object_get_ex(parsed_json,"outbound_packets_in_range_min",&j_outbound_packets_in_range_min);
    json_object_object_get_ex(parsed_json,"max_diff_time_inbound_threshold",&j_max_diff_time_inbound_threshold);
    json_object_object_get_ex(parsed_json,"min_diff_time_inbound_threshold",&j_min_diff_time_inbound_threshold);
    json_object_object_get_ex(parsed_json,"number_of_videos_to_output_statistics_per_video",&j_number_of_videos_to_output_statistics_per_video);
    json_object_object_get_ex(parsed_json,"max_number_of_transaction_per_video",&j_max_number_of_transaction_per_video);
    json_object_object_get_ex(parsed_json,"video_connection_timeout",&j_video_connection_timeout);
    json_object_object_get_ex(parsed_json,"max_number_of_connections",&j_max_number_of_connections);
    json_object_object_get_ex(parsed_json,"minimum_video_connection_size",&j_minimum_video_connection_size);

    request_packet_threshold= json_object_get_int(j_request_packet_threshold);
    inbound_packets_in_range_min= json_object_get_int(j_inbound_packets_in_range_min);
    inbound_packets_in_range_max= json_object_get_int(j_inbound_packets_in_range_max);
    outbound_packets_in_range_min= json_object_get_int(j_outbound_packets_in_range_min);
    outbound_packets_in_range_max=request_packet_threshold-1;
    max_diff_time_inbound_threshold=json_object_get_int(j_max_diff_time_inbound_threshold);
    min_diff_time_inbound_threshold= json_object_get_int(j_min_diff_time_inbound_threshold);
    number_of_videos_to_output_statistics_per_video= json_object_get_int(j_number_of_videos_to_output_statistics_per_video);
    max_number_of_transaction_per_video= json_object_get_int(j_max_number_of_transaction_per_video);
    video_connection_timeout= json_object_get_int(j_video_connection_timeout);
    max_number_of_connections= json_object_get_int(j_max_number_of_connections);
    minimum_video_connection_size=json_object_get_int(j_minimum_video_connection_size);

    //read data from pcap file
    char errbuff[PCAP_ERRBUF_SIZE]; //error buffer
    pcap_t * p_pcapfile_data = pcap_open_offline("data.pcap", errbuff); //open file and create pcap handler
    

    
    FILE *p_output_file = fopen ( "out-data.csv", "w" ) ;//write to file 
     struct sniff_ethernet *p_ethernet_header; /* The ethernet header */
    struct sniff_ip *p_header_ip; /* The IP header */
    u_int size_ip_header;
    u_short sport,dport;
    int protocol_packet,apoch_time, is_server,is_range;

    fprintf(p_output_file,"Conn_id, server_ip, server_port, client_ip, client_port, protocol, Transaction_id, Start time\n");
    file=fopen("trans.csv","w");
    fprintf(file,"Conn_id, Transaction_id, Start time, num_inbound_packets_in_range, server_ip, server_port, client_ip, client_port, protocol, num_outbound_packets_in_range, max_packet_size_inbound, min_packet_size_inbound\n");


    struct pcap_pkthdr *p_header_packet; //The header that pcap gives us
    u_char *p_data_packet;//The actual packet
    int packetCount = 0,size_packet;
    //go over all packets
    while (pcap_next_ex(p_pcapfile_data, &p_header_packet, &p_data_packet) >= 0)
    {
        // Show the packet number
        printf("Packet # %i\n", ++packetCount);
        size_packet= p_header_packet->len;
        // Show the size in bytes of the packet
        printf("Packet size: %d bytes\n",size_packet);
        //fprintf(p_output_file,"Packet size: %d bytes\n", header->len);

        //check if we need it.
        // Show a warning if the length captured is different
        // if (header->len != header->caplen)
        //     printf("Warning! Capture size different than packet size: %ld bytes\n", header->len);
        
        // Show Epoch Time
        printf("Epoch Time: %d:%d seconds\n", p_header_packet->ts.tv_sec, p_header_packet->ts.tv_usec);

        p_ethernet_header = (struct sniff_ethernet*)(p_data_packet);
        p_header_ip = (struct sniff_ip*)(p_data_packet + SIZE_ETHERNET);
        size_ip_header = IP_HL(p_header_ip)*4;
        if (size_ip_header < 20) {
            printf(" ERROR: * Invalid IP header length: %u bytes\n", size_ip_header);  
            continue;      
        }
        packet_header *p_udp_header;
        p_udp_header = (packet_header *)(p_data_packet + SIZE_ETHERNET+ size_ip_header);
        /* convert from network byte order to host byte order */
        sport = ntohs( p_udp_header->sport );
        dport = ntohs( p_udp_header->dport );
        printf("sport %hu dport %hu\n,",sport,dport);
        
        //ip adress
        char *srcname=strdup(inet_ntoa(p_header_ip->ip_src));
        char *dstname=strdup(inet_ntoa(p_header_ip->ip_dst));
        printf("src address: %s dest address: %s \n", srcname, dstname);
        int result= five_tuple_key(srcname,dstname,p_header_ip->ip_p,sport,dport);
        protocol_packet=p_header_ip->ip_p;
        printf("protocol %d\n\n",protocol_packet);
        // struct tm *info;   
        // info = localtime( header->ts.tv_sec);
        // printf("Current local time and date: %s", asctime(info));
        apoch_time=p_header_packet->ts.tv_sec;
        //filter the packets
        if((sport==443||dport==443)&& protocol_packet==17)
        {          
            struct conn_data* p_conn_data=(struct conn_data*)malloc(sizeof(struct conn_data));


            p_conn_data->protocol=17;
            //if the server send packet
            if(sport==443){
                    p_conn_data->server_ip=srcname;
                    p_conn_data->server_port=sport;
                    p_conn_data->client_ip=dstname;
                    p_conn_data->client_port=dport;            
                    p_conn_data->conn_id=-1;  
                    //if it's data
                    if(size_packet>inbound_packets_in_range_min&&size_packet<inbound_packets_in_range_max )
                        {
                            is_range=1;
                            is_server=1;
                            insert(p_conn_data,is_range,is_server,apoch_time,size_packet);                            
                            fprintf(p_output_file,"1, %-20s, %-6hu, %-20s, %-6hu, %-3d,%-3d,%7d %d:%d \n",srcname,sport,dstname,dport, protocol_packet,size_packet,result, p_header_packet->ts.tv_sec, p_header_packet->ts.tv_usec);
                        }
                    else
                    {
                         is_range=0;
                         is_server=1;
                         insert(p_conn_data,is_range,is_server,apoch_time,size_packet);
                    }
            }
           else{
            //if the client send packet
                    p_conn_data->client_ip=srcname;
                    p_conn_data->server_ip=dstname;
                    p_conn_data->server_port=dport;
                    p_conn_data->client_port=sport;            
                    p_conn_data->conn_id=-1;
                    //if it's request
                    if(size_packet>request_packet_threshold){  
                         is_range=1;
                         is_server=0;         
                        insert(p_conn_data,is_range,is_server,apoch_time,size_packet);
                        fprintf(p_output_file,"1, %-20s, %-6hu, %-20s, %-6hu, %-3d, %-3d,%7d %d:%d \n",srcname,sport,dstname,dport, protocol_packet,size_packet,result, p_header_packet->ts.tv_sec, p_header_packet->ts.tv_usec);
}
                    else
                    {
                         is_range=0;
                         is_server=0;
                         insert(p_conn_data,is_range,is_server,apoch_time,size_packet);
                    }
               }
              // free(p_conn_data);
        }
       // free(srcname);
       // free(dstname);       
       // printf("seq number: %u ack number: %u \n", (unsigned int)tcp-> th_seq, (unsigned int)tcp->th_ack);
       // fprintf(p_output_file,"seq number: %u ack number: %u \n", (unsigned int)tcp-> th_seq, (unsigned int)tcp->th_ack);
      
    }

free_data();
    fclose (p_output_file);
    fclose(file);
     return(0);
}