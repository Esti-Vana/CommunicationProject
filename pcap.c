#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <json-c/json.h>
#include <limits.h>
#include <time.h>

#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6
#define BUDDER_ERR_SIZE 1024
#define BUFFER_SIZE 10000
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

int minimum_video_connection_size, request_packet_threshold, inbound_packets_in_range_min, inbound_packets_in_range_max;
int max_number_of_connections, max_number_of_transaction_per_video, video_connection_timeout;

FILE *p_videos_data_file;
FILE *p_output_file;
struct ConnDataItem **hashArray;
struct ConnDataItem *item;
int connection_id_index = 0, timer = -1;
// the list contains open connections funcs: printList, insertFirst, delete
struct node_conn_list *head = NULL;
struct node_conn_list *current = NULL;
struct video *p_video_data;
struct video
{
   int num_videos_watched, Sum_size_of_videos, Sum_number_of_TDRs;
};
struct conn_data
{
   char buffer[BUFFER_SIZE];
   int conn_id, protocol, len;
   char *server_ip, *client_ip;
   u_short server_port, client_port;
   int last_packet_time, conn_size;
};
struct Transaction_data
{
   int Transaction_id, num_outbound_packets_in_range, num_inbound_packets_in_range;
   long Start_time, Start_time_ms;

   int max_packet_size_inbound, min_packet_size_inbound;
   int max_diff_time_inbound, min_diff_time_inbound, last_packet_time, RTT_m, RTT_ms;
};
struct ConnDataItem
{

   struct conn_data *p_conn_data;
   struct Transaction_data *p_transaction_data;
   int key;
   struct ConnDataItem *next;
};
struct node_conn_list
{
   int hashIndex, conn_id;
   struct node_conn_list *next;
};
/* The ethernet header */
struct sniff_ethernet
{
   u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
   u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
   u_short ether_type;                 /* IP? ARP? RARP? etc */
};
/* IP header */
struct sniff_ip
{
   u_char ip_vhl;         /* version << 4 | header length >> 2 */
   u_char ip_tos;         /* type of service */
   u_short ip_len;        /* total length */
   u_short ip_id;         /* identification */
   u_short ip_off;        /* fragment offset field */
#define IP_RF 0x8000      /* reserved fragment flag */
#define IP_DF 0x4000      /* dont fragment flag */
#define IP_MF 0x2000      /* more fragments flag */
#define IP_OFFMASK 0x1fff /* mask for fragmenting bits */
   u_char ip_ttl;         /* time to live */
   u_char ip_p;           /* protocol */
   u_short ip_sum;        /* checksum */
   struct in_addr ip_src;
   struct in_addr ip_dst; /* source and dest address */
};
/* packet header*/
typedef struct packet_header
{
   u_short sport; // Source port
   u_short dport; // Destination port
   u_short len;   // Datagram length
   u_short crc;   // Checksum
} packet_header;

char *convert_apoch_time(long apoch_time)
{
   struct tm *newtime;
   char am_pm[] = "AM";
   long long_time = apoch_time;

   newtime = localtime(&long_time);
   if (newtime->tm_hour > 12)
      strcpy(am_pm, "PM");
   if (newtime->tm_hour > 12)
      newtime->tm_hour -= 12;
   if (newtime->tm_hour == 0)
      newtime->tm_hour = 12;
   char *buff = malloc(sizeof(char) * 50);
   if (buff == NULL)
   {
      printf("Allocation fault");
      exit(1);
   }
   sprintf(buff, "%.19s %s  %i", asctime(newtime), am_pm, 1900 + newtime->tm_year);
   return buff;
}
void insert_to_List(int hashIndex, int conn_id)
{
   // insert the connection insert at the beginning of the list
   struct node_conn_list *link = (struct node_conn_list *)malloc(sizeof(struct node_conn_list));
   if (link == NULL)
   {
      printf("Allocation fault");
      exit(1);
   }
   link->hashIndex = hashIndex;
   link->conn_id = conn_id;
   link->next = head;
   head = link;
}
struct node_conn_list *delete_connection_from_list(int conn_id)
{
   // Delete the connection when it is closed

   struct node_conn_list *current = head;
   struct node_conn_list *previous = NULL;
   if (head == NULL)
      return NULL;
   // navigate through list
   while (current->conn_id != conn_id)
   {
      // if it is last node
      if (current->next == NULL)
         return NULL;
      else
      {
         previous = current;
         current = current->next;
      }
   }
   // found a match, update the list
   if (current == head)
      head = head->next;
   else
      previous->next = current->next;
   return current;
}
int five_tuple_key(char *server_ip, char *client_ip, int protocol, u_short server_port, u_short client_port)
{
   // sum the numerical value of 5 tuples
   int result = atof(server_ip) + atof(client_ip) + protocol + (int)server_port + (int)client_port;
   int key = result % max_number_of_connections;
   return key;
}
int compare_five_tuples(struct conn_data *p1, struct conn_data *p2)
{
   if (strcmp(p1->client_ip, p2->client_ip) == 0 && strcmp(p1->server_ip, p2->server_ip) == 0 && p1->protocol == p2->protocol && p1->server_port == p2->server_port && p1->client_port == p2->client_port)
   {
      return 1;
   }
   if (strcmp(p1->client_ip, p2->server_ip) == 0 && strcmp(p1->server_ip, p2->client_ip) == 0 && p1->protocol == p2->protocol && p1->server_port == p2->client_port && p1->client_port == p2->server_port)
      return 1;
   return 0;
}
void write_to_buffer_transaction_data(struct Transaction_data *p_transaction_data, struct conn_data *p_conn_data)
{
   char *readable_time = convert_apoch_time(p_transaction_data->Start_time);
   // print the transaction data to the buffer of the connection.
   if (p_transaction_data->num_inbound_packets_in_range == 1)
      p_conn_data->len += sprintf(p_conn_data->buffer + p_conn_data->len, "%d, %d, %s, %d, %s, %hu, %s, %hu, %d, %d, 0, 0, 0, 0, 0 \n", p_conn_data->conn_id, p_transaction_data->Transaction_id, readable_time, p_transaction_data->num_inbound_packets_in_range, p_conn_data->server_ip, p_conn_data->server_port, p_conn_data->client_ip, p_conn_data->client_port, p_conn_data->protocol, p_transaction_data->num_outbound_packets_in_range);
   else
      p_conn_data->len += sprintf(p_conn_data->buffer + p_conn_data->len, "%d, %d, %s, %d, %s, %hu, %s, %hu, %d, %d,   %d, %d,%d,%d, %d.%d \n", p_conn_data->conn_id, p_transaction_data->Transaction_id, readable_time, p_transaction_data->num_inbound_packets_in_range, p_conn_data->server_ip, p_conn_data->server_port, p_conn_data->client_ip, p_conn_data->client_port, p_conn_data->protocol, p_transaction_data->num_outbound_packets_in_range, p_transaction_data->max_packet_size_inbound, p_transaction_data->min_packet_size_inbound, p_transaction_data->max_diff_time_inbound, p_transaction_data->min_diff_time_inbound, p_transaction_data->RTT_m, p_transaction_data->RTT_ms);
   free(readable_time);
}
void delete_connection_from_Hash(int hashIndex, int conn_id)
{
   int MBs = 1024 * 1024 * minimum_video_connection_size, is_head = 0;
   struct ConnDataItem *head = hashArray[hashIndex], *prev = NULL;
   // if there isn't this connection
   if (head == NULL)
      return NULL;
   // find the right connection
   while (head->p_conn_data->conn_id != conn_id)
   {
      if (head->next == NULL)
         return NULL;
      else
      {
         prev = head;
         head = head->next;
      }
   }
   // update the list in hashArray[hashIndex]. if the right connection is head
   if (head == hashArray[hashIndex])
      hashArray[hashIndex] = head->next;
   else
      prev->next = head->next;

   if (head->p_conn_data->conn_size >= MBs)
   {
      // send the last transation to write in bufer and dump all data to the file
      write_to_buffer_transaction_data(head->p_transaction_data, head->p_conn_data);
      fprintf(p_output_file, "%s", head->p_conn_data->buffer);
      fflush(p_output_file);
   }
   p_video_data->Sum_size_of_videos += head->p_conn_data->conn_size;
   free(head->p_conn_data->client_ip);
   free(head->p_conn_data->server_ip);
   free(head->p_transaction_data);
   free(head->p_conn_data);
   free(head);
}
void timer_delete_Inactive_connections(int arrival_time)
{
   struct node_conn_list *temp2 = head;
   struct ConnDataItem *temp3 = NULL;
   // go over all open connection list and find the connections that have not received packets
   while (temp2 != NULL)
   {
      temp3 = hashArray[temp2->hashIndex];
      while (temp3 != NULL)
      {
         if (temp3->p_conn_data->conn_id == temp2->conn_id && temp3->p_conn_data->last_packet_time < arrival_time - video_connection_timeout)
         {
            delete_connection_from_Hash(temp2->hashIndex, temp2->conn_id);
            delete_connection_from_list(temp2->conn_id);
         }
         temp3 = temp3->next;
      }
      temp2 = temp2->next;
   }
   timer = arrival_time;
}
void insert_packet_to_Hash(struct conn_data *p_conn_data, int in_range, int is_server, int arrival_time, int arrival_time_ms, int size_packet)
{
   int hashIndex, diff_time;
   // find the hasn number
   hashIndex = five_tuple_key(p_conn_data->server_ip, p_conn_data->client_ip, p_conn_data->protocol, p_conn_data->server_port, p_conn_data->client_port);

   // if pass video_connection_timeout
   if (timer < arrival_time - video_connection_timeout)
      timer_delete_Inactive_connections(arrival_time);

   struct ConnDataItem *temp = hashArray[hashIndex];
   // if its packet from server, or from client- but not request.
   if (in_range != 1 || is_server != 0)
   {
      while (temp != NULL)
      {
         if (compare_five_tuples(temp->p_conn_data, p_conn_data) == 1)
         {
            // if it's packet from client but less than request packet threshold
            if (in_range == 0 && is_server == 0)
               temp->p_transaction_data->num_outbound_packets_in_range++;
            // if it's packet from server in range- do statistics
            if (in_range == 1 && is_server == 1)
            {
               if (temp->p_transaction_data->num_inbound_packets_in_range == 1)
               {
                  temp->p_transaction_data->RTT_m = arrival_time - temp->p_transaction_data->Start_time;
                  temp->p_transaction_data->RTT_ms = arrival_time_ms - temp->p_transaction_data->Start_time_ms;
               }
               temp->p_conn_data->conn_size += size_packet;
               temp->p_transaction_data->num_inbound_packets_in_range++;

               if (size_packet > temp->p_transaction_data->max_packet_size_inbound)
               {
                  temp->p_transaction_data->max_packet_size_inbound = size_packet;
               }
               if (size_packet < temp->p_transaction_data->min_packet_size_inbound)
               {
                  temp->p_transaction_data->min_packet_size_inbound = size_packet;
               }
               diff_time = arrival_time - temp->p_transaction_data->last_packet_time;
               if (diff_time > temp->p_transaction_data->max_diff_time_inbound)
                  temp->p_transaction_data->max_diff_time_inbound = diff_time;

               if (diff_time < temp->p_transaction_data->min_diff_time_inbound)
                  temp->p_transaction_data->min_diff_time_inbound = diff_time;
               temp->p_transaction_data->last_packet_time = arrival_time;
            }
            break;
         }
         temp = temp->next;
      }
      // in any case update the last_packet_time of the connection
      if (temp != NULL)
         temp->p_conn_data->last_packet_time = arrival_time;
      free(p_conn_data);
      return;
   }
   // if request
   if (in_range == 1 && is_server == 0)
   {
      // if there is an open connection
      while (temp != NULL)
      {
         if (compare_five_tuples(temp->p_conn_data, p_conn_data) == 1)
         {
            write_to_buffer_transaction_data(temp->p_transaction_data, temp->p_conn_data);
            p_video_data->Sum_number_of_TDRs++;
            // init transaction data
            temp->p_transaction_data->Start_time = arrival_time;
            temp->p_transaction_data->Start_time_ms = arrival_time_ms;
            temp->p_transaction_data->Transaction_id++;
            temp->p_transaction_data->num_outbound_packets_in_range = 0;
            temp->p_transaction_data->num_inbound_packets_in_range = 1;
            temp->p_transaction_data->max_packet_size_inbound = -1;
            temp->p_transaction_data->min_packet_size_inbound = INT_MAX;
            temp->p_transaction_data->max_diff_time_inbound = -1;
            temp->p_transaction_data->min_diff_time_inbound = INT_MAX;
            temp->p_conn_data->last_packet_time = arrival_time;
            temp->p_transaction_data->last_packet_time = arrival_time;
            if (temp->p_transaction_data->Transaction_id == max_number_of_transaction_per_video)
            {
               delete_connection_from_Hash(temp->key, temp->p_conn_data->conn_id);
               delete_connection_from_list(temp->p_conn_data->conn_id);
            }
            return;
         }
         temp = temp->next;
      }

      // init connection data
      struct ConnDataItem *item;
      item = (struct ConnDataItem *)malloc(sizeof(struct ConnDataItem));
      if (item == NULL)
      {
         printf("Allocation fault");
         exit(1);
      }
      item->p_conn_data = p_conn_data;
      item->key = hashIndex;
      item->p_conn_data->conn_id = ++connection_id_index;
      item->p_transaction_data = (struct Transaction_data *)malloc(sizeof(struct Transaction_data));
      if (item->p_transaction_data == NULL)
      {
         printf("Allocation fault");
         exit(1);
      }
      item->p_transaction_data->Start_time = arrival_time;
      item->p_transaction_data->Start_time_ms = arrival_time_ms;
      item->p_transaction_data->Transaction_id = 1;
      item->p_transaction_data->num_outbound_packets_in_range = 0;
      item->p_transaction_data->num_inbound_packets_in_range = 1;
      item->p_transaction_data->max_packet_size_inbound = -1;
      item->p_transaction_data->min_packet_size_inbound = INT_MAX;
      item->p_conn_data->conn_size = 0;
      item->p_transaction_data->max_diff_time_inbound = -1;
      item->p_transaction_data->min_diff_time_inbound = INT_MAX;
      item->p_conn_data->last_packet_time = arrival_time;
      item->p_transaction_data->last_packet_time = arrival_time;
      item->p_conn_data->len = 0;
      p_video_data->num_videos_watched = connection_id_index;
      p_video_data->Sum_number_of_TDRs++;
      // insert the new connection to the list of open connections
      insert_to_List(hashIndex, item->p_conn_data->conn_id);
      // insert the new connection to the hash table
      if (temp != NULL)
      {
         while (temp->next != NULL)
         {
            temp = temp->next;
         }
         temp->next = item;
      }
      else
      {
         item->next = NULL;
         hashArray[hashIndex] = item;
      }
   }
}
void free_data()
{
   struct ConnDataItem *head, *prev = NULL;
   // go over the hash table and free the items that not null.
   for (size_t i = 0; i < max_number_of_connections; i++)
   {
      head = hashArray[i];
      // if there is some connection in the same index.
      while (head != NULL)
      {
         free(head->p_conn_data->server_ip);
         free(head->p_conn_data->client_ip);
         free(head->p_conn_data);
         free(head->p_transaction_data);
         prev = head->next;
         free(head);
         head = prev;
      }
      free(hashArray[i]);
   }
   free(p_video_data);
}
int main(int argc, char *argv[])
{
   // read data from config file.
   FILE *p_configFile;
   char buffer[BUDDER_ERR_SIZE];
   struct json_object *parsed_json, *j_request_packet_threshold, *j_inbound_packets_in_range_min, *j_inbound_packets_in_range_max;
   struct json_object *j_minimum_video_connection_size, *j_max_number_of_connections, *j_max_number_of_transaction_per_video, *j_video_connection_timeout;

   p_configFile = fopen("config.json", "r");
   fread(buffer, BUDDER_ERR_SIZE, 1, p_configFile);
   fclose(p_configFile);
   parsed_json = json_tokener_parse(buffer);
   json_object_object_get_ex(parsed_json, "request_packet_threshold", &j_request_packet_threshold);
   json_object_object_get_ex(parsed_json, "inbound_packets_in_range_min", &j_inbound_packets_in_range_min);
   json_object_object_get_ex(parsed_json, "inbound_packets_in_range_max", &j_inbound_packets_in_range_max);
   json_object_object_get_ex(parsed_json, "max_number_of_transaction_per_video", &j_max_number_of_transaction_per_video);
   json_object_object_get_ex(parsed_json, "video_connection_timeout", &j_video_connection_timeout);
   json_object_object_get_ex(parsed_json, "max_number_of_connections", &j_max_number_of_connections);
   json_object_object_get_ex(parsed_json, "minimum_video_connection_size", &j_minimum_video_connection_size);

   // put the values in the Global variables
   request_packet_threshold = json_object_get_int(j_request_packet_threshold);
   inbound_packets_in_range_min = json_object_get_int(j_inbound_packets_in_range_min);
   inbound_packets_in_range_max = json_object_get_int(j_inbound_packets_in_range_max);
   max_number_of_transaction_per_video = json_object_get_int(j_max_number_of_transaction_per_video);
   video_connection_timeout = json_object_get_int(j_video_connection_timeout);
   max_number_of_connections = json_object_get_int(j_max_number_of_connections);
   minimum_video_connection_size = json_object_get_int(j_minimum_video_connection_size);

   // read data from pcap file
   char errbuff[BUDDER_ERR_SIZE];
   pcap_t *p_pcapfile_data = pcap_open_offline("data.pcap", errbuff);
   hashArray = (struct ConnDataItem **)malloc(sizeof(struct ConnDataItem *) * max_number_of_connections);
   if (hashArray == NULL)
   {
      printf("Allocation fault");
      exit(1);
   }
   p_output_file = fopen("out-data.csv", "w");

   // open video data file and init Global variable
   p_videos_data_file = fopen("video-data.csv", "w");
   p_video_data = (struct video *)malloc(sizeof(struct video));
   if (p_video_data == NULL)
   {
      printf("Allocation fault");
      exit(1);
   }
   p_video_data->Sum_size_of_videos = 0;
   p_video_data->Sum_number_of_TDRs = 0;

   // headers
   struct sniff_ethernet *p_ethernet_header;
   struct sniff_ip *p_header_ip;
   struct pcap_pkthdr *p_header_packet;
   u_char *p_data_packet; // The actual packet
   u_int size_ip_header;
   u_short sport, dport;
   int protocol_packet, apoch_time_s, apoch_time_ms, is_server, in_range, size_packet, packetCount = 0, count_conn;
   char *ip_source, *ip_dest;

   fprintf(p_output_file, "Conn_id, Transaction_id, Start time, num_inbound_packets_in_range, server_ip, server_port, client_ip, client_port, protocol, num_outbound_packets_in_range, max_packet_size_inbound, min_packet_size_inbound,max_diff_time_inbound,min_diff_time_inbound,RTT\n");

   // go over all packets
   while (pcap_next_ex(p_pcapfile_data, &p_header_packet, &p_data_packet) >= 0)
   {
      printf("Packet # %i\n", ++packetCount);
      size_packet = p_header_packet->len;
      p_ethernet_header = (struct sniff_ethernet *)(p_data_packet);
      p_header_ip = (struct sniff_ip *)(p_data_packet + SIZE_ETHERNET);
      size_ip_header = IP_HL(p_header_ip) * 4;
      if (size_ip_header < 20)
      {
         printf(" ERROR: * Invalid IP header length: %u bytes\n", size_ip_header);
         continue;
      }
      packet_header *p_udp_header;
      p_udp_header = (packet_header *)(p_data_packet + SIZE_ETHERNET + size_ip_header);

      // rescue 5 tuples
      /* convert from network byte order to host byte order */
      sport = ntohs(p_udp_header->sport);
      dport = ntohs(p_udp_header->dport);
      ip_source = strdup(inet_ntoa(p_header_ip->ip_src));
      ip_dest = strdup(inet_ntoa(p_header_ip->ip_dst));
      if (ip_source == NULL || ip_dest == NULL)
      {
         printf("Allocation fault");
         exit(1);
      }
      protocol_packet = p_header_ip->ip_p;

      apoch_time_s = p_header_packet->ts.tv_sec;
      apoch_time_ms = p_header_packet->ts.tv_usec;

      // filter the packets
      if ((sport == 443 || dport == 443) && protocol_packet == 17)
      {
         struct conn_data *p_conn_data = (struct conn_data *)malloc(sizeof(struct conn_data));
         if (p_conn_data == NULL)
         {
            printf("Allocation fault");
            exit(1);
         }
         p_conn_data->protocol = 17;

         // if the server send the packet
         if (sport == 443)
         {
            p_conn_data->server_ip = ip_source;
            p_conn_data->server_port = sport;
            p_conn_data->client_ip = ip_dest;
            p_conn_data->client_port = dport;
            p_conn_data->conn_id = -2; // init number
            // if it's data
            if (size_packet > inbound_packets_in_range_min && size_packet < inbound_packets_in_range_max)
            {
               in_range = 1;
               is_server = 1;
               insert_packet_to_Hash(p_conn_data, in_range, is_server, apoch_time_s, apoch_time_ms, size_packet);
            }
            else
            {
               in_range = 0;
               is_server = 1;
               insert_packet_to_Hash(p_conn_data, in_range, is_server, apoch_time_s, apoch_time_ms, size_packet);
            }
         }
         else
         {
            // if the client send the packet
            p_conn_data->client_ip = ip_source;
            p_conn_data->client_port = sport;
            p_conn_data->server_ip = ip_dest;
            p_conn_data->server_port = dport;
            p_conn_data->conn_id = -2;
            // if it's request
            if (size_packet > request_packet_threshold)
            {
               in_range = 1;
               is_server = 0;
               insert_packet_to_Hash(p_conn_data, in_range, is_server, apoch_time_s, apoch_time_ms, size_packet);
            }
            else
            {
               in_range = 0;
               is_server = 0;
               insert_packet_to_Hash(p_conn_data, in_range, is_server, apoch_time_s, apoch_time_ms, size_packet);
            }
         }
      }
   }
   // Delete all connections that remain open
   struct node_conn_list *temp = head, *prev;
   while (temp != NULL)
   {
      delete_connection_from_Hash(temp->hashIndex, temp->conn_id);
      prev = delete_connection_from_list(temp->conn_id);
      temp = temp->next;
      free(prev);
   }

   // print the videos data to file
   fprintf(p_videos_data_file, "count videos, size of videos,average num TDRs\n");
   count_conn = p_video_data->num_videos_watched;
   fprintf(p_videos_data_file, "%d, %d, %d\n", count_conn, p_video_data->Sum_size_of_videos / count_conn, p_video_data->Sum_number_of_TDRs / count_conn);

   free_data();
   fclose(p_videos_data_file);
   fclose(p_output_file);
   return (0);
}
// functions for tests
void display_hash_table()
{
   int i = 0;
   struct ConnDataItem *head = hashArray[i];
   for (i = 0; i < max_number_of_connections; i++)
   {
      if (hashArray[i] != NULL)
      {
         head = hashArray[i];
         while (head != NULL)
         {
            printf(" (%d,%d,%d)", head->key, head->p_conn_data->conn_id, head->p_transaction_data->num_inbound_packets_in_range);
            head = head->next;
         }
      }
      else
         printf(" ~~ ");
   }
   printf("\n");
}
void printList()
{
   struct node_conn_list *ptr = head;

   // start from the beginning
   while (ptr != NULL)
   {
      printf("(%d, %d) ", ptr->hashIndex, ptr->conn_id);
      ptr = ptr->next;
   }
   printf(" ]");
}