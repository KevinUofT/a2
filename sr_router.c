/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h> 
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_nat.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

static int enable_nat = 0;
const char eth1[32] = "eth1";
const char eth2[32] = "eth2";

void sr_init(struct sr_instance* sr, 
        int flag,  
        struct sr_nat_timeout_s setting)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */
    if (flag){
      if (sr_nat_init(&(sr->nat), setting) != 0){
        fprintf(stderr,"Error setting up NAT\n");
        exit(1);
      }

      enable_nat = 1;
    }
    

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);

    /* fill in code here */
    
    /* Error checking: the minimum length of ethernet frame */
    if ( len < sizeof(sr_ethernet_hdr_t) ){
        fprintf(stderr , "** Error: packet is wayy to short \n");
        return;
    }

    uint16_t frametype = ethertype(packet);
    /* if the packet is arp packet */
    if (frametype == ethertype_arp){
      sr_handle_arppacket(sr, packet, len, interface);
    }

    /* if the packet is ip packet */
    if (frametype == ethertype_ip){
      sr_handle_ippacket(sr, packet, len, interface);
    }



}/* end sr_ForwardPacket */



int sr_handle_arppacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{

    /* Error checking: the minimum length of ARP packet */   
    if ( len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t) ){
        fprintf(stderr , "** Error: packet is wayy to short \n");
        return -1;
    }

    /* set up header */
    sr_ethernet_hdr_t *e_hdr = (sr_ethernet_hdr_t *)(packet);
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    assert(e_hdr);
    assert(arp_hdr);

    struct sr_if* if_list;
    struct sr_arpreq* arpreq_temp;
    struct sr_packet* packet_temp;

    /* receive Interface information, and check whether the message is to me */
    if ((if_list = sr_get_interface(sr, interface)) == 0) {
      fprintf(stderr , "** Error: Interface problem \n");
      return -1;
    }

    /* if the ARP packet is not for me, just ignore this packet, return -1 */
    if (if_list->ip != arp_hdr->ar_tip) {
      fprintf(stderr , "** Ingore: the ARP packet is not for us \n"); 
      return -1;
    }


    /* if this is an arp reply */
    if (arp_hdr->ar_op == htons(arp_op_reply)){

      /* Cache the arp reply, go through my request queue */
      arpreq_temp = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);

      /* send outstanding packets */
      if (arpreq_temp != NULL){

        packet_temp = arpreq_temp->packets;

        while (1){

          /* substitute Request Queue packet's information with ARP Reply information */

          /* set up header */
          sr_ethernet_hdr_t *buf_hdr = (sr_ethernet_hdr_t *)(packet_temp->buf);
          sr_ip_hdr_t *buf_iphdr = (sr_ip_hdr_t *)(packet_temp->buf + sizeof(sr_ethernet_hdr_t));

          /* recheck interface */
          if_list = sr_get_interface(sr, packet_temp->iface);
          assert(if_list);

          /* set up Ethernet header */
          memcpy(buf_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
          memcpy(buf_hdr->ether_shost, if_list->addr, ETHER_ADDR_LEN);

          /* set up IP header */
          buf_iphdr->ip_ttl--;
          buf_iphdr->ip_sum = buf_iphdr->ip_sum >> 16;

          buf_iphdr->ip_sum = cksum(buf_iphdr, sizeof(sr_ip_hdr_t));

          sr_send_packet(sr, packet_temp->buf, packet_temp->len, packet_temp->iface);

          if (packet_temp->next == NULL){
            break;
          }

          packet_temp = packet_temp->next; 
        }

        sr_arpreq_destroy(&(sr->cache), arpreq_temp);

      }
      return 0;
    }

    /* if this is an arp request */
    else{

      /* Construct an ARP Reply and Send it back */

      /* set arp header */ 
      arp_hdr->ar_tip = arp_hdr->ar_sip;
      arp_hdr->ar_sip = if_list->ip;
      arp_hdr->ar_op = htons(arp_op_reply);
      memcpy(arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
      memcpy(arp_hdr->ar_sha, if_list->addr, ETHER_ADDR_LEN);

      /* set ethernet header */
      memcpy(e_hdr->ether_dhost, e_hdr->ether_shost, ETHER_ADDR_LEN);
      memcpy(e_hdr->ether_shost, if_list->addr, ETHER_ADDR_LEN);


      sr_send_packet(sr, packet, len, interface); 
      return 0;
    }

}



int sr_handle_ippacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{

    /* Error checking: the minimum length of IP packet */
    if ( len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) ){
        fprintf(stderr , "** Error: packet is wayy to short \n");
        return -1;
    }

    sr_ethernet_hdr_t *e_hdr = (sr_ethernet_hdr_t *)(packet);
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t *)(packet
         + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /* Error checking: using checksum to check whether there is error bits */
    if (cksum(ip_hdr, sizeof(sr_ip_hdr_t)) != 0xffff){
      fprintf(stderr , "** Error: ippacket cksum fatal\n");
      return -1;
    }



    /*check each interface, see whether the packet is to me */
    struct sr_if *iface;
    int flag = 0;
    int nat_reply_special_mark = 0;

    for (iface = sr->if_list; iface != NULL; iface = iface->next){
      if (ip_hdr->ip_dst == iface->ip) {
        flag = 1;
        
        /* If it is a ICMP echo reply, only available WHEN NAT is function */
        if (enable_nat && (icmp_hdr->icmp_type == 0)){
          /* if the case is reply, meaning forward it, similar to case not for me */
          flag = 0;
          nat_reply_special_mark = 1;
        }
        break;
      }
    }
    
    struct sr_if* if_list;
    if_list = sr_get_interface(sr, interface);

    /* If the packet is for me */
    if (flag == 1){
      
      /* If the packet is ICMP */
      if (ip_hdr->ip_p == ip_protocol_icmp){

        /* Sanity-check */
        if ( len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) +
        sizeof(sr_icmp_hdr_t) ){
          fprintf(stderr , "** Error: packet is wayy to short \n");
          return -1;
        }
      
        /* Error checking: using checksum to check whether there is error bits */
        if (cksum(icmp_hdr, len - sizeof(struct sr_ethernet_hdr) - 
              sizeof(struct sr_ip_hdr)) != 0xffff){
          fprintf(stderr , "** Error: Echo reply cksum fatal\n");
          return -1;
        }

        /* If it is ICMP echo req, send echo reply */
        if (icmp_hdr->icmp_type == 8){

          /* Create a copy */

          uint8_t* new_packet;
          new_packet = sr_copy_packet(packet, len);

          /* Headers */

          sr_ethernet_hdr_t *new_e_hdr = (sr_ethernet_hdr_t *)(new_packet);
          sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
          sr_icmp_hdr_t* new_icmp_hrd = (sr_icmp_hdr_t *)(new_packet 
            + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

          /* Using Routing Table to Recheck */

          struct sr_rt* rtable;
          rtable = sr_helper_rtable(sr, ip_hdr->ip_src);    

          int eth2_flag = 0;
          /* if Nat is enable */
          if (enable_nat){

            sr_icmp_t8_hdr_t* new_icmp_hrd_t8 = (sr_icmp_t8_hdr_t *)(new_packet 
            + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

            /* if message is coming from internal host -> send reply back to host */
            if (strncmp(eth1, interface, 5) == 0){

              /* Set up rest IP Header */
              new_ip_hdr->ip_ttl = 0xff;
              new_ip_hdr->ip_p = ip_protocol_icmp;
              new_ip_hdr->ip_sum = new_ip_hdr->ip_sum >> 16;
              new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

              /* Set up ICMP Header */
              new_icmp_hrd_t8->icmp_type = 0;
              new_icmp_hrd_t8->icmp_sum = new_icmp_hrd_t8->icmp_sum >> 16;
              new_icmp_hrd_t8->icmp_sum = cksum(new_icmp_hrd_t8, len - sizeof(struct sr_ethernet_hdr) - 
                sizeof(struct sr_ip_hdr));

            }

            /* if message is coming from external host */
            if (strncmp(eth2, interface, 5) == 0){
              
              /* check mapping */
              struct sr_nat_mapping* mapping;
              mapping = sr_nat_lookup_external(&(sr->nat), new_icmp_hrd_t8->port, nat_mapping_icmp);

              /* Hit */
              if (mapping != NULL){

                /* aiming host ip */
                rtable = sr_helper_rtable(sr, mapping->ip_int);

                /* Set up IP Header */
                new_ip_hdr->ip_dst = mapping->ip_int;
                new_ip_hdr->ip_ttl--;
                new_ip_hdr->ip_p = ip_protocol_icmp;
                new_ip_hdr->ip_sum = new_ip_hdr->ip_sum >> 16;
                new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

                /* Set up ICMP Header */
                new_icmp_hrd_t8->port = mapping->aux_int;
                new_icmp_hrd_t8->icmp_sum = new_icmp_hrd_t8->icmp_sum >> 16;
                new_icmp_hrd_t8->icmp_sum = cksum(new_icmp_hrd_t8, len - sizeof(struct sr_ethernet_hdr) - 
                  sizeof(struct sr_ip_hdr));
              }

              /* Missed -> send reply ?*/

              else{

                eth2_flag = 1;

                /* Set up rest IP Header */
                new_ip_hdr->ip_ttl = 0xff;
                new_ip_hdr->ip_p = ip_protocol_icmp;
                new_ip_hdr->ip_sum = new_ip_hdr->ip_sum >> 16;
                new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

                /* Set up ICMP Header */
                new_icmp_hrd_t8->icmp_type = 0;
                new_icmp_hrd_t8->icmp_sum = new_icmp_hrd_t8->icmp_sum >> 16;
                new_icmp_hrd_t8->icmp_sum = cksum(new_icmp_hrd_t8, len - sizeof(struct sr_ethernet_hdr) - 
                  sizeof(struct sr_ip_hdr));

              }

            free(mapping);
            }


          }

          /* if Nat is disable, or keep original functionality */
          if ((enable_nat == 0) || (strncmp(eth1, interface, 5) == 0) || (eth2_flag == 1) ){

            /* Set up IP Header */
            uint32_t ip_dest = new_ip_hdr->ip_dst;
            new_ip_hdr->ip_dst = new_ip_hdr->ip_src;
            new_ip_hdr->ip_src = ip_dest;
          }

          if (rtable->gw.s_addr){

            /* Update Interface */
            if_list = sr_get_interface(sr, rtable->interface);


            /* if Nat is disable, or keep original functionality */
            if (enable_nat == 0){

              /* Set up rest IP Header */
              new_ip_hdr->ip_ttl = 0xff;
              new_ip_hdr->ip_p = ip_protocol_icmp;
              new_ip_hdr->ip_sum = new_ip_hdr->ip_sum >> 16;
              new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));
        
              /* Set up ICMP Header */
              new_icmp_hrd->icmp_type = 0;
              new_icmp_hrd->icmp_sum = new_icmp_hrd->icmp_sum >> 16;
              new_icmp_hrd->icmp_sum = cksum(new_icmp_hrd, len - sizeof(struct sr_ethernet_hdr) - 
                sizeof(struct sr_ip_hdr));
            }
            

            /* Check Cache */
            struct sr_arpentry * entry;
            entry = sr_arpcache_lookup(&(sr->cache), rtable->gw.s_addr);

            /* Hit */
            if (entry){
              
              /* Set up Ethernet Header */
              memcpy(new_e_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
              memcpy(new_e_hdr->ether_shost, if_list->addr, ETHER_ADDR_LEN);

              /* send icmp echo reply packet */
              /*
              printf("Send packet:\n");
              print_hdrs(new_packet, len);
              */
              sr_send_packet(sr, new_packet, len, rtable->interface);
            }

            /* Miss */
            else{
              uint8_t *arp_packet = sr_create_arppacket(if_list->addr, if_list->ip, rtable->gw.s_addr);
              sr_send_packet(sr, arp_packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr), rtable->interface);
              sr_arpcache_queuereq(&(sr->cache), rtable->gw.s_addr, new_packet, len, rtable->interface);
            }
         
          }
          
          free(rtable);
          free(new_packet);
        }
      }


      /* if it is TCP/UDP, send ICMP port unreachable */
      else if ((ip_hdr->ip_p == 0x0006) || (ip_hdr->ip_p == 0x0011)){
        
        /* Sanity-check */
        if ( len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)){
          fprintf(stderr , "** Error: packet is wayy to short \n");
          return -1;
        }
        /* Port unreachable (type 3, code 3) */
        sr_handle_unreachable(sr, packet, interface, 3, 3);
      }
    }

   


    /* if the packet is not for me */
    else{

      /* Error checking: whether the IP packet has time out, 
      and if it is time out, send an ICMP message to sources IP*/
      if (ip_hdr->ip_ttl <= 1){
        fprintf(stderr , "** Error: ippacket time out\n");

        /* Time exceeded (type 11, code 0) */
        sr_handle_unreachable(sr, packet, interface, 11, 0);
      }

      /* checking routing table, perform LPM */
      struct sr_rt* rtable;


      if (nat_reply_special_mark && (strncmp(interface, eth2, 5)==0) ){
        /* from outside to inside, special case */

        sr_icmp_t8_hdr_t* icmp_hrd_t8 = (sr_icmp_t8_hdr_t *)(packet 
            + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      
        /* check mapping */
        struct sr_nat_mapping* mapping;
        mapping = sr_nat_lookup_external(&(sr->nat), icmp_hrd_t8->port, nat_mapping_icmp);

        if (mapping != NULL){
          rtable = sr_helper_rtable(sr, mapping->ip_int); 
        }

        /*free(mapping);*/
      }

      else{
        rtable = sr_helper_rtable(sr, ip_hdr->ip_dst);
      }
     

      /* if not match, provide ICMP net unreachable */
      if (!rtable->gw.s_addr){

        /* Destination net unreachable (type 3, code 0) */
        sr_handle_unreachable(sr, packet, interface, 3, 0);
      }


      /* if match, check ARP cache */
      else{

        struct sr_arpentry* entry;

        /* get new interface */
        if_list = sr_get_interface(sr, rtable->interface);


        /* if NAT on function*/
        if (enable_nat){

          sr_icmp_t8_hdr_t* icmp_hrd_t8 = (sr_icmp_t8_hdr_t *)(packet 
            + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

          
          /* from inside to outside */
          if (strncmp(interface, eth1, 5)==0){

            /* checking the nat mapping table*/
            struct sr_nat_mapping* mapping;
            mapping = sr_nat_lookup_internal(&(sr->nat), ip_hdr->ip_src, icmp_hrd_t8->port, nat_mapping_icmp);

            /* not found, create a new mapping */
            if (mapping == NULL){
              mapping = sr_nat_insert_mapping(&(sr->nat), ip_hdr->ip_src, icmp_hrd_t8->port, nat_mapping_icmp);
            }

            /* update ip_src to eth2 interface ip */
            ip_hdr->ip_src = if_list->ip;

            /* update icmp t8 header */
            icmp_hrd_t8->port = mapping->aux_ext;
            icmp_hrd_t8->icmp_sum = icmp_hrd_t8->icmp_sum >> 16;
            icmp_hrd_t8->icmp_sum = cksum(icmp_hrd_t8, len - sizeof(struct sr_ethernet_hdr) - 
              sizeof(struct sr_ip_hdr));

            /*free(mapping);*/

          }

          /* dst to me */
          if (nat_reply_special_mark){

            /* from outside to inside, it is a reply, give to internal hosts */
            if (strncmp(interface, eth2, 5)==0){

              /* check mapping */
              struct sr_nat_mapping* mapping;
              mapping = sr_nat_lookup_external(&(sr->nat), icmp_hrd_t8->port, nat_mapping_icmp);

              if (mapping != NULL){

                /* Set up IP Header */
                ip_hdr->ip_dst = mapping->ip_int;

                /* Set up ICMP Header */
                icmp_hrd_t8->port = mapping->aux_int;
                icmp_hrd_t8->icmp_sum = icmp_hrd_t8->icmp_sum >> 16;
                icmp_hrd_t8->icmp_sum = cksum(icmp_hrd_t8, len - sizeof(struct sr_ethernet_hdr) - 
                  sizeof(struct sr_ip_hdr));
              }

              /* case not Mapping is fit, send unreachable? */
              else{
                /* Port unreachable (type 3, code 3) */
                sr_handle_unreachable(sr, packet, interface, 3, 3);
              }

              free(mapping);
            }
          }

          /* dst not to me */
          else{
            /* from outside to inside, doesnt exist this case, send unreachable */
            if (strncmp(interface, eth2, 5)==0){

              /* Port unreachable (type 3, code 3) */
              sr_handle_unreachable(sr, packet, interface, 3, 3);

            }

          }
          
        }

        /* if Hit, Send */
        if ((entry = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst)) != NULL){

          /* setup Ip Header */
          ip_hdr->ip_ttl--;
          ip_hdr->ip_sum = ip_hdr->ip_sum >> 16;
          ip_hdr->ip_sum = cksum(ip_hdr, 4*(ip_hdr->ip_hl));

          /* set up Etherent header */
          memcpy(e_hdr->ether_shost, if_list->addr, ETHER_ADDR_LEN);
          memcpy(e_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);

          sr_send_packet(sr, packet, len, if_list->name); 
          free(entry);

        }

        /*if Miss */
        else{
          sr_arpcache_queuereq(&(sr->cache), rtable->gw.s_addr, packet, len, rtable->interface);
        
        }
      }

      free(rtable);
    }

  return 0;
}

/* create an new packet using incoming packet */
uint8_t* sr_copy_packet(uint8_t* packet, unsigned int len){

  uint8_t * new_packet = (uint8_t *)malloc(len);
  memcpy(new_packet, packet, len);

  return new_packet;
}
/* Handle Unreachable Case */
void sr_handle_unreachable(struct sr_instance* sr,
            uint8_t * packet,
            char* interface,
            uint8_t icmp_type,
            uint8_t icmp_code){

  /* init length */
  unsigned int total_len = sizeof(sr_ethernet_hdr_t)
   + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);

  /* malloc new space for the new packet and copy the information from an IP to it */
  uint8_t * new_packet = (uint8_t *)malloc(total_len);
  memcpy(new_packet, packet, sizeof(sr_ethernet_hdr_t)
   + sizeof(sr_ip_hdr_t));

  /*set up all the header*/
  sr_ethernet_hdr_t *new_e_hdr = (sr_ethernet_hdr_t *)(new_packet);
  sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t* new_icmp_hrd_t3 = (sr_icmp_t3_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t)
   + sizeof(sr_ip_hdr_t));

  /* Check interface */
  struct sr_if* if_list;
  if_list = sr_get_interface(sr, interface);

  struct sr_if* iface;
  for (iface = sr->if_list; iface != NULL; iface = iface->next){
    if(iface->ip == new_ip_hdr->ip_src){
      return;
    }
  }

  /* set up ethernet necessary information */
  new_e_hdr->ether_type = htons(ethertype_ip);
  memcpy(new_e_hdr->ether_dhost, new_e_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(new_e_hdr->ether_shost, if_list->addr, ETHER_ADDR_LEN);

  /* set up ip necessary information */

  if ((icmp_type == 3) && (icmp_code == 3)){
    uint32_t temp_store = new_ip_hdr->ip_dst;

    new_ip_hdr->ip_dst = new_ip_hdr->ip_src;
    new_ip_hdr->ip_src = temp_store;

  }

  else{
    new_ip_hdr->ip_dst = new_ip_hdr->ip_src;
    new_ip_hdr->ip_src = if_list->ip;
  }

  new_ip_hdr->ip_p = ip_protocol_icmp;
  new_ip_hdr->ip_ttl = 0xff;  

  /* make a ip checksum */
  new_ip_hdr->ip_sum = new_ip_hdr->ip_sum >> 16;
  new_ip_hdr->ip_sum = cksum(new_ip_hdr, 4*(new_ip_hdr->ip_hl)); 

  /* set up icmp necessary information */
  new_icmp_hrd_t3->icmp_type = icmp_type;
  new_icmp_hrd_t3->icmp_code = icmp_code;
  memcpy(new_icmp_hrd_t3->data, packet + sizeof(struct sr_ethernet_hdr), ICMP_DATA_SIZE);

  new_icmp_hrd_t3->icmp_sum = new_icmp_hrd_t3->icmp_sum >> 16;
  new_icmp_hrd_t3->icmp_sum = cksum(new_icmp_hrd_t3, sizeof(sr_icmp_t3_hdr_t)); 

  /* send ICMP out */
  sr_send_packet(sr, new_packet, total_len, interface);
  free(new_packet);
  
}

/* routing table helper, to get the mask number in order to provide LPM */
struct sr_rt *sr_helper_rtable(struct sr_instance* sr, uint32_t ip)
{

  struct sr_rt *rtable = (struct sr_rt *)malloc(sizeof(struct sr_rt));
  rtable->gw.s_addr = 0;
  rtable->mask.s_addr = 0;

  struct sr_rt *rt;
  for (rt = sr->routing_table; rt != NULL; rt = rt->next) {
    if (((ip & rt->mask.s_addr) == rt->dest.s_addr) && 
        (rt->mask.s_addr > rtable->mask.s_addr)) {
      memcpy(rtable, rt, sizeof(struct sr_rt));      
    }
  }

  return rtable;
} 
