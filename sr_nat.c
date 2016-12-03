#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include "sr_utils.h"


int sr_nat_init(struct sr_nat *nat, struct sr_nat_timeout_s setting) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  /* Initialize any variables here */
  /*struct in_addr external;
  struct in_addr internal;
  inet_pton(AF_INET, "172.64.3.1", &(external));
  inet_pton(AF_INET, "10.0.1.11", &(internal));

  nat->ext_ip = external.s_addr;
  nat->int_ip = internal.s_addr;*/
  nat->setting = setting;



  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */
  if (nat){

    /* initial pointer for mappings and conns*/
    struct sr_nat_mapping *mapping = nat->mappings;
    struct sr_nat_mapping *curr_mapping;

    struct sr_nat_connection *conn;
    struct sr_nat_connection *curr_conn;

    /* free all the mappings */ 
    while (mapping != NULL){
      curr_mapping = mapping;

      conn = mapping->conns;
      /* free all the conns in mapping */
      while (conn != NULL){
        curr_conn = conn;
        conn = conn->next;
        free(curr_conn);
      }

      mapping = mapping->next;
      free(curr_mapping);

    } 
  }


  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */
    struct sr_nat_mapping *mapping = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
    struct sr_nat_mapping *curr;
    mapping->next = nat->mappings;
    nat->mappings = mapping;


    struct sr_nat_connection *conn = (struct sr_nat_connection *)malloc(sizeof(struct sr_nat_connection));
    struct sr_nat_connection *curr_conn;

    while (nat->mappings->next != NULL){
      /* case that mapping is ICMP */
      if (nat->mappings->next->type == nat_mapping_icmp){

        if (difftime(curtime, nat->mappings->next->last_updated) >= nat->setting.ICMP_timeout){
          nat->mappings->next = nat->mappings->next->next;
          curr = nat->mappings->next;
          free(curr);
        }
        else{
          nat->mappings = nat->mappings->next;
        }
      }

      /* case for TCP */
      else{
        conn->next = nat->mappings->next->conns;
        nat->mappings->next->conns->next = conn;
        while (nat->mappings->next->conns->next != NULL){

          /* TCP Established State */
          if (nat->mappings->next->conns->next->state == ESTABLISHED){
            if (difftime(curtime, nat->mappings->next->conns->next->last_updated) >= nat->setting.TCP_Est_timeout){
              nat->mappings->next->conns->next = nat->mappings->next->conns->next->next;
              curr_conn = nat->mappings->next->conns->next;
              free(curr_conn);
            }
          }

          /* In other state */
          else{
            if (difftime(curtime, nat->mappings->next->conns->next->last_updated) >= nat->setting.TCP_Tran_timeout){
              nat->mappings->next->conns->next = nat->mappings->next->conns->next->next;
              curr_conn = nat->mappings->next->conns->next;
              free(curr_conn);
            }
          } 
        }

        /* if there are still some TCP working */
        if (conn->next != NULL){
          nat->mappings->next->conns = conn->next;
        }

        /* if all TCP timeout, removing the mapping */
        else{
          nat->mappings->next = nat->mappings->next->next;
          curr = nat->mappings->next;
          free(curr);
        }
      }
    }

    nat->mappings = mapping->next;
    free(mapping);
    free(conn);

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type,
    uint32_t source_ip, uint16_t source_port, int ack, int syn, int fin) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *mapping = NULL;

  time_t curtime = time(NULL);

  /* if type is ICMP, No need to look up TCP */
  if (type == nat_mapping_icmp){

    for(mapping = nat->mappings; mapping != NULL; mapping = mapping->next){
      if (mapping->aux_ext == aux_ext && mapping->type == type){
        copy = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
        memcpy(copy, mapping, sizeof(struct sr_nat_mapping)); 
      }
    }
  }

  /* similar case as internal */
  else{

    struct sr_nat_connection* connection = NULL;

    /* find right mapping */
    for(mapping = nat->mappings; mapping != NULL; mapping = mapping->next){
      if (mapping->aux_ext == aux_ext && mapping->type == type){
        copy = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
        memcpy(copy, mapping, sizeof(struct sr_nat_mapping)); 

        /* find right connection */
        for (connection = mapping->conns; connection != NULL; connection = connection->next){
          if (connection->target_ip == source_ip && connection->target_port == source_port){
            /* update it */
            sr_nat_update_connection_ext(connection, ack, syn, fin, curtime);
          }

        }
      }
    }

  }


  if(copy != NULL)
  printf("lookup_external: int port %d, ext port %d\n", ntohs(copy->aux_int), ntohs(aux_ext));


  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type,
  uint32_t target_ip, uint16_t target_port, int ack, int syn, int fin) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *mapping = NULL;

  time_t curtime = time(NULL);

  /* if type is ICMP, No need to look up TCP */
  if (type == nat_mapping_icmp){

    for(mapping = nat->mappings; mapping != NULL; mapping = mapping->next){
      if (mapping->ip_int == ip_int && mapping->aux_int == aux_int && mapping->type == type){
        copy = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
        memcpy(copy, mapping, sizeof(struct sr_nat_mapping)); 
      }
    }    
  }

  /* if type is TCP, Need to look up conns */
  else{

    struct sr_nat_connection* connection = NULL;
    int flag_check = 0;

    /* find right mapping */
    for(mapping = nat->mappings; mapping != NULL; mapping = mapping->next){
      if (mapping->ip_int == ip_int && mapping->aux_int == aux_int && mapping->type == type){
        copy = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
        memcpy(copy, mapping, sizeof(struct sr_nat_mapping)); 

        /* find right connection and update it*/
        for (connection = mapping->conns; connection != NULL; connection = connection->next){
          if (connection->target_ip == target_ip && connection->target_port == target_port){
            flag_check = 1;
            sr_nat_update_connection_int(connection, ack, syn, fin, curtime);
          }
        }

        /* if we have the mapping, but not the conn, create a connection and update it */
        if (flag_check == 0){
          connection = sr_create_connection(target_ip, target_port, curtime);

          /* set it at the front */
          connection->next = mapping->conns;
          mapping->conns = connection;

          /*update it */
          sr_nat_update_connection_int(connection, ack, syn, fin, curtime);

        }

      }
    }
  }
  

  if(copy != NULL)
  printf("lookup_internal: int port %d, ext port %d\n", ntohs(aux_int), ntohs(copy->aux_ext));


  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_instance* sr, struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type,
  uint32_t target_ip, uint16_t target_port, int ack, int syn, int fin ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));

  time_t curtime = time(NULL);
  mapping->type = type;
  mapping->ip_int = ip_int;
  /*mapping->ip_ext = nat->ext_ip;*/
  mapping->ip_ext = sr_get_interface(sr, "eth2")->ip;
  mapping->aux_int = aux_int;
  mapping->last_updated = curtime;

  /* look for unused port */
  struct sr_nat_mapping *temp_mapping;
  uint16_t port = 1024;

  while (1){

    for (temp_mapping = nat->mappings; temp_mapping != NULL; temp_mapping = temp_mapping->next){
      if (port == temp_mapping->aux_ext){
        port += 1;
        break;
      }
    }

    if (temp_mapping == NULL){
      break;
    }
  } 
  
  mapping->aux_ext = port;
  

  /* set up conns for Case ICMP or TCP*/
  if (type == nat_mapping_icmp){
    mapping->conns = NULL;
  }

  else{
    mapping->conns = sr_create_connection(target_ip, target_port, curtime);
    sr_nat_update_connection_int(mapping->conns, ack, syn, fin, curtime);
  }

  
  /* put back to nat->mappings */
  mapping->next = nat->mappings;
  nat->mappings = mapping;

  /* make a copy to return */
  struct sr_nat_mapping *copy = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
  memcpy(copy, mapping, sizeof(struct sr_nat_mapping));

  printf("nat_insert: int port %d, ext port %d\n", ntohs(mapping->aux_int), ntohs(mapping->aux_ext));

  pthread_mutex_unlock(&(nat->lock));

  return copy;
}


/* create a new connection */
struct sr_nat_connection* sr_create_connection(uint32_t target_ip,
 uint16_t target_port, time_t last_updated){

  struct sr_nat_connection* new_conn;
  new_conn = (struct sr_nat_connection *)malloc(sizeof(struct sr_nat_connection));

  new_conn->target_ip = target_ip;
  new_conn->target_port = target_port;
  new_conn->last_updated = last_updated;
  new_conn->state = LISTEN;

  return new_conn;

}

void sr_nat_update_connection_ext(struct sr_nat_connection *conn, int ack, int syn, int fin, time_t last_updated){
  /* case 010 */
  if ((!ack) && syn && (!fin)){
    conn->state = SYN_RECEIVED;
  }

  /* case 100 and previous state is SYN_RCVD */
  else if (ack && (!syn) && (!fin) && (conn->state == SYN_RECEIVED)){
    conn->state = ESTABLISHED;
  }

  /* case 001 and ESTABLISHED */
  else if (!ack && !syn && fin && (conn->state == ESTABLISHED)){
    conn->state = CLOSE_WAIT;
  }

  /* case 101 and FIN_WAIT_1 */
  else if (ack && !syn && fin && (conn->state == FIN_WAIT_1)){
    conn->state = FIN_WAIT_2;
  }

  /* case 001 and FIN_WAIT_1 */
  else if (!ack && !syn && fin && (conn->state == FIN_WAIT_1)){
    conn->state = CLOSING;
  }

  /* case 100 and CLOSING */
  else if (ack && !syn && !fin && (conn->state == CLOSING)){
    conn->state = TIME_WAIT;
  }

  /* case 001 and FIN_WAIT_2 */
  else if (!ack && !syn && fin && (conn->state == FIN_WAIT_2)){
    conn->state = TIME_WAIT;
  }

  /* case 100 and LAST_ACK */
  else if (ack && !syn && !fin && (conn->state == LAST_ACK)){
    conn->state = CLOSED;
  }

  conn->last_updated = last_updated;
}

void sr_nat_update_connection_int(struct sr_nat_connection *conn, int ack, int syn, int fin, time_t last_updated){

  /* case 010 */
  if ((!ack) && syn && (!fin)){
    conn->state = SYN_SENT;
  }

  /* case 100 and previous state is SYN_SENT */
  else if (ack && (!syn) && (!fin) && (conn->state == SYN_SENT)){
    conn->state = ESTABLISHED;
  }

  /* case 001 and SYN_RECEIVED */
  else if (!ack && !syn && fin && (conn->state == SYN_RECEIVED)){
    conn->state = FIN_WAIT_1;
  }

  /* case 001 and ESTABLISHED */
  else if (!ack && !syn && fin && (conn->state == ESTABLISHED)){
    conn->state = FIN_WAIT_1;
  }

  /* case 101 and FIN_WAIT_1 */
  else if (ack && !syn && fin && (conn->state == ESTABLISHED)){
    conn->state = CLOSE_WAIT;
  }

  /* case 001 and CLOSING */
  else if (!ack && !syn && fin && (conn->state == CLOSE_WAIT)){
    conn->state = LAST_ACK;
  }

  /* case 100 and FIN_WAIT_1 */
  else if (ack && !syn && !fin && (conn->state == FIN_WAIT_1)){
    conn->state = CLOSING;
  }

  /* case 100 and TIME_WAIT */
  else if (ack && !syn && !fin && (conn->state == FIN_WAIT_2)){
    conn->state = TIME_WAIT;
  }

  conn->last_updated = last_updated;
}

