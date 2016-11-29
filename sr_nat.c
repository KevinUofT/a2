#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>



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
  struct in_addr external;
  struct in_addr internal;
  inet_pton(AF_INET, "172.64.3.1", &(external));
  inet_pton(AF_INET, "10.0.1.11", &(internal));

  nat->ext_ip = external.s_addr;
  nat->int_ip = internal.s_addr;
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

    struct sr_nat_connection *conn = mapping->conns;
    struct sr_nat_connection *curr_conn;

    /* free all the mappings */ 
    while (mapping != NULL){
      curr_mapping = mapping;

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
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *mapping = NULL;

  for(mapping = nat->mappings; mapping != NULL; mapping = mapping->next){
    if (mapping->aux_ext == aux_ext && mapping->type == type){
      copy = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, mapping, sizeof(struct sr_nat_mapping)); 
    }
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *mapping = NULL;

  for(mapping = nat->mappings; mapping != NULL; mapping = mapping->next){
    if (mapping->ip_int == ip_int && mapping->aux_int == aux_int && mapping->type == type){
      copy = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, mapping, sizeof(struct sr_nat_mapping)); 
    }
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));

  time_t curtime = time(NULL);
  mapping->type = type;
  mapping->ip_int = ip_int;
  mapping->ip_ext = nat->ext_ip;
  mapping->aux_int = aux_int;
  mapping->last_updated = curtime;

  /* look for unused port */
  struct sr_nat_mapping *temp_mapping;
  uint16_t port = 1024;
  uint16_t flag = port;

  while (1){

    for (temp_mapping = nat->mappings; temp_mapping != NULL; temp_mapping = temp_mapping->next){
      if (port == temp_mapping->aux_ext){
        port += 1;
        break;
      }
    }

    if (flag == port){
      break;
    }
  } 
  
  mapping->aux_ext = htons(port);


  /* set up conns for Case ICMP or TCP*/
  if (type == nat_mapping_icmp){
    mapping->conns = NULL;
  }

  else{
    struct sr_nat_connection *conn = mapping->conns;
    conn->last_updated = curtime;
  }

  
  /* put back to nat->mappings */
  mapping->next = nat->mappings;
  nat->mappings = mapping;

  pthread_mutex_unlock(&(nat->lock));
  return mapping;
}
