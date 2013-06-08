/*
* transport.c 
*
* CS244a HW#3 (Reliable Transport)
*
* This file implements the STCP layer that sits between the
* mysocket and network layers. You are required to fill in the STCP
* functionality in this file. 
*
*/


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h> // rand()
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"

#define MAX_SEND_WINDOW_SIZE 3027
#define MAX_RECV_WINDOW_SIZE 3027
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_ACK  0x10
#define TH_URG  0x20



enum { CSTATE_ESTABLISHED, CLOSE_WAIT, LAST_ACK, FIN_WAIT1, FIN_WAIT2, CLOSING};    /* obviously you should have more states */


/* this structure is global to a mysocket descriptor */
typedef struct
{
  bool_t done;    /* TRUE once connection is closed */

	int connection_state;   /* state of the connection (established, etc.) */
	tcp_seq initial_sequence_num;

	/* any other connection-wide global variables go here */
	tcp_seq seq;
	tcp_seq base;
	uint32_t ack_num;
	stcp_event_type_t eventflag;
	bool_t is_active;
} context_t;


static void generate_initial_seq(context_t *ctx, bool_t is_active);
static void control_loop(mysocket_t sd, context_t *ctx);
struct tcphdr patch_h( uint32_t seq, uint32_t ack, uint8_t off, uint8_t flags);


/* initialise the transport layer, and start the main loop, handling
* any data from the peer or the application.  this function should not
* return until the connection is closed.
*/
void transport_init(mysocket_t sd, bool_t is_active)
{
	struct tcphdr header;
	struct tcphdr *header_r;
	context_t *ctx;
	size_t len;
	char dst[STCP_MSS];
	ctx = (context_t *) calloc(1, sizeof(context_t));

	assert(ctx);

	generate_initial_seq(ctx, is_active);
	/* XXX: you should send a SYN packet here if is_active, or wait for one
	* to arrive if !is_active.  after the handshake completes, unblock the
	* application with stcp_unblock_application(sd).  you may also use
	* this to communicate an error condition back to the application, e.g.
	* if connection fails; to do so, just set errno appropriately (e.g. to
	* ECONNREFUSED, etc.) before calling the function.
	*/

	ctx->seq = ctx->initial_sequence_num;
	ctx->is_active = is_active;
	if(is_active){
		header = patch_h(ctx->seq , 0, 5, TH_SYN);
		stcp_network_send(sd, &header, 20, NULL);
		ctx->seq = ctx->seq+1;

		memset(dst, 0, STCP_MSS);//dst = (char *)calloc(1, sizeof(tcphdr));
		len = stcp_network_recv(sd, dst, STCP_MSS);
		header_r= (struct tcphdr *)dst;

		if(!((header_r->th_flags & TH_SYN) && (header_r->th_flags & TH_ACK))){
			exit(1);
		}
		ctx->ack_num = header_r->th_seq+1;
		ctx->base = header_r->th_ack;

		if(ctx->base != ctx->seq){
			exit(0);
		}

		//ctx->connection_state = SYN_RCVD;

		header = patch_h(ctx->seq , ctx->ack_num, 5, TH_ACK);
		stcp_network_send(sd, &header, 20, NULL);
		ctx->seq = ctx->seq+1;

	}else if(!is_active){

		memset(dst, 0, STCP_MSS);//dst = (char *)calloc(1, sizeof(tcphdr));
		stcp_network_recv(sd, dst, STCP_MSS);
		header_r= (struct tcphdr *)dst;

		if(!(header_r->th_flags & TH_SYN)){
			exit(1);
		}

		ctx->ack_num = header_r->th_seq+1;
		//ctx->connection_state = SYN_RCVD;

		header = patch_h( ctx->seq , ctx->ack_num, 5, TH_SYN + TH_ACK);
		stcp_network_send(sd, &header, 20, NULL);
		ctx->seq = ctx->seq+1;

		memset(dst, 0, STCP_MSS);//dst = (char *)calloc(1, sizeof(tcphdr));
		len = stcp_network_recv(sd, dst, STCP_MSS);
		header_r= (struct tcphdr *)dst;

		if(!(header_r->th_flags & TH_ACK)){
			exit(1);
		}

		ctx->ack_num =ctx->ack_num + len - 19;
		ctx->base = header_r->th_ack;
	}

	ctx->connection_state = CSTATE_ESTABLISHED;
	stcp_unblock_application(sd);

	control_loop(sd, ctx);

	/* do any cleanup here */
	free(ctx);
}


/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq(context_t *ctx, bool_t is_active)
{
	int rnd;
	assert(ctx);
	srand(time(NULL)+is_active);

#ifdef FIXED_INITNUM
	/* please don't change this! */
	ctx->initial_sequence_num = 1;
#else
	/* you have to fill this up */
	/*ctx->initial_sequence_num =;*/

	rnd =  rand()%256 +1;
	ctx->initial_sequence_num =rnd;

#endif
}


/* control_loop() is the main STCP loop; it repeatedly waits for one of the
* following to happen:
*   - incoming data from the peer
*   - new data from the application (via mywrite())
*   - the socket to be closed (via myclose())
*   - a timeout
*/
static void control_loop(mysocket_t sd, context_t *ctx)
{
	struct tcphdr header;
	struct tcphdr *header_r;
	char recv_packet[STCP_MSS];
	char recv_data[STCP_MSS-20];
	size_t len;

	assert(ctx);
	ctx->eventflag = ANY_EVENT;
	while (!ctx->done)
	{
		unsigned int event;
		/* see stcp_api.h or stcp_api.c for details of this function */
		/* XXX: you will need to change some of these arguments! */

		event = stcp_wait_for_event(sd, ctx->eventflag, NULL);

		/* check whether it was the network, app, or a close request */
		if (event & APP_DATA){
			memset(recv_data, 0, STCP_MSS-20);
			len = stcp_app_recv(sd, recv_data, STCP_MSS-20);
			header = patch_h(ctx->seq, ctx->ack_num, 5, 0);
			stcp_network_send(sd, &header, 20, recv_data, len, NULL);
			ctx->seq = ctx->seq + len;

		}
		if(event & NETWORK_DATA){
			memset(recv_packet, 0, STCP_MSS);
			len = stcp_network_recv(sd, recv_packet, STCP_MSS);
			header_r= (struct tcphdr *)recv_packet;

			if(len > (size_t)(4*header_r->th_off)){
				ctx->ack_num = header_r->th_seq;
				ctx->base = header_r->th_ack;
				stcp_app_send(sd, recv_packet+20, len-20);
			}else if( len == (size_t)(4*header_r->th_off)){
				ctx->base = header_r->th_ack;
			}else{
				printf("error! network data received less then 20\n");
				exit(0);
			}

			if(header_r->th_flags & TH_FIN){
				if(ctx->connection_state == CSTATE_ESTABLISHED){
					ctx->connection_state = CLOSE_WAIT;
					stcp_fin_received(sd);
				}else if(ctx->connection_state == FIN_WAIT1){
					header = patch_h(ctx->seq, ctx->ack_num, 5, TH_ACK);
					stcp_network_send(sd, &header, 20, NULL);
					stcp_fin_received(sd);
					return;
				}else if(ctx->connection_state == FIN_WAIT2){
					header = patch_h(ctx->seq, ctx->ack_num, 5, TH_ACK);
					stcp_network_send(sd, &header, 20, NULL);
					stcp_fin_received(sd);
					return;
				}
			}
			if(header_r->th_flags & TH_ACK){
				if(ctx->connection_state == LAST_ACK){
					return;
				}else if(ctx->connection_state == FIN_WAIT1){
					ctx->connection_state = FIN_WAIT2;
				}				
			}
			if(len > (size_t)(4*header_r->th_off)){
				header = patch_h(ctx->seq, ctx->ack_num, 5, TH_ACK);
				stcp_network_send(sd, &header, 20, NULL);
			}
		}

		if(event & APP_CLOSE_REQUESTED){
			if(ctx->connection_state == CLOSE_WAIT){
				ctx->connection_state = LAST_ACK;
			}else if(ctx->connection_state == CSTATE_ESTABLISHED){
				ctx->connection_state = FIN_WAIT1;
			}
			header = patch_h(ctx->seq, ctx->ack_num, 5, TH_FIN);
			stcp_network_send(sd, &header, 20, NULL);
		}
	}
}

/* etc. */



/**********************************************************************/
/* our_dprintf
*
* Send a formatted message to stdout.
* 
* format               A printf-style format string.
*
* This function is equivalent to a printf, but may be
* changed to log errors to a file if desired.
*
* Calls to this function are generated by the dprintf amd
* dperror macros in transport.h
*/
void our_dprintf(const char *format,...)
{
	va_list argptr;
	char buffer[1024];

	assert(format);
	va_start(argptr, format);
	vsnprintf(buffer, sizeof(buffer), format, argptr);
	va_end(argptr);
	fputs(buffer, stdout);
	fflush(stdout);
}


struct tcphdr patch_h(uint32_t seq, uint32_t ack, uint8_t off, uint8_t flags){
	struct tcphdr patch;
	patch.th_win = MAX_SEND_WINDOW_SIZE;
	patch.th_seq = seq;
	patch.th_ack = ack;
	patch.th_off = off;
	patch.th_flags |= flags;
	return patch;
}
