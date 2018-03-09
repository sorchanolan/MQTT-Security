/*
 * Copyright (c) 2017 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <net/mqtt.h>

#include <net/net_context.h>
#include <net/net_mgmt.h>

#include <misc/printk.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

#include "config.h"

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/platform.h"
//#include "mbedtls/config.h"
#include "mbedtls/cipher.h"
#include "mbedtls/md4.h"
#include "mbedtls/md5.h"
#include "mbedtls/ripemd160.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/arc4.h"
#include "mbedtls/des.h"
#include "mbedtls/aes.h"
#include "mbedtls/cmac.h"
#include "mbedtls/blowfish.h"
#include "mbedtls/camellia.h"
#include "mbedtls/gcm.h"
#include "mbedtls/ccm.h"
#include "mbedtls/havege.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/hmac_drbg.h"
#include "mbedtls/rsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/dhm.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/error.h"
#include "mbedtls/memory_buffer_alloc.h"

/* Container for some structures used by the MQTT publisher app. */
struct mqtt_client_ctx {
	struct mqtt_connect_msg connect_msg;
	struct mqtt_publish_msg pub_msg;
	struct mqtt_ctx mqtt_ctx;
	void *connect_data;
	void *disconnect_data;
	void *publish_data;
};

/* Callback to tell us when we have a net connection */
#if defined(CONFIG_NET_MGMT_EVENT)
static struct net_mgmt_event_callback cb;
#endif

/* MQTT publisher semaphore */
K_SEM_DEFINE(pub_sem, 0, 2);
K_MUTEX_DEFINE(pub_data);

#define MESSAGE_128 "SawLFz4OB4Cx23d"
#define NUM_MESSAGES 10
#define TOPIC "topic"

static bool message_changed=false;

const char* keys[] = {"Gv5BBQvjxDFNgjy", "rh4KTvALW6pyHRKr36yUcu4", "9PMkFNpjm7oikrhqYd3fEi9byIdz7GG"};
static unsigned char* curr_msg[256];
static char encrypted_msg[400];
static int loop_count = 1;
static int ret = 1;
static int num = 0x1;
static unsigned char tmp[200];
unsigned long i;

static void prepare_msg(struct mqtt_publish_msg *pub_msg,
				     enum mqtt_qos qos);
static struct mqtt_client_ctx pub_ctx;
                                     
static size_t max_used, max_blocks, max_bytes;                        
static size_t prv_used, prv_blocks;  

#define SS_STACK_SIZE 2048
#define SS_PRIORITY 5

#define MEM_BLOCK_OVERHEAD  ( 2 * sizeof( size_t ) )
#define HEAP_SIZE       (1u << 16)  // 64k
#define BUFSIZE         256

static void memory_measure_init() {                                 
    mbedtls_memory_buffer_alloc_cur_get( &prv_used, &prv_blocks ); 
    mbedtls_memory_buffer_alloc_max_reset( );
}

static void memory_measure_print() {                         
    mbedtls_memory_buffer_alloc_max_get( &max_used, &max_blocks ); 
 
    max_used -= prv_used;                                          
    max_blocks -= prv_blocks;                                      
    max_bytes = max_used + MEM_BLOCK_OVERHEAD * max_blocks;        
    printk( "%6u heap bytes %6u %6u %6u %6u \r\n", (unsigned) max_bytes, (unsigned) max_used, (unsigned) max_blocks, (unsigned) prv_used, (unsigned) prv_blocks );
}

K_THREAD_STACK_DEFINE(ss_stack_area, SS_STACK_SIZE);
struct k_thread ss_thread;

static void run_experiment(char *title, int index, int keysize, void (*encrypt)(int,int)) {
	uint32_t start_time;
	uint32_t stop_time;
	uint32_t cycles_spent;
	uint32_t nanoseconds_spent = 0;
	int avg_overhead = 0;

	for (int arr_index = 0; arr_index < NUM_MESSAGES; arr_index++) {
		k_sleep(APP_SLEEP_MSECS);
		k_mutex_lock(&pub_data, K_FOREVER);
		memset( curr_msg, ++num, sizeof( curr_msg ) );

		start_time = k_cycle_get_32();
		
		encrypt(index, keysize);
		size_t msg_size = strlen(encrypted_msg);
		avg_overhead += msg_size;
		printk("%d\n", msg_size);
	 	prepare_msg(&pub_ctx.pub_msg, MQTT_QoS0);
	 	int rc = mqtt_tx_publish(&pub_ctx.mqtt_ctx, &pub_ctx.pub_msg);

		k_mutex_unlock(&pub_data);
		k_sem_give(&pub_sem);

		stop_time = k_cycle_get_32();
		cycles_spent = stop_time - start_time;
		nanoseconds_spent = nanoseconds_spent + SYS_CLOCK_HW_CYCLES_TO_NS(cycles_spent);
	}
	avg_overhead = avg_overhead / NUM_MESSAGES;
	printk("%s: Time spent:%" PRIu32 "\nAverage overhead: %d\n", title, nanoseconds_spent, avg_overhead);		
}

/*****************************************************************/
							/*AES*/
/*****************************************************************/
static void encrypt_aes_ecb(int index, int keysize) {
	mbedtls_aes_context aes_ctx;
	mbedtls_aes_init( &aes_ctx );
	mbedtls_aes_setkey_enc( &aes_ctx, keys[index], keysize );
	mbedtls_aes_crypt_ecb( &aes_ctx, MBEDTLS_AES_ENCRYPT, curr_msg, encrypted_msg );
	mbedtls_aes_free( &aes_ctx );	
}

static void encrypt_aes_cbc(int index, int keysize) {
	mbedtls_aes_context aes_ctx;
	mbedtls_aes_init( &aes_ctx );
	mbedtls_aes_setkey_enc( &aes_ctx, keys[index], keysize );
	mbedtls_aes_crypt_cbc( &aes_ctx, MBEDTLS_AES_ENCRYPT, BUFSIZE, tmp, curr_msg, encrypted_msg );
	mbedtls_aes_free( &aes_ctx );	
}

static void encrypt_aes_ccm(int index, int keysize) {
	mbedtls_ccm_context ccm;
    mbedtls_ccm_init( &ccm );
	mbedtls_ccm_setkey( &ccm, MBEDTLS_CIPHER_ID_AES, keys[index], keysize );
	mbedtls_ccm_encrypt_and_tag( &ccm, BUFSIZE, tmp, 4, NULL, 0, curr_msg, encrypted_msg, tmp, 8 );
	mbedtls_ccm_free( &ccm );
}

static void encrypt_aes_ctr(int index, int keysize) {
    size_t nc_offset = 0;
    unsigned char stream_block[16];
	mbedtls_aes_context ctr;
    mbedtls_aes_init( &ctr );
	mbedtls_aes_setkey_enc( &ctr, keys[index], keysize );
	mbedtls_aes_crypt_ctr( &ctr, BUFSIZE, &nc_offset, tmp, stream_block, curr_msg, encrypted_msg );
	mbedtls_aes_free( &ctr );
}

static void encrypt_aes_gcm(int index, int keysize) {
	mbedtls_gcm_context gcm;
	mbedtls_gcm_init( &gcm );
	mbedtls_gcm_setkey( &gcm, MBEDTLS_CIPHER_ID_AES, keys[index], keysize );
	mbedtls_gcm_crypt_and_tag( &gcm, MBEDTLS_GCM_ENCRYPT, BUFSIZE, tmp, 4, NULL, 0, curr_msg, encrypted_msg, 8, tmp );
	mbedtls_gcm_free( &gcm );
}

static void encrypt_aes_cfb128(int index, int keysize) {
	mbedtls_aes_context aes_ctx;
	mbedtls_aes_init( &aes_ctx );
	mbedtls_aes_setkey_enc( &aes_ctx, keys[index], keysize );
	mbedtls_aes_crypt_cfb128( &aes_ctx, MBEDTLS_AES_ENCRYPT, BUFSIZE, 32, tmp, curr_msg, encrypted_msg );
	mbedtls_aes_free( &aes_ctx );
}

/*****************************************************************/
						  /*CAMELLIA*/
/*****************************************************************/

static void encrypt_camellia_ecb(int index, int keysize) {
	mbedtls_camellia_context camellia;
    mbedtls_camellia_init( &camellia );
    mbedtls_camellia_setkey_enc( &camellia, keys[index], keysize );
    mbedtls_camellia_crypt_ecb( &camellia, MBEDTLS_CAMELLIA_ENCRYPT, curr_msg, encrypted_msg );
    mbedtls_camellia_free( &camellia );
}

static void encrypt_camellia_cbc(int index, int keysize) {
	mbedtls_camellia_context camellia;
    mbedtls_camellia_init( &camellia );
    mbedtls_camellia_setkey_enc( &camellia, keys[index], keysize );
    mbedtls_camellia_crypt_cbc( &camellia, MBEDTLS_CAMELLIA_ENCRYPT, BUFSIZE, tmp, curr_msg, encrypted_msg );
    mbedtls_camellia_free( &camellia );
}

static void encrypt_camellia_cfb128(int index, int keysize) {
	mbedtls_camellia_context camellia;
    mbedtls_camellia_init( &camellia );
    mbedtls_camellia_setkey_enc( &camellia, keys[index], keysize );
    mbedtls_camellia_crypt_cfb128( &camellia, MBEDTLS_CAMELLIA_ENCRYPT, BUFSIZE, 32, tmp, curr_msg, encrypted_msg );
    mbedtls_camellia_free( &camellia );
}

static void encrypt_camellia_ctr(int index, int keysize) {
    size_t nc_offset = 0;
    unsigned char stream_block[16];
	mbedtls_camellia_context ctr;
    mbedtls_camellia_init( &ctr );
	mbedtls_camellia_setkey_enc( &ctr, keys[index], keysize );
	mbedtls_camellia_crypt_ctr( &ctr, BUFSIZE, &nc_offset, tmp, stream_block, curr_msg, encrypted_msg );
	mbedtls_camellia_free( &ctr );
}

static void encrypt_camellia_gcm(int index, int keysize) {
	mbedtls_gcm_context gcm;
	mbedtls_gcm_init( &gcm );
	mbedtls_gcm_setkey( &gcm, MBEDTLS_CIPHER_ID_CAMELLIA, keys[index], keysize );
	mbedtls_gcm_crypt_and_tag( &gcm, MBEDTLS_GCM_ENCRYPT, BUFSIZE, tmp, 4, NULL, 0, curr_msg, encrypted_msg, 8, tmp );
	mbedtls_gcm_free( &gcm );
}

static void encrypt_camellia_ccm(int index, int keysize) {
	mbedtls_ccm_context ccm;
    mbedtls_ccm_init( &ccm );
	mbedtls_ccm_setkey( &ccm, MBEDTLS_CIPHER_ID_CAMELLIA, keys[index], keysize );
	mbedtls_ccm_encrypt_and_tag( &ccm, BUFSIZE, tmp, 4, NULL, 0, curr_msg, encrypted_msg, tmp, 8 );
	mbedtls_ccm_free( &ccm );
}

/*****************************************************************/
						  /*BLOWFISH*/
/*****************************************************************/

static void encrypt_blowfish_cbc(int index, int keysize) {
	mbedtls_blowfish_context blowfish;
    mbedtls_blowfish_init( &blowfish );
    mbedtls_blowfish_setkey( &blowfish, tmp, keysize );
    mbedtls_blowfish_crypt_cbc( &blowfish, MBEDTLS_BLOWFISH_ENCRYPT, BUFSIZE, tmp, curr_msg, encrypted_msg );
    mbedtls_blowfish_free( &blowfish );
}

static void encrypt_blowfish_ecb(int index, int keysize) {
	mbedtls_blowfish_context blowfish;
    mbedtls_blowfish_init( &blowfish );
    mbedtls_blowfish_setkey( &blowfish, keys[index], keysize );
    mbedtls_blowfish_crypt_ecb( &blowfish, MBEDTLS_BLOWFISH_ENCRYPT, curr_msg, encrypted_msg );
    mbedtls_blowfish_free( &blowfish );
}

static void encrypt_blowfish_ctr(int index, int keysize) {
    size_t nc_offset = 0;
    unsigned char stream_block[16];
	mbedtls_blowfish_context ctr;
    mbedtls_blowfish_init( &ctr );
	mbedtls_blowfish_setkey( &ctr, keys[index], keysize );
	mbedtls_blowfish_crypt_ctr( &ctr, BUFSIZE, &nc_offset, tmp, stream_block, curr_msg, encrypted_msg );
	mbedtls_blowfish_free( &ctr );
}

static void encrypt_blowfish_cfb64(int index, int keysize) {
	mbedtls_blowfish_context blowfish_ctx;
	mbedtls_blowfish_init( &blowfish_ctx );
	mbedtls_blowfish_setkey( &blowfish_ctx, keys[index], keysize );
	mbedtls_blowfish_crypt_cfb64( &blowfish_ctx, MBEDTLS_BLOWFISH_ENCRYPT, BUFSIZE, 32, tmp, curr_msg, encrypted_msg );
	mbedtls_blowfish_free( &blowfish_ctx );
}

/*****************************************************************/
						  /*ARCFOUR*/
/*****************************************************************/

static void encrypt_arc4_128(int index, int keysize) {
	mbedtls_arc4_context arc4;
    mbedtls_arc4_init( &arc4 );
    mbedtls_arc4_setup( &arc4, keys[0], keysize );
    mbedtls_arc4_crypt( &arc4, BUFSIZE, &curr_msg, encrypted_msg );
    mbedtls_arc4_free( &arc4 );
}


void message_thread()
{
	memset( curr_msg, num, sizeof( curr_msg ) );
	memset( tmp, num, sizeof( tmp ) );

	const int *list;
	const mbedtls_cipher_info_t *cipher_info;
	list = mbedtls_cipher_list();
    while( *list )
    {
        cipher_info = mbedtls_cipher_info_from_type( *list );
        printk( "%s\n", cipher_info->name );
        list++;
    }

	k_sleep(APP_SLEEP_MSECS);
	int index;
	char buf[30];	

	run_experiment("ARC4_128", tmp, 128, encrypt_arc4_128);

	for (int keysize = 128; keysize <= 256; keysize += 64) {
		index = (keysize - 128) / 64;

		snprintf(buf, sizeof buf, "CAMELLIA_ECB_%d", keysize);
		run_experiment(buf, index, keysize, encrypt_camellia_ecb);
		
		snprintf(buf, sizeof buf, "CAMELLIA_CBC_%d", keysize);
		run_experiment(buf, index, keysize, encrypt_camellia_cbc);
	
		snprintf(buf, sizeof buf, "CAMELLIA_CTR_%d", keysize);
		run_experiment(buf, index, keysize, encrypt_camellia_ctr);
	
		snprintf(buf, sizeof buf, "CAMELLIA_CCM_%d", keysize);
		run_experiment(buf, index, keysize, encrypt_camellia_ccm);
	
		snprintf(buf, sizeof buf, "CAMELLIA_GCM_%d", keysize);
		run_experiment(buf, index, keysize, encrypt_camellia_gcm);
	
	// 	snprintf(buf, sizeof buf, "CAMELLIA_CFB128_%d", keysize);
	// 	run_experiment(buf, index, keysize, encrypt_camellia_cfb128);
	
		snprintf(buf, sizeof buf, "AES_CBC_%d", keysize);
		run_experiment(buf, index, keysize, encrypt_aes_cbc);
	
		snprintf(buf, sizeof buf, "AES_ECB_%d", keysize);
		run_experiment(buf, index, keysize, encrypt_aes_ecb);
	
		snprintf(buf, sizeof buf, "AES_CCM_%d", keysize);
		run_experiment(buf, index, keysize, encrypt_aes_ccm);
	
		snprintf(buf, sizeof buf, "AES_CTR_%d", keysize);
		run_experiment(buf, index, keysize, encrypt_aes_ctr);
	
		snprintf(buf, sizeof buf, "AES_GCM_%d", keysize);
		run_experiment(buf, index, keysize, encrypt_aes_gcm);
	
	// 	snprintf(buf, sizeof buf, "AES_CFB128_%d", keysize);
	// 	run_experiment(buf, index, keysize, encrypt_aes_cfb128);
	
	// 	snprintf(buf, sizeof buf, "BLOWFISH_CTR_%d", keysize);
	// 	run_experiment(buf, index, keysize, encrypt_blowfish_ctr);
	
	// 	snprintf(buf, sizeof buf, "BLOWFISH_ECB_%d", keysize);
	// 	run_experiment(buf, index, keysize, encrypt_blowfish_ecb);
	
	// 	snprintf(buf, sizeof buf, "BLOWFISH_CBC_%d", keysize);
	// 	run_experiment(buf, index, keysize, encrypt_blowfish_cbc);
	
	// 	snprintf(buf, sizeof buf, "BLOWFISH_CFB64_%d", keysize);
	// 	run_experiment(buf, index, keysize, encrypt_blowfish_cfb64);
	}

	exit:
		printk("Experiments complete.\n");
}


static void start_message_thread()
{
	k_tid_t ss_tid = k_thread_create(&ss_thread, ss_stack_area,
								 K_THREAD_STACK_SIZEOF(ss_stack_area),
								 message_thread,
								 NULL, NULL, NULL,
								 SS_PRIORITY, 0, K_NO_WAIT);
}


/* The signature of this routine must match the connect callback declared at
 * the mqtt.h header.
 */
static void connect_cb(struct mqtt_ctx *mqtt_ctx)
{
	struct mqtt_client_ctx *client_ctx;

	client_ctx = CONTAINER_OF(mqtt_ctx, struct mqtt_client_ctx, mqtt_ctx);

	printk("[%s:%d]", __func__, __LINE__);

	if (client_ctx->connect_data) {
		printk(" user_data: %s",
		       (const char *)client_ctx->connect_data);
	}

	printk("\n");
}

/* The signature of this routine must match the disconnect callback declared at
 * the mqtt.h header.
 */
static void disconnect_cb(struct mqtt_ctx *mqtt_ctx)
{
	struct mqtt_client_ctx *client_ctx;

	client_ctx = CONTAINER_OF(mqtt_ctx, struct mqtt_client_ctx, mqtt_ctx);

	printk("[%s:%d]", __func__, __LINE__);

	if (client_ctx->disconnect_data) {
		printk(" user_data: %s",
		       (const char *)client_ctx->disconnect_data);
	}

	printk("\n");
}

/**
 * The signature of this routine must match the publish_tx callback declared at
 * the mqtt.h header.
 *
 * NOTE: we have two callbacks for MQTT Publish related stuff:
 *	- publish_tx, for publishers
 *	- publish_rx, for subscribers
 *
 * Applications must keep a "message database" with pkt_id's. So far, this is
 * not implemented here. For example, if we receive a PUBREC message with an
 * unknown pkt_id, this routine must return an error, for example -EINVAL or
 * any negative value.
 */
static int publish_cb(struct mqtt_ctx *mqtt_ctx, u16_t pkt_id,
		      enum mqtt_packet type)
{
	struct mqtt_client_ctx *client_ctx;
	const char *str;
	int rc = 0;

	client_ctx = CONTAINER_OF(mqtt_ctx, struct mqtt_client_ctx, mqtt_ctx);

	switch (type) {
	case MQTT_PUBACK:
		str = "MQTT_PUBACK";
		break;
	case MQTT_PUBCOMP:
		str = "MQTT_PUBCOMP";
		break;
	case MQTT_PUBREC:
		str = "MQTT_PUBREC";
		break;
	default:
		rc = -EINVAL;
		str = "Invalid MQTT packet";
	}

	printk("[%s:%d] <%s> packet id: %u", __func__, __LINE__, str, pkt_id);

	if (client_ctx->publish_data) {
		printk(", user_data: %s",
		       (const char *)client_ctx->publish_data);
	}

	printk("\n");

	return rc;
}

/**
 * The signature of this routine must match the malformed callback declared at
 * the mqtt.h header.
 */
static void malformed_cb(struct mqtt_ctx *mqtt_ctx, u16_t pkt_type)
{
	printk("[%s:%d] pkt_type: %u\n", __func__, __LINE__, pkt_type);
}

static char *get_message_payload(enum mqtt_qos qos) 
{
	static char payload[450];
	snprintf(payload, sizeof(payload), "%s\n", encrypted_msg);
	loop_count++;
	return payload;
}

static void prepare_msg(struct mqtt_publish_msg *pub_msg,
				     enum mqtt_qos qos)
{
	/* MQTT message payload may be anything, we we use C strings */
	pub_msg->msg = get_message_payload(qos);
	/* Payload's length */
	pub_msg->msg_len = strlen(pub_msg->msg);
	/* MQTT Quality of Service */
	pub_msg->qos = qos;
	/* Message's topic */
	pub_msg->topic = TOPIC;
	pub_msg->topic_len = strlen(pub_msg->topic);
	/* Packet Identifier, always use different values */
	pub_msg->pkt_id = sys_rand32_get();
}

#define RC_STR(rc)	((rc) == 0 ? "OK" : "ERROR")

#define PRINT_RESULT(func, rc)	\
	printk("[%s:%d] %s: %d <%s>\n", __func__, __LINE__, \
	       (func), rc, RC_STR(rc))

#define PUB_STACK_SIZE 2048
#define PUB_PRIORITY 5

K_THREAD_STACK_DEFINE(pub_stack_area, PUB_STACK_SIZE);
struct k_thread pub_thread;

void publisher_thread(void * unused1, void * unused2, void * unused3)
{
	ARG_UNUSED(unused1);
	ARG_UNUSED(unused2);
	ARG_UNUSED(unused3);

	int i, rc;

	/* Set everything to 0 and later just assign the required fields. */
	memset(&pub_ctx, 0x00, sizeof(pub_ctx));

	/* connect, disconnect and malformed may be set to NULL */
	pub_ctx.mqtt_ctx.connect = connect_cb;

	pub_ctx.mqtt_ctx.disconnect = disconnect_cb;
	pub_ctx.mqtt_ctx.malformed = malformed_cb;

	pub_ctx.mqtt_ctx.net_init_timeout = APP_NET_INIT_TIMEOUT;
	pub_ctx.mqtt_ctx.net_timeout = APP_TX_RX_TIMEOUT;

	pub_ctx.mqtt_ctx.peer_addr_str = SERVER_ADDR;
	pub_ctx.mqtt_ctx.peer_port = SERVER_PORT;

	/* Publisher apps TX the MQTT PUBLISH msg */
	pub_ctx.mqtt_ctx.publish_tx = publish_cb;

	/* The connect message will be sent to the MQTT server (broker).
	 * If clean_session here is 0, the mqtt_ctx clean_session variable
	 * will be set to 0 also. Please don't do that, set always to 1.
	 * Clean session = 0 is not yet supported.
	 */
	pub_ctx.connect_msg.user_name = TB_ACCESS_TOKEN;
	pub_ctx.connect_msg.user_name_len = strlen(TB_ACCESS_TOKEN);
	pub_ctx.connect_msg.clean_session = 1;

	pub_ctx.connect_data = "CONNECTED";
	pub_ctx.disconnect_data = "DISCONNECTED";
	pub_ctx.publish_data = "PUBLISH";

	while ((rc = k_sem_take(&pub_sem, K_FOREVER)) == 0) {

		rc = mqtt_init(&pub_ctx.mqtt_ctx, MQTT_APP_PUBLISHER);
		PRINT_RESULT("mqtt_init", rc);

		if (rc != 0) {
			goto exit_pub;
		}

		i = 0;
		do {
			rc = mqtt_connect(&pub_ctx.mqtt_ctx);
			PRINT_RESULT("mqtt_connect", rc);
		} while (rc != 0 && i++ < APP_CONN_TRIES);

		if (rc != 0) {
			goto exit_pub;
		}

		i = 0;
		do {
			rc = mqtt_tx_connect(&pub_ctx.mqtt_ctx, &pub_ctx.connect_msg);
			PRINT_RESULT("mqtt_tx_connect", rc);
			k_sleep(APP_TX_CONN_WAIT_MSECS);
		} while (rc == 0 && i++ < APP_TX_CONN_TRIES && !pub_ctx.mqtt_ctx.connected);

		if (!pub_ctx.mqtt_ctx.connected) {
			mqtt_close(&pub_ctx.mqtt_ctx);
			goto exit_pub;
		} 

		do {
			bool data_changed = false;
			k_mutex_lock(&pub_data, K_FOREVER);

			if (message_changed) {
				prepare_msg(&pub_ctx.pub_msg, MQTT_QoS0);
				message_changed=false;
				data_changed = true;
			}

			k_mutex_unlock(&pub_data);

			if (data_changed) {
				rc = mqtt_tx_publish(&pub_ctx.mqtt_ctx, &pub_ctx.pub_msg);
				PRINT_RESULT("mqtt_tx_publish", rc);
			}
		} while ((rc = k_sem_take(&pub_sem, APP_CONN_IDLE_TIMEOUT)) == 0);

		rc = mqtt_tx_disconnect(&pub_ctx.mqtt_ctx);
		PRINT_RESULT("mqtt_tx_disconnect", rc);

		k_sleep(APP_TX_RX_TIMEOUT);

		rc = mqtt_close(&pub_ctx.mqtt_ctx);
		PRINT_RESULT("mqtt_close", rc);

		k_sleep(APP_TX_RX_TIMEOUT);
	}

exit_pub:

	printk("\nPublisher terminated!!\n");
}


static void start_publisher()
{
	k_tid_t tt_tid = k_thread_create(&pub_thread, pub_stack_area,
                                 K_THREAD_STACK_SIZEOF(pub_stack_area),
                                 publisher_thread,
                                 NULL, NULL, NULL,
                                 PUB_PRIORITY, 0, K_NO_WAIT);
}


static void event_iface_up(struct net_mgmt_event_callback *cb,
			   u32_t mgmt_event, struct net_if *iface)
{
	start_publisher();
	start_message_thread();
}


void main(void)
{
	struct net_if *iface = net_if_get_default();

#if defined(CONFIG_NET_MGMT_EVENT)
	/* Subscribe to NET_IF_UP if interface is not ready */
	if (!atomic_test_bit(iface->flags, NET_IF_UP)) {
		net_mgmt_init_event_callback(&cb, event_iface_up, NET_EVENT_IF_UP);
		net_mgmt_add_event_callback(&cb);
	}
#else
	event_iface_up(NULL, NET_EVENT_IF_UP, iface);
#endif

	return;
}
