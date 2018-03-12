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
#include "mbedtls/aes.h"

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

#define RC_STR(rc)	((rc) == 0 ? "OK" : "ERROR")
#define PRINT_RESULT(func, rc)	\
	printk("[%s:%d] %s: %d <%s>\n", __func__, __LINE__, \
	       (func), rc, RC_STR(rc))

#define TOPIC "t"
#define UNENCRYPTED_MSG "hello please encrypt me"

#define SS_STACK_SIZE 2048
#define SS_PRIORITY 5

#define MEM_BLOCK_OVERHEAD  ( 2 * sizeof( size_t ) )
#define HEAP_SIZE       (1u << 16)  // 64k
#define BUFSIZE         500
#define PAYLOAD_SIZE	122
#define NONCE_SIZE		16
#define FRAGMENT_OFFSET_SIZE 1

static bool message_changed=false;

const char* keys[] = {"Gv5BBQvjxDFNgjy", "rh4KTvALW6pyHRKr36yUcu4", "9PMkFNpjm7oikrhqYd3fEi9byIdz7GG"};
//static unsigned char unencrypted_msg[50] = "hello please encrypt me";
static unsigned char encrypted_msg[400];
static unsigned char msg_to_send[PAYLOAD_SIZE];
static unsigned char nonce_counter[NONCE_SIZE];
unsigned long i;

static void prepare_msg(struct mqtt_publish_msg *pub_msg,
				     enum mqtt_qos qos, unsigned char* msg_to_send);
static struct mqtt_client_ctx pub_ctx;

K_THREAD_STACK_DEFINE(ss_stack_area, SS_STACK_SIZE);
struct k_thread ss_thread;

static char *rand_string(char *str, size_t size)
{
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.-#'?!";
    if (size) {
        --size;
        for (size_t n = 0; n < size; n++) {
            int key = rand() % (int) (sizeof charset - 1);
            str[n] = 'a';//charset[key];
        }
        str[size] = '\0';
    }
    return str;
}

static void encrypt_aes_ctr(unsigned char *encrypted_msg, unsigned char* nonce_counter) {
    size_t nc_offset = 0;
    unsigned char stream_block[16];
    rand_string(nonce_counter, sizeof(nonce_counter));
    printk("\nnonce:%s\n", nonce_counter);
	mbedtls_aes_context ctr;
    mbedtls_aes_init( &ctr );
	mbedtls_aes_setkey_enc( &ctr, keys[2], 256 );
	mbedtls_aes_crypt_ctr( &ctr, BUFSIZE, &nc_offset, nonce_counter, stream_block, UNENCRYPTED_MSG, encrypted_msg );
	mbedtls_aes_free( &ctr );
	memset(encrypted_msg, "s", 100);
}

void message_thread()
{
	while(true) {
		k_sleep(APP_SLEEP_MSECS);
		k_mutex_lock(&pub_data, K_FOREVER);
		// static unsigned char encrypted_msg[400];
		// static unsigned char msg_to_send[PAYLOAD_SIZE];
		// static unsigned char nonce_counter[NONCE_SIZE];

		encrypt_aes_ctr(encrypted_msg, nonce_counter);
		size_t msg_size = strlen(encrypted_msg);
	 	printk("\nmsg (%d):%s\n", msg_size, encrypted_msg);

	 // 	int char_count = 0;
	 // 	unsigned char num_fragments = 0;
		// while (char_count <= msg_size) {
			// k_sleep(APP_SLEEP_MSECS);
			// k_mutex_lock(&pub_data, K_FOREVER);

			// static unsigned char fragment[PAYLOAD_SIZE - FRAGMENT_OFFSET_SIZE];
			// int fragment_size = PAYLOAD_SIZE - NONCE_SIZE - FRAGMENT_OFFSET_SIZE - 1;
			// strncpy(fragment, encrypted_msg, fragment_size);
			// snprintf(msg_to_send, sizeof(msg_to_send), "%c%s%s\n", 0, nonce_counter, fragment);

			// unsigned char fragment[PAYLOAD_SIZE - FRAGMENT_OFFSET_SIZE];
			// if (num_fragments == 0) {
			// 	strncpy(fragment, encrypted_msg, PAYLOAD_SIZE - NONCE_SIZE - FRAGMENT_OFFSET_SIZE - 1);
			// 	snprintf(msg_to_send, sizeof(msg_to_send), "%c%s%s\n", num_fragments, nonce_counter, fragment);
			// 	char_count += PAYLOAD_SIZE - NONCE_SIZE - FRAGMENT_OFFSET_SIZE - 1;
			// } else {
			// 	strncpy(fragment, encrypted_msg+char_count, PAYLOAD_SIZE - FRAGMENT_OFFSET_SIZE - 1);
			// 	snprintf(msg_to_send, sizeof(msg_to_send), "%c%s\n", num_fragments, fragment);
			// 	char_count+= PAYLOAD_SIZE - FRAGMENT_OFFSET_SIZE - 1;
			// }

			strcpy(msg_to_send, encrypted_msg);
			printk("\nmsg to send:%s\n", msg_to_send);
			prepare_msg(&pub_ctx.pub_msg, MQTT_QoS0, msg_to_send);
			int rc = mqtt_tx_publish(&pub_ctx.mqtt_ctx, &pub_ctx.pub_msg);
			PRINT_RESULT("mqtt_tx_publish", rc);
			//num_fragments++;
		 // 	message_changed = true;
			k_mutex_unlock(&pub_data);
			k_sem_give(&pub_sem);
	// 		k_sleep(APP_SLEEP_MSECS);
		}
	// }
}

// static char *get_message_payload(enum mqtt_qos qos) 
// {
// 	// static char payload[PAYLOAD_SIZE];
// 	// snprintf(payload, sizeof(payload), "%s\n", msg_to_send);
// 	printk("\npayload:%s\n", msg_to_send);
// 	return msg_to_send;
// }

static void start_message_thread()
{
	k_thread_create(&ss_thread, ss_stack_area,
								 K_THREAD_STACK_SIZEOF(ss_stack_area),
								 message_thread,
								 NULL, NULL, NULL,
								 SS_PRIORITY, 0, K_NO_WAIT);
}

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

static void malformed_cb(struct mqtt_ctx *mqtt_ctx, u16_t pkt_type)
{
	printk("[%s:%d] pkt_type: %u\n", __func__, __LINE__, pkt_type);
}

static void prepare_msg(struct mqtt_publish_msg *pub_msg, enum mqtt_qos qos, unsigned char* msg_to_send)
{
	//printk("\nsending:%s\n", msg_to_send);
	/* MQTT message payload may be anything, we we use C strings */
	pub_msg->msg = msg_to_send;
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

#define PUB_STACK_SIZE 2048
#define PUB_PRIORITY 5

K_THREAD_STACK_DEFINE(pub_stack_area, PUB_STACK_SIZE);
struct k_thread pub_thread;

void publisher_thread(void * unused1, void * unused2, void * unused3)
{
	printk("Start publisher thread");
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

	printk("pub ctx set up\n");

	while ((rc = k_sem_take(&pub_sem, K_FOREVER)) == 0) {
		printk("loop\n");
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
				prepare_msg(&pub_ctx.pub_msg, MQTT_QoS0, '\0');
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
	k_thread_create(&pub_thread, pub_stack_area,
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
