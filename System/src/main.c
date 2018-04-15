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
#include <stdlib.h>
#include <math.h>

#include <json.h>

#include "config.h"

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/platform.h"
#include "mbedtls/aes.h"
#include "mbedtls/base64.h"

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

#define PAYLOAD_SIZE 124
#define TOPIC "t"
#define NEW_KEY_TOPIC "new_key"
#define EXISTING_KEY_TOPIC "existing_key"
#define REGISTER_TOPIC "register"
#define private_topic "QpdK8pub1"
#define private_key "NOgcmOABscIenR9GIQFUgPy8EKOUbaem"
#define input_topic "input"

#define USERNAME "pub1"
#define PASSWORD "pword"

#define NELEMENTS(x)  (sizeof(x) / sizeof((x)[0]))

#define RC_STR(rc)	((rc) == 0 ? "OK" : "ERROR")

#define PRINT_RESULT(func, rc)	\
	printk("[%s:%d] %s: %d <%s>\n", __func__, __LINE__, \
	       (func), rc, RC_STR(rc))

static bool message_changed=false;
static bool time_to_subscribe=true;
// static bool subscribed_private_topic=false;

const char* keys[] = {"Gv5BBQvjxDFNgjyo", "rh4KTvALW6pyHRKr36yUcu4o", "9PMkFNpjm7oikrhqYd3fEi9byIdz7GGo"};
static unsigned char* msgs_to_send[] = {"try encrypt thishello", "hello", "hello my name is Sorcha Nolan and I would like to be encrypted yay it works well I hope it does i dunno hello my name is Sorcha Nolan and I would like to be encrypted yay it works well I hope it does i dunno", "hi Stefan       ", "yay it works well I hope it does i dunno", "encrypt me you piece of shit"};
static char encrypted_msg[400];

// const char* private_key = "vUFq3LeKMQwA/xnOS3xzAA6Pyws=";
// const char* private_topic = "QpdK8pub1";
static bool registered = false;
static bool requesting = false;
static bool new_msg_input = false;
static char input_msg[1024];

struct encryption_key {
   int kid;
   unsigned char *k;
   unsigned char key[33];
   unsigned char nonce[17];
   int t;
   s64_t ts;
};

static struct encryption_key enc_key;

int i;

static void prepare_msg(struct mqtt_publish_msg *pub_msg,
				     enum mqtt_qos qos, unsigned char* topic, unsigned char* payload);
static struct mqtt_client_ctx pub_ctx;

#define SS_STACK_SIZE 2048
#define SS_PRIORITY 5
#define BUFSIZE         500

K_THREAD_STACK_DEFINE(ss_stack_area, SS_STACK_SIZE);
struct k_thread ss_thread;

static char *rand_string(char *str, size_t size)
{
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    if (size) {
        --size;
        for (size_t n = 0; n < size; n++) {
            int key = rand() % (int) (sizeof charset - 1);
            str[n] = charset[key];
        }
        str[size] = '\0';
    }
    return str;
}

static void encrypt_aes_ctr(unsigned char* nonce, unsigned char* msg_to_send) {
	printk("decrypted key: %s\n", enc_key.key);
    size_t nc_offset = 0;
    unsigned char stream_block[strlen(msg_to_send)];
	mbedtls_aes_context ctr;
    mbedtls_aes_init( &ctr );
	mbedtls_aes_setkey_enc( &ctr, enc_key.key, 256 );
	mbedtls_aes_crypt_ctr( &ctr, strlen(msg_to_send), &nc_offset, nonce, stream_block, msg_to_send, encrypted_msg );
	mbedtls_aes_free( &ctr );
	printk("msg length: %d, enc msg length: %d\n", strlen(msg_to_send), strlen(encrypted_msg));
}

static void decrypt_key_aes_ctr(unsigned char* nonce, unsigned char* encrypted_key) {
    size_t nc_offset = 0;
    unsigned char stream_block[PAYLOAD_SIZE];
    unsigned char key[33];
	mbedtls_aes_context ctr;
    mbedtls_aes_init( &ctr );
	mbedtls_aes_setkey_enc( &ctr, private_key, 256 );
	mbedtls_aes_crypt_ctr( &ctr, strlen(encrypted_key), &nc_offset, nonce, stream_block, encrypted_key, key );
	mbedtls_aes_free( &ctr );
	key[32] = '\0';
	strcpy(enc_key.key, key);
}

static void request_new_key() {
	unsigned char payload[PAYLOAD_SIZE];
	unsigned char pwdhash[20];
	mbedtls_sha1(PASSWORD, sizeof(PASSWORD), pwdhash);
	unsigned char b64pwdhash[PAYLOAD_SIZE];
	unsigned int olen = PAYLOAD_SIZE;

	mbedtls_base64_encode( b64pwdhash, PAYLOAD_SIZE, &olen, pwdhash, sizeof(pwdhash) );
	snprintf(payload, sizeof(payload), "{\"u\": \"%s\", \"p\": \"%s\",\"l\": %d}", USERNAME, b64pwdhash, 32);
	printk("\nkey request:%s\n", payload);
	prepare_msg(&pub_ctx.pub_msg, MQTT_QoS0, NEW_KEY_TOPIC, payload);
 	int rc = mqtt_tx_publish(&pub_ctx.mqtt_ctx, &pub_ctx.pub_msg);
 	PRINT_RESULT("mqtt_tx_publish", rc);
 	if (rc == 0) {
 		requesting = true;
 	}
}

static bool check_key() {
	printk("Checking key.\n");
	if (enc_key.kid == 0) {
		printk("Key has not been received yet.\n");
		if (!requesting) {
			request_new_key();
		}
		return false;
	}

	s64_t time_left = (enc_key.ts - k_uptime_get()) / (60 * 1000);
	printk("Key expires in %lld minutes.", time_left);
	if (k_uptime_get() > enc_key.ts) {
		printk("Key has expired. Requesting new key.\n");
		request_new_key();
		return false;
	}

	if (strlen(enc_key.key) != 32) {
		printk("Incorrect key length. Requesting new key.\n");
		request_new_key();
	}

	return true;
}

static void do_encryption(char* msg) {
	unsigned char nonce[9];
	unsigned char nonce_to_be_used[17];
	printk("\nMessage to send: %s\n", msg);
	int loop_count = 0;
	do {
		memset(&encrypted_msg, 0x00, sizeof(encrypted_msg));
		memset(&nonce_to_be_used, 0x00, sizeof(nonce_to_be_used));
		rand_string(nonce, sizeof(nonce));
		strcpy(nonce_to_be_used, nonce);
		strcat(nonce_to_be_used, "00000000");
		encrypt_aes_ctr(nonce_to_be_used, msg);
		loop_count++;
	} while(strlen(msg) != strlen(encrypted_msg) && loop_count < 10);

	size_t msg_size = strlen(encrypted_msg);

	unsigned char payload[PAYLOAD_SIZE];
	unsigned char tmp[msg_size + sizeof(nonce) + 3];
	int msb = enc_key.kid / 256;
	unsigned char keyid_msb = (unsigned char) msb;
	int lsb = enc_key.kid % 256;
	unsigned char keyid_lsb = (unsigned char) lsb;
	snprintf(tmp, sizeof(tmp), "%c%c%s%s", keyid_msb, keyid_lsb, nonce, encrypted_msg);
 	printk("\nEncrypted message with nonce: %s\n\n", tmp);

	int num_fragments = sizeof(tmp) / (PAYLOAD_SIZE-2);
	if (sizeof(tmp) % PAYLOAD_SIZE != 0)
		num_fragments++;

	for (i = 1; i <= num_fragments; i++) {
		char fragment_offset = (char) i;
		if (i == num_fragments)
			fragment_offset = 0xff;
		snprintf(payload, sizeof(payload), "%c%s", fragment_offset, tmp + ((PAYLOAD_SIZE-2)*(i-1)));
 		// printk("\nmsg fragment %d:%s\n", i, payload);
		prepare_msg(&pub_ctx.pub_msg, MQTT_QoS0, TOPIC, payload);
	 	int rc = mqtt_tx_publish(&pub_ctx.mqtt_ctx, &pub_ctx.pub_msg);
	 	PRINT_RESULT("mqtt_tx_publish", rc);
	 	if (rc < 0) 
	 		break;
		k_sleep(1000);
	}
}

void message_thread()
{
	int index = 0;
	while(true) {
 		// k_sleep(1000);
		k_mutex_lock(&pub_data, K_FOREVER);

		if (new_msg_input) {
			if (check_key()) {
				// do_encryption(msgs_to_send[index]);
				do_encryption(input_msg);
				index++;
				if (index == NELEMENTS(msgs_to_send))
					index = 0;
				new_msg_input = false;
			}
		}
		
		k_mutex_unlock(&pub_data);	
		k_sem_give(&pub_sem);
		k_sleep(APP_SLEEP_MSECS);
	}
}

static void register_device() {
	unsigned char pwdhash[20];
	mbedtls_sha1(PASSWORD, sizeof(PASSWORD), pwdhash);
	unsigned char b64pwdhash[PAYLOAD_SIZE];
	unsigned char register_payload[PAYLOAD_SIZE];
	unsigned int olen = PAYLOAD_SIZE;

	mbedtls_base64_encode( b64pwdhash, PAYLOAD_SIZE, &olen, pwdhash, sizeof(pwdhash) );
	snprintf(register_payload, PAYLOAD_SIZE, "{\"u\":\"%s\",\"p\":\"%s\"}", USERNAME, b64pwdhash);
	printk("Register payload: %s\n", register_payload);

	prepare_msg(&pub_ctx.pub_msg, MQTT_QoS0, REGISTER_TOPIC, register_payload);
 	int rc = mqtt_tx_publish(&pub_ctx.mqtt_ctx, &pub_ctx.pub_msg);
 	PRINT_RESULT("mqtt_tx_publish", rc);
	registered = true;
}

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

static int subscribe_cb(struct mqtt_ctx *ctx, u16_t pkt_id,
		 u8_t items, enum mqtt_qos qos[])
{
	/* Successful subscription to MQTT topic */

	printk("[%s:%d] <%s> packet id: %u\n", __func__, __LINE__, "MQTT_SUBACK", pkt_id);
	return 0;
}

static int unsubscribe_cb(struct mqtt_ctx *ctx, u16_t pkt_id)
{
	printk("[%s:%d] <%s> packet id: %u\n", __func__, __LINE__, "MQTT_UNSUBACK", pkt_id);
	return 0;
}

static int publish_tx_cb(struct mqtt_ctx *mqtt_ctx, u16_t pkt_id,
		      enum mqtt_packet type)
{
	const char *str;
	int rc = 0;

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

	printk("[%s:%d] <%s> packet id: %u\n", __func__, __LINE__, str, pkt_id);

	return rc;
}

static bool starts_with(const char *pre, const char *str)
{
    return strncmp(pre, str, strlen(pre)) == 0;
}

static void get_registered(char *json, int json_len) {

	struct json_reg_params {
			char* k;
			char* t;
		};

	static const struct json_obj_descr json_reg_descr_params[] = {
		JSON_OBJ_DESCR_PRIM(struct json_reg_params, k, JSON_TOK_STRING),
		JSON_OBJ_DESCR_PRIM(struct json_reg_params, t, JSON_TOK_STRING),
	};

	struct json_reg_params rx_json_reg={};

	json_obj_parse(json, json_len, json_reg_descr_params, ARRAY_SIZE(json_reg_descr_params), &rx_json_reg);
}

static void msg_received(char *msg) {

}

static void input_msg_received(char *msg) {
	printk("Input message received: %s", msg);
	memset(&input_msg, 0x00, sizeof(input_msg));
	if (starts_with("rand", msg)) {
		msg = msg + 5;
		int rand_length = atoi(msg);
		char rand_str[rand_length]; 
		rand_string(rand_str, rand_length);
		printk("rand str (%d): %s", rand_length, rand_str);
		// do_encryption(rand_str);
		strncpy(input_msg, rand_str, strlen(rand_str));
	} else {
		// do_encryption(msg);
		strncpy(input_msg, msg, strlen(msg));
	}
	new_msg_input = true;
}

static void new_key_received(char *json, int json_len) {
	printk("new key response:%s\n", json);

	static const struct json_obj_descr json_key_descr_params[] = {
		JSON_OBJ_DESCR_PRIM(struct encryption_key, k, JSON_TOK_STRING),
		JSON_OBJ_DESCR_PRIM(struct encryption_key, t, JSON_TOK_NUMBER),
		JSON_OBJ_DESCR_PRIM(struct encryption_key, kid, JSON_TOK_NUMBER),
	};

	json_obj_parse(json, json_len, json_key_descr_params, ARRAY_SIZE(json_key_descr_params), &enc_key);

	s64_t time_now = k_uptime_get();
	enc_key.ts = time_now + enc_key.t;

	unsigned char nonce[9];
	unsigned char b64decoded[PAYLOAD_SIZE];
	strncpy(nonce, enc_key.k, sizeof(nonce));
	nonce[8] = '\0';
	unsigned char nonce_counter[17];
	strncpy(nonce_counter, nonce, sizeof(nonce));
	strcat(nonce_counter, "00000000");
	// nonce_counter[16] = '\0';
	unsigned char *b64 = enc_key.k + 8;
	strcpy(enc_key.nonce, nonce_counter);

	unsigned int olen = PAYLOAD_SIZE;
	mbedtls_base64_decode( b64decoded, PAYLOAD_SIZE, &olen, b64, strlen(b64) );

	decrypt_key_aes_ctr(nonce_counter, b64decoded);

	printk("[%s:%d] parsed params: msg:%s, kid:%d, ts:%lld, nonce: %s, key:%s\n",
	__func__, __LINE__, enc_key.k, enc_key.kid, enc_key.ts, enc_key.nonce, enc_key.key);
	requesting = false;
}

static void handleResponse(char *topic, char *msg, int msg_len) {
	// if (starts_with(USERNAME, topic)) {
	// 	get_registered(msg, msg_len);
	// } else 
	if (starts_with(private_topic, topic)) {
		new_key_received(msg, msg_len);
	} else if (starts_with(TOPIC, topic)) {
		msg_received(msg);
	} else if (starts_with(input_topic, topic)) {
		input_msg_received(msg);
	}
}

static int publish_rx_cb(struct mqtt_ctx *ctx, struct mqtt_publish_msg *msg,
		  u16_t pkt_id, enum mqtt_packet type)
{
	const char *str;
	int rc = 0;

	/* Received a MQTT message published to a topic to which
	 * we have subscribed. In this case, this will mean an RPC
	 * request originated from our thingsboard instance. */

	switch (type) {
	case MQTT_PUBLISH:
		str = "MQTT_PUBLISH";
		break;
	default:
		rc = -EINVAL;
		str = "Invalid or unsupported MQTT packet";
	}

	msg->msg[msg->msg_len] = 0;

	printk("[%s:%d] <%s> packet id: %u\n    msg: %s\n\n",
		__func__, __LINE__, str, pkt_id, msg->topic);

	handleResponse(msg->topic, msg->msg, msg->msg_len);

	return rc;
}

static void malformed_cb(struct mqtt_ctx *mqtt_ctx, u16_t pkt_type)
{
	printk("[%s:%d] pkt_type: %u\n", __func__, __LINE__, pkt_type);
}

static char *get_message_payload(enum mqtt_qos qos, unsigned char* payload) 
{
	static char pl[PAYLOAD_SIZE];
	snprintf(pl, sizeof(pl), "%s\n", payload);
	return payload;
}

static void prepare_msg(struct mqtt_publish_msg *pub_msg,
				     enum mqtt_qos qos, unsigned char* topic, unsigned char* payload)
{
	/* MQTT message payload may be anything, we use C strings */
	pub_msg->msg = get_message_payload(qos, payload);
	/* Payload's length */
	pub_msg->msg_len = strlen(pub_msg->msg);
	/* MQTT Quality of Service */
	pub_msg->qos = qos;
	/* Message's topic */
	pub_msg->topic = topic;
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
	pub_ctx.mqtt_ctx.publish_tx = publish_tx_cb;
	pub_ctx.mqtt_ctx.publish_rx = publish_rx_cb;
	pub_ctx.mqtt_ctx.subscribe = subscribe_cb;

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

		rc = mqtt_init(&pub_ctx.mqtt_ctx, MQTT_APP_PUBLISHER_SUBSCRIBER);
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

		const char *private_topic_arr[] = {private_topic};
		const char *input_topic_arr[] = {input_topic};
		const enum mqtt_qos QOS[] = {MQTT_QoS0};

		rc = mqtt_tx_subscribe(&pub_ctx.mqtt_ctx, sys_rand32_get(), 1,
		private_topic_arr, QOS);
		PRINT_RESULT("mqtt_tx_subscribe", rc);
		rc = mqtt_tx_subscribe(&pub_ctx.mqtt_ctx, sys_rand32_get(), 1,
		input_topic_arr, QOS);
		PRINT_RESULT("mqtt_tx_subscribe", rc);

		do {
			bool data_changed = false;
			k_mutex_lock(&pub_data, K_FOREVER);

			if (message_changed) {
				//prepare_msg(&pub_ctx.pub_msg, MQTT_QoS0);
				message_changed=false;
				data_changed = true;
			}

			k_mutex_unlock(&pub_data);

			if (data_changed) {
				//rc = mqtt_tx_publish(&pub_ctx.mqtt_ctx, &pub_ctx.pub_msg);
				//PRINT_RESULT("mqtt_tx_publish", rc);
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
