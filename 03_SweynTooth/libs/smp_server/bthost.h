/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2012  Intel Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */
#ifndef __BTHOST
#define __BTHOST

#include <stdint.h>
#include <sys/uio.h>
#include "bluetooth.h"
#include "bt.h"
#include "util.h"
#include "rfcomm.h"

typedef void (*bthost_ready_cb)(void);

typedef void (*bthost_send_func)(const struct iovec *iov, int iovlen,
								 void *user_data);

typedef void (*bthost_new_conn_cb)(uint16_t handle, void *user_data);

typedef void (*bthost_cmd_complete_cb)(uint16_t opcode, uint8_t status,
									   const void *param, uint8_t len,
									   void *user_data);

typedef void (*bthost_cid_hook_func_t)(const void *data, uint16_t len,
									   void *user_data);

typedef void (*bthost_l2cap_rsp_cb)(uint8_t code, const void *data,
									uint16_t len, void *user_data);

typedef void (*bthost_l2cap_connect_cb)(uint16_t handle, uint16_t cid,
										void *user_data);

typedef void (*bthost_rfcomm_chan_hook_func_t)(const void *data, uint16_t len,
											   void *user_data);

typedef void (*bthost_rfcomm_connect_cb)(uint16_t handle, uint16_t cid,
										 void *user_data, bool status);

struct smp
{
	struct bthost *bthost;
	struct smp_conn *conn;
	struct bt_crypto *crypto;
};

struct smp_conn
{
	struct smp *smp;
	uint16_t handle;
	uint8_t addr_type;
	bool out;
	bool sc;
	bool initiator;
	uint8_t method;
	uint8_t local_key_dist;
	uint8_t remote_key_dist;
	uint8_t ia[6];
	uint8_t ia_type;
	uint8_t ra[6];
	uint8_t ra_type;
	uint8_t tk[16];
	uint8_t prnd[16];
	uint8_t rrnd[16];
	uint8_t pcnf[16];
	uint8_t preq[7];
	uint8_t prsp[7];
	uint8_t ltk[16];

	uint8_t local_sk[32];
	uint8_t local_pk[64];
	uint8_t remote_pk[64];
	uint8_t dhkey[32];
	uint8_t mackey[16];

	uint8_t passkey_notify;
	uint8_t passkey_round;
};

struct cid_hook
{
	uint16_t cid;
	bthost_cid_hook_func_t func;
	void *user_data;
	struct cid_hook *next;
};

struct rfcomm_chan_hook
{
	uint8_t channel;
	bthost_rfcomm_chan_hook_func_t func;
	void *user_data;
	struct rfcomm_chan_hook *next;
};

struct btconn
{
	uint16_t handle;
	uint8_t bdaddr[6];
	uint8_t addr_type;
	uint8_t encr_mode;
	uint16_t next_cid;
	uint64_t fixed_chan;
	struct l2conn *l2conns;
	struct rcconn *rcconns;
	struct cid_hook *cid_hooks;
	struct rfcomm_chan_hook *rfcomm_chan_hooks;
	struct btconn *next;
	void *smp_data;
};

struct l2conn
{
	uint16_t scid;
	uint16_t dcid;
	uint16_t psm;
	struct l2conn *next;
};

struct rcconn
{
	uint8_t channel;
	uint16_t scid;
	struct rcconn *next;
};

struct l2cap_pending_req
{
	uint8_t ident;
	bthost_l2cap_rsp_cb cb;
	void *user_data;
	struct l2cap_pending_req *next;
};

struct l2cap_conn_cb_data
{
	uint16_t psm;
	bthost_l2cap_connect_cb func;
	void *user_data;
	struct l2cap_conn_cb_data *next;
};

struct rfcomm_conn_cb_data
{
	uint8_t channel;
	bthost_rfcomm_connect_cb func;
	void *user_data;
	struct rfcomm_conn_cb_data *next;
};

struct rfcomm_connection_data
{
	uint8_t channel;
	struct btconn *conn;
	bthost_rfcomm_connect_cb cb;
	void *user_data;
};

struct cmd
{
	struct cmd *next;
	struct cmd *prev;
	uint8_t data[256 + sizeof(struct bt_hci_cmd_hdr)];
	uint16_t len;
};

struct cmd_queue
{
	struct cmd *head;
	struct cmd *tail;
};

struct bthost
{
	bool ready;
	bthost_ready_cb ready_cb;
	uint8_t bdaddr[6];
	uint8_t features[8];
	bthost_send_func send_handler;
	void *send_data;
	struct cmd_queue cmd_q;
	uint8_t ncmd;
	struct btconn *conns;
	bthost_cmd_complete_cb cmd_complete_cb;
	void *cmd_complete_data;
	bthost_new_conn_cb new_conn_cb;
	void *new_conn_data;
	struct rfcomm_connection_data *rfcomm_conn_data;
	struct l2cap_conn_cb_data *new_l2cap_conn_data;
	struct rfcomm_conn_cb_data *new_rfcomm_conn_data;
	struct l2cap_pending_req *l2reqs;
	uint8_t pin[16];
	uint8_t pin_len;
	uint8_t io_capability;
	uint8_t auth_req;
	bool reject_user_confirm;
	void *smp_data;
	bool conn_init;
	bool le;
	bool sc;
};

struct bthost *bthost_create(void);

void init_conn(struct bthost *bthost, uint16_t handle,
			   const uint8_t *bdaddr, uint8_t addr_type);

void btconn_free(struct btconn *conn);

void bthost_destroy(struct bthost *bthost);

void bthost_notify_ready(struct bthost *bthost, bthost_ready_cb cb);

void bthost_set_send_handler(struct bthost *bthost, bthost_send_func handler,
							 void *user_data);

void bthost_receive_h4(struct bthost *bthost, const void *data, uint16_t len);

void bthost_set_cmd_complete_cb(struct bthost *bthost,
								bthost_cmd_complete_cb cb, void *user_data);

void bthost_set_connect_cb(struct bthost *bthost, bthost_new_conn_cb cb,
						   void *user_data);

void bthost_hci_connect(struct bthost *bthost, const uint8_t *bdaddr,
						uint8_t addr_type);

void bthost_hci_ext_connect(struct bthost *bthost, const uint8_t *bdaddr,
							uint8_t addr_type);

void bthost_hci_disconnect(struct bthost *bthost, uint16_t handle,
						   uint8_t reason);

void bthost_add_cid_hook(struct bthost *bthost, uint16_t handle, uint16_t cid,
						 bthost_cid_hook_func_t func, void *user_data);

void bthost_send_cid(struct bthost *bthost, uint16_t handle, uint16_t cid,
					 const void *data, uint16_t len);
void bthost_send_cid_v(struct bthost *bthost, uint16_t handle, uint16_t cid,
					   const struct iovec *iov, int iovcnt);

bool bthost_l2cap_req(struct bthost *bthost, uint16_t handle, uint8_t req,
					  const void *data, uint16_t len,
					  bthost_l2cap_rsp_cb cb, void *user_data);

void bthost_write_scan_enable(struct bthost *bthost, uint8_t scan);

void bthost_set_adv_data(struct bthost *bthost, const uint8_t *data,
						 uint8_t len);
void bthost_set_adv_enable(struct bthost *bthost, uint8_t enable);

void bthost_set_ext_adv_data(struct bthost *bthost, const uint8_t *data,
							 uint8_t len);
void bthost_set_ext_adv_enable(struct bthost *bthost, uint8_t enable);

void bthost_write_ssp_mode(struct bthost *bthost, uint8_t mode);

void bthost_write_le_host_supported(struct bthost *bthost, uint8_t mode);

void bthost_request_auth(struct bthost *bthost, uint16_t handle);

void bthost_le_start_encrypt(struct bthost *bthost, uint16_t handle,
							 const uint8_t ltk[16]);

void bthost_add_l2cap_server(struct bthost *bthost, uint16_t psm,
							 bthost_l2cap_connect_cb func, void *user_data);

void bthost_set_sc_support(struct bthost *bthost, bool enable);

void bthost_set_pin_code(struct bthost *bthost, const uint8_t *pin,
						 uint8_t pin_len);
void bthost_set_io_capability(struct bthost *bthost, uint8_t io_capability);
uint8_t bthost_get_io_capability(struct bthost *bthost);
void bthost_set_auth_req(struct bthost *bthost, uint8_t auth_req);
uint8_t bthost_get_auth_req(struct bthost *bthost);
void bthost_set_reject_user_confirm(struct bthost *bthost, bool reject);
bool bthost_get_reject_user_confirm(struct bthost *bthost);

bool bthost_bredr_capable(struct bthost *bthost);

uint64_t bthost_conn_get_fixed_chan(struct bthost *bthost, uint16_t handle);

void bthost_add_rfcomm_server(struct bthost *bthost, uint8_t channel,
							  bthost_rfcomm_connect_cb func, void *user_data);

bool bthost_connect_rfcomm(struct bthost *bthost, uint16_t handle,
						   uint8_t channel, bthost_rfcomm_connect_cb func,
						   void *user_data);

void bthost_add_rfcomm_chan_hook(struct bthost *bthost, uint16_t handle,
								 uint8_t channel,
								 bthost_rfcomm_chan_hook_func_t func,
								 void *user_data);

void bthost_send_rfcomm_data(struct bthost *bthost, uint16_t handle,
							 uint8_t channel, const void *data,
							 uint16_t len);

void bthost_start(struct bthost *bthost);

/* LE SMP support */

void *smp_start(struct bthost *bthost);
void smp_stop(void *smp_data);
void *smp_conn_add(void *smp_data, uint16_t handle, const uint8_t *ia,
				   const uint8_t *ra, uint8_t addr_type, bool conn_init);
void smp_conn_del(void *conn_data);
void smp_conn_encrypted(void *conn_data, uint8_t encrypt);
void smp_data(void *conn_data, const void *data, uint16_t len);
void smp_bredr_data(void *conn_data, const void *data, uint16_t len);
int smp_get_ltk(void *smp_data, uint64_t rand, uint16_t ediv, uint8_t *ltk);
void smp_pair(void *conn_data, uint8_t io_cap, uint8_t auth_req);

#endif