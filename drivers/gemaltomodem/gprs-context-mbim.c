/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2008-2011  Intel Corporation. All rights reserved.
 *  Copyright (C) 2018 Gemalto M2M
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/gprs-context.h>

#include <glib.h>

#include "drivers/mbimmodem/mbim.h"
#include "drivers/mbimmodem/mbim-message.h"
#include "drivers/mbimmodem/mbimmodem.h"

#include "gatchat.h"
#include "gatresult.h"

#include <ofono/gemalto.h>

static const char *cgpaddr_prefix[] = { "+CGPADDR:", NULL };
static const char *cgcontrdp_prefix[] = { "+CGCONTRDP:", NULL };

enum state {
	STATE_IDLE,
	STATE_ENABLING,
	STATE_DISABLING,
	STATE_ACTIVE,
};

struct gprs_context_data {
	struct mbim_device *device;
	unsigned int active_context;
	enum ofono_gprs_proto proto;
	enum state state;
	ofono_gprs_context_cb_t cb;
	void *cb_data;
	GAtChat *chat;
	unsigned int at_cid;
	char address[64];
	char netmask[64];
	char gateway[64];
	char dns1[64];
	char dns2[64];
};

static uint32_t proto_to_context_ip_type(enum ofono_gprs_proto proto)
{
	switch (proto) {
	case OFONO_GPRS_PROTO_IP:
		return 1; /* MBIMContextIPTypeIPv4 */
	case OFONO_GPRS_PROTO_IPV6:
		return 2; /* MBIMContextIPTypeIPv6 */
	case OFONO_GPRS_PROTO_IPV4V6:
		return 3; /* MBIMContextIPTypeIPv4v6 */
	}

	return 0;
}

static uint32_t auth_method_to_auth_protocol(enum ofono_gprs_auth_method method)
{
	switch (method) {
	case OFONO_GPRS_AUTH_METHOD_CHAP:
		return 2; /* MBIMAuthProtocolChap */
	case OFONO_GPRS_AUTH_METHOD_PAP:
		return 1; /* MBIMAuthProtocolPap */
	case OFONO_GPRS_AUTH_METHOD_NONE:
		return 0; /* MBIMAUthProtocolNone */
	}

	return 0; /* MBIMAUthProtocolNone */
}

static void mbim_deactivate_cb(struct mbim_message *message, void *user)
{
	struct ofono_gprs_context *gc = user;
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);

	DBG("");

	gcd->active_context = 0;
	gcd->state = STATE_IDLE;

	if (!gcd->cb)
		return;

	if (mbim_message_get_error(message) != 0)
		CALLBACK_WITH_FAILURE(gcd->cb, gcd->cb_data);
	else
		CALLBACK_WITH_SUCCESS(gcd->cb, gcd->cb_data);
}

static void gemalto_gprs_deactivate_primary(struct ofono_gprs_context *gc,
					unsigned int cid,
					ofono_gprs_context_cb_t cb, void *data)
{
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	struct mbim_message *message;

	DBG("cid %u", cid);

	gcd->state = STATE_DISABLING;
	gcd->cb = cb;
	gcd->cb_data = data;

	message = mbim_message_new(mbim_uuid_basic_connect,
					MBIM_CID_CONNECT,
					MBIM_COMMAND_TYPE_SET);
	mbim_message_set_arguments(message, "uusssuuu16y",
					cid, 0, NULL, NULL, NULL, 0, 0, 0,
					mbim_context_type_internet);

	if (mbim_device_send(gcd->device, GPRS_CONTEXT_GROUP, message,
				mbim_deactivate_cb, gc, NULL) > 0)
		return;

	mbim_message_unref(message);

	if (cb)
		CALLBACK_WITH_FAILURE(cb, data);
}

static void contrdp_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct ofono_gprs_context *gc = user_data;
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	int cid, bearer_id;
	const char *apn, *ip_mask, *gw;
	const char *dns1, *dns2;
	GAtResultIter iter;
	gboolean found = FALSE;
	struct ofono_modem *modem;
	const char *interface;
	const char *dns[3];


	DBG("ok %d", ok);

	if (!ok) {
		DBG("Unable to get context dynamic paramerers");
		goto skip;
	}

	g_at_result_iter_init(&iter, result);

	while (g_at_result_iter_next(&iter, "+CGCONTRDP:")) {
		if (!g_at_result_iter_next_number(&iter, &cid))
			goto skip;
		if (!g_at_result_iter_next_number(&iter, &bearer_id))
			goto skip;
		if (!g_at_result_iter_next_string(&iter, &apn))
			goto skip;
		if (!g_at_result_iter_next_string(&iter, &ip_mask))
			goto skip;
		if (!g_at_result_iter_next_string(&iter, &gw))
			goto skip;
		if (!g_at_result_iter_next_string(&iter, &dns1))
			goto skip;
		if (!g_at_result_iter_next_string(&iter, &dns2))
			goto skip;

		if ((unsigned int) cid == gcd->active_context) {
			found = TRUE;

			/* if it was already set by CGPADDR, we keep it */
			if (strcmp(gcd->address, "") != 0)
				strncpy(gcd->netmask,
					&ip_mask[strlen(gcd->address) + 1],
					sizeof(gcd->netmask));

			strncpy(gcd->gateway, gw, sizeof(gcd->gateway));
			strncpy(gcd->dns1, dns1, sizeof(gcd->dns1));
			strncpy(gcd->dns2, dns2, sizeof(gcd->dns2));
		}
	}

	if (found == FALSE)
		goto skip;

	ofono_info("MASK: %s", gcd->netmask);
	ofono_info("GW: %s", gcd->gateway);
	ofono_info("DNS: %s, %s", gcd->dns1, gcd->dns2);

	dns[0] = gcd->dns1;
	dns[1] = gcd->dns2;
	dns[2] = 0;

	ofono_gprs_context_set_ipv4_address(gc, gcd->address, TRUE);
	ofono_gprs_context_set_ipv4_netmask(gc, gcd->netmask);
	ofono_gprs_context_set_ipv4_gateway(gc, gcd->gateway);
	ofono_gprs_context_set_ipv4_dns_servers(gc, dns);

skip:
	gcd->state = STATE_ACTIVE;
	modem = ofono_gprs_context_get_modem(gc);
	interface = ofono_modem_get_string(modem, "NetworkInterface");
	ofono_gprs_context_set_interface(gc, interface);

	if (*gcd->address) {
		ofono_info("IP: %s", gcd->address);
		ofono_gprs_context_set_ipv4_address(gc, gcd->address, TRUE);
	} else {
		/* DHCP in this case */
		ofono_gprs_context_set_ipv4_address(gc, NULL, FALSE); /* DHCP */
	}

	CALLBACK_WITH_SUCCESS(gcd->cb, gcd->cb_data);
	gcd->cb = NULL;
	gcd->cb_data = NULL;
}

static void address_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct ofono_gprs_context *gc = user_data;
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	int cid;
	const char *address;
	char buf[64];
	GAtResultIter iter;

	DBG("ok %d", ok);

	memset(gcd->address, 0, sizeof(gcd->address));

	if (!ok) {
		DBG("Unable to get context address");
		goto skip;
	}

	g_at_result_iter_init(&iter, result);

	// TODO: define the cid properly and uncomment the lines below.
	// as fallback, get the first IP that shows up

	while (g_at_result_iter_next(&iter, "+CGPADDR:")) {

		if (!g_at_result_iter_next_number(&iter, &cid))
			continue;

	//	if ((unsigned int) cid != gcd->active_context)
	//		continue;

		if (!g_at_result_iter_next_string(&iter, &address))
			continue;

		strncpy(gcd->address, address, sizeof(gcd->address));
		break; // we got an address, we are happy
	}

skip:

	sprintf(buf, "AT+CGCONTRDP"); // ask for all, then filter later
	if (g_at_chat_send(gcd->chat, buf, cgcontrdp_prefix,
					contrdp_cb, gc, NULL) > 0)
		return;
}

static void mbim_ip_configuration_cb(struct mbim_message *message, void *user)
{
	struct ofono_gprs_context *gc = user;
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	struct ofono_modem *modem = ofono_gprs_context_get_modem(gc);
	const char *interface;
	uint32_t session_id;
	uint32_t ipv4_config_available;
	uint32_t ipv6_config_available;
	uint32_t n_ipv4_addr;
	uint32_t ipv4_addr_offset;
	uint32_t n_ipv6_addr;
	uint32_t ipv6_addr_offset;
	uint32_t ipv4_gw_offset;
	uint32_t ipv6_gw_offset;
	uint32_t n_ipv4_dns;
	uint32_t ipv4_dns_offset;
	uint32_t n_ipv6_dns;
	uint32_t ipv6_dns_offset;
	uint32_t ipv4_mtu;
	uint32_t ipv6_mtu;

	struct in6_addr ipv6;
	struct in_addr ipv4;
	char buf[INET6_ADDRSTRLEN];

	DBG("%u", mbim_message_get_error(message));

	if (mbim_message_get_error(message) != 0)
		goto error;

	if (!mbim_message_get_arguments(message, "uuuuuuuuuuuuuuu",
				&session_id,
				&ipv4_config_available, &ipv6_config_available,
				&n_ipv4_addr, &ipv4_addr_offset,
				&n_ipv6_addr, &ipv6_addr_offset,
				&ipv4_gw_offset, &ipv6_gw_offset,
				&n_ipv4_dns, &ipv4_dns_offset,
				&n_ipv6_dns, &ipv6_dns_offset,
				&ipv4_mtu, &ipv6_mtu))
		goto error;

	if (gcd->proto == OFONO_GPRS_PROTO_IPV6)
		goto ipv6;

	if (ipv4_config_available & 0x1) { /* Address Info present */
		uint32_t prefix;

		if (!mbim_message_get_ipv4_element(message, ipv4_addr_offset,
							&prefix, &ipv4))
			goto error;

		inet_ntop(AF_INET, &ipv4, buf, sizeof(buf));
		ofono_gprs_context_set_ipv4_address(gc, buf, TRUE);
		ofono_gprs_context_set_ipv4_prefix_length(gc, prefix);
	} else {
		char buf[64];

		/* we try via AT interface */
		sprintf(buf, "AT+CGPADDR"); // ask for all, then filter later

		if (g_at_chat_send(gcd->chat, buf, cgpaddr_prefix,
						address_cb, gc, NULL) > 0)
			return;

		ofono_gprs_context_set_ipv4_address(gc, NULL, FALSE);
	}

	if (ipv4_config_available & 0x2) { /* IPv4 Gateway info */
		if (!mbim_message_get_ipv4_address(message,
							ipv4_gw_offset, &ipv4))
			goto error;

		inet_ntop(AF_INET, &ipv4, buf, sizeof(buf));

		ofono_gprs_context_set_ipv4_gateway(gc, buf);
	}

	if (ipv4_config_available & 0x3) { /* IPv4 DNS Info */
		const char *dns[3];
		char dns1[INET_ADDRSTRLEN];
		char dns2[INET_ADDRSTRLEN];

		memset(dns, 0, sizeof(dns));

		if (n_ipv4_dns > 1) { /* Grab second DNS */
			if (!mbim_message_get_ipv4_address(message,
							ipv4_dns_offset + 4,
							&ipv4))
				goto error;

			inet_ntop(AF_INET, &ipv4, dns2, sizeof(dns2));
			dns[1] = dns2;
		}

		if (n_ipv4_dns > 0) { /* Grab first DNS */
			if (!mbim_message_get_ipv4_address(message,
							ipv4_dns_offset,
							&ipv4))
				goto error;

			inet_ntop(AF_INET, &ipv4, dns1, sizeof(dns1));
			dns[0] = dns1;

			ofono_gprs_context_set_ipv4_dns_servers(gc, dns);
		}
	}

	if (gcd->proto == OFONO_GPRS_PROTO_IP)
		goto done;
ipv6:
	if (ipv6_config_available & 0x1) { /* Address Info present */
		uint32_t prefix;

		if (!mbim_message_get_ipv6_element(message, ipv6_addr_offset,
							&prefix, &ipv6))
			goto error;

		inet_ntop(AF_INET6, &ipv6, buf, sizeof(buf));
		ofono_gprs_context_set_ipv6_address(gc, buf);
		ofono_gprs_context_set_ipv6_prefix_length(gc, prefix);
	}

	if (ipv6_config_available & 0x2) { /* IPv6 Gateway info */
		if (!mbim_message_get_ipv6_address(message,
							ipv6_gw_offset, &ipv6))
			goto error;

		inet_ntop(AF_INET6, &ipv6, buf, sizeof(buf));

		ofono_gprs_context_set_ipv6_gateway(gc, buf);
	}

	if (ipv6_config_available & 0x3) { /* IPv6 DNS Info */
		const char *dns[3];
		char dns1[INET6_ADDRSTRLEN];
		char dns2[INET6_ADDRSTRLEN];

		memset(dns, 0, sizeof(dns));

		if (n_ipv6_dns > 1) { /* Grab second DNS */
			if (!mbim_message_get_ipv6_address(message,
							ipv6_dns_offset + 16,
							&ipv6))
				goto error;

			inet_ntop(AF_INET6, &ipv6, dns2, sizeof(dns2));
			dns[1] = dns2;
		}

		if (n_ipv6_dns > 0) { /* Grab first DNS */
			if (!mbim_message_get_ipv6_address(message,
							ipv6_dns_offset,
							&ipv6))
				goto error;

			inet_ntop(AF_INET6, &ipv6, dns1, sizeof(dns1));
			dns[0] = dns1;

			ofono_gprs_context_set_ipv6_dns_servers(gc, dns);
		}
	}
done:

	gcd->state = STATE_ACTIVE;
	interface = ofono_modem_get_string(modem, "NetworkInterface");
	ofono_gprs_context_set_interface(gc, interface);

	CALLBACK_WITH_SUCCESS(gcd->cb, gcd->cb_data);
	gcd->cb = NULL;
	gcd->cb_data = NULL;
	return;

error:
	CALLBACK_WITH_FAILURE(gcd->cb, gcd->cb_data);
	gcd->state = STATE_IDLE;
	gcd->cb = NULL;
	gcd->cb_data = NULL;

	message = mbim_message_new(mbim_uuid_basic_connect,
					MBIM_CID_CONNECT,
					MBIM_COMMAND_TYPE_SET);
	mbim_message_set_arguments(message, "uusssuuu16y",
					gcd->active_context, 0,
					NULL, NULL, NULL, 0, 0, 0,
					mbim_context_type_internet);

	if (!mbim_device_send(gcd->device, GPRS_CONTEXT_GROUP, message,
				NULL, NULL, NULL))
		mbim_message_unref(message);
}

static void mbim_activate_cb(struct mbim_message *message, void *user)
{
	struct ofono_gprs_context *gc = user;
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);

	DBG("");

	if (mbim_message_get_error(message) != 0)
		goto error;

	message = mbim_message_new(mbim_uuid_basic_connect,
					MBIM_CID_IP_CONFIGURATION,
					MBIM_COMMAND_TYPE_QUERY);
	mbim_message_set_arguments(message, "uuuuuuuuuuuuuuu",
				gcd->active_context,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

	if (mbim_device_send(gcd->device, GPRS_CONTEXT_GROUP, message,
				mbim_ip_configuration_cb, gc, NULL) > 0)
		return;

error:
	CALLBACK_WITH_FAILURE(gcd->cb, gcd->cb_data);
	gcd->state = STATE_IDLE;
	gcd->cb = NULL;
	gcd->cb_data = NULL;
}

static void gemalto_gprs_activate_primary(struct ofono_gprs_context *gc,
				const struct ofono_gprs_primary_context *ctx,
				ofono_gprs_context_cb_t cb, void *data)
{
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	struct mbim_message *message;
	const char *username = NULL;
	const char *password = NULL;

	DBG("cid %u", ctx->cid);

	// TODO: add at+cgdaddr and at^sgauth commands here

	gcd->state = STATE_ENABLING;
	gcd->cb = cb;
	gcd->cb_data = data;
	gcd->active_context = ctx->cid;
	gcd->proto = ctx->proto;

	if (ctx->auth_method != OFONO_GPRS_AUTH_METHOD_NONE && ctx->username[0])
		username = ctx->username;

	if (ctx->auth_method != OFONO_GPRS_AUTH_METHOD_NONE && ctx->password[0])
		password = ctx->password;

	message = mbim_message_new(mbim_uuid_basic_connect,
					MBIM_CID_CONNECT,
					MBIM_COMMAND_TYPE_SET);
	mbim_message_set_arguments(message, "uusssuuu16y",
				ctx->cid,
				1, /* MBIMActivationCommandActivate */
				ctx->apn,
				username,
				password,
				0, /*MBIMCompressionNone */
				auth_method_to_auth_protocol(ctx->auth_method),
				proto_to_context_ip_type(ctx->proto),
				mbim_context_type_internet);

	if (mbim_device_send(gcd->device, GPRS_CONTEXT_GROUP, message,
				mbim_activate_cb, gc, NULL) > 0)
		return;

	mbim_message_unref(message);
	CALLBACK_WITH_FAILURE(cb, data);
}

static void gemalto_gprs_detach_shutdown(struct ofono_gprs_context *gc,
						unsigned int cid)
{
	DBG("");
	gemalto_gprs_deactivate_primary(gc, cid, NULL, NULL);
}

static void mbim_connect_notify(struct mbim_message *message, void *user)
{
	uint32_t session_id;
	uint32_t activation_state;
	uint32_t voice_call_state;
	uint32_t ip_type;
	uint8_t context_type[16];
	uint32_t nw_error;
	char uuidstr[37];

	DBG("");

	if (!mbim_message_get_arguments(message, "uuuu16yu",
					&session_id, &activation_state,
					&voice_call_state, &ip_type,
					context_type, &nw_error))
		return;

	DBG("session_id: %u, activation_state: %u, ip_type: %u",
			session_id, activation_state, ip_type);
	l_uuid_to_string(context_type, uuidstr, sizeof(uuidstr));
	DBG("context_type: %s, nw_error: %u", uuidstr, nw_error);
}

static int gemalto_gprs_context_probe(struct ofono_gprs_context *gc,
					unsigned int vendor, void *data)
{
	struct gemalto_mbim_composite *composite = data;
	struct mbim_device *device = composite->device;
	struct gprs_context_data *gcd;

	DBG("gemaltombim");

	if (!mbim_device_register(device, GPRS_CONTEXT_GROUP,
					mbim_uuid_basic_connect,
					MBIM_CID_CONNECT,
					mbim_connect_notify, gc, NULL))
		return -EIO;

	gcd = l_new(struct gprs_context_data, 1);
	gcd->device = mbim_device_ref(device);
	gcd->chat = g_at_chat_clone(composite->chat);
	gcd->at_cid = composite->at_cid;

	ofono_gprs_context_set_data(gc, gcd);

	return 0;
}

static void gemalto_gprs_context_remove(struct ofono_gprs_context *gc)
{
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);

	DBG("");

	ofono_gprs_context_set_data(gc, NULL);

	mbim_device_cancel_group(gcd->device, GPRS_CONTEXT_GROUP);
	mbim_device_unregister_group(gcd->device, GPRS_CONTEXT_GROUP);
	mbim_device_unref(gcd->device);
	gcd->device = NULL;
	g_at_chat_unref(gcd->chat);
	gcd->chat = NULL;
	l_free(gcd);
}

static const struct ofono_gprs_context_driver driver = {
	.name			= "gemaltomodemmbim",
	.probe			= gemalto_gprs_context_probe,
	.remove			= gemalto_gprs_context_remove,
	.activate_primary	= gemalto_gprs_activate_primary,
	.deactivate_primary	= gemalto_gprs_deactivate_primary,
	.detach_shutdown	= gemalto_gprs_detach_shutdown
};

extern void gemalto_gprs_context_mbim_init();
extern void gemalto_gprs_context_mbim_exit();

void gemalto_gprs_context_mbim_init(void)
{
	ofono_gprs_context_driver_register(&driver);
}

void gemalto_gprs_context_mbim_exit(void)
{
	ofono_gprs_context_driver_unregister(&driver);
}
