/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2017 Piotr Haber. All rights reserved.
 *  Copyright (C) 2018 Sebastian Arnd. All rights reserved.
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>

#include <glib.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/gprs-context.h>

#include "gatchat.h"
#include "gatresult.h"

#include "gemaltomodem.h"

static const char *none_prefix[] = { NULL };

enum state {
	STATE_IDLE,
	STATE_ENABLING,
	STATE_DISABLING,
	STATE_ACTIVE,
};

struct gprs_context_data {
	GAtChat *chat;
	unsigned int active_context;
	char username[OFONO_GPRS_MAX_USERNAME_LENGTH + 1];
	char password[OFONO_GPRS_MAX_PASSWORD_LENGTH + 1];
	enum ofono_gprs_auth_method auth_method;
	enum state state;
	enum ofono_gprs_proto proto;
	char address[64];
	char netmask[64];
	char gateway[64];
	char dns1[64];
	char dns2[64];
	ofono_gprs_context_cb_t cb;
	void *cb_data;
	int use_wwan;
};

static gboolean gemalto_get_auth_command(struct ofono_modem *modem, int cid,
				enum ofono_gprs_auth_method auth_method,
				const char *username, const char *password,
				char *buf, guint buflen)
{
	int gto_auth = ofono_modem_get_integer(modem, "Gemalto_Auth");
	int len;
	/*
	 * 0: use cgauth
	 * 1: use sgauth(pwd, user)
	 * 2: use sgauth(user, pwd)
	 */

	int auth_type;

	switch (auth_method) {
	case OFONO_GPRS_AUTH_METHOD_PAP:
		auth_type=1;
		break;
	case OFONO_GPRS_AUTH_METHOD_CHAP:
		auth_type=2;
		break;
	case OFONO_GPRS_AUTH_METHOD_NONE:
	default:
		auth_type=0;
		break;
	}

	if (auth_type != 0 && (!*username || !*password))
		return FALSE;

	switch (gto_auth) {
	case 1:
	case 2:
		len = snprintf(buf, buflen, "AT^SGAUTH=%d", cid);
		break;
	case 0:
	default:
		len = snprintf(buf, buflen, "AT+CGAUTH=%d", cid);
		break;
	}

	buflen -= len;

	switch(auth_type) {
	case 0:

		switch (gto_auth) {
		case 2:
			snprintf(buf+len, buflen, ",0,\"\",\"\"");
			break;
		case 0:
		case 1:
		default:
			snprintf(buf+len, buflen, ",0");
			break;
		}
		break;

	case 1:
	case 2:

		switch (gto_auth) {
		case 1:
			snprintf(buf+len, buflen, ",%d,\"%s\",\"%s\"",
					auth_type, password, username);
			break;
		case 0:
		case 2:
		default:
			snprintf(buf+len, buflen, ",%d,\"%s\",\"%s\"",
					auth_type, username, password);
		}
		break;

	default:
		return FALSE;
	}

	return TRUE;
}

static void gemalto_get_cgdcont_command(struct ofono_modem *modem,
			guint cid, enum ofono_gprs_proto proto, const char *apn,
							char *buf, guint buflen)
{
	int len = snprintf(buf, buflen, "AT+CGDCONT=%u", cid);
	buflen-=len;

	if(!apn) /* it will remove the context */
		return;

	switch (proto) {
	case OFONO_GPRS_PROTO_IPV6:
		snprintf(buf+len, buflen, ",\"IPV6\",\"%s\"", apn);
		break;
	case OFONO_GPRS_PROTO_IPV4V6:
		snprintf(buf+len, buflen, ",\"IPV4V6\",\"%s\"", apn);
		break;
	case OFONO_GPRS_PROTO_IP:
	default:
		snprintf(buf+len, buflen, ",\"IP\",\"%s\"", apn);
		break;
	}
}

static void failed_setup(struct ofono_gprs_context *gc,
				GAtResult *result, gboolean deactivate)
{
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	struct ofono_error error;
	char buf[64];

	DBG("deactivate %d", deactivate);

	if (deactivate == TRUE) {

		if(gcd->use_wwan)
			sprintf(buf, "AT^SWWAN=0,%u", gcd->active_context);
		else
			sprintf(buf, "AT+CGACT=0,%u", gcd->active_context);

		g_at_chat_send(gcd->chat, buf, none_prefix, NULL, NULL, NULL);
	}

	gcd->active_context = 0;
	gcd->state = STATE_IDLE;

	if (result == NULL) {
		CALLBACK_WITH_FAILURE(gcd->cb, gcd->cb_data);
		return;
	}

	decode_at_error(&error, g_at_result_final_response(result));
	gcd->cb(&error, gcd->cb_data);
}

static void activate_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct ofono_gprs_context *gc = user_data;
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);

	DBG("ok %d", ok);

	if (!ok) {
		ofono_error("Unable activate context");
		/*
		 * We've reported sucess already, so can't just call
		 * failed_setup we call ofono_gprs_context_deactivated instead.
		 * Thats not a clean solution at all, but as it seems there is
		 * no clean way to determine whether it is possible to activate
		 * the context before issuing AT^SWWAN. A possible workaround
		 * might be to issue AT+CGACT=1 and AT+CGACT=0 and try if that
		 * works, before calling CALLBACK_WITH_SUCCESS.
		 */
		ofono_gprs_context_deactivated(gc, gcd->active_context);
		gcd->active_context = 0;
		gcd->state = STATE_IDLE;
		return;
	}
	/* We've reported sucess already */
}

static void setup_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct ofono_gprs_context *gc = user_data;
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	char buf[32 + OFONO_GPRS_MAX_USERNAME_LENGTH +
					OFONO_GPRS_MAX_PASSWORD_LENGTH +1];
	struct ofono_modem *modem = ofono_gprs_context_get_modem(gc);
	const char *interface;

	if (!ok) {
		ofono_error("Failed to setup context");
		failed_setup(gc, result, FALSE);
		return;
	}

	if(gemalto_get_auth_command(modem, gcd->active_context, gcd->auth_method,
			gcd->username, gcd->password, buf, sizeof(buf))) {
		if (!g_at_chat_send(gcd->chat, buf, none_prefix, NULL, NULL,
									NULL))
		goto error;
	}
	/*
	 * note that if the auth command is not ok we skip it and continue
	 * but if the sending fails we do an error
	 */

	if(gcd->use_wwan)
		sprintf(buf, "AT^SWWAN=1,%u", gcd->active_context);
	else
		sprintf(buf, "AT+CGACT=%u,1", gcd->active_context);

	if (g_at_chat_send(gcd->chat, buf, none_prefix,
					activate_cb, gc, NULL) > 0){

		interface = ofono_modem_get_string(modem, "NetworkInterface");

		ofono_gprs_context_set_interface(gc, interface);
		ofono_gprs_context_set_ipv4_address(gc, NULL, FALSE);

		/*
		 * We report sucess already here because some modules need a
		 * DHCP request to complete the AT^SWWAN command sucessfully
		 */
		gcd->state = STATE_ACTIVE;

		CALLBACK_WITH_SUCCESS(gcd->cb, gcd->cb_data);

		return;
	}

error:
	failed_setup(gc, NULL, FALSE);
}

static void gemaltowwan_gprs_activate_primary(struct ofono_gprs_context *gc,
				const struct ofono_gprs_primary_context *ctx,
				ofono_gprs_context_cb_t cb, void *data)
{
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	char buf[OFONO_GPRS_MAX_APN_LENGTH + 128];
	struct ofono_modem *modem = ofono_gprs_context_get_modem(gc);

	DBG("cid %u", ctx->cid);

	gcd->use_wwan=ofono_modem_get_integer(modem, "Gemalto_WWAN");
	gcd->active_context = ctx->cid;
	gcd->cb = cb;
	gcd->cb_data = data;
	memcpy(gcd->username, ctx->username, sizeof(ctx->username));
	memcpy(gcd->password, ctx->password, sizeof(ctx->password));
	gcd->state = STATE_ENABLING;
	gcd->proto = ctx->proto;
	gcd->auth_method = ctx->auth_method;

	gemalto_get_cgdcont_command(modem, ctx->cid, ctx->proto, ctx->apn, buf,
								sizeof(buf));

	if (g_at_chat_send(gcd->chat, buf, none_prefix,
				setup_cb, gc, NULL) > 0)
		return;

	CALLBACK_WITH_FAILURE(cb, data);
}

static void deactivate_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct ofono_gprs_context *gc = user_data;
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);

	DBG("ok %d", ok);

	gcd->active_context = 0;
	gcd->state = STATE_IDLE;

	CALLBACK_WITH_SUCCESS(gcd->cb, gcd->cb_data);
}

static void gemaltowwan_gprs_deactivate_primary(struct ofono_gprs_context *gc,
					unsigned int cid,
					ofono_gprs_context_cb_t cb, void *data)
{
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	char buf[64];

	DBG("cid %u", cid);

	gcd->state = STATE_DISABLING;
	gcd->cb = cb;
	gcd->cb_data = data;

	if(gcd->use_wwan)
		sprintf(buf, "AT^SWWAN=0,%u", gcd->active_context);
	else
		sprintf(buf, "AT+CGACT=%u,0", gcd->active_context);

	if (g_at_chat_send(gcd->chat, buf, none_prefix,
				deactivate_cb, gc, NULL) > 0)
		return;

	CALLBACK_WITH_SUCCESS(cb, data);
}

static void cgev_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_gprs_context *gc = user_data;
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	const char *event;
	int cid = 0;
	GAtResultIter iter;

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CGEV:"))
		return;

	if (!g_at_result_iter_next_unquoted_string(&iter, &event))
		return;

	if (!g_str_has_prefix(event, "ME PDN DEACT"))
		return;

	sscanf(event, "%*s %*s %*s %u", &cid);

	DBG("cid %d", cid);

	if ((unsigned int) cid != gcd->active_context)
		return;

	ofono_gprs_context_deactivated(gc, gcd->active_context);

	gcd->active_context = 0;
	gcd->state = STATE_IDLE;
}

static int gemaltowwan_gprs_context_probe(struct ofono_gprs_context *gc,
					unsigned int model, void *data)
{
	GAtChat *chat = data;
	struct gprs_context_data *gcd;
	struct ofono_modem *modem = ofono_gprs_context_get_modem(gc);

	DBG("");

	gcd = g_try_new0(struct gprs_context_data, 1);
	if (gcd == NULL)
		return -ENOMEM;

	if(modem)
		gcd->use_wwan=ofono_modem_get_integer(modem, "Gemalto_WWAN");
	gcd->chat = g_at_chat_clone(chat);
	ofono_gprs_context_set_data(gc, gcd);
	g_at_chat_register(chat, "+CGEV:", cgev_notify, FALSE, gc, NULL);

	return 0;
}

static void gemaltowwan_gprs_context_remove(struct ofono_gprs_context *gc)
{
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);

	DBG("");

	ofono_gprs_context_set_data(gc, NULL);

	g_at_chat_unref(gcd->chat);
	g_free(gcd);
}

static void gemaltowwan_gprs_detach_shutdown(struct ofono_gprs_context *gc,
					unsigned int cid)
{
	DBG("cid %u", cid);

	ofono_gprs_context_deactivated(gc, cid);
}

static struct ofono_gprs_context_driver driver = {
	.name			= "gemaltowwanmodem",
	.probe			= gemaltowwan_gprs_context_probe,
	.remove			= gemaltowwan_gprs_context_remove,
	.activate_primary	= gemaltowwan_gprs_activate_primary,
	.deactivate_primary	= gemaltowwan_gprs_deactivate_primary,
	.detach_shutdown	= gemaltowwan_gprs_detach_shutdown,
};

void gemaltowwan_gprs_context_init(void)
{
	ofono_gprs_context_driver_register(&driver);
}

void gemaltowwan_gprs_context_exit(void)
{
	ofono_gprs_context_driver_unregister(&driver);
}
