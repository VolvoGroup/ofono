/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2017  Intel Corporation. All rights reserved.
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

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

#include <ofono/modem.h>
#include <ofono/gprs-context.h>
#include <ofono/log.h>
#include <ofono/lte.h>

#include "gatchat.h"
#include "gatresult.h"

#include "atmodem.h"
#include "vendor.h"

struct lte_driver_data {
	GAtChat *chat;
	unsigned int vendor;
};

struct lte_cb_data {
	const struct ofono_lte_default_attach_info *info;
	ofono_lte_cb_t cb;
	const struct ofono_lte *lte;
	void *data;
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

static void at_lte_set_default_auth_info_cb(gboolean ok, GAtResult *result,
							gpointer user_data)
{
	struct lte_cb_data *lcbd = user_data;
	struct ofono_error error;
	ofono_lte_cb_t cb = lcbd->cb;
	void *data = lcbd->data;

	DBG("ok %d", ok);

	decode_at_error(&error, g_at_result_final_response(result));
	cb(&error, data);
}

static void gemalto_lte_set_default_auth_info(const struct ofono_lte *lte,
			const struct ofono_lte_default_attach_info *info,
			ofono_lte_cb_t cb, void *data)
{
	struct lte_cb_data *lcbd = data;
	void* ud = lcbd->data;
	struct lte_driver_data *ldd = ofono_lte_get_data(lte);
	struct ofono_modem *modem = ofono_lte_get_modem(lte);
	char buf[32 + OFONO_GPRS_MAX_USERNAME_LENGTH +
					OFONO_GPRS_MAX_PASSWORD_LENGTH +1];

	if(!gemalto_get_auth_command(modem, 1, info->auth_method,
			info->username, info->password, buf, sizeof(buf))) {
		g_free(lcbd);
		goto set_auth_failure;
	}

	if(g_at_chat_send(ldd->chat, buf, NULL, at_lte_set_default_auth_info_cb,
							lcbd, g_free) > 0)
		return;

set_auth_failure:
	CALLBACK_WITH_FAILURE(cb, ud);
}

static void at_lte_set_default_auth_info(const struct ofono_lte *lte,
			const struct ofono_lte_default_attach_info *info,
			ofono_lte_cb_t cb, void *data)
{
	struct lte_cb_data *lcbd = data;
	void* ud = lcbd->data;
	struct lte_driver_data *ldd = ofono_lte_get_data(lte);
	char buf[32 + OFONO_GPRS_MAX_USERNAME_LENGTH +
					OFONO_GPRS_MAX_PASSWORD_LENGTH +1];
	guint buflen = sizeof(buf);

	snprintf(buf, buflen, "AT+CGAUTH=0,");
	buflen-=strlen(buf);

	switch(info->auth_method) {
	case OFONO_GPRS_AUTH_METHOD_NONE:
		snprintf(buf+strlen(buf), buflen, "0");
		break;
	case OFONO_GPRS_AUTH_METHOD_PAP:
		snprintf(buf+strlen(buf), buflen, "1,\"%s\",\"%s\"",
						info->username, info->password);
		break;
	case OFONO_GPRS_AUTH_METHOD_CHAP:
		snprintf(buf+strlen(buf), buflen, "2,\"%s\",\"%s\"",
						info->username, info->password);
		break;
	default:
		g_free(lcbd);
		goto set_auth_failure;
		break;
	}

	if(g_at_chat_send(ldd->chat, buf, NULL, at_lte_set_default_auth_info_cb,
							lcbd, g_free) > 0)
		return;

set_auth_failure:
	CALLBACK_WITH_FAILURE(cb, ud);
}

static void at_lte_set_default_attach_info_cb(gboolean ok, GAtResult *result,
							gpointer user_data)
{
	struct lte_cb_data *lcbd = user_data;
	struct lte_driver_data *ldd = ofono_lte_get_data(lcbd->data);
	struct ofono_error error;

	DBG("ok %d", ok);

	if (ok) {
		switch (ldd->vendor) {
		case OFONO_VENDOR_GEMALTO:
			gemalto_lte_set_default_auth_info(lcbd->lte,
					lcbd->info, lcbd->cb, user_data);
			return;
			break;
		default:
			at_lte_set_default_auth_info(lcbd->lte,
					lcbd->info, lcbd->cb, user_data);
			return;
			break;
		}
	}

	decode_at_error(&error, g_at_result_final_response(result));
	lcbd->cb(&error, lcbd->data);
}

static void gemalto_lte_set_default_attach_info(const struct ofono_lte *lte,
			const struct ofono_lte_default_attach_info *info,
			ofono_lte_cb_t cb, void *data)
{
	struct lte_driver_data *ldd = ofono_lte_get_data(lte);
	struct ofono_modem *modem = ofono_lte_get_modem(lte);
	char buf[32 + OFONO_GPRS_MAX_APN_LENGTH  +1];
	struct lte_cb_data *lcbd;
	int gto_autoconf = ofono_modem_get_integer(modem, "Gemalto_Autoconf");

	/*
	 * to be completed. May require additional properties in the driver
	 * current values plan for Gemalto_Autoconf:
	 * 0: no autoconf (or no param set)
	 * 1: autoconf activated but fallback selected
	 * 2: autoconf activated, profile selected,
	 *		but custom attach apn required for this application
	 * 3-9: rfu
	 * 10: autoconf default bearer and ims
	 * 20: autoconf 10 + autoconf private apn
	 */
	if(gto_autoconf>=10) {
		CALLBACK_WITH_SUCCESS(cb, data);
		return;
	}

	lcbd = g_new0(struct lte_cb_data, 1);
	lcbd->data = data;
	lcbd->info = info;
	lcbd->cb = cb;
	lcbd->lte = lte;

	gemalto_get_cgdcont_command(modem, 1, info->proto, info->apn, buf,
								sizeof(buf));

	if (g_at_chat_send(ldd->chat, buf, NULL,
			at_lte_set_default_attach_info_cb, lcbd, NULL) > 0)
		return;

	CALLBACK_WITH_FAILURE(cb, data);
}

static void at_lte_set_default_attach_info(const struct ofono_lte *lte,
			const struct ofono_lte_default_attach_info *info,
			ofono_lte_cb_t cb, void *data)
{
	struct lte_driver_data *ldd = ofono_lte_get_data(lte);
	char buf[32 + OFONO_GPRS_MAX_APN_LENGTH  +1];
	struct lte_cb_data *lcbd;

	if(ldd->vendor==OFONO_VENDOR_GEMALTO) {
		gemalto_lte_set_default_attach_info(lte, info, cb, data);
		return;
	}

	lcbd = g_new0(struct lte_cb_data, 1);
	lcbd->data = data;
	lcbd->info = info;
	lcbd->cb = cb;
	lcbd->lte = lte;

	if (strlen(info->apn) > 0)
		snprintf(buf, sizeof(buf), "AT+CGDCONT=0,\"IP\",\"%s\"",
							info->apn);
	else
		snprintf(buf, sizeof(buf), "AT+CGDCONT=0,\"IP\"");

	if (g_at_chat_send(ldd->chat, buf, NULL,
			at_lte_set_default_attach_info_cb, lcbd, NULL) > 0)
		return;

	CALLBACK_WITH_FAILURE(cb, data);
}

static gboolean lte_delayed_register(gpointer user_data)
{
	ofono_lte_register(user_data);

	return FALSE;
}

static int at_lte_probe(struct ofono_lte *lte, unsigned int vendor, void *data)
{
	GAtChat *chat = data;
	struct lte_driver_data *ldd;

	DBG("at lte probe");

	ldd = g_try_new0(struct lte_driver_data, 1);
	if (!ldd)
		return -ENOMEM;

	ldd->chat = g_at_chat_clone(chat);
	ldd->vendor = vendor;

	ofono_lte_set_data(lte, ldd);

	g_idle_add(lte_delayed_register, lte);

	return 0;
}

static void at_lte_remove(struct ofono_lte *lte)
{
	struct lte_driver_data *ldd = ofono_lte_get_data(lte);

	DBG("at lte remove");

	g_at_chat_unref(ldd->chat);

	ofono_lte_set_data(lte, NULL);

	g_free(ldd);
}

static struct ofono_lte_driver driver = {
	.name				= "atmodem",
	.probe				= at_lte_probe,
	.remove				= at_lte_remove,
	.set_default_attach_info	= at_lte_set_default_attach_info,
};

void at_lte_init(void)
{
	ofono_lte_driver_register(&driver);
}

void at_lte_exit(void)
{
	ofono_lte_driver_unregister(&driver);
}
