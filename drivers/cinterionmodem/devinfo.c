/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2008-2011  Intel Corporation. All rights reserved.
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

#include <string.h>
#include <glib.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/devinfo.h>

#include "gatchat.h"
#include "gatresult.h"

#include "cinterionmodem.h"
#include "modemmodel.h"

static const char *gcap_prefix[] = { "+GCAP:", NULL };

struct cint_devinfo_data {
	GAtChat *chat;
	guint gcap_timer;
	unsigned int modem;
};

static void attr_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_devinfo_query_cb_t cb = cbd->cb;
	const char *prefix = cbd->user;
	struct ofono_error error;
	const char *attr;

	cint_util_decode_at_error(&error, g_at_result_final_response(result));

	if (!ok) {
		cb(&error, NULL, cbd->data);
		return;
	}

	if (cint_util_parse_attr(result, prefix, &attr) == FALSE) {
		CALLBACK_WITH_FAILURE(cb, NULL, cbd->data);
		return;
	}

	cb(&error, attr, cbd->data);
}

static void cint_query_manufacturer(struct ofono_devinfo *info,
				ofono_devinfo_query_cb_t cb, void *data)
{
	struct cb_data *cbd = cb_data_new(cb, data);
	struct cint_devinfo_data *did = ofono_devinfo_get_data(info);

	cbd->user = "+CGMI:";

	if (g_at_chat_send(did->chat, "AT+CGMI", NULL, attr_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, NULL, data);
}

static void cint_query_model(struct ofono_devinfo *info,
				ofono_devinfo_query_cb_t cb, void *data)
{
	struct cb_data *cbd = cb_data_new(cb, data);
	struct cint_devinfo_data *did = ofono_devinfo_get_data(info);

	cbd->user = "+CGMM:";

	if (g_at_chat_send(did->chat, "AT+CGMM", NULL, attr_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, NULL, data);
}

static void cint_query_revision(struct ofono_devinfo *info,
				ofono_devinfo_query_cb_t cb, void *data)
{
	struct cb_data *cbd = cb_data_new(cb, data);
	struct cint_devinfo_data *did = ofono_devinfo_get_data(info);

	cbd->user = "+CGMR:";

	if (g_at_chat_send(did->chat, "AT+CGMR", NULL, attr_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, NULL, data);
}

static void cint_query_serial(struct ofono_devinfo *info,
				ofono_devinfo_query_cb_t cb, void *data)
{
	struct cb_data *cbd = cb_data_new(cb, data);
	struct cint_devinfo_data *did = ofono_devinfo_get_data(info);
	

	cbd->user = "+CGSN:";

	if (g_at_chat_send(did->chat, "AT+CGSN", NULL, attr_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, NULL, data);
}

static void capability_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct ofono_devinfo *info = user_data;
	
	ofono_devinfo_register(info);
}

static gboolean cint_gcap_delay_cb(gpointer user_data)
{
	struct ofono_devinfo *info = user_data;
	struct cint_devinfo_data *did = ofono_devinfo_get_data(info);
	did->gcap_timer = 0;

	g_at_chat_send(did->chat, "AT+GCAP", gcap_prefix,
					capability_cb, info, NULL);

	return FALSE;
}

static int cint_devinfo_probe(struct ofono_devinfo *info, unsigned int vendor,
				void *data)
{
	GAtChat *chat = g_at_chat_clone(data);
	struct cint_devinfo_data *did = g_try_new0(struct cint_devinfo_data, 1);
	did->chat = chat;
	did->modem = vendor;

	ofono_devinfo_set_data(info, did);

	did->gcap_timer = g_timeout_add_seconds(5, cint_gcap_delay_cb, info);

	return 0;
}

static void cint_devinfo_remove(struct ofono_devinfo *info)
{
	struct cint_devinfo_data *did = ofono_devinfo_get_data(info);

	ofono_devinfo_set_data(info, NULL);

	if (did->gcap_timer != 0)
		g_source_remove(did->gcap_timer);

	g_at_chat_unref(did->chat);
	g_free(did);
}

static struct ofono_devinfo_driver driver = {
	.name			= "cinterionmodem",
	.probe			= cint_devinfo_probe,
	.remove			= cint_devinfo_remove,
	.query_manufacturer	= cint_query_manufacturer,
	.query_model		= cint_query_model,
	.query_revision		= cint_query_revision,
	.query_serial		= cint_query_serial,
};

void cint_devinfo_init(void)
{
	ofono_devinfo_driver_register(&driver);
}

void cint_devinfo_exit(void)
{
	ofono_devinfo_driver_unregister(&driver);
}
