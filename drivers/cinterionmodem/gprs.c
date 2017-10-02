/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2008-2011  Intel Corporation. All rights reserved.
 *  Copyright (C) 2010  ST-Ericsson AB.
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
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <glib.h>

#include <ofono.h>
#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/gprs.h>
#include <ofono/sim.h>

#include "gatchat.h"
#include "gatresult.h"

#include "cinterionmodem.h"
#include "modemmodel.h"

static void cint_cgreg_test_cb(gboolean ok, GAtResult *result,
				gpointer user_data);

static const char *cgreg_prefix[] = { "+CGREG:", NULL };
static const char *cgdcont_prefix[] = { "+CGDCONT:", NULL };
static const char *none_prefix[] = { NULL };

struct cinterion_gprs_data {
	GAtChat *chat;
	unsigned int modem;
};

static void cint_cgatt_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_gprs_cb_t cb = cbd->cb;
	struct ofono_error error;

	DBG("ok %d", ok);

	cint_util_decode_at_error(&error, g_at_result_final_response(result));

	cb(&error, cbd->data);
}

static void cint_gprs_set_attached(struct ofono_gprs *gprs, int attached,
					ofono_gprs_cb_t cb, void *data)
{
        CALLBACK_WITH_SUCCESS(cb, data);
}

static void cint_cgreg_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_gprs_status_cb_t cb = cbd->cb;
	struct cinterion_gprs_data *gd = cbd->user;
	struct ofono_error error;
	int status;

	cint_util_decode_at_error(&error, g_at_result_final_response(result));

	if (!ok) {
		cb(&error, -1, cbd->data);
		return;
	}

	if (cint_util_parse_reg(result, "+CGREG:", NULL, &status,
				NULL, NULL, NULL, gd->modem) == FALSE) {
		CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
		return;
	}

	cb(&error, status, cbd->data);
}

static void cint_gprs_registration_status(struct ofono_gprs *gprs,
					ofono_gprs_status_cb_t cb,
					void *data)
{
	struct cinterion_gprs_data *gd = ofono_gprs_get_data(gprs);
	struct cb_data *cbd = cb_data_new(cb, data);
	cbd->user = gd;

	if (g_at_chat_send(gd->chat, "AT+CGREG?", cgreg_prefix,
				cint_cgreg_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, -1, data);
}

static void cgreg_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_gprs *gprs = user_data;
	struct cinterion_gprs_data *gd = ofono_gprs_get_data(gprs);
	int status;
	int bearer;

	if (cint_util_parse_reg_unsolicited(result, "+CGREG:", &status,
			NULL, NULL, &bearer, gd->modem) == FALSE)
		return;

	ofono_gprs_status_notify(gprs, status);

	/* If no bearer data is available, don't notify */
	if(bearer != -1)
		ofono_gprs_bearer_notify(gprs, bearer);
}

static void cgev_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_gprs *gprs = user_data;
	GAtResultIter iter;
	const char *event;

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CGEV:"))
		return;

	if (!g_at_result_iter_next_unquoted_string(&iter, &event))
		return;

	/* TODO: Handle NW REACT */

	if (g_str_equal(event, "NW DETACH") ||
		g_str_equal(event, "ME DETACH")) {
		ofono_gprs_detached_notify(gprs);
		return;
	}
}

static void cint_ciev_ceer_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_gprs *gprs = user_data;
	const char *report;
	GAtResultIter iter;

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CIEV: ceer,"))
		return;
	/*
	 * No need to check release cause group
	 * as we only subscribe to no. 5
	 */
	if (!g_at_result_iter_skip_next(&iter))
		return;
	if (!g_at_result_iter_next_string(&iter, &report))
		return;

	/* TODO: Handle more of these? */

	if (g_str_equal(report, "Regular deactivation")) {
		ofono_gprs_detached_notify(gprs);
		return;
	}
}

static void cint_ciev_bearer_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_gprs *gprs = user_data;
	int bearer;
	GAtResultIter iter;

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CIEV: psinfo,"))
		return;
	if (!g_at_result_iter_next_number(&iter, &bearer))
		return;

	/* Go from Cinterion representation to oFono representation */
	switch (bearer) {
	case 0: /* GPRS/EGPRS not available */
		/* Same as "no bearer"? */
		bearer = 0;
		break;
	case 1: /* GPRS available, ignore this one */
		return;
	case 2: /* GPRS attached */
		bearer = 1;
		break;
	case 3: /* EGPRS available, ignore this one */
		return;
	case 4: /* EGPRS attached */
		bearer = 2;
		break;
	case 5: /* UMTS available, ignore this one */
		return;
	case 6: /* UMTS attached */
		bearer = 3;
		break;
	case 7: /* HSDPA available, ignore this one */
		return;
	case 8: /* HSDPA attached */
		bearer = 5;
		break;
	case 9: /* HSDPA/HSUPA available, ignore this one */
		return;
	case 10: /* HSDPA/HSUPA attached */
		bearer = 6;
		break;
	/* TODO: Limit these cases to ALS3? */
	case 16: /* E-UTRA available, ignore this one */
		return;
	case 17: /* E-UTRA attached */
		bearer = 7;
		break;
	default: /* Assume that non-parsable values mean "no bearer" */
		bearer = 0;
		break;
	}

	ofono_gprs_bearer_notify(gprs, bearer);
}

static void gprs_initialized(gboolean ok, GAtResult *result,
						gpointer user_data)
{
	struct ofono_gprs *gprs = user_data;
	struct cinterion_gprs_data *gd = ofono_gprs_get_data(gprs);

	g_at_chat_register(gd->chat, "+CIEV: psinfo,", cint_ciev_bearer_notify,
						FALSE, gprs, NULL);
	g_at_chat_register(gd->chat, "+CIEV: ceer,", cint_ciev_ceer_notify,
						FALSE, gprs, NULL);
	g_at_chat_register(gd->chat, "+CGEV:", cgev_notify, FALSE, gprs, NULL);
	g_at_chat_register(gd->chat, "+CGREG:", cgreg_notify,
						FALSE, gprs, NULL);

	ofono_gprs_register(gprs);
}

static void cint_cgreg_test_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	struct ofono_gprs *gprs = user_data;
	struct cinterion_gprs_data *gd = ofono_gprs_get_data(gprs);
	gint range[2];
	GAtResultIter iter;
	int cgreg1 = 0;
	int cgreg2 = 0;
	const char *cmd;

	if (!ok)
		goto error;

	g_at_result_iter_init(&iter, result);

retry:
	if (!g_at_result_iter_next(&iter, "+CGREG:"))
		goto error;

	if (!g_at_result_iter_open_list(&iter))
		goto retry;

	while (g_at_result_iter_next_range(&iter, &range[0], &range[1])) {
		if (1 >= range[0] && 1 <= range[1])
			cgreg1 = 1;
		if (2 >= range[0] && 2 <= range[1])
			cgreg2 = 1;
	}

	g_at_result_iter_close_list(&iter);

	if (cgreg2)
		cmd = "AT+CGREG=2";
	else if (cgreg1)
		cmd = "AT+CGREG=1";
	else
		goto error;

	g_at_chat_send(gd->chat, cmd, none_prefix, NULL, NULL, NULL);


	switch (gd->modem) {
	case CINTERION_ALS3:
		g_at_chat_send(gd->chat, "AT+CGEREP=2", NULL,
					NULL, NULL, NULL);
		break;
	default:
		break;
	}

	g_at_chat_send(gd->chat, "AT^SIND=\"psinfo\",1", none_prefix,
		gprs_initialized, gprs, NULL);

	return;

error:
	ofono_info("GPRS not supported on this device");
	ofono_gprs_remove(gprs);
}

static void cint_cgdcont_test_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	struct ofono_gprs *gprs = user_data;
	struct cinterion_gprs_data *gd = ofono_gprs_get_data(gprs);
	GAtResultIter iter;
	int min, max;
	const char *pdp_type;
	gboolean found = FALSE;

	if (!ok)
		goto error;

	g_at_result_iter_init(&iter, result);

	/* Cinterion modems do not encapsulate the IP string in paranthesis */
	while (!found && g_at_result_iter_next(&iter, "+CGDCONT:")) {

		if (!g_at_result_iter_open_list(&iter))
			continue;

		if (g_at_result_iter_next_range(&iter, &min, &max) == FALSE)
			continue;

		if (g_at_result_iter_skip_next(&iter) == FALSE)
			continue;

		if (!g_at_result_iter_next_string(&iter, &pdp_type))
			continue;

		/* We look for IP PDPs */
		if (g_str_equal(pdp_type, "IP"))
			found = TRUE;
	}

	if (found == FALSE)
		goto error;

	switch (gd->modem) {
	case CINTERION_ALS3:
	case CINTERION_GENERIC:
		break;
	}

	ofono_gprs_set_cid_range(gprs, min, max);

	g_at_chat_send(gd->chat, "AT+CGREG=?", cgreg_prefix,
			cint_cgreg_test_cb, gprs, NULL);

	return;

error:
	ofono_info("GPRS by WWAN not supported on this device");
	ofono_gprs_remove(gprs);
}

static int cint_gprs_probe(struct ofono_gprs *gprs,
					unsigned int vendor, void *data)
{
	GAtChat *chat = g_at_chat_clone(data);
	struct cinterion_gprs_data *gd =
		g_try_new0(struct cinterion_gprs_data, 1);
	gd->chat = chat;
	gd->modem = vendor;

	ofono_gprs_set_data(gprs, gd);

	g_at_chat_send(chat, "AT+CGDCONT=?", cgdcont_prefix,
			cint_cgdcont_test_cb, gprs, NULL);

	return 0;
}

static void cint_gprs_remove(struct ofono_gprs *gprs)
{
	struct cinterion_gprs_data *gd = ofono_gprs_get_data(gprs);

	ofono_gprs_set_data(gprs, NULL);

	g_at_chat_unref(gd->chat);
	g_free(gd);
}

static struct ofono_gprs_driver driver = {
	.name			= "cinterionmodem",
	.probe			= cint_gprs_probe,
	.remove			= cint_gprs_remove,
	.set_attached		= cint_gprs_set_attached,
	.attached_status	= cint_gprs_registration_status,
};

void cint_gprs_init(void)
{
	ofono_gprs_driver_register(&driver);
}

void cint_gprs_exit(void)
{
	ofono_gprs_driver_unregister(&driver);
}
