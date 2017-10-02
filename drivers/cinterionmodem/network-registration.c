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

#include <glib.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/netreg.h>

#include "gatchat.h"
#include "gatresult.h"

#include "common.h"
#include "cinterionmodem.h"
#include "modemmodel.h"

static const char *none_prefix[] = { NULL };
static const char *creg_prefix[] = { "+CREG:", NULL };
static const char *cops_prefix[] = { "+COPS:", NULL };
static const char *csq_prefix[] = { "+CSQ:", NULL };
static const char *sind_prefix[] = { "^SIND:", NULL };

struct netreg_data {
	GAtChat *chat;
	unsigned int modem;
	char mcc[OFONO_MAX_MCC_LENGTH + 1];
	char mnc[OFONO_MAX_MNC_LENGTH + 1];
	unsigned int csq_source;
	int signal_index; /* If strength is reported via CIND */
	int signal_min; /* min strength reported via CIND */
	int signal_max; /* max strength reported via CIND */
	int signal_invalid; /* invalid strength reported via CIND */
	int tech;
};

struct tech_query {
	int status;
	int lac;
	int ci;
	struct ofono_netreg *netreg;
};

static void extract_mcc_mnc(const char *str, char *mcc, char *mnc)
{
	/* Three digit country code */
	strncpy(mcc, str, OFONO_MAX_MCC_LENGTH);
	mcc[OFONO_MAX_MCC_LENGTH] = '\0';

	/* Usually a 2 but sometimes 3 digit network code */
	strncpy(mnc, str + OFONO_MAX_MCC_LENGTH, OFONO_MAX_MNC_LENGTH);
	mnc[OFONO_MAX_MNC_LENGTH] = '\0';
}

static void cint_creg_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	struct netreg_data *nd = cbd->user;
	ofono_netreg_status_cb_t cb = cbd->cb;
	int status, lac, ci, tech;
	struct ofono_error error;

	cint_util_decode_at_error(&error, g_at_result_final_response(result));

	if (!ok) {
		cb(&error, -1, -1, -1, -1, cbd->data);
		return;
	}

	if (cint_util_parse_reg(result, "+CREG:", NULL, &status, &lac, &ci,
					&tech, nd->modem) == FALSE) {
		CALLBACK_WITH_FAILURE(cb, -1, -1, -1, -1, cbd->data);
		return;
	}

	if ((status == 1 || status == 5) && (tech == -1))
		tech = nd->tech;

	cb(&error, status, lac, ci, tech, cbd->data);
}

static void cint_registration_status(struct ofono_netreg *netreg,
					ofono_netreg_status_cb_t cb,
					void *data)
{
	struct netreg_data *nd = ofono_netreg_get_data(netreg);
	struct cb_data *cbd = cb_data_new(cb, data);

	cbd->user = nd;

	if (g_at_chat_send(nd->chat, "AT+CREG?", creg_prefix,
				cint_creg_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, -1, -1, -1, -1, data);
}

static void cops_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	struct netreg_data *nd = ofono_netreg_get_data(cbd->user);
	ofono_netreg_operator_cb_t cb = cbd->cb;
	struct ofono_network_operator op;
	GAtResultIter iter;
	int format, tech;
	const char *name;
	struct ofono_error error;

	cint_util_decode_at_error(&error, g_at_result_final_response(result));

	if (!ok)
		goto error;

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+COPS:"))
		goto error;

	g_at_result_iter_skip_next(&iter);

	ok = g_at_result_iter_next_number(&iter, &format);

	if (ok == FALSE || format != 0)
		goto error;

	if (g_at_result_iter_next_string(&iter, &name) == FALSE)
		goto error;

	/* Default to GSM */
	if (g_at_result_iter_next_number(&iter, &tech) == FALSE)
		tech = ACCESS_TECHNOLOGY_GSM;

	strncpy(op.name, name, OFONO_MAX_OPERATOR_NAME_LENGTH);
	op.name[OFONO_MAX_OPERATOR_NAME_LENGTH] = '\0';

	strncpy(op.mcc, nd->mcc, OFONO_MAX_MCC_LENGTH);
	op.mcc[OFONO_MAX_MCC_LENGTH] = '\0';

	strncpy(op.mnc, nd->mnc, OFONO_MAX_MNC_LENGTH);
	op.mnc[OFONO_MAX_MNC_LENGTH] = '\0';

	/* Set to current */
	op.status = 2;
	op.tech = tech;

	DBG("cops_cb: %s, %s %s %d", name, nd->mcc, nd->mnc, tech);

	cb(&error, &op, cbd->data);
	g_free(cbd);

	return;

error:
	cb(&error, NULL, cbd->data);

	g_free(cbd);
}

static void cops_numeric_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	struct netreg_data *nd = ofono_netreg_get_data(cbd->user);
	ofono_netreg_operator_cb_t cb = cbd->cb;
	GAtResultIter iter;
	const char *str;
	int format;
	int len;
	struct ofono_error error;

	cint_util_decode_at_error(&error, g_at_result_final_response(result));

	if (!ok)
		goto error;

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+COPS:"))
		goto error;

	g_at_result_iter_skip_next(&iter);

	ok = g_at_result_iter_next_number(&iter, &format);

	if (ok == FALSE || format != 2)
		goto error;

	if (g_at_result_iter_next_string(&iter, &str) == FALSE)
		goto error;

	len = strspn(str, "0123456789");

	if (len != 5 && len != 6)
		goto error;

	extract_mcc_mnc(str, nd->mcc, nd->mnc);

	DBG("Cops numeric got mcc: %s, mnc: %s", nd->mcc, nd->mnc);

	ok = g_at_chat_send(nd->chat, "AT+COPS=3,0", none_prefix,
						NULL, NULL, NULL);

	if (ok)
		ok = g_at_chat_send(nd->chat, "AT+COPS?", cops_prefix,
					cops_cb, cbd, NULL);

	if (ok)
		return;

error:
	cb(&error, NULL, cbd->data);
	g_free(cbd);
}

static void cint_current_operator(struct ofono_netreg *netreg,
				ofono_netreg_operator_cb_t cb, void *data)
{
	struct netreg_data *nd = ofono_netreg_get_data(netreg);
	struct cb_data *cbd = cb_data_new(cb, data);
	gboolean ok;

	cbd->user = netreg;

	ok = g_at_chat_send(nd->chat, "AT+COPS=3,2", none_prefix,
							NULL, NULL, NULL);

	if (ok)
		ok = g_at_chat_send(nd->chat, "AT+COPS?", cops_prefix,
						cops_numeric_cb, cbd, NULL);

	if (ok)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, NULL, data);
}

static void cops_list_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_netreg_operator_list_cb_t cb = cbd->cb;
	struct ofono_network_operator *list;
	GAtResultIter iter;
	int num = 0;
	struct ofono_error error;

	cint_util_decode_at_error(&error, g_at_result_final_response(result));

	if (!ok) {
		cb(&error, 0, NULL, cbd->data);
		return;
	}

	g_at_result_iter_init(&iter, result);

	while (g_at_result_iter_next(&iter, "+COPS:")) {
		while (g_at_result_iter_skip_next(&iter))
			num += 1;
	}

	DBG("Got %d elements", num);

	list = g_try_new0(struct ofono_network_operator, num);
	if (list == NULL) {
		CALLBACK_WITH_FAILURE(cb, 0, NULL, cbd->data);
		return;
	}

	num = 0;
	g_at_result_iter_init(&iter, result);

	while (g_at_result_iter_next(&iter, "+COPS:")) {
		int status, tech, plmn;
		const char *l, *s, *n;
		gboolean have_long = FALSE;

		while (1) {
			if (!g_at_result_iter_open_list(&iter))
				break;

			if (!g_at_result_iter_next_number(&iter, &status))
				break;

			list[num].status = status;

			if (!g_at_result_iter_next_string(&iter, &l))
				break;

			if (strlen(l) > 0) {
				have_long = TRUE;
				strncpy(list[num].name, l,
					OFONO_MAX_OPERATOR_NAME_LENGTH);
			}

			if (!g_at_result_iter_next_string(&iter, &s))
				break;

			if (strlen(s) > 0 && !have_long)
				strncpy(list[num].name, s,
					OFONO_MAX_OPERATOR_NAME_LENGTH);

			list[num].name[OFONO_MAX_OPERATOR_NAME_LENGTH] = '\0';

			if (!g_at_result_iter_next_string(&iter, &n))
				break;

			extract_mcc_mnc(n, list[num].mcc, list[num].mnc);

			if (!g_at_result_iter_next_number(&iter, &tech))
				tech = ACCESS_TECHNOLOGY_GSM;

			list[num].tech = tech;

			if (!g_at_result_iter_next_number(&iter, &plmn))
				plmn = 0;

			if (!g_at_result_iter_close_list(&iter))
				break;

			num += 1;
		}
	}

	DBG("Got %d operators", num);

{
	int i = 0;

	for (; i < num; i++) {
		DBG("Operator: %s, %s, %s, status: %d, %d",
			list[i].name, list[i].mcc, list[i].mnc,
			list[i].status, list[i].tech);
	}
}

	cb(&error, num, list, cbd->data);

	g_free(list);
}

static void cint_list_operators(struct ofono_netreg *netreg,
				ofono_netreg_operator_list_cb_t cb, void *data)
{
	struct netreg_data *nd = ofono_netreg_get_data(netreg);
	struct cb_data *cbd = cb_data_new(cb, data);

	if (g_at_chat_send(nd->chat, "AT+COPS=?", cops_prefix,
				cops_list_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, 0, NULL, data);
}

static void register_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_netreg_register_cb_t cb = cbd->cb;
	struct ofono_error error;

	cint_util_decode_at_error(&error, g_at_result_final_response(result));

	cb(&error, cbd->data);
}

static void cint_register_auto(struct ofono_netreg *netreg,
				ofono_netreg_register_cb_t cb, void *data)
{
	struct netreg_data *nd = ofono_netreg_get_data(netreg);
	struct cb_data *cbd = cb_data_new(cb, data);

	if (g_at_chat_send(nd->chat, "AT+COPS=0", none_prefix,
				register_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, data);
}

static void cint_register_manual(struct ofono_netreg *netreg,
				const char *mcc, const char *mnc,
				ofono_netreg_register_cb_t cb, void *data)
{
	struct netreg_data *nd = ofono_netreg_get_data(netreg);
	struct cb_data *cbd = cb_data_new(cb, data);
	char buf[128];

	snprintf(buf, sizeof(buf), "AT+COPS=1,2,\"%s%s\"", mcc, mnc);

	if (g_at_chat_send(nd->chat, buf, none_prefix,
				register_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, data);
}

static void cint_ciev_rssi_notify(GAtResult* result, gpointer user_data)
{
	struct ofono_netreg *netreg = user_data;
	struct netreg_data *nd = ofono_netreg_get_data(netreg);
	int strength;
	GAtResultIter iter;

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CIEV: rssi,"))
		return;

	if (!g_at_result_iter_next_number(&iter, &strength))
		return;

	if (strength == 99)
		strength = -1;
	else
		strength = (strength * 100) / 5;

	ofono_netreg_strength_notify(netreg, strength);
}

static void cint_csq_notify(GAtResult* result, gpointer user_data)
{
	struct ofono_netreg *netreg = user_data;
	int strength;
	GAtResultIter iter;

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CSQ:"))
		return;

	g_at_result_iter_next_number(&iter, &strength);

	DBG("csq_notify: %d", strength);

	if (strength == 99)
		strength = -1;
	else
		strength = (strength * 100) / 31;

	ofono_netreg_strength_notify(netreg, strength);
}

static void csq_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_netreg_strength_cb_t cb = cbd->cb;
	int strength;
	GAtResultIter iter;
	struct ofono_error error;

	cint_util_decode_at_error(&error, g_at_result_final_response(result));

	if (!ok) {
		cb(&error, -1, cbd->data);
		return;
	}

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CSQ:")) {
		CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
		return;
	}

	g_at_result_iter_next_number(&iter, &strength);

	DBG("csq_cb: %d", strength);

	if (strength == 99)
		strength = -1;
	else
		strength = (strength * 100) / 31;

	cb(&error, strength, cbd->data);
}

static void cint_signal_strength(struct ofono_netreg *netreg,
				ofono_netreg_strength_cb_t cb, void *data)
{
	struct netreg_data *nd = ofono_netreg_get_data(netreg);
	struct cb_data *cbd = cb_data_new(cb, data);

	if (g_at_chat_send(nd->chat, "AT+CSQ", csq_prefix,
				csq_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, -1, data);
}

static void creg_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_netreg *netreg = user_data;
	struct netreg_data *nd = ofono_netreg_get_data(netreg);
	int status, lac, ci, tech;
	struct tech_query *tq;

	if (cint_util_parse_reg_unsolicited(result, "+CREG:", &status,
				&lac, &ci, &tech, 0) == FALSE)
		return;

	if (status != 1 && status != 5)
		goto notify;

	tq = g_try_new0(struct tech_query, 1);
	if (tq == NULL)
		goto notify;

	tq->status = status;
	tq->lac = lac;
	tq->ci = ci;
	tq->netreg = netreg;

	g_free(tq);

	if ((status == 1 || status == 5) && tech == -1)
		tech = nd->tech;

notify:
	ofono_netreg_status_notify(netreg, status, lac, ci, tech);
}

static gboolean cint_csq_query(gpointer user_data)
{
	struct ofono_netreg *netreg = user_data;
	struct netreg_data *nd = ofono_netreg_get_data(netreg);

	g_at_chat_send(nd->chat, "AT+CSQ", none_prefix, NULL, NULL, NULL);

	return TRUE;
}

static void cint_sind_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct ofono_netreg *netreg = user_data;
	struct netreg_data *nd = ofono_netreg_get_data(netreg);

	if (!ok) {
		ofono_warn("SIND rssi failed! Fallback to CSQ polling.");

		g_at_chat_register(nd->chat, "+CSQ:", cint_csq_notify,
						FALSE, netreg, NULL);
		nd->csq_source =
			g_timeout_add_seconds(5, cint_csq_query, netreg);
		goto out;
	}

	DBG("");

	nd->signal_index = 0;

	g_at_chat_register(nd->chat, "+CIEV: rssi,",
				cint_ciev_rssi_notify, FALSE, netreg, NULL);

	g_at_chat_register(nd->chat, "+CREG:",
				creg_notify, FALSE, netreg, NULL);

out:
	ofono_netreg_register(netreg);
}


static void cint_creg_set_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct ofono_netreg *netreg = user_data;
	struct netreg_data *nd = ofono_netreg_get_data(netreg);

	if (!ok) {
		ofono_error("Unable to initialize Network Registration");
		ofono_netreg_remove(netreg);
		return;
	}

	switch (nd->modem) {
	case CINTERION_ALS3:
		/*
		 * The ALS3 modem has no URC for signal strength,
		 * we'll need to poll. Ask the modem every 5 seconds.
		 */
		g_at_chat_register(nd->chat, "+CSQ:", cint_csq_notify,
						FALSE, netreg, NULL);
		nd->csq_source =
			g_timeout_add_seconds(5, cint_csq_query, netreg);

		g_at_chat_register(nd->chat, "+CREG:",
				creg_notify, FALSE, netreg, NULL);
		ofono_netreg_register(netreg);
		break;
	default:
		ofono_warn("Signal Strength reporting is not available for"
			"this modem. Please implement the functionality.");
		ofono_netreg_register(netreg);
		break;
	}
}

static void cint_creg_test_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	struct ofono_netreg *netreg = user_data;
	struct netreg_data *nd = ofono_netreg_get_data(netreg);
	gint range[2];
	GAtResultIter iter;
	int creg1 = 0;
	int creg2 = 0;

	if (!ok)
		goto error;

	g_at_result_iter_init(&iter, result);

retry:
	if (!g_at_result_iter_next(&iter, "+CREG:"))
		goto error;

	if (!g_at_result_iter_open_list(&iter))
		goto retry;

	while (g_at_result_iter_next_range(&iter, &range[0], &range[1])) {
		if (1 >= range[0] && 1 <= range[1])
			creg1 = 1;
		if (2 >= range[0] && 2 <= range[1])
			creg2 = 1;
	}

	g_at_result_iter_close_list(&iter);

	if (creg2) {
		g_at_chat_send(nd->chat, "AT+CREG=2", none_prefix,
				cint_creg_set_cb, netreg, NULL);
		return;
	}

	if (creg1) {
		g_at_chat_send(nd->chat, "AT+CREG=1", none_prefix,
				cint_creg_set_cb, netreg, NULL);
		return;
	}

error:
	ofono_error("Unable to initialize Network Registration");
	ofono_netreg_remove(netreg);
}

static int cint_netreg_probe(struct ofono_netreg *netreg, unsigned int vendor,
				void *data)
{
	GAtChat *chat = data;
	struct netreg_data *nd;

	nd = g_new0(struct netreg_data, 1);

	nd->chat = g_at_chat_clone(chat);
	nd->modem = vendor;
	nd->tech = -1;
	ofono_netreg_set_data(netreg, nd);

	g_at_chat_send(nd->chat, "AT+CREG=?", creg_prefix,
			cint_creg_test_cb, netreg, NULL);

	return 0;
}

static void cint_netreg_remove(struct ofono_netreg *netreg)
{
	struct netreg_data *nd = ofono_netreg_get_data(netreg);

	if (nd->csq_source)
		g_source_remove(nd->csq_source);

	ofono_netreg_set_data(netreg, NULL);

	g_at_chat_unref(nd->chat);
	g_free(nd);
}

static struct ofono_netreg_driver driver = {
	.name				= "cinterionmodem",
	.probe				= cint_netreg_probe,
	.remove				= cint_netreg_remove,
	.registration_status		= cint_registration_status,
	.current_operator		= cint_current_operator,
	.list_operators			= cint_list_operators,
	.register_auto			= cint_register_auto,
	.register_manual		= cint_register_manual,
	.strength			= cint_signal_strength,
};

void cint_netreg_init(void)
{
	ofono_netreg_driver_register(&driver);
}

void cint_netreg_exit(void)
{
	ofono_netreg_driver_unregister(&driver);
}
