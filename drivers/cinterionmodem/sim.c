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

#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <glib.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/sim.h>

#include "gatchat.h"
#include "gatresult.h"
#include "simutil.h"

#include "cinterionmodem.h"
#include "modemmodel.h"

#define EF_STATUS_INVALIDATED 0
#define EF_STATUS_VALID 1

static const char *crsm_prefix[] = { "+CRSM:", NULL };
static const char *cpin_prefix[] = { "+CPIN:", NULL };
static const char *clck_prefix[] = { "+CLCK:", NULL };
static const char *spic_prefix[] = { "^SPIC:", NULL };
static const char *none_prefix[] = { NULL };

struct sim_data {
	GAtChat *chat;
	unsigned int modem;
	guint ready_id;
	struct cint_util_sim_state_query *sim_state_query;
};

struct cint_callback_data {
	void *data;
	int facility;
};

static void cint_sim_free(gpointer data)
{
	struct cb_data* cbd = data;

	if(cbd != NULL)
		g_free(cbd->data);

	g_free(cbd);
}


static void cint_crsm_info_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	GAtResultIter iter;
	ofono_sim_file_info_cb_t cb = cbd->cb;
	struct ofono_error error;
	const guint8 *response;
	gint sw1, sw2, len;
	int flen, rlen;
	int str;
	unsigned char access[3];
	unsigned char file_status;

	cint_util_decode_at_error(&error, g_at_result_final_response(result));

	if (!ok) {
		cb(&error, -1, -1, -1, NULL, EF_STATUS_INVALIDATED, cbd->data);
		return;
	}

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CRSM:"))
		goto error;

	g_at_result_iter_next_number(&iter, &sw1);
	g_at_result_iter_next_number(&iter, &sw2);

	if (!g_at_result_iter_next_hexstring(&iter, &response, &len) ||
			(sw1 != 0x90 && sw1 != 0x91 && sw1 != 0x92) ||
			(sw1 == 0x90 && sw2 != 0x00)) {
		memset(&error, 0, sizeof(error));

		error.type = OFONO_ERROR_TYPE_SIM;
		error.error = (sw1 << 8) | sw2;

		cb(&error, -1, -1, -1, NULL, EF_STATUS_INVALIDATED, cbd->data);
		return;
	}

	DBG("crsm_info_cb: %02x, %02x, %i", sw1, sw2, len);

	if (response[0] == 0x62) {
		ok = sim_parse_3g_get_response(response, len, &flen, &rlen,
						&str, access, NULL);

		file_status = EF_STATUS_VALID;
	} else
		ok = sim_parse_2g_get_response(response, len, &flen, &rlen,
						&str, access, &file_status);

	if (!ok)
		goto error;

	cb(&error, flen, str, rlen, access, file_status, cbd->data);

	return;

error:
	CALLBACK_WITH_FAILURE(cb, -1, -1, -1, NULL,
				EF_STATUS_INVALIDATED, cbd->data);
}

static void cint_sim_read_info(struct ofono_sim *sim, int fileid,
				const unsigned char *path,
				unsigned int path_len,
				ofono_sim_file_info_cb_t cb, void *data)
{
	struct sim_data *sd = ofono_sim_get_data(sim);
	struct cb_data *cbd = cb_data_new(cb, data);
	cbd->user = sd;
	char buf[128];
	unsigned int len;

	len = snprintf(buf, sizeof(buf), "AT+CRSM=192,%i", fileid);

	if (path_len != 0)
		len += sprintf(buf + len, ",0,0,255");

	if (path_len > 0) {
		len += sprintf(buf + len, ",,\"");

		for (; path_len; path_len--)
			len += sprintf(buf + len, "%02hhX", *path++);

		buf[len++] = '\"';
		buf[len] = '\0';
	}

	if (g_at_chat_send(sd->chat, buf, crsm_prefix,
				cint_crsm_info_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, -1, -1, -1, NULL,
				EF_STATUS_INVALIDATED, data);
}

static void cint_crsm_read_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	struct cb_data *cbd = user_data;
	GAtResultIter iter;
	ofono_sim_read_cb_t cb = cbd->cb;
	struct ofono_error error;
	const guint8 *response;
	gint sw1, sw2, len;

	cint_util_decode_at_error(&error, g_at_result_final_response(result));

	if (!ok) {
		cb(&error, NULL, 0, cbd->data);
		return;
	}

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CRSM:")) {
		CALLBACK_WITH_FAILURE(cb, NULL, 0, cbd->data);
		return;
	}

	g_at_result_iter_next_number(&iter, &sw1);
	g_at_result_iter_next_number(&iter, &sw2);

	if ((sw1 != 0x90 && sw1 != 0x91 && sw1 != 0x92 && sw1 != 0x9f) ||
			(sw1 == 0x90 && sw2 != 0x00)) {
		memset(&error, 0, sizeof(error));

		error.type = OFONO_ERROR_TYPE_SIM;
		error.error = (sw1 << 8) | sw2;

		cb(&error, NULL, 0, cbd->data);
		return;
	}

	if (!g_at_result_iter_next_hexstring(&iter, &response, &len)) {
		CALLBACK_WITH_FAILURE(cb, NULL, 0, cbd->data);
		return;
	}

	DBG("crsm_read_cb: %02x, %02x, %d", sw1, sw2, len);

	cb(&error, response, len, cbd->data);
}

static void cint_sim_read_binary(struct ofono_sim *sim, int fileid,
				int start, int length,
				const unsigned char *path,
				unsigned int path_len,
				ofono_sim_read_cb_t cb, void *data)
{
	struct sim_data *sd = ofono_sim_get_data(sim);
	struct cb_data *cbd = cb_data_new(cb, data);
	cbd->user = sd;
	char buf[64];
	unsigned int len;

	len = snprintf(buf, sizeof(buf), "AT+CRSM=176,%i,%i,%i,%i", fileid,
			start >> 8, start & 0xff, length);

	if (path_len > 0) {
		buf[len++] = ',';
		buf[len++] = ',';
		buf[len++] = '\"';

		for (; path_len; path_len--)
			len += sprintf(buf + len, "%02hhX", *path++);

		buf[len++] = '\"';
		buf[len] = '\0';
	}

	if (g_at_chat_send(sd->chat, buf, crsm_prefix,
				cint_crsm_read_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, NULL, 0, data);
}

static void cint_sim_read_record(struct ofono_sim *sim, int fileid,
				int record, int length,
				const unsigned char *path,
				unsigned int path_len,
				ofono_sim_read_cb_t cb, void *data)
{
	struct sim_data *sd = ofono_sim_get_data(sim);
	struct cb_data *cbd = cb_data_new(cb, data);
	cbd->user = sd;
	char buf[128];

	snprintf(buf, sizeof(buf), "AT+CRSM=178,%i,%i,4,%i", fileid,
			record, length);

	if (g_at_chat_send(sd->chat, buf, crsm_prefix,
				cint_crsm_read_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, NULL, 0, data);
}

static void cint_crsm_update_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	struct cb_data *cbd = user_data;
	GAtResultIter iter;
	ofono_sim_write_cb_t cb = cbd->cb;
	struct ofono_error error;
	gint sw1, sw2;

	cint_util_decode_at_error(&error, g_at_result_final_response(result));

	if (!ok) {
		cb(&error, cbd->data);
		return;
	}

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CRSM:")) {
		CALLBACK_WITH_FAILURE(cb, cbd->data);
		return;
	}

	g_at_result_iter_next_number(&iter, &sw1);
	g_at_result_iter_next_number(&iter, &sw2);

	if ((sw1 != 0x90 && sw1 != 0x91 && sw1 != 0x92 && sw1 != 0x9f) ||
			(sw1 == 0x90 && sw2 != 0x00)) {
		memset(&error, 0, sizeof(error));

		error.type = OFONO_ERROR_TYPE_SIM;
		error.error = (sw1 << 8) | sw2;
	}

	DBG("crsm_update_cb: %02x, %02x", sw1, sw2);

	cb(&error, cbd->data);
}

static void cint_sim_update_file(struct ofono_sim *sim, int cmd, int fileid,
				int p1, int p2, int p3,
				const unsigned char *value,
				const unsigned char *path,
				unsigned int path_len,
				ofono_sim_write_cb_t cb, void *data)
{
	struct sim_data *sd = ofono_sim_get_data(sim);
	struct cb_data *cbd = cb_data_new(cb, data);
	cbd->user = sd;
	char *buf;
	int len, ret;
	int size = 38 + p3 * 2;

	DBG("");

	buf = g_try_new(char, size);
	if (buf == NULL)
		goto error;

	len = sprintf(buf, "AT+CRSM=%i,%i,%i,%i,%i,\"", cmd, fileid,p1, p2, p3);

	for (; p3; p3--)
		len += sprintf(buf + len, "%02hhX", *value++);

	buf[len++] = '\"';
	buf[len] = '\0';

	ret = g_at_chat_send(sd->chat, buf, crsm_prefix,
				cint_crsm_update_cb, cbd, g_free);

	g_free(buf);

	if (ret > 0)
		return;

error:
	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, data);
}

static void cint_sim_update_binary(struct ofono_sim *sim, int fileid,
					int start, int length,
					const unsigned char *value,
					const unsigned char *path,
					unsigned int path_len,
					ofono_sim_write_cb_t cb, void *data)
{
	cint_sim_update_file(sim, 214, fileid, start >> 8, start & 0xff,
				length, value, path, path_len, cb, data);
}

static void cint_sim_update_record(struct ofono_sim *sim, int fileid,
					int record, int length,
					const unsigned char *value,
					const unsigned char *path,
					unsigned int path_len,
					ofono_sim_write_cb_t cb, void *data)
{
	cint_sim_update_file(sim, 220, fileid, record, 4, length,
				value, path, path_len, cb, data);
}

static void cint_sim_update_cyclic(struct ofono_sim *sim, int fileid,
					int length, const unsigned char *value,
					const unsigned char *path,
					unsigned int path_len,
					ofono_sim_write_cb_t cb, void *data)
{
	cint_sim_update_file(sim, 220, fileid, 0, 3, length, value,
				path, path_len, cb, data);
}

static void cint_cimi_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	GAtResultIter iter;
	ofono_sim_imsi_cb_t cb = cbd->cb;
	struct ofono_error error;
	const char *imsi;
	int i;

	cint_util_decode_at_error(&error, g_at_result_final_response(result));

	if (!ok) {
		cb(&error, NULL, cbd->data);
		return;
	}

	g_at_result_iter_init(&iter, result);

	for (i = 0; i < g_at_result_num_response_lines(result); i++)
		g_at_result_iter_next(&iter, NULL);

	imsi = g_at_result_iter_raw_line(&iter);

	DBG("cimi_cb: %s", imsi);

	cb(&error, imsi, cbd->data);
}

static void cint_read_imsi(struct ofono_sim *sim, ofono_sim_imsi_cb_t cb,
				void *data)
{
	struct sim_data *sd = ofono_sim_get_data(sim);
	struct cb_data *cbd = cb_data_new(cb, data);
	cbd->user = sd;

	if (g_at_chat_send(sd->chat, "AT+CIMI", NULL,
				cint_cimi_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, NULL, data);
}

static void cint_spic_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	struct cint_callback_data *cb_data = cbd->data;
	ofono_sim_pin_retries_cb_t cb = cbd->cb;
	const char *final = g_at_result_final_response(result);
	GAtResultIter iter;
	struct ofono_error error;
	int retries[OFONO_SIM_PASSWORD_INVALID];
	static int pin = -1;
	static int puk = -1;
	static int pin2 = -1;
	static int puk2 = -1;
	int retry_count;

	cint_util_decode_at_error(&error, final);

	if (!ok) {
		cb(&error, NULL, cb_data->data);
		return;
	}

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "^SPIC:"))
		goto error;

	if (!g_at_result_iter_next_number(&iter, &retry_count))
		goto error;

	switch(cb_data->facility)
	{
	case OFONO_SIM_PASSWORD_SIM_PIN:
		pin = retry_count;
		break;
	case OFONO_SIM_PASSWORD_SIM_PUK:
		puk = retry_count;
		break;
	case OFONO_SIM_PASSWORD_SIM_PIN2:
		pin2 = retry_count;
		break;
	case OFONO_SIM_PASSWORD_SIM_PUK2:
		puk2 = retry_count;
		break;
	default:
		break;
	}

	if (pin >= 0 && puk >= 0 && pin2 >= 0 && puk2 >= 0) {
		retries[OFONO_SIM_PASSWORD_SIM_PIN] = pin;
		retries[OFONO_SIM_PASSWORD_SIM_PUK] = puk;
		retries[OFONO_SIM_PASSWORD_SIM_PIN2] = pin2;
		retries[OFONO_SIM_PASSWORD_SIM_PUK2] = puk2;
		cb(&error, retries, cb_data->data);
	}

	return;

error:
	CALLBACK_WITH_FAILURE(cb, NULL, cb_data->data);
}

static void cint_pin_retries_query(struct ofono_sim *sim,
					ofono_sim_pin_retries_cb_t cb,
					void *data)
{
	/*
	 * Cinterion modems requires the query to be done per code instead of
	 * displaying all the counters immediately.
	 * This also requires sending a specialized data struct as cbd->data
	 * so we can know which counter is for which code.
	 *
	 * TODO:
	 * The solution presented is highly ineffective but appears required.
	 * Attempted optimizations resulted in double free corruptions.
	 */
	struct sim_data *sd = ofono_sim_get_data(sim);
	struct cb_data *cbd;
	struct cint_callback_data *cb_data;

	DBG("");

	cb_data = g_try_new0(struct cint_callback_data, 1);
	cb_data->data = data;
	cb_data->facility = OFONO_SIM_PASSWORD_SIM_PIN;
	cbd = cb_data_new(cb, cb_data);
	if (!g_at_chat_send(sd->chat, "AT^SPIC=SC", spic_prefix,
				cint_spic_cb, cbd, cint_sim_free) > 0)
		goto error;

	cb_data = g_try_new0(struct cint_callback_data, 1);
	cb_data->data = data;
	cb_data->facility = OFONO_SIM_PASSWORD_SIM_PUK;
	cbd = cb_data_new(cb, cb_data);
	if (!g_at_chat_send(sd->chat, "AT^SPIC=SC,1", spic_prefix,
				cint_spic_cb, cbd, cint_sim_free) > 0)
		goto error;

	cb_data = g_try_new0(struct cint_callback_data, 1);
	cb_data->data = data;
	cb_data->facility = OFONO_SIM_PASSWORD_SIM_PIN2;
	cbd = cb_data_new(cb, cb_data);
	if (!g_at_chat_send(sd->chat, "AT^SPIC=P2", spic_prefix,
				cint_spic_cb, cbd, cint_sim_free) > 0)
		goto error;

	cb_data = g_try_new0(struct cint_callback_data, 1);
	cb_data->data = data;
	cb_data->facility = OFONO_SIM_PASSWORD_SIM_PUK2;
	cbd = cb_data_new(cb, cb_data);
	if (!g_at_chat_send(sd->chat, "AT^SPIC=P2,1", spic_prefix,
				cint_spic_cb, cbd, cint_sim_free) > 0)
		goto error;

	return;

error:
	cint_sim_free(cbd);

	CALLBACK_WITH_FAILURE(cb, NULL, data);
}

static struct {
	enum ofono_sim_password_type type;
	const char *name;
} const at_sim_name[] = {
	{ OFONO_SIM_PASSWORD_NONE,		"READY"		},
	{ OFONO_SIM_PASSWORD_SIM_PIN,		"SIM PIN"	},
	{ OFONO_SIM_PASSWORD_SIM_PUK,		"SIM PUK"	},
	{ OFONO_SIM_PASSWORD_PHSIM_PIN,		"PH-SIM PIN"	},
	{ OFONO_SIM_PASSWORD_PHFSIM_PIN,	"PH-FSIM PIN"	},
	{ OFONO_SIM_PASSWORD_PHFSIM_PUK,	"PH-FSIM PUK"	},
	{ OFONO_SIM_PASSWORD_SIM_PIN2,		"SIM PIN2"	},
	{ OFONO_SIM_PASSWORD_SIM_PUK2,		"SIM PUK2"	},
	{ OFONO_SIM_PASSWORD_PHNET_PIN,		"PH-NET PIN"	},
	{ OFONO_SIM_PASSWORD_PHNET_PUK,		"PH-NET PUK"	},
	{ OFONO_SIM_PASSWORD_PHNETSUB_PIN,	"PH-NETSUB PIN"	},
	{ OFONO_SIM_PASSWORD_PHNETSUB_PUK,	"PH-NETSUB PUK"	},
	{ OFONO_SIM_PASSWORD_PHSP_PIN,		"PH-SP PIN"	},
	{ OFONO_SIM_PASSWORD_PHSP_PUK,		"PH-SP PUK"	},
	{ OFONO_SIM_PASSWORD_PHCORP_PIN,	"PH-CORP PIN"	},
	{ OFONO_SIM_PASSWORD_PHCORP_PUK,	"PH-CORP PUK"	},
};

static void cint_cpin_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	GAtResultIter iter;
	ofono_sim_passwd_cb_t cb = cbd->cb;
	struct ofono_error error;
	const char *pin_required;
	int pin_type = OFONO_SIM_PASSWORD_INVALID;
	int i;
	int len = sizeof(at_sim_name) / sizeof(*at_sim_name);
	const char *final = g_at_result_final_response(result);

	cint_util_decode_at_error(&error, final);

	if (!ok) {
		cb(&error, -1, cbd->data);
		return;
	}

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CPIN:")) {
		CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
		return;
	}

	g_at_result_iter_next_unquoted_string(&iter, &pin_required);

	for (i = 0; i < len; i++) {
		if (strcmp(pin_required, at_sim_name[i].name))
			continue;

		pin_type = at_sim_name[i].type;
		break;
	}

	if (pin_type == OFONO_SIM_PASSWORD_INVALID) {
		CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
		return;
	}

	DBG("crsm_pin_cb: %s", pin_required);

	cb(&error, pin_type, cbd->data);
}

static void cint_pin_query(struct ofono_sim *sim, ofono_sim_passwd_cb_t cb,
			void *data)
{
	struct sim_data *sd = ofono_sim_get_data(sim);
	struct cb_data *cbd = cb_data_new(cb, data);

	cbd->user = sim;

	if (g_at_chat_send(sd->chat, "AT+CPIN?", cpin_prefix,
				cint_cpin_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, -1, data);
}

static void cint_pin_send_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_sim_lock_unlock_cb_t cb = cbd->cb;
	struct ofono_error error;

	cint_util_decode_at_error(&error, g_at_result_final_response(result));

	if (!ok)
		goto done;

done:
	cb(&error, cbd->data);

	g_free(cbd);
}

static void cint_pin_send(struct ofono_sim *sim, const char *passwd,
			ofono_sim_lock_unlock_cb_t cb, void *data)
{
	struct sim_data *sd = ofono_sim_get_data(sim);
	struct cb_data *cbd = cb_data_new(cb, data);
	char buf[64];
	int ret;

	cbd->user = sd;

	snprintf(buf, sizeof(buf), "AT+CPIN=\"%s\"", passwd);

	ret = g_at_chat_send(sd->chat, buf, none_prefix,
				cint_pin_send_cb, cbd, NULL);

	memset(buf, 0, sizeof(buf));

	if (ret > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, data);
}

static void cint_pin_send_puk(struct ofono_sim *sim, const char *puk,
				const char *passwd,
				ofono_sim_lock_unlock_cb_t cb, void *data)
{
	struct sim_data *sd = ofono_sim_get_data(sim);
	struct cb_data *cbd = cb_data_new(cb, data);
	char buf[64];
	int ret;

	cbd->user = sd;

	snprintf(buf, sizeof(buf), "AT+CPIN=\"%s\",\"%s\"", puk, passwd);

	ret = g_at_chat_send(sd->chat, buf, none_prefix,
				cint_pin_send_cb, cbd, NULL);

	memset(buf, 0, sizeof(buf));

	if (ret > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, data);
}

static void cint_lock_unlock_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_sim_lock_unlock_cb_t cb = cbd->cb;
	struct ofono_error error;

	cint_util_decode_at_error(&error, g_at_result_final_response(result));

	cb(&error, cbd->data);
}

static const char *const at_clck_cpwd_fac[] = {
	[OFONO_SIM_PASSWORD_SIM_PIN] = "SC",
	[OFONO_SIM_PASSWORD_SIM_PIN2] = "P2",
	[OFONO_SIM_PASSWORD_PHSIM_PIN] = "PS",
	[OFONO_SIM_PASSWORD_PHFSIM_PIN] = "PF",
	[OFONO_SIM_PASSWORD_PHNET_PIN] = "PN",
	[OFONO_SIM_PASSWORD_PHNETSUB_PIN] = "PU",
	[OFONO_SIM_PASSWORD_PHSP_PIN] = "PP",
	[OFONO_SIM_PASSWORD_PHCORP_PIN] = "PC",
};

static void cint_pin_enable(struct ofono_sim *sim,
				enum ofono_sim_password_type passwd_type,
				int enable, const char *passwd,
				ofono_sim_lock_unlock_cb_t cb, void *data)
{
	struct sim_data *sd = ofono_sim_get_data(sim);
	struct cb_data *cbd = cb_data_new(cb, data);
	cbd->user = sd;
	char buf[64];
	int ret;
	unsigned int len = sizeof(at_clck_cpwd_fac) / sizeof(*at_clck_cpwd_fac);

	if (passwd_type >= len || at_clck_cpwd_fac[passwd_type] == NULL)
		goto error;

	snprintf(buf, sizeof(buf), "AT+CLCK=\"%s\",%i,\"%s\"",
			at_clck_cpwd_fac[passwd_type], enable ? 1 : 0, passwd);

	ret = g_at_chat_send(sd->chat, buf, none_prefix,
				cint_lock_unlock_cb, cbd, g_free);

	memset(buf, 0, sizeof(buf));

	if (ret > 0)
		return;

error:
	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, data);
}

static void cint_change_passwd(struct ofono_sim *sim,
				enum ofono_sim_password_type passwd_type,
				const char *old_passwd, const char *new_passwd,
				ofono_sim_lock_unlock_cb_t cb, void *data)
{
	struct sim_data *sd = ofono_sim_get_data(sim);
	struct cb_data *cbd = cb_data_new(cb, data);
	cbd->user = sd;
	char buf[64];
	int ret;
	unsigned int len = sizeof(at_clck_cpwd_fac) / sizeof(*at_clck_cpwd_fac);

	if (passwd_type >= len ||
			at_clck_cpwd_fac[passwd_type] == NULL)
		goto error;

	snprintf(buf, sizeof(buf), "AT+CPWD=\"%s\",\"%s\",\"%s\"",
			at_clck_cpwd_fac[passwd_type], old_passwd, new_passwd);


	ret = g_at_chat_send(sd->chat, buf, none_prefix,
				cint_lock_unlock_cb, cbd, g_free);

	memset(buf, 0, sizeof(buf));

	if (ret > 0)
		return;

error:
	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, data);
}

static void cint_lock_status_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	struct cb_data *cbd = user_data;
	GAtResultIter iter;
	ofono_query_facility_lock_cb_t cb = cbd->cb;
	struct ofono_error error;
	int locked;

	cint_util_decode_at_error(&error, g_at_result_final_response(result));

	if (!ok) {
		cb(&error, -1, cbd->data);
		return;
	}

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CLCK:")) {
		CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
		return;
	}
	
	g_at_result_iter_next_number(&iter, &locked);

	DBG("lock_status_cb: %i", locked);

	cb(&error, locked, cbd->data);
}

static void cint_pin_query_enabled(struct ofono_sim *sim,
				enum ofono_sim_password_type passwd_type,
				ofono_query_facility_lock_cb_t cb, void *data)
{
	struct sim_data *sd = ofono_sim_get_data(sim);
	struct cb_data *cbd = cb_data_new(cb, data);
	cbd->user = sd;
	char buf[64];
	unsigned int len = sizeof(at_clck_cpwd_fac) / sizeof(*at_clck_cpwd_fac);

	if (passwd_type >= len || at_clck_cpwd_fac[passwd_type] == NULL)
		goto error;

	snprintf(buf, sizeof(buf), "AT+CLCK=\"%s\",2",
			at_clck_cpwd_fac[passwd_type]);

	if (g_at_chat_send(sd->chat, buf, clck_prefix,
				cint_lock_status_cb, cbd, g_free) > 0)
		return;

error:
	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, -1, data);
}

static gboolean cint_sim_register(gpointer user)
{
	struct ofono_sim *sim = user;

	ofono_sim_register(sim);

	return FALSE;
}

static void sim_state_cb(gboolean present, gpointer user_data)
{
	struct ofono_sim *sim = user_data;
	struct sim_data *sd = ofono_sim_get_data(sim);

	cint_util_sim_state_query_free(sd->sim_state_query);
	sd->sim_state_query = NULL;

	g_idle_add(cint_sim_register, sim);
}

static int cint_sim_probe(struct ofono_sim *sim, unsigned int vendor,
				void *data)
{
	GAtChat *chat = data;
	struct sim_data *sd;

	sd = g_new0(struct sim_data, 1);
	sd->chat = g_at_chat_clone(chat);
	sd->modem = vendor;

	ofono_sim_set_data(sim, sd);

	switch (sd->modem) {
	/*
	 * The ALS3 modem does not allow any CRSM commands before SIM
	 * init has completed, so wait until the SIM is ready before
	 * moving on.
	 */
	case CINTERION_ALS3:
		sd->sim_state_query =
			cint_util_sim_state_query_new(sd->chat,
				2, 20, sim_state_cb, sim, NULL);
		break;
	default:
		g_idle_add(cint_sim_register, sim);
		break;
	}

	return 0;
}

static void cint_sim_remove(struct ofono_sim *sim)
{
	struct sim_data *sd = ofono_sim_get_data(sim);

	g_idle_remove_by_data(sim);
	/* Cleanup potential SIM state polling */
	cint_util_sim_state_query_free(sd->sim_state_query);

	ofono_sim_set_data(sim, NULL);

	g_at_chat_unref(sd->chat);
	g_free(sd);
}

static struct ofono_sim_driver driver = {
	.name			= "cinterionmodem",
	.probe			= cint_sim_probe,
	.remove			= cint_sim_remove,
	.read_file_info		= cint_sim_read_info,
	.read_file_transparent	= cint_sim_read_binary,
	.read_file_linear	= cint_sim_read_record,
	.read_file_cyclic	= cint_sim_read_record,
	.write_file_transparent	= cint_sim_update_binary,
	.write_file_linear	= cint_sim_update_record,
	.write_file_cyclic	= cint_sim_update_cyclic,
	.read_imsi		= cint_read_imsi,
	.query_passwd_state	= cint_pin_query,
	.query_pin_retries	= cint_pin_retries_query,
	.send_passwd		= cint_pin_send,
	.reset_passwd		= cint_pin_send_puk,
	.lock			= cint_pin_enable,
	.change_passwd		= cint_change_passwd,
	.query_facility_lock		= cint_pin_query_enabled,
};

void cint_sim_init(void)
{
	ofono_sim_driver_register(&driver);
}

void cint_sim_exit(void)
{
	ofono_sim_driver_unregister(&driver);
}
