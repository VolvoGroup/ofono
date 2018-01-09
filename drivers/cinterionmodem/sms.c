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

#include <glib.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/sms.h>
#include "smsutil.h"
#include "util.h"

#include "gatchat.h"
#include "gatresult.h"

#include "cinterionmodem.h"
#include "modemmodel.h"

static const char *csca_prefix[] = { "+CSCA:", NULL };
static const char *cgsms_prefix[] = { "+CGSMS:", NULL };
static const char *csms_prefix[] = { "+CSMS:", NULL };
static const char *cmgf_prefix[] = { "+CMGF:", NULL };
static const char *cpms_prefix[] = { "+CPMS:", NULL };
static const char *cnmi_prefix[] = { "+CNMI:", NULL };
static const char *cmgs_prefix[] = { "+CMGS:", NULL };
static const char *cmgl_prefix[] = { "+CMGL:", NULL };
static const char *none_prefix[] = { NULL };

static gboolean set_cmgf(gpointer user_data);
static gboolean set_cpms(gpointer user_data);
static void cint_cmgl_set_cpms(struct ofono_sms *sms, int store);

#define MAX_CMGF_RETRIES 10
#define MAX_CPMS_RETRIES 10

static const char *storages[] = {
	"SM",
	"ME",
	"MT",
	"SR",
	"BM",
};

struct sms_data {
	int store;
	int incoming;
	int retries;
	gboolean expect_sr;
	gboolean cnma_enabled;
	char *cnma_ack_pdu;
	int cnma_ack_pdu_len;
	guint timeout_source;
	GAtChat *chat;
	unsigned int modem;
};

struct cpms_request {
	struct ofono_sms *sms;
	int store;
	int index;
	gboolean expect_sr;
};

static void cint_csca_set_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_sms_sca_set_cb_t cb = cbd->cb;
	struct ofono_error error;

	cint_util_decode_at_error(&error, g_at_result_final_response(result));

	cb(&error, cbd->data);
}

static void cint_csca_set(struct ofono_sms *sms,
			const struct ofono_phone_number *sca,
			ofono_sms_sca_set_cb_t cb, void *user_data)
{
	struct sms_data *data = ofono_sms_get_data(sms);
	struct cb_data *cbd = cb_data_new(cb, user_data);
	char buf[64];

	snprintf(buf, sizeof(buf), "AT+CSCA=\"%s\",%d", sca->number, sca->type);

	if (g_at_chat_send(data->chat, buf, csca_prefix,
				cint_csca_set_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, user_data);
}

static void cint_csca_query_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	struct cb_data *cbd = user_data;
	GAtResultIter iter;
	ofono_sms_sca_query_cb_t cb = cbd->cb;
	struct ofono_error error;
	struct ofono_phone_number sca;
	const char *number;

	cint_util_decode_at_error(&error, g_at_result_final_response(result));

	if (!ok) {
		cb(&error, NULL, cbd->data);
		return;
	}

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CSCA:"))
		goto err;

	if (!g_at_result_iter_next_string(&iter, &number))
		goto err;

	if (number[0] == '+') {
		number = number + 1;
		sca.type = 145;
	} else {
		sca.type = 129;
	}

	strncpy(sca.number, number, OFONO_MAX_PHONE_NUMBER_LENGTH);
	sca.number[OFONO_MAX_PHONE_NUMBER_LENGTH] = '\0';

	g_at_result_iter_next_number(&iter, &sca.type);

	DBG("csca_query_cb: %s, %d", sca.number, sca.type);

	cb(&error, &sca, cbd->data);

	return;

err:
	CALLBACK_WITH_FAILURE(cb, NULL, cbd->data);
}

static void cint_csca_query(struct ofono_sms *sms, ofono_sms_sca_query_cb_t cb,
					void *user_data)
{
	struct sms_data *data = ofono_sms_get_data(sms);
	struct cb_data *cbd = cb_data_new(cb, user_data);

	if (g_at_chat_send(data->chat, "AT+CSCA?", csca_prefix,
				cint_csca_query_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, NULL, user_data);
}

static void cint_cmgs_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	GAtResultIter iter;
	ofono_sms_submit_cb_t cb = cbd->cb;
	struct ofono_error error;
	int mr;

	cint_util_decode_at_error(&error, g_at_result_final_response(result));

	if (!ok) {
		cb(&error, -1, cbd->data);
		return;
	}

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CMGS:"))
		goto err;

	if (!g_at_result_iter_next_number(&iter, &mr))
		goto err;

	DBG("Got MR: %d", mr);

	cb(&error, mr, cbd->data);
	return;

err:
	CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
}

static void cint_cmgs(struct ofono_sms *sms, const unsigned char *pdu,
			int pdu_len, int tpdu_len, int mms,
			ofono_sms_submit_cb_t cb, void *user_data)
{
	struct sms_data *data = ofono_sms_get_data(sms);
	struct cb_data *cbd = cb_data_new(cb, user_data);
	char buf[512];
	int len;

	switch (data->modem) {
	/* The LTE modem does not support CMMS=1 even though it acks it */
	case CINTERION_ALS3:
		break;
	default:
		if (mms) {
			snprintf(buf, sizeof(buf), "AT+CMMS=%d", mms);

			g_at_chat_send(data->chat, buf, none_prefix, NULL, NULL, NULL);
		}
		break;
	}

	len = snprintf(buf, sizeof(buf), "AT+CMGS=%d\r", tpdu_len);
	encode_hex_own_buf(pdu, pdu_len, 0, buf+len);

	if (g_at_chat_send(data->chat, buf, cmgs_prefix,
				cint_cmgs_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, -1, user_data);
}

static void cint_cgsms_set_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_sms_sca_set_cb_t cb = cbd->cb;
	struct ofono_error error;

	cint_util_decode_at_error(&error, g_at_result_final_response(result));

	cb(&error, cbd->data);
}

static void cint_cgsms_set(struct ofono_sms *sms, int bearer,
			ofono_sms_bearer_set_cb_t cb, void *user_data)
{
	struct sms_data *data = ofono_sms_get_data(sms);
	struct cb_data *cbd = cb_data_new(cb, user_data);
	char buf[64];

	snprintf(buf, sizeof(buf), "AT+CGSMS=%d", bearer);

	if (g_at_chat_send(data->chat, buf, none_prefix,
				cint_cgsms_set_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, user_data);
}

static void cint_cgsms_query_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_sms_bearer_query_cb_t cb = cbd->cb;
	struct ofono_error error;
	GAtResultIter iter;
	int bearer;

	cint_util_decode_at_error(&error, g_at_result_final_response(result));

	if (!ok) {
		cb(&error, -1, cbd->data);
		return;
	}

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CGSMS:"))
		goto err;

	g_at_result_iter_next_number(&iter, &bearer);

	cb(&error, bearer, cbd->data);

	return;

err:
	CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
}

static void cint_cgsms_query(struct ofono_sms *sms,
				ofono_sms_bearer_query_cb_t cb,
				void *user_data)
{
	struct sms_data *data = ofono_sms_get_data(sms);
	struct cb_data *cbd = cb_data_new(cb, user_data);

	if (g_at_chat_send(data->chat, "AT+CGSMS?", cgsms_prefix,
				cint_cgsms_query_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, -1, user_data);
}

static void cint_cnma_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	if (!ok)
		ofono_error("CNMA acknowledgement failed: "
				"Further SMS reception is not guaranteed");
}

/* Cinterion modems omit the comma before the PDU size field */
static gboolean cint_parse_cmt(GAtResult *result, const char **pdu, int *pdulen)
{
	GAtResultIter iter;

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CMT:"))
		return FALSE;

	if (!g_at_result_iter_next_number(&iter, pdulen))
		return FALSE;

	*pdu = g_at_result_pdu(result);

	return TRUE;
}

static inline void cint_ack_delivery(struct ofono_sms *sms)
{
	struct sms_data *data = ofono_sms_get_data(sms);
	char buf[16];

	DBG("");

	/* We must acknowledge the PDU using CNMA */
	/* 0 should be a safe fallback if ack is not needed */
	snprintf(buf, sizeof(buf), "AT+CNMA=%d", data->cnma_ack_pdu ? 1 : 0);

	g_at_chat_send(data->chat, buf, none_prefix, cint_cnma_cb, NULL, NULL);
}

static void cint_cds_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);
	long pdu_len;
	int tpdu_len;
	const char *hexpdu;
	unsigned char pdu[176];
	GAtResultIter iter;

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CDS:"))
		goto err;

	if (!g_at_result_iter_next_number(&iter, &tpdu_len))
		goto err;

	hexpdu = g_at_result_pdu(result);

	if (strlen(hexpdu) > sizeof(pdu) * 2) {
		ofono_error("Bad PDU length in CDS notification");
		return;
	}

	DBG("Got new Status-Report PDU via CDS: %s, %d", hexpdu, tpdu_len);

	/* Decode pdu and notify about new SMS status report */
	decode_hex_own_buf(hexpdu, -1, &pdu_len, 0, pdu);
	ofono_sms_status_notify(sms, pdu, pdu_len, tpdu_len);

	if (data->cnma_enabled)
		cint_ack_delivery(sms);

	return;

err:
	ofono_error("Unable to parse CDS notification");
}

static void cint_cmt_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_sms *sms = user_data;
	const char *hexpdu;
	long pdu_len;
	int tpdu_len;
	unsigned char pdu[176];

	if (!cint_parse_cmt(result, &hexpdu, &tpdu_len)) {
		ofono_error("Unable to parse CMT notification");
		return;
	}

	if (strlen(hexpdu) > sizeof(pdu) * 2) {
		ofono_error("Bad PDU length in CMT notification");
		return;
	}

	DBG("Got new SMS Deliver PDU via CMT: %s, %d", hexpdu, tpdu_len);

	decode_hex_own_buf(hexpdu, -1, &pdu_len, 0, pdu);
	ofono_sms_deliver_notify(sms, pdu, pdu_len, tpdu_len);

	cint_ack_delivery(sms);
}

static void cint_cmgr_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);
	GAtResultIter iter;
	const char *hexpdu;
	unsigned char pdu[176];
	long pdu_len;
	int tpdu_len;

	DBG("");

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CMGR:"))
		goto err;

	if (!g_at_result_iter_skip_next(&iter))
		goto err;

	if (!g_at_result_iter_skip_next(&iter))
		goto err;

	if (!g_at_result_iter_next_number(&iter, &tpdu_len))
		goto err;

	hexpdu = g_at_result_pdu(result);

	if (strlen(hexpdu) > sizeof(pdu) * 2)
		goto err;

	DBG("Got PDU: %s, with len: %d", hexpdu, tpdu_len);

	decode_hex_own_buf(hexpdu, -1, &pdu_len, 0, pdu);

	if (data->expect_sr)
		ofono_sms_status_notify(sms, pdu, pdu_len, tpdu_len);
	else
		ofono_sms_deliver_notify(sms, pdu, pdu_len, tpdu_len);
	return;

err:
	ofono_error("Unable to parse CMGR response");
}

static void cint_cmgr_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	if (!ok)
		ofono_error("Received a CMTI indication but CMGR failed!");
}

static void cint_cmgd_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	if (!ok)
		ofono_error("Unable to delete received SMS");
}

static void cint_cmgr_cpms_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	struct cpms_request *req = user_data;
	struct ofono_sms *sms = req->sms;
	struct sms_data *data = ofono_sms_get_data(sms);
	char buf[128];

	if (!ok) {
		ofono_error("Received CMTI/CDSI, but CPMS request failed");
		return;
	}

	data->store = req->store;
	data->expect_sr = req->expect_sr;

	snprintf(buf, sizeof(buf), "AT+CMGR=%d", req->index);

	g_at_chat_send(data->chat, buf, none_prefix, cint_cmgr_cb, NULL, NULL);

	/* We don't buffer SMS on the SIM/ME, send along a CMGD as well */
	snprintf(buf, sizeof(buf), "AT+CMGD=%d", req->index);

	g_at_chat_send(data->chat, buf, none_prefix, cint_cmgd_cb, NULL, NULL);
}

static void cint_send_cmgr_cpms(struct ofono_sms *sms, int store, int index,
				gboolean expect_sr)
{
	struct sms_data *data = ofono_sms_get_data(sms);

	if (store == data->store) {
		struct cpms_request req;

		req.sms = sms;
		req.store = store;
		req.index = index;
		req.expect_sr = expect_sr;

		cint_cmgr_cpms_cb(TRUE, NULL, &req);
	} else {
		char buf[128];
		const char *incoming = storages[data->incoming];
		struct cpms_request *req = g_new(struct cpms_request, 1);

		req->sms = sms;
		req->store = store;
		req->index = index;
		req->expect_sr = expect_sr;

		snprintf(buf, sizeof(buf), "AT+CPMS=\"%s\",\"%s\",\"%s\"",
				storages[store], storages[store], incoming);

		g_at_chat_send(data->chat, buf, cpms_prefix, cint_cmgr_cpms_cb,
				req, g_free);
	}
}

static void cint_cmti_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_sms *sms = user_data;
	enum cint_util_sms_store store;
	int index;

	if (cint_util_parse_sms_index_delivery(result, "+CMTI:",
						&store, &index) == FALSE)
		goto error;

	if (store != CINT_UTIL_SMS_STORE_SM && store != CINT_UTIL_SMS_STORE_ME)
		goto error;

	DBG("Got a CMTI indication at %s, index: %d", storages[store], index);
	cint_send_cmgr_cpms(sms, store, index, FALSE);
	return;

error:
	ofono_error("Unable to parse CMTI notification");
}

static void cint_cdsi_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_sms *sms = user_data;
	enum cint_util_sms_store store;
	int index;

	if (cint_util_parse_sms_index_delivery(result, "+CDSI:",
						&store, &index) == FALSE)
		goto error;

	/* Some modems actually store status reports in SM, and not SR */
	if (store != CINT_UTIL_SMS_STORE_SR && store != CINT_UTIL_SMS_STORE_SM &&
			store != CINT_UTIL_SMS_STORE_ME)
		goto error;

	DBG("Got a CDSI indication at %s, index: %d", storages[store], index);
	cint_send_cmgr_cpms(sms, store, index, TRUE);
	return;

error:
	ofono_error("Unable to parse CDSI notification");
}

static void cint_cmgl_done(struct ofono_sms *sms)
{
	struct sms_data *data = ofono_sms_get_data(sms);

	DBG("");

	if (data->incoming == CINT_UTIL_SMS_STORE_MT &&
			data->store == CINT_UTIL_SMS_STORE_ME) {
		cint_cmgl_set_cpms(sms, CINT_UTIL_SMS_STORE_SM);
		return;
	}

	g_at_chat_register(data->chat, "+CMTI:", cint_cmti_notify, FALSE,
				sms, NULL);
	g_at_chat_register(data->chat, "+CMT:", cint_cmt_notify, TRUE,
				sms, NULL);
	g_at_chat_register(data->chat, "+CDS:", cint_cds_notify, TRUE,
				sms, NULL);
	g_at_chat_register(data->chat, "+CDSI:", cint_cdsi_notify, FALSE,
				sms, NULL);

	/* We treat CMGR just like a notification */
	g_at_chat_register(data->chat, "+CMGR:", cint_cmgr_notify, TRUE,
				sms, NULL);
}

static void cint_cmgl_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);
	GAtResultIter iter;
	const char *hexpdu;
	unsigned char pdu[176];
	long pdu_len;
	int tpdu_len;
	int index;
	int status;
	char buf[16];

	DBG("");

	g_at_result_iter_init(&iter, result);

	while (g_at_result_iter_next(&iter, "+CMGL:")) {
		if (!g_at_result_iter_next_number(&iter, &index))
			goto err;

		if (!g_at_result_iter_next_number(&iter, &status))
			goto err;

		if (!g_at_result_iter_skip_next(&iter))
			goto err;

		if (!g_at_result_iter_next_number(&iter, &tpdu_len))
			goto err;

		/* Only MT messages */
		if (status != 0 && status != 1)
			continue;

		hexpdu = g_at_result_pdu(result);

		DBG("Found an old SMS PDU: %s, with len: %d",
				hexpdu, tpdu_len);

		if (strlen(hexpdu) > sizeof(pdu) * 2)
			continue;

		decode_hex_own_buf(hexpdu, -1, &pdu_len, 0, pdu);
		ofono_sms_deliver_notify(sms, pdu, pdu_len, tpdu_len);

		/* We don't buffer SMS on the SIM/ME, send along a CMGD */
		snprintf(buf, sizeof(buf), "AT+CMGD=%d", index);
		g_at_chat_send(data->chat, buf, none_prefix,
				cint_cmgd_cb, NULL, NULL);
	}
	return;

err:
	ofono_error("Unable to parse CMGL response");
}

static void cint_cmgl_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct ofono_sms *sms = user_data;

	if (!ok)
		DBG("Initial listing SMS storage failed!");

	cint_cmgl_done(sms);
}

static void cint_cmgl_cpms_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	struct cpms_request *req = user_data;
	struct ofono_sms *sms = req->sms;
	struct sms_data *data = ofono_sms_get_data(sms);

	if (!ok) {
		ofono_error("Initial CPMS request failed");
		cint_cmgl_done(sms);
		return;
	}

	data->store = req->store;

	g_at_chat_send_pdu_listing(data->chat, "AT+CMGL=4", cmgl_prefix,
				cint_cmgl_notify, cint_cmgl_cb, sms, NULL);
}

static void cint_cmgl_set_cpms(struct ofono_sms *sms, int store)
{
	struct sms_data *data = ofono_sms_get_data(sms);

	if (store == data->store) {
		struct cpms_request req;

		req.sms = sms;
		req.store = store;

		cint_cmgl_cpms_cb(TRUE, NULL, &req);
	} else {
		char buf[128];
		const char *readwrite = storages[store];
		const char *incoming = storages[data->incoming];
		struct cpms_request *req = g_new(struct cpms_request, 1);

		req->sms = sms;
		req->store = store;

		snprintf(buf, sizeof(buf), "AT+CPMS=\"%s\",\"%s\",\"%s\"",
				readwrite, readwrite, incoming);

		g_at_chat_send(data->chat, buf, cpms_prefix, cint_cmgl_cpms_cb,
				req, g_free);
	}
}

static void cint_sms_initialized(struct ofono_sms *sms)
{
	struct sms_data *data = ofono_sms_get_data(sms);

	/* Inspect and free the incoming SMS storage */
	if (data->incoming == CINT_UTIL_SMS_STORE_MT)
		cint_cmgl_set_cpms(sms, CINT_UTIL_SMS_STORE_ME);
	else
		cint_cmgl_set_cpms(sms, data->incoming);

	ofono_sms_register(sms);
}

static void cint_sms_not_supported(struct ofono_sms *sms)
{
	ofono_error("SMS not supported by this modem.  If this is in error"
			" please submit patches to support this hardware");

	ofono_sms_remove(sms);
}

static void cint_cnmi_set_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct ofono_sms *sms = user_data;

	if (!ok)
		return cint_sms_not_supported(sms);

	cint_sms_initialized(sms);
}

static void construct_ack_pdu(struct sms_data *d)
{
	struct sms ackpdu;
	unsigned char pdu[164];
	int len;
	int tpdu_len;

	DBG("");

	memset(&ackpdu, 0, sizeof(ackpdu));

	ackpdu.type = SMS_TYPE_DELIVER_REPORT_ACK;

	if (!sms_encode(&ackpdu, &len, &tpdu_len, pdu))
		goto err;

	/* Constructing an <ackpdu> according to 27.005 Section 4.6 */
	if (len != tpdu_len)
		goto err;

	d->cnma_ack_pdu = encode_hex(pdu, tpdu_len, 0);
	if (d->cnma_ack_pdu == NULL)
		goto err;

	d->cnma_ack_pdu_len = tpdu_len;
	return;

err:
	ofono_error("Unable to construct Deliver ACK PDU");
}

static void cint_set_cnmi(struct ofono_sms *sms)
{
	struct sms_data *data = ofono_sms_get_data(sms);

	if (data->cnma_enabled)
		construct_ack_pdu(data);

	/*
	 * Using +CNMI=2,2,2,1,1 sometimes causes an URC to miss,
	 * then we cannot wake up on SMS messages as +CNMI on
	 * Cinterion modems revert to 2,0,2,0,1 or 0,0,0,0,1 in the
	 * case of not sending an ack on a +CMT SMS.
	 * Use +CMTI mode which auto-acks everything but Class 0 SMS.
	 */
	g_at_chat_send(data->chat, "AT+CNMI=2,1,0,1,1", cnmi_prefix,
			cint_cnmi_set_cb, sms, NULL);
}

static void cint_cpms_set_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);

	if (ok)
		return cint_set_cnmi(sms);

	data->retries += 1;

	if (data->retries == MAX_CPMS_RETRIES) {
		ofono_error("Unable to set preferred storage");
		return cint_sms_not_supported(sms);
	}

	data->timeout_source = g_timeout_add_seconds(1, set_cpms, sms);
}

static gboolean set_cpms(gpointer user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);
	const char *store = storages[data->store];
	const char *incoming = storages[data->incoming];
	char buf[128];

	snprintf(buf, sizeof(buf), "AT+CPMS=\"%s\",\"%s\",\"%s\"",
			store, store, incoming);

	g_at_chat_send(data->chat, buf, cpms_prefix,
			cint_cpms_set_cb, sms, NULL);

	data->timeout_source = 0;

	return FALSE;
}

static void cint_cmgf_set_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);

	if (ok) {
		data->retries = 0;
		set_cpms(sms);
		return;
	}

	data->retries += 1;

	if (data->retries == MAX_CMGF_RETRIES) {
		DBG("Unable to enter PDU mode");
		return cint_sms_not_supported(sms);
	}

	data->timeout_source = g_timeout_add_seconds(1, set_cmgf, sms);
}

static gboolean set_cmgf(gpointer user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);

	g_at_chat_send(data->chat, "AT+CMGF=0", cmgf_prefix,
			cint_cmgf_set_cb, sms, NULL);

	data->timeout_source = 0;

	return FALSE;
}

static void cint_cpms_query_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);
	gboolean supported = FALSE;

	if (ok) {
		int mem = 0, mem_max;
		GAtResultIter iter;
		const char *store;
		gboolean me_supported[3];
		gboolean sm_supported[3];
		gboolean mt_supported[3];

		memset(me_supported, 0, sizeof(me_supported));
		memset(sm_supported, 0, sizeof(sm_supported));
		memset(mt_supported, 0, sizeof(mt_supported));

		g_at_result_iter_init(&iter, result);

		if (!g_at_result_iter_next(&iter, "+CPMS:"))
			goto out;

		mem_max = 3;

		for (mem = 0; mem < mem_max; mem++) {
			if (!g_at_result_iter_open_list(&iter))
				goto out;

			while (g_at_result_iter_next_string(&iter, &store)) {
				if (!strcmp(store, "ME"))
					me_supported[mem] = TRUE;
				else if (!strcmp(store, "SM"))
					sm_supported[mem] = TRUE;
				else if (!strcmp(store, "MT"))
					mt_supported[mem] = TRUE;
			}

			if (!g_at_result_iter_close_list(&iter))
				goto out;
		}

		if (!sm_supported[2] && !me_supported[2]
				&& !mt_supported[2])
			goto out;

		if (sm_supported[0] && sm_supported[1]) {
			supported = TRUE;
			data->store = CINT_UTIL_SMS_STORE_SM;
		}

		if (me_supported[0] && me_supported[1]) {
			supported = TRUE;
			data->store = CINT_UTIL_SMS_STORE_ME;
		}

		/* This seems to be a special case, where the modem will
		 * pick & route the SMS to any of the storages supported by
		 * mem1
		 */
		if (mt_supported[2] && (sm_supported[0] || me_supported[0]))
			data->incoming = CINT_UTIL_SMS_STORE_MT;

		if (sm_supported[2])
			data->incoming = CINT_UTIL_SMS_STORE_SM;

		if (me_supported[2])
			data->incoming = CINT_UTIL_SMS_STORE_ME;
	}
out:
	if (!supported)
		return cint_sms_not_supported(sms);

	set_cmgf(sms);
}

static void cint_cmgf_query_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);
	gboolean supported = FALSE;

	if (ok) {
		GAtResultIter iter;
		int mode;

		g_at_result_iter_init(&iter, result);

		if (!g_at_result_iter_next(&iter, "+CMGF:"))
			goto out;

		if (!g_at_result_iter_open_list(&iter))
			goto out;

		/* Look for mode 0 (PDU mode) */
		while (g_at_result_iter_next_number(&iter, &mode))
			if (mode == 0)
				supported = TRUE;
	}

out:
	if (!supported)
		return cint_sms_not_supported(sms);

	g_at_chat_send(data->chat, "AT+CPMS=?", cpms_prefix,
			cint_cpms_query_cb, sms, NULL);
}

static void cint_csms_status_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);
	gboolean supported = FALSE;

	if (ok) {
		GAtResultIter iter;
		int service;
		int mt;
		int mo;

		g_at_result_iter_init(&iter, result);

		if (!g_at_result_iter_next(&iter, "+CSMS:"))
			goto out;


		if (!g_at_result_iter_next_number(&iter, &service))
			goto out;

		if (!g_at_result_iter_next_number(&iter, &mt))
			goto out;

		if (!g_at_result_iter_next_number(&iter, &mo))
			goto out;

		if (service == 1)
			data->cnma_enabled = TRUE;

		if (mt == 1 && mo == 1)
			supported = TRUE;
	}

out:
	if (!supported)
		return cint_sms_not_supported(sms);

	/* Now query supported text format */
	g_at_chat_send(data->chat, "AT+CMGF=?", cmgf_prefix,
			cint_cmgf_query_cb, sms, NULL);
}

static void cint_csms_set_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);

	g_at_chat_send(data->chat, "AT+CSMS?", csms_prefix,
			cint_csms_status_cb, sms, NULL);
}

static void cint_csms_query_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	struct ofono_sms *sms = user_data;
	struct sms_data *data = ofono_sms_get_data(sms);
	gboolean cnma_supported = FALSE;
	GAtResultIter iter;
	int status_min, status_max;
	char buf[128];

	if (!ok)
		return cint_sms_not_supported(sms);

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CSMS:"))
		goto out;

	if (!g_at_result_iter_open_list(&iter))
		goto out;

	while (g_at_result_iter_next_range(&iter, &status_min, &status_max))
		if (status_min <= 1 && 1 <= status_max)
			cnma_supported = TRUE;

	DBG("CSMS query parsed successfully");

out:
	snprintf(buf, sizeof(buf), "AT+CSMS=%d", cnma_supported ? 1 : 0);

	g_at_chat_send(data->chat, buf, csms_prefix,
			cint_csms_set_cb, sms, NULL);
}

static int cint_sms_probe(struct ofono_sms *sms, unsigned int vendor,
				void *user)
{
	GAtChat *chat = user;
	struct sms_data *data;

	data = g_new0(struct sms_data, 1);
	data->chat = g_at_chat_clone(chat);
	data->modem = vendor;

	/*
	 * URC:s indicating new incoming SMS are to be sent to application-port
	 */
	g_at_chat_send(data->chat, "AT^SCFG=\"URC/DstIfc\",\"app\"", none_prefix,
			NULL, NULL, NULL);

	ofono_sms_set_data(sms, data);

	g_at_chat_send(data->chat, "AT+CSMS=?", csms_prefix,
			cint_csms_query_cb, sms, NULL);

	return 0;
}

static void cint_sms_remove(struct ofono_sms *sms)
{
	struct sms_data *data = ofono_sms_get_data(sms);

	g_free(data->cnma_ack_pdu);

	if (data->timeout_source > 0)
		g_source_remove(data->timeout_source);

	g_at_chat_unref(data->chat);
	g_free(data);

	ofono_sms_set_data(sms, NULL);
}

static struct ofono_sms_driver driver = {
	.name		= "cinterionmodem",
	.probe		= cint_sms_probe,
	.remove		= cint_sms_remove,
	.sca_query	= cint_csca_query,
	.sca_set	= cint_csca_set,
	.submit		= cint_cmgs,
	.bearer_query	= cint_cgsms_query,
	.bearer_set	= cint_cgsms_set,
};

void cint_sms_init(void)
{
	ofono_sms_driver_register(&driver);
}

void cint_sms_exit(void)
{
	ofono_sms_driver_unregister(&driver);
}
