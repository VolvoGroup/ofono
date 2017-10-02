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

enum cint_util_sms_store {
	CINT_UTIL_SMS_STORE_SM =	0,
	CINT_UTIL_SMS_STORE_ME =	1,
	CINT_UTIL_SMS_STORE_MT =	2,
	CINT_UTIL_SMS_STORE_SR =	3,
	CINT_UTIL_SMS_STORE_BM =	4,
};

/* 3GPP TS 27.007 Release 8 Section 5.5 */
enum cint_util_charset {
	CINT_UTIL_CHARSET_GSM =		0x1,
	CINT_UTIL_CHARSET_HEX =		0x2,
	CINT_UTIL_CHARSET_IRA =		0x4,
	CINT_UTIL_CHARSET_PCCP437 =	0x8,
	CINT_UTIL_CHARSET_PCDN =		0x10,
	CINT_UTIL_CHARSET_UCS2 =		0x20,
	CINT_UTIL_CHARSET_UTF8 =		0x40,
	CINT_UTIL_CHARSET_8859_1 =	0x80,
	CINT_UTIL_CHARSET_8859_2 =	0x100,
	CINT_UTIL_CHARSET_8859_3 =	0x200,
	CINT_UTIL_CHARSET_8859_4 =	0x400,
	CINT_UTIL_CHARSET_8859_5 =	0x800,
	CINT_UTIL_CHARSET_8859_6 =	0x1000,
	CINT_UTIL_CHARSET_8859_C =	0x2000,
	CINT_UTIL_CHARSET_8859_A =	0x4000,
	CINT_UTIL_CHARSET_8859_G =	0x8000,
	CINT_UTIL_CHARSET_8859_H =	0x10000,
};

typedef void (*cint_util_sim_inserted_cb_t)(gboolean present, void *userdata);

void cint_util_decode_at_error(struct ofono_error *error, const char *final);
gint cint_util_call_compare_by_status(gconstpointer a, gconstpointer b);
gint cint_util_call_compare_by_phone_number(gconstpointer a, gconstpointer b);
gint cint_util_call_compare_by_id(gconstpointer a, gconstpointer b);
gint cint_util_call_compare(gconstpointer a, gconstpointer b);
GSList *cint_util_parse_clcc(GAtResult *result, unsigned int *mpty_ids);
gboolean cint_util_parse_reg(GAtResult *result,
				const char *prefix,
				int *mode, int *status,
				int *lac, int *ci, int *tech,
				unsigned int modem);
gboolean cint_util_parse_reg_unsolicited(GAtResult *result,
					const char *prefix,
					int *status, int *lac,
					int *ci, int *tech,
					unsigned int modem);

gboolean cint_util_parse_sms_index_delivery(GAtResult *result,
					const char *prefix,
					enum cint_util_sms_store *store,
					int *index);

gboolean cint_util_parse_cscs_supported(GAtResult *result, int *supported);
gboolean cint_util_parse_cscs_query(GAtResult *result,
				enum cint_util_charset *charset);

gboolean cint_util_parse_attr(GAtResult *result, const char *prefix,
				const char **out_attr);

struct cint_util_sim_state_query *cint_util_sim_state_query_new(GAtChat *chat,
						guint interval,
						guint num_times,
						cint_util_sim_inserted_cb_t cb,
						void *userdata,
						GDestroyNotify destroy);
void cint_util_sim_state_query_free(struct cint_util_sim_state_query *req);

struct cb_data {
	void *cb;
	void *data;
	void *user;
};

static inline struct cb_data *cb_data_new(void *cb, void *data)
{
	struct cb_data *ret;

	ret = g_new0(struct cb_data, 1);
	ret->cb = cb;
	ret->data = data;

	return ret;
}

static inline int cint_util_convert_signal_strength(int strength)
{
	int result;

	if (strength == 99)
		result = -1;
	else
		result = (strength * 100) / 31;

	return result;
}

#define CALLBACK_WITH_FAILURE(cb, args...)		\
	do {						\
		struct ofono_error cb_e;		\
		cb_e.type = OFONO_ERROR_TYPE_FAILURE;	\
		cb_e.error = 0;				\
							\
		cb(&cb_e, ##args);			\
	} while (0)					\

#define CALLBACK_WITH_SUCCESS(f, args...)		\
	do {						\
		struct ofono_error e;			\
		e.type = OFONO_ERROR_TYPE_NO_ERROR;	\
		e.error = 0;				\
		f(&e, ##args);				\
	} while (0)
