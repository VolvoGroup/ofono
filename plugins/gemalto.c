/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2017 Vincent Cesson. All rights reserved.
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
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <linux/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <glib.h>
#include <gatchat.h>
#include <gattty.h>
#include <gdbus.h>
#include "ofono.h"
#define OFONO_API_SUBJECT_TO_CHANGE
#include <ofono/dbus.h>
#include <ofono/plugin.h>
#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/devinfo.h>
#include <ofono/netreg.h>
#include <ofono/phonebook.h>
#include <ofono/sim.h>
#include <ofono/sms.h>
#include <ofono/gprs.h>
#include <ofono/gprs-context.h>
#include <ofono/location-reporting.h>
#include <drivers/atmodem/atutil.h>
#include <drivers/atmodem/vendor.h>
#include <string.h>

#ifdef HAVE_ELL
#include <ell/ell.h>
#include <drivers/mbimmodem/mbim.h>
#include <drivers/mbimmodem/mbim-message.h>
#include <drivers/mbimmodem/mbim-desc.h>
#endif

#include <drivers/qmimodem/qmi.h>

#include <src/storage.h>

#define REDCOLOR "\x1b\x5b\x30\x31\x3b\x33\x31\x6d"
#define NOCOLOR "\x1b\x5b\x30\x30\x6d"

#define HARDWARE_MONITOR_INTERFACE OFONO_SERVICE ".gemalto.HardwareMonitor"
#define GEMALTO_NITZ_TIME_INTERFACE OFONO_SERVICE ".gemalto.TimeServices"
#define COMMAND_PASSTHROUGH_INTERFACE OFONO_SERVICE ".gemalto.CommandPassthrough"

enum gemalto_connection_type {
	GEMALTO_CONNECTION_SERIAL=1,
	GEMALTO_CONNECTION_USB=2,
};

enum gemalto_device_state {
	STATE_ABSENT=0,
	STATE_PROBE=1,
	STATE_TESTING=2,
	STATE_PRESENT=3,
	STATE_PROBE_DIRECT=4,
	STATE_PROBE_INVERSE=5,
	STATE_PROBE_DIRECT_INVERSE=6,
};

enum auth_option {
	GEMALTO_CGAUTH_USER_PWD_PARTIAL=0,
	GEMALTO_SGAUTH_PWD_USER_PARTIAL=1,
	GEMALTO_SGAUTH_USER_PWD_FULL=2, /* TODO: use it when needed */
};

enum gprs_option {
	NO_GPRS=0,
	USE_SWWAN=1,
	USE_CTX17=2,
	USE_CTX3=3,
	USE_PPP=4,
};

static const char *none_prefix[] = { NULL };
static const char *sctm_prefix[] = { "^SCTM:", NULL };
static const char *sbv_prefix[] = { "^SBV:", NULL };

struct gemalto_hardware_monitor {
	DBusMessage *msg;
	int32_t temperature;
	int32_t voltage;
};

struct gemalto_command_passthrough {
	DBusMessage *msg;
};

struct gemalto_data {
	gboolean init_done;
	GAtChat *at_tmp;
	GAtChat *app;
	GAtChat *mdm;
	struct ofono_sim *sim;
	gboolean have_sim;
	struct at_util_sim_state_query *sim_state_query;
	struct gemalto_hardware_monitor *hm;
	struct gemalto_command_passthrough * cpt;
	guint modem_ready_id;
	guint trial_cmd_id;
	guint modem_ready_id_inv;
	guint trial_cmd_id_inv;

	guint model;
	guint probing_timer;
	guint init_waiting_time;

	enum gemalto_connection_type conn;
	enum gemalto_device_state mbim;
	enum gemalto_device_state qmi;
	enum gemalto_device_state ecmncm;
	enum gemalto_device_state gina;
	enum gemalto_device_state appport;
	enum gemalto_device_state mdmport;
	gboolean inverse_enum;
	gboolean use_mdm_for_app;
	gboolean voice_avail;
	enum auth_option auth_syntax;
	enum gprs_option gprs_opt;
	gboolean autoattach;
	gboolean autoconfig;
	gboolean autoactivation;
	gboolean vts_with_quotes;

	void *device; /* struct mbim_device* or struct qmi_device* */

	/* mbim data */
	uint16_t max_segment;
	uint8_t max_outstanding;
	uint8_t max_sessions;
};

static void gemalto_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	ofono_info("%s%s", prefix, str);
}

static const char *gemalto_get_string(struct ofono_modem *modem, const char *k)
{
	const char *v;

	if (!modem || !k || !*k)
		return NULL;

	v = ofono_modem_get_string(modem, k);

	if (!v || !*v)
		return NULL;

	return v;
}

#ifdef HAVE_ELL
static int mbim_parse_descriptors(struct gemalto_data *md, const char *file)
{
	void *data;
	size_t len;
	const struct mbim_desc *desc = NULL;
	const struct mbim_extended_desc *ext_desc = NULL;

	data = l_file_get_contents(file, &len);
	if (!data)
		return -EIO;

	if (!mbim_find_descriptors(data, len, &desc, &ext_desc)) {
		l_free(data);
		return -ENOENT;
	}

	if (desc)
		md->max_segment = L_LE16_TO_CPU(desc->wMaxControlMessage);

	if (ext_desc)
		md->max_outstanding = ext_desc->bMaxOutstandingCommandMessages;

	l_free(data);
	return 0;
}

static int mbim_probe(struct ofono_modem *modem, struct gemalto_data *data)
{
	const char *descriptors;
	int err;

	descriptors = gemalto_get_string(modem, "DescriptorFile");

	if (!descriptors)
		return -EINVAL;

	data->max_outstanding = 1;

	err = mbim_parse_descriptors(data, descriptors);
	if (err < 0) {
		DBG("Warning, unable to load descriptors, setting defaults");
		data->max_segment = 512;
	}

	DBG("MaxSegment: %d, MaxOutstanding: %d",
		data->max_segment, data->max_outstanding);

	return 0;
}
#endif

static int gemalto_probe(struct ofono_modem *modem)
{
	struct gemalto_data *data;

	data = g_try_new0(struct gemalto_data, 1);
	if (data == NULL)
		return -ENOMEM;

#ifdef HAVE_ELL
	mbim_probe(modem, data);
#endif

	ofono_modem_set_data(modem, data);

	return 0;
}

static void gemalto_remove(struct ofono_modem *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);

#ifdef HAVE_ELL
	if (data->mbim!=STATE_ABSENT) {
		mbim_device_shutdown(data->device);
	}

#endif

	if (data->qmi==STATE_PRESENT) {
		qmi_device_unref(data->device);
		data->device = NULL;
	}

	if (data->app) {
		g_at_chat_unregister_all(data->app);
		g_at_chat_unref(data->app);
		data->app = NULL;
	}

	if (data->mdm) {
		g_at_chat_unregister_all(data->mdm);
		g_at_chat_unref(data->mdm);
		data->mdm = NULL;
	}

	/* Cleanup potential SIM state polling */
	at_util_sim_state_query_free(data->sim_state_query);
	data->sim_state_query = NULL;

	ofono_modem_set_data(modem, NULL);
	g_free(data);
}

static GAtChat *open_device(const char *device)
{
	GAtSyntax *syntax;
	GIOChannel *channel;
	GAtChat *chat;
	GHashTable *options;

	options = g_hash_table_new(g_str_hash, g_str_equal);
	if (options == NULL)
		return NULL;

	g_hash_table_insert(options, "Baud", "115200");
	g_hash_table_insert(options, "StopBits", "1");
	g_hash_table_insert(options, "DataBits", "8");
	g_hash_table_insert(options, "Parity", "none");
	g_hash_table_insert(options, "XonXoff", "off");
	g_hash_table_insert(options, "RtsCts", "on");
	g_hash_table_insert(options, "Local", "on");
	g_hash_table_insert(options, "Read", "on");

	DBG("Opening device %s", device);

	channel = g_at_tty_open(device, options);
	g_hash_table_destroy(options);

	if (channel == NULL)
		return NULL;

	syntax = g_at_syntax_new_gsm_permissive();
	chat = g_at_chat_new(channel, syntax);
	g_at_syntax_unref(syntax);
	g_io_channel_unref(channel);

	if (chat == NULL)
		return NULL;

	return chat;
}

static void sim_ready_cb(gboolean present, gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);
	struct ofono_sim *sim = data->sim;

	at_util_sim_state_query_free(data->sim_state_query);
	data->sim_state_query = NULL;

	DBG("sim present: %d", present);

	ofono_sim_inserted_notify(sim, present);
}

static void gemalto_ciev_simstatus_notify(GAtResultIter *iter,
					struct ofono_modem *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);
	struct ofono_sim *sim = data->sim;
	int status;

	DBG("sim status %d", status);

	if (!g_at_result_iter_next_number(iter, &status))
		return;

	switch (status) {
	/* SIM is removed from the holder */
	case 0:
		ofono_sim_inserted_notify(sim, FALSE);
		break;

	/* SIM is inserted inside the holder */
	case 1:
		/* The SIM won't be ready yet */
		data->sim_state_query = at_util_sim_state_query_new(data->app,
					1, 20, sim_ready_cb, modem,
					NULL);
		break;

	/* USIM initialization completed. UE has finished reading USIM data. */
	case 5:
		ofono_sim_initialized_notify(sim);
		break;

	default:
		break;
	}
}

static void gemalto_signal(const char *iface, const char *name,
	const char *value, struct ofono_modem *modem)
{
	DBusMessageIter sub_iter,iter;
	const char *path = ofono_modem_get_path(modem);
	DBusConnection *conn = ofono_dbus_get_connection();

	DBusMessage *signal = dbus_message_new_signal(path,
					iface,
					name);

	DBG("");

	if (signal == NULL) {
		DBG("Cannot create new signal message");
		return;
	}

	dbus_message_iter_init_append(signal, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
							"s", &sub_iter);
	if (!dbus_message_iter_append_basic(&sub_iter,
				DBUS_TYPE_STRING, &value)) {
		DBG("Out of memory!");
		return;
	}

	dbus_message_iter_close_container(&iter, &sub_iter);
	g_dbus_send_message(conn, signal);
}

static void gemalto_ciev_nitz_notify(GAtResultIter *iter,
					struct ofono_modem *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);
	const char *nitz_data;
	char buf[32];

	/* Example: +CIEV: nitz,<time>,<timezone>,<daylight> */
	if (!g_at_result_iter_next_string(iter, &nitz_data))
		return;

	DBG("nitz_data  %s", nitz_data);

	sprintf(buf, "AT+CCLK=\"%s\"", nitz_data);
	g_at_chat_send(data->app, buf, none_prefix, NULL, NULL, NULL);

	gemalto_signal(GEMALTO_NITZ_TIME_INTERFACE, "NitzUpdated", nitz_data,
									modem);
}

static void gemalto_ciev_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_modem *modem = user_data;

	const char *sim_status = "simstatus";
	const char *nitz_status = "nitz";
	const char *ind_str;
	GAtResultIter iter;

	g_at_result_iter_init(&iter, result);

	/* Example: +CIEV: simstatus,<status> */
	if (!g_at_result_iter_next(&iter, "+CIEV:"))
		return;

	if (!g_at_result_iter_next_unquoted_string(&iter, &ind_str))
		return;

	if (g_str_equal(sim_status, ind_str)) {
		gemalto_ciev_simstatus_notify(&iter, modem);
	} else if (g_str_equal(nitz_status, ind_str)) {
		gemalto_ciev_nitz_notify(&iter, modem);
	}
}

static void sim_state_cb(gboolean present, gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);

	at_util_sim_state_query_free(data->sim_state_query);
	data->sim_state_query = NULL;

	data->have_sim = present;
	ofono_modem_set_powered(modem, TRUE);

	/* Register for specific sim status reports */
	g_at_chat_register(data->app, "+CIEV:",
			gemalto_ciev_notify, FALSE, modem, NULL);

	g_at_chat_send(data->app, "AT^SIND=\"simstatus\",1", none_prefix,
			NULL, NULL, NULL);
	g_at_chat_send(data->app, "AT^SIND=\"nitz\",1", none_prefix,
			NULL, NULL, NULL);
}

static void cfun_enable(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);

	if (!ok) {
		g_at_chat_unref(data->app);
		data->app = NULL;

		g_at_chat_unref(data->mdm);
		data->mdm = NULL;

		ofono_modem_set_powered(modem, FALSE);
		return;
	}

	data->sim_state_query = at_util_sim_state_query_new(data->app,
						2, 20, sim_state_cb, modem,
						NULL);
}

static void gemalto_sctmb_notify(GAtResult *result, gpointer user_data)
{
	GAtResultIter iter;
	gint value;
	char *val;

	g_at_result_iter_init(&iter, result);
	g_at_result_iter_next(&iter, "^SCTM_B:");
	g_at_result_iter_next_number(&iter, &value);

	switch(value) {
	case -1:
		val="Below low temperature alert limit";
		break;
	case 0:
		val="Normal operating temperature";
		break;
	case 1:
		val="Above upper temperature alert limit";
		break;
	case 2:
		val="Above uppermost temperature limit";
		break;
	default: /* unvalid value, do not output signal*/
		return;
	}

	gemalto_signal(HARDWARE_MONITOR_INTERFACE, "CriticalTemperature", val,
								user_data);
}

static void gemalto_sbc_notify(GAtResult *result, gpointer user_data)
{
	GAtResultIter iter;
	const char *value;

	g_at_result_iter_init(&iter, result);
	g_at_result_iter_next(&iter, "^SBC:");
	g_at_result_iter_next_unquoted_string(&iter, &value);
	gemalto_signal(HARDWARE_MONITOR_INTERFACE, "CriticalVoltage", value,
								user_data);
}

static void gemalto_sctm_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct gemalto_data *data = user_data;
	DBusMessage *reply;
	GAtResultIter iter;
	DBusMessageIter dbus_iter;
	DBusMessageIter dbus_dict;

	if (data->hm->msg == NULL)
		return;

	if (!ok)
		goto error;

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "^SCTM:"))
		goto error;

	if (!g_at_result_iter_skip_next(&iter))
		goto error;

	if (!g_at_result_iter_skip_next(&iter))
		goto error;

	if (!g_at_result_iter_next_number(&iter, &data->hm->temperature))
		goto error;

	reply = dbus_message_new_method_return(data->hm->msg);

	dbus_message_iter_init_append(reply, &dbus_iter);

	dbus_message_iter_open_container(&dbus_iter, DBUS_TYPE_ARRAY,
			OFONO_PROPERTIES_ARRAY_SIGNATURE,
			&dbus_dict);

	ofono_dbus_dict_append(&dbus_dict, "Temperature",
			DBUS_TYPE_INT32, &data->hm->temperature);

	ofono_dbus_dict_append(&dbus_dict, "Voltage",
			DBUS_TYPE_UINT32, &data->hm->voltage);

	dbus_message_iter_close_container(&dbus_iter, &dbus_dict);

	__ofono_dbus_pending_reply(&data->hm->msg, reply);

	return;

error:
	__ofono_dbus_pending_reply(&data->hm->msg,
			__ofono_error_failed(data->hm->msg));
}

static void gemalto_sbv_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct gemalto_data *data = user_data;
	GAtResultIter iter;

	if (!ok)
		goto error;

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "^SBV:"))
		goto error;

	if (!g_at_result_iter_next_number(&iter, &data->hm->voltage))
		goto error;

	if (g_at_chat_send(data->app, "AT^SCTM?", sctm_prefix, gemalto_sctm_cb,
				data, NULL) > 0)
		return;

error:
	__ofono_dbus_pending_reply(&data->hm->msg,
			__ofono_error_failed(data->hm->msg));
}

static DBusMessage *hardware_monitor_get_statistics(DBusConnection *conn,
							DBusMessage *msg,
							void *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);

	DBG("");

	if (data->hm->msg != NULL)
		return __ofono_error_busy(msg);

	if (!g_at_chat_send(data->app, "AT^SBV", sbv_prefix, gemalto_sbv_cb,
			data, NULL))
		return __ofono_error_failed(msg);

	data->hm->msg = dbus_message_ref(msg);

	return NULL;
}

static DBusMessage *gemalto_set_modem_datetime(DBusConnection *conn,
							DBusMessage *msg,
							void *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);
	time_t t = time(NULL);
	struct tm tm;
	gchar cclk_cmd[32];

	/* Set date and time */
	tm = *localtime(&t);
	strftime(cclk_cmd, 32, "AT+CCLK=\"%y/%m/%d,%T\"", &tm);
	g_at_chat_send(data->app, cclk_cmd, none_prefix, NULL, NULL, NULL);
	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable hardware_monitor_methods[] = {
	{ GDBUS_ASYNC_METHOD("GetStatistics",
			NULL, GDBUS_ARGS({ "Statistics", "a{sv}" }),
			hardware_monitor_get_statistics) },
	{}
};

static const GDBusSignalTable hardware_monitor_signals[] = {
	{ GDBUS_SIGNAL("CriticalTemperature",
			GDBUS_ARGS({ "temperature", "a{sv}" }) )},
	{ GDBUS_SIGNAL("CriticalVoltage",
			GDBUS_ARGS({ "voltage", "a{sv}" }) )},
	{}
};

static const GDBusMethodTable gsmTime_methods[] = {
	{ GDBUS_ASYNC_METHOD("SetModemDatetime",
			NULL, NULL, gemalto_set_modem_datetime) },
	{}
};

static const GDBusSignalTable gsmTime_signals[] = {
	{ GDBUS_SIGNAL("NitzUpdated",
			GDBUS_ARGS({ "time", "a{sv}" }) )},
	{}
};


static void gemalto_hardware_monitor_cleanup(void *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);
	struct gemalto_hardware_monitor *hm = data->hm;

	if (hm)
		g_free(hm);

	hm=NULL;
}

static int gemalto_hardware_monitor_enable(struct ofono_modem *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path = ofono_modem_get_path(modem);

	DBG("");

	/* Create Hardware Monitor DBus interface */
	data->hm = g_try_new0(struct gemalto_hardware_monitor, 1);
	if (data->hm == NULL)
		return -EIO;

	/* Listen to over/undertemperature URCs (activated with AT^SCTM) */
	g_at_chat_register(data->app, "^SCTM_B:",
		gemalto_sctmb_notify, FALSE, NULL, NULL);
	/* Listen to over/under voltage URCs (automatic URC) */
	g_at_chat_register(data->app, "^SBC:",
		gemalto_sbc_notify, FALSE, NULL, NULL);
	/* Enable temperature URC and value output */
	g_at_chat_send(data->app, "AT^SCTM=1,1", none_prefix, NULL, NULL, NULL);

	if (!g_dbus_register_interface(conn, path, HARDWARE_MONITOR_INTERFACE,
					hardware_monitor_methods,
					hardware_monitor_signals,
					NULL,
					modem,
					gemalto_hardware_monitor_cleanup)) {
		ofono_error("Could not register %s interface under %s",
					HARDWARE_MONITOR_INTERFACE, path);
		g_free(data->hm);
		return -EIO;
	}

	ofono_modem_add_interface(modem, HARDWARE_MONITOR_INTERFACE);
	return 0;
}

static int gemalto_time_enable(struct ofono_modem *modem)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path = ofono_modem_get_path(modem);

	DBG("GSM network time probe for modem: %p (%s)", modem, path);

	if (!g_dbus_register_interface(conn, path,
					GEMALTO_NITZ_TIME_INTERFACE,
					gsmTime_methods,
					gsmTime_signals,
					NULL,
					modem,
					NULL)) {
		DBG("Networkt time: Could not register interface %s, path %s",
					GEMALTO_NITZ_TIME_INTERFACE, path);
		return -EIO;
	} else {
		ofono_info("Network time: Registered inteface %s, path %s",
					GEMALTO_NITZ_TIME_INTERFACE, path);
	}

	ofono_modem_add_interface(modem, GEMALTO_NITZ_TIME_INTERFACE);
	return 0;
}


static ofono_bool_t modem_from_data_cmp(struct ofono_modem *modem,
					void *userdata)
{
	void *value = ofono_modem_get_data(modem);

	if (value==userdata)
		return TRUE;

	return FALSE;
}

static struct ofono_modem *modem_from_data(void *userdata)
{
	return ofono_modem_find(modem_from_data_cmp, userdata);
};

static int command_passthrough_signal_answer(const char *answer,
							gpointer user_data)
{
	struct cb_data *cbd = user_data;
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path;
	DBusMessage *signal;
	DBusMessageIter iter;
	struct ofono_modem *modem;

	if (!cbd || !conn)
		return -1;

	modem = modem_from_data(cbd->data);

	if (!modem)
		return -1;

 	path = ofono_modem_get_path(modem);

 	if (!path)
 		return -1;

	signal = dbus_message_new_signal(path, COMMAND_PASSTHROUGH_INTERFACE,
								"Answer");
	if (!signal) {
		ofono_error("Unable to allocate new %s.PropertyChanged signal",
						COMMAND_PASSTHROUGH_INTERFACE);
		return -1;
	}

	dbus_message_iter_init_append(signal, &iter);

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &answer);

	DBG("");

	return g_dbus_send_message(conn, signal);
}

static void command_passthrough_cb(gboolean ok, GAtResult *result,
							gpointer user_data)
{
	GAtResultIter iter;
	guint len=0;
	char *answer;

	g_at_result_iter_init(&iter, result);

	while (g_at_result_iter_next(&iter, NULL)) {
		len+=strlen(g_at_result_iter_raw_line(&iter))+2;
	}

	len+=strlen(g_at_result_final_response(result))+3;
	answer = g_new0(char, len);
	g_at_result_iter_init(&iter, result);

	while (g_at_result_iter_next(&iter, NULL)) {
		sprintf(answer+strlen(answer),"%s\r\n",
					g_at_result_iter_raw_line(&iter));
	}

	sprintf(answer+strlen(answer),"%s\r\n",
					g_at_result_final_response(result));

	DBG("answer_len: %u, answer_string: %s", len, answer);
	command_passthrough_signal_answer(answer, user_data);

	g_free(answer);
	g_free(user_data);
}

static DBusMessage *command_passthrough_simple(DBusConnection *conn,
							DBusMessage *msg,
							void *user_data)
{
	struct gemalto_data *data = user_data;
	struct cb_data *cbd = cb_data_new(NULL, user_data);
	DBusMessageIter iter;
	const char *command;

	if (!cbd)
		return __ofono_error_not_available(msg);

	cbd->user = msg;

	if (!dbus_message_iter_init(msg, &iter))
		return g_dbus_create_error(msg, DBUS_ERROR_INVALID_ARGS,
							"No arguments given");

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return g_dbus_create_error(msg, DBUS_ERROR_INVALID_ARGS,
					"Invalid argument type: '%c'",
					dbus_message_iter_get_arg_type(&iter));

	dbus_message_iter_get_basic(&iter, &command);
	g_at_chat_send(data->app, command, NULL, command_passthrough_cb, cbd,
									NULL);

	return dbus_message_new_method_return(msg);
}

static void executeWithPrompt(GAtChat *port, const char *command,
			const char *prompt, const char *argument, void *cb,
			void *cbd, void *freecall)
{
	char *buf;
	const char *expected_array[2] = {0,0};

	buf = g_strdup_printf("%s\r%s", command, argument);

	if (strlen(argument)>=2 && g_str_equal(argument+strlen(argument)-2,
									"^Z"))
		sprintf(buf+strlen(buf)-2,"\x1a");

	if (strlen(argument)>=2 && g_str_equal(argument+strlen(argument)-2,
									"\\r"))
		sprintf(buf+strlen(buf)-2,"\r");

	expected_array[0]=prompt;
	g_at_chat_send_and_expect_short_prompt(port, buf, expected_array,
							cb, cbd, freecall);
	free(buf);
}

static DBusMessage *command_passthrough_with_prompt(DBusConnection *conn,
							DBusMessage *msg,
							void *user_data)
{
	struct gemalto_data *data = user_data;
	struct cb_data *cbd = cb_data_new(NULL, user_data);
	DBusMessageIter iter;
	const char *command, *prompt, *argument;

	if (!cbd)
		return __ofono_error_not_available(msg);

	cbd->user = msg;

	if (!dbus_message_iter_init(msg, &iter))
		return g_dbus_create_error(msg, DBUS_ERROR_INVALID_ARGS,
							"No arguments given");

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return g_dbus_create_error(msg, DBUS_ERROR_INVALID_ARGS,
					"Invalid argument type: '%c'",
					dbus_message_iter_get_arg_type(&iter));

	dbus_message_iter_get_basic(&iter, &command);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return g_dbus_create_error(msg, DBUS_ERROR_INVALID_ARGS,
					"Invalid argument type: '%c'",
					dbus_message_iter_get_arg_type(&iter));

	dbus_message_iter_get_basic(&iter, &prompt);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return g_dbus_create_error(msg, DBUS_ERROR_INVALID_ARGS,
					"Invalid argument type: '%c'",
					dbus_message_iter_get_arg_type(&iter));

	dbus_message_iter_get_basic(&iter, &argument);

	executeWithPrompt(data->app, command, prompt, argument,
		command_passthrough_cb, cbd, NULL);

	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable command_passthrough_methods[] = {
	{ GDBUS_ASYNC_METHOD("Simple",
		GDBUS_ARGS({ "command", "s" }),
		NULL,
		command_passthrough_simple) },
	{ GDBUS_ASYNC_METHOD("WithPrompt",
		GDBUS_ARGS({ "command", "s" }, { "prompt", "s" },
							{ "argument", "s" }),
		NULL,
		command_passthrough_with_prompt) },
	{}
};

static const GDBusSignalTable command_passthrough_signals[] = {
	{ GDBUS_SIGNAL("Answer",
		GDBUS_ARGS({ "answer", "s" })) },
	{ }
};

static void gemalto_command_passthrough_cleanup(void *user_data)
{
	struct gemalto_data *data = user_data;
	struct gemalto_command_passthrough *cpt = data->cpt;

	g_free(cpt);
	data->cpt=NULL;
}

static void passthrough_stored(void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);
	const char *vid = gemalto_get_string(modem, "Vendor");
	const char *pid = gemalto_get_string(modem, "Model");
	char store[32];
	int index;
	char *command, *prompt, *argument;
	char key[32];
	GKeyFile *f;

	sprintf(store,"%s-%s/passthrough", vid, pid);
	f = storage_open(NULL, store);

	if (!f)
		return;

	for (index=0;;index++) {
		sprintf(key, "command_%d", index);
		command = g_key_file_get_string(f, "Simple", key, NULL);

		if (!command)
			break;

		DBG("executing stored command simple: %s", command);
		g_at_chat_send(data->app, command, NULL, NULL, NULL, NULL);
	}

	for (index=0;;index++) {
		sprintf(key, "command_%d", index);
		command = g_key_file_get_string(f, "WithPrompt", key, NULL);
		sprintf(key, "prompt_%d", index);
		prompt = g_key_file_get_string(f, "WithPrompt", key, NULL);
		sprintf(key, "argument_%d", index);
		argument = g_key_file_get_string(f, "WithPrompt", key, NULL);

		if (!command || !prompt || !argument)
			break;

		DBG("executing stored command with prompt: %s", command);
		executeWithPrompt(data->app, command, prompt, argument,
			NULL, NULL, NULL);
	}

	storage_close(NULL, store, f, FALSE);
}

static int gemalto_command_passthrough_enable(struct ofono_modem *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path = ofono_modem_get_path(modem);

	DBG("");

	/* Create Command Passthrough DBus interface */
	data->cpt = g_try_new0(struct gemalto_command_passthrough, 1);
	if (data->cpt == NULL)
		return -EIO;

	if (!g_dbus_register_interface(conn, path, COMMAND_PASSTHROUGH_INTERFACE,
					command_passthrough_methods,
					command_passthrough_signals,
					NULL,
					data,
					gemalto_command_passthrough_cleanup)) {
		ofono_error("Could not register %s interface under %s",
					COMMAND_PASSTHROUGH_INTERFACE, path);
		g_free(data->cpt);
		data->cpt=NULL;
		return -EIO;
	}

	ofono_modem_add_interface(modem, COMMAND_PASSTHROUGH_INTERFACE);
	passthrough_stored(modem);
	return 0;
}

static void gemalto_exit_urc_notify(GAtResult *result, gpointer user_data)
{
	GAtResultIter iter;
	const char *error_message;

	g_at_result_iter_init(&iter, result);
	g_at_result_iter_next(&iter, "^EXIT:");
	g_at_result_iter_next_unquoted_string(&iter, &error_message);

	ofono_error("Modem exited! Cause: %s", error_message);
	// TODO: change to not-initialized for serial modules.
	// For usb modules automatic because they disappear from enumeration
}

static void saic_probe(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct gemalto_data *data = ofono_modem_get_data(user_data);

	if (ok)
		data->voice_avail = TRUE;
	else
		data->voice_avail = FALSE;
}

static void sgauth_probe(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct gemalto_data *data = ofono_modem_get_data(user_data);

	if (ok)
		data->auth_syntax = GEMALTO_SGAUTH_PWD_USER_PARTIAL;
	else
		data->auth_syntax = GEMALTO_CGAUTH_USER_PWD_PARTIAL;
}

#ifdef HAVE_ELL
static void mbim_device_closed(void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *md = ofono_modem_get_data(modem);

	if (!md)
		return;

	md->mbim = STATE_PROBE; /* reset for future attempt */

	if (md->device)
		mbim_device_unref(md->device);

	md->device = NULL;
}
#endif

static void gemalto_powersave(struct ofono_modem *modem, ofono_bool_t enable);

static int gemalto_initialize(void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);
	char *urcdest;

	if (data->inverse_enum) {
		ofono_modem_set_string(modem, "GNSS",
					gemalto_get_string(modem, "GNSSBis"));
		ofono_modem_set_string(modem, "RSA",
					gemalto_get_string(modem, "RSABis"));
	}

	DBG("app:%d, mdm:%d, mbim:%d, qmi:%d",
		data->appport==STATE_PRESENT,
		data->mdmport==STATE_PRESENT,
		data->mbim==STATE_PRESENT,
		data->qmi==STATE_PRESENT);

	if (data->appport==STATE_ABSENT && data->mdmport==STATE_ABSENT) {
		DBG("no AT interface available. Removing this device.");
		ofono_modem_set_powered(modem, FALSE);
		return -EINVAL;
	}

	urcdest = "AT^SCFG=\"URC/DstIfc\",\"app\"";

	if (data->appport==STATE_ABSENT) {
		data->use_mdm_for_app = TRUE;
		data->app=data->mdm;
		urcdest = "AT^SCFG=\"URC/DstIfc\",\"mdm\"";
	}

#ifdef HAVE_ELL
	if (data->mbim == STATE_PRESENT) {
		mbim_device_set_disconnect_handler(data->device,
				mbim_device_closed, modem, NULL);

	}
#endif

	if (!data->mdm && (data->gina==STATE_PRESENT)) {
		data->mdm=data->app; /*GINA modem can start PPP from any port*/
		data->mdmport = STATE_PRESENT;
	}

	if (data->mdmport==STATE_PRESENT && data->gprs_opt==NO_GPRS)
		data->gprs_opt=USE_PPP;

	g_at_chat_send(data->app, "ATE0", none_prefix, NULL, NULL, NULL);

	if (data->gina!=STATE_PRESENT)
		g_at_chat_send(data->app, urcdest, none_prefix, NULL, NULL,
									NULL);

	/* numeric error codes are interpreted by atmodem/atutil.c functions */
	g_at_chat_send(data->app, "AT+CMEE=1", none_prefix, NULL, NULL, NULL);

	if (data->mdm)
		g_at_chat_send(data->mdm, "AT&C0", none_prefix, NULL, NULL,
									NULL);

	g_at_chat_send(data->app, "AT&C0", none_prefix, NULL, NULL, NULL);
	gemalto_command_passthrough_enable(modem);
	/* watchdog */
	g_at_chat_register(data->app, "^EXIT", gemalto_exit_urc_notify, FALSE,
								NULL, NULL);
	ofono_devinfo_create(modem, OFONO_VENDOR_GEMALTO, "atmodem", data->app);
	g_at_chat_send(data->app,
		"AT^SCFG=\"MEopMode/PwrSave\",\"enabled\",52,50", none_prefix,
							NULL, NULL, NULL);
	gemalto_hardware_monitor_enable(modem);
	gemalto_time_enable(modem);
	g_at_chat_send(data->app, "AT+CFUN=4", none_prefix, cfun_enable, modem,
									NULL);
	ofono_location_reporting_create(modem, 0, "gemaltomodem", data->app);
	g_at_chat_send(data->app, "AT^SAIC?", NULL, saic_probe, modem, NULL);
	g_at_chat_send(data->app, "AT^SGAUTH?", NULL, sgauth_probe, modem,
									NULL);

  // make modem settings match ofono start value (implicit)
	gemalto_powersave(modem, FALSE);

	data->init_done = TRUE;

	return FALSE;
}

#if NEED_THREADS
static gpointer closeport_thread(gpointer user_data)
{
	GAtChat *port = user_data;
	g_at_chat_unref(port);
	DBG("port closed in a separate thread");
	return g_thread_self ();
}

static guint closeport_thnum=0;
#endif

static void closeport(gpointer user_data)
{
	GAtChat *port = user_data;

#if NEED_THREADS
	char s[32];

	sprintf(s, "closeport_%u",closeport_thnum++);

	if (!g_thread_new(s, closeport_thread, user_data))
#endif
	/* in case of thread creation failure or no thread support: */
		g_at_chat_unref(port);

}

static int gemalto_enable_mdm_fail(void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);

	if (data->probing_timer) {
		g_source_remove(data->probing_timer);
		data->probing_timer = 0; /* remove the timer reference */
	}

	data->mdmport = STATE_ABSENT;

	if (data->mdmport==STATE_PROBE_DIRECT ||
				data->mdmport==STATE_PROBE_DIRECT_INVERSE) {
		g_at_chat_unregister(data->mdm, data->modem_ready_id);
		data->modem_ready_id = 0;
		closeport(data->mdm);
		data->trial_cmd_id = 0;
		data->mdm=NULL;
	}

	if (data->mdmport==STATE_PROBE_INVERSE ||
				data->mdmport==STATE_PROBE_DIRECT_INVERSE) {
		g_at_chat_unregister(data->at_tmp, data->modem_ready_id_inv);
		data->modem_ready_id_inv = 0;
		closeport(data->at_tmp);
		data->trial_cmd_id_inv = 0;
		data->at_tmp=NULL;
	}

	gemalto_initialize(user_data);
	return FALSE;
}

static void gemalto_enable_mdm_startup_inv(GAtResult *result,
							gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);
	const char *mdm = gemalto_get_string(modem, "MdmBis");

	if (data->probing_timer) {
		g_source_remove(data->probing_timer);
		data->probing_timer = 0; /* remove the timer reference */
	}

	if (data->mdmport==STATE_PROBE_DIRECT_INVERSE) {
		g_at_chat_unregister(data->mdm, data->modem_ready_id);
		data->modem_ready_id = 0;
		closeport(data->mdm);
		data->trial_cmd_id = 0;
		data->mdm=NULL;
	}

	data->modem_ready_id_inv = 0;
	data->trial_cmd_id_inv = 0;

	/*
	 * As the modem wasn't ready to handle AT commands when we opened
	 * it, we have to close and reopen the device mdm.
	 */
	g_at_chat_unref(data->at_tmp);
	data->at_tmp=NULL;
	data->mdm = open_device(mdm);

	if (data->mdm) {
		g_at_chat_set_debug(data->mdm, gemalto_debug, "Mdm: ");
		data->mdmport = STATE_PRESENT;
		data->inverse_enum=TRUE;
	} else {
		data->mdmport = STATE_ABSENT;
	}

	gemalto_initialize(modem);
}

static void gemalto_enable_mdm_startup(GAtResult *result, gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);
	const char *mdm = gemalto_get_string(modem, "Modem");

	if (data->probing_timer) {
		g_source_remove(data->probing_timer);
		data->probing_timer = 0; /* remove the timer reference */
	}

	if (data->mdmport==STATE_PROBE_DIRECT_INVERSE) {
		g_at_chat_unregister(data->at_tmp, data->modem_ready_id_inv);
		data->modem_ready_id_inv = 0;
		closeport(data->at_tmp);
		data->trial_cmd_id_inv = 0;
		data->at_tmp=NULL;
	}

	data->modem_ready_id = 0;
	data->trial_cmd_id = 0;

	/*
	 * As the modem wasn't ready to handle AT commands when we opened
	 * it, we have to close and reopen the device mdm.
	 */
	g_at_chat_unref(data->mdm);
	data->mdm = open_device(mdm);

	if (data->mdm) {
		g_at_chat_set_debug(data->mdm, gemalto_debug, "Mdm: ");
		data->mdmport = STATE_PRESENT;
	} else {
		data->mdmport = STATE_ABSENT;
	}

	gemalto_initialize(modem);
}

static void gemalto_enable_mdm_cb_inv(gboolean ok, GAtResult *result, gpointer
								user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);

	if (data->probing_timer) {
		g_source_remove(data->probing_timer);
		data->probing_timer = 0; /* remove the timer reference */
	}

	if (data->mdmport==STATE_PROBE_DIRECT_INVERSE) {
		g_at_chat_unregister(data->mdm, data->modem_ready_id);
		data->modem_ready_id = 0;
		/*
		 * this unref might take 30 seconds on some models
		 */
		closeport(data->mdm);
		data->trial_cmd_id = 0;
		data->mdm=NULL;
	}

	data->mdmport = STATE_PRESENT;
	data->inverse_enum=TRUE;
	g_at_chat_unregister(data->at_tmp, data->modem_ready_id_inv);
	data->modem_ready_id_inv = 0;
	data->trial_cmd_id_inv = 0;
	data->mdm=data->at_tmp;
	data->at_tmp=NULL;
	gemalto_initialize(modem);
}

static void gemalto_enable_mdm_cb(gboolean ok, GAtResult *result,
							gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);

	if (data->probing_timer) {
		g_source_remove(data->probing_timer);
		data->probing_timer = 0; /* remove the timer reference */
	}

	if (data->mdmport==STATE_PROBE_DIRECT_INVERSE) {
		g_at_chat_unregister(data->at_tmp, data->modem_ready_id_inv);
		data->modem_ready_id_inv = 0;
		/*
		 * this unref might take 30 seconds on some models
		 */
		closeport(data->at_tmp);
		data->trial_cmd_id_inv = 0;
		data->at_tmp=NULL;
	}

	data->mdmport = STATE_PRESENT;
	g_at_chat_unregister(data->mdm, data->modem_ready_id);
	data->modem_ready_id = 0;
	data->trial_cmd_id = 0;
	gemalto_initialize(modem);
}

static int gemalto_enable_mdm(void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);
	const char *mdm = NULL, *mdmInv = NULL;

	if (data->mdmport==STATE_PROBE_DIRECT ||
				data->mdmport==STATE_PROBE_DIRECT_INVERSE)
		mdm = gemalto_get_string(modem, "Modem");

	if (data->mdmport==STATE_PROBE_INVERSE ||
				data->mdmport==STATE_PROBE_DIRECT_INVERSE)
		mdmInv = gemalto_get_string(modem, "MdmBis");

	DBG("%s, %s", mdm, mdmInv);

	if (!mdm && !mdmInv)
		return gemalto_initialize(user_data);

	if (mdm)
		data->mdm = open_device(mdm);

	if (mdmInv)
		data->at_tmp = open_device(mdmInv);

	if (!data->mdm && !data->at_tmp)
		return gemalto_initialize(user_data);

	/* watchdog in case the mdm interface is not available */
	data->probing_timer = g_timeout_add_seconds(data->init_waiting_time,
						gemalto_enable_mdm_fail, modem);
	/* shorten the watchdog for the next attempt (boot completed now) */
	data->init_waiting_time = 3;

	if (data->mdm) {
		g_at_chat_set_debug(data->mdm, gemalto_debug, "Mdm: ");
		/* Try the AT command. If it doesn't work, wait for ^SYSSTART */
		data->modem_ready_id = g_at_chat_register(data->mdm,
			"^SYSSTART", gemalto_enable_mdm_startup, FALSE,
			modem, NULL);
		data->trial_cmd_id = g_at_chat_send(data->mdm, "AT",
			none_prefix, gemalto_enable_mdm_cb, modem, NULL);
	}

	if (data->at_tmp) {
		g_at_chat_set_debug(data->at_tmp, gemalto_debug, "Mdm: ");
		/* Try the AT command. If it doesn't work, wait for ^SYSSTART */
		data->modem_ready_id_inv = g_at_chat_register(data->at_tmp,
			"^SYSSTART", gemalto_enable_mdm_startup_inv, FALSE,
			modem, NULL);
		data->trial_cmd_id_inv = g_at_chat_send(data->at_tmp, "AT",
			none_prefix, gemalto_enable_mdm_cb_inv, modem, NULL);
	}

	return -EINPROGRESS;
}

static int gemalto_enable_app_fail(void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);

	if (data->probing_timer) {
		g_source_remove(data->probing_timer);
		data->probing_timer = 0; /* remove the timer reference */
	}

	data->appport = STATE_ABSENT;

	if (data->appport==STATE_PROBE_DIRECT ||
				data->appport==STATE_PROBE_DIRECT_INVERSE) {
		g_at_chat_unregister(data->app, data->modem_ready_id);
		data->modem_ready_id = 0;
		closeport(data->app);
		data->trial_cmd_id = 0;
		data->app=NULL;
	}

	if (data->appport==STATE_PROBE_INVERSE ||
				data->appport==STATE_PROBE_DIRECT_INVERSE) {
		g_at_chat_unregister(data->at_tmp, data->modem_ready_id_inv);
		data->modem_ready_id_inv = 0;
		closeport(data->at_tmp);
		data->trial_cmd_id_inv = 0;
		data->at_tmp=NULL;
	}

	gemalto_enable_mdm(user_data);
	return FALSE;
}

static void gemalto_enable_app_startup_inv(GAtResult *result,
							gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);
	const char *app = gemalto_get_string(modem, "AppBis");

	if (data->probing_timer) {
		g_source_remove(data->probing_timer);
		data->probing_timer = 0; /* remove the timer reference */
	}

	if (data->appport==STATE_PROBE_DIRECT_INVERSE) {
		g_at_chat_unregister(data->app, data->modem_ready_id);
		data->modem_ready_id = 0;
		closeport(data->app);
		data->trial_cmd_id = 0;
		data->app=NULL;
	}

	if (data->mdmport==STATE_PROBE_DIRECT_INVERSE)
		data->mdmport=STATE_PROBE_INVERSE;

	data->modem_ready_id_inv = 0;
	data->trial_cmd_id_inv = 0;

	/*
	 * As the modem wasn't ready to handle AT commands when we opened
	 * it, we have to close and reopen the device app.
	 */
	g_at_chat_unref(data->at_tmp);
	data->at_tmp=NULL;
	data->app = open_device(app);

	if (data->app) {
		g_at_chat_set_debug(data->app, gemalto_debug, "App: ");
		data->appport = STATE_PRESENT;
		data->inverse_enum=TRUE;
	} else {
		data->appport = STATE_ABSENT;
	}

	gemalto_enable_mdm(modem);
}

static void gemalto_enable_app_startup(GAtResult *result, gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);
	const char *app = gemalto_get_string(modem, "Application");

	if (data->probing_timer) {
		g_source_remove(data->probing_timer);
		data->probing_timer = 0; /* remove the timer reference */
	}

	if (data->appport==STATE_PROBE_DIRECT_INVERSE) {
		g_at_chat_unregister(data->at_tmp, data->modem_ready_id_inv);
		data->modem_ready_id_inv = 0;
		closeport(data->at_tmp);
		data->trial_cmd_id_inv = 0;
		data->at_tmp=NULL;
	}

	if (data->mdmport==STATE_PROBE_DIRECT_INVERSE)
		data->mdmport=STATE_PROBE_DIRECT;

	data->modem_ready_id = 0;
	data->trial_cmd_id = 0;

	/*
	 * As the modem wasn't ready to handle AT commands when we opened
	 * it, we have to close and reopen the device app.
	 */
	g_at_chat_unref(data->app);
	data->app = open_device(app);

	if (data->app) {
		g_at_chat_set_debug(data->app, gemalto_debug, "App: ");
		data->appport = STATE_PRESENT;
	} else {
		data->appport = STATE_ABSENT;
	}

	gemalto_enable_mdm(modem);
}

static void gemalto_enable_app_cb_inv(gboolean ok, GAtResult *result,
							gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);

	if (data->probing_timer) {
		g_source_remove(data->probing_timer);
		data->probing_timer = 0; /* remove the timer reference */
	}

	if (data->appport==STATE_PROBE_DIRECT_INVERSE) {
		g_at_chat_unregister(data->app, data->modem_ready_id);
		data->modem_ready_id = 0;
		closeport(data->app);
		data->trial_cmd_id = 0;
		data->app=NULL;
	}

	if (data->mdmport==STATE_PROBE_DIRECT_INVERSE)
		data->mdmport=STATE_PROBE_INVERSE;

	data->appport = STATE_PRESENT;
	data->inverse_enum=TRUE;
	g_at_chat_unregister(data->at_tmp, data->modem_ready_id_inv);
	data->modem_ready_id_inv = 0;
	data->trial_cmd_id_inv = 0;
	data->app=data->at_tmp;
	data->at_tmp=NULL;
	gemalto_enable_mdm(modem);
}

static void gemalto_enable_app_cb(gboolean ok, GAtResult *result,
							gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);

	if (data->probing_timer) {
		g_source_remove(data->probing_timer);
		data->probing_timer = 0; /* remove the timer reference */
	}

	if (data->appport==STATE_PROBE_DIRECT_INVERSE) {
		g_at_chat_unregister(data->at_tmp, data->modem_ready_id_inv);
		data->modem_ready_id_inv = 0;
		closeport(data->at_tmp);
		data->trial_cmd_id_inv = 0;
		data->at_tmp=NULL;
	}

	if (data->mdmport==STATE_PROBE_DIRECT_INVERSE)
		data->mdmport=STATE_PROBE_DIRECT;

	data->appport = STATE_PRESENT;
	g_at_chat_unregister(data->app, data->modem_ready_id);
	data->modem_ready_id = 0;
	data->trial_cmd_id = 0;
	gemalto_enable_mdm(modem);
}

static int gemalto_enable_app(struct ofono_modem *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);
	const char *app=NULL, *appInv=NULL;

	DBG("%p", modem);

	if (data->appport==STATE_PROBE_DIRECT ||
				data->appport==STATE_PROBE_DIRECT_INVERSE)
		app = gemalto_get_string(modem, "Application");
	if (data->appport==STATE_PROBE_INVERSE ||
				data->appport==STATE_PROBE_DIRECT_INVERSE)
		appInv = gemalto_get_string(modem, "AppBis");

	DBG("%s, %s", app, appInv);

	if (!app && !appInv)
		return gemalto_enable_mdm(modem);

	if (app)
		data->app = open_device(app);
	if (appInv)
		data->at_tmp = open_device(appInv);

	if (!data->app && !data->at_tmp)
		return gemalto_enable_mdm(modem);

	/* watchdog in case the app interface is not available */
	data->probing_timer = g_timeout_add_seconds(data->init_waiting_time,
					gemalto_enable_app_fail, modem);
	/* shorten the watchdog for the next attempt (boot time elapsed) */
	data->init_waiting_time = 3;

	if (data->app) {
		DBG("attempting DIRECT enum");
		g_at_chat_set_debug(data->app, gemalto_debug, "App: ");
		/* Try the AT command. If it doesn't work, wait for ^SYSSTART */
		data->modem_ready_id = g_at_chat_register(data->app,
			"^SYSSTART", gemalto_enable_app_startup, FALSE, modem,
			NULL);
		data->trial_cmd_id = g_at_chat_send(data->app, "AT",
			none_prefix, gemalto_enable_app_cb, modem, NULL);
	}

	if (data->at_tmp) {
		DBG("attempting INVERSE enum");
		g_at_chat_set_debug(data->at_tmp, gemalto_debug, "App: ");
		/* Try the AT command. If it doesn't work, wait for ^SYSSTART */
		data->modem_ready_id_inv = g_at_chat_register(data->at_tmp,
			"^SYSSTART", gemalto_enable_app_startup_inv, FALSE,
			modem, NULL);
		data->trial_cmd_id_inv = g_at_chat_send(data->at_tmp, "AT",
			none_prefix, gemalto_enable_app_cb_inv, modem, NULL);
	}

	return -EINPROGRESS;
}

#ifdef HAVE_ELL
static void mbim_device_caps_info_cb(struct mbim_message *message, void *user)
{
	struct ofono_modem *modem = user;
	struct gemalto_data *md = ofono_modem_get_data(modem);
	uint32_t device_type;
	uint32_t cellular_class;
	uint32_t voice_class;
	uint32_t sim_class;
	uint32_t data_class;
	uint32_t sms_caps;
	uint32_t control_caps;
	uint32_t max_sessions;
	char *custom_data_class;
	char *device_id;
	char *firmware_info;
	char *hardware_info;
	bool r;

	if (mbim_message_get_error(message) != 0)
		goto error;

	r = mbim_message_get_arguments(message, "uuuuuuuussss",
					&device_type, &cellular_class,
					&voice_class, &sim_class, &data_class,
					&sms_caps, &control_caps, &max_sessions,
					&custom_data_class, &device_id,
					&firmware_info, &hardware_info);
	if (!r)
		goto error;

	md->max_sessions = max_sessions;

	DBG("DeviceId: %s", device_id);
	DBG("FirmwareInfo: %s", firmware_info);
	DBG("HardwareInfo: %s", hardware_info);

	ofono_modem_set_string(modem, "DeviceId", device_id);
	ofono_modem_set_string(modem, "FirmwareInfo", firmware_info);

	l_free(custom_data_class);
	l_free(device_id);
	l_free(firmware_info);
	l_free(hardware_info);

	message = mbim_message_new(mbim_uuid_basic_connect,
					MBIM_CID_DEVICE_SERVICE_SUBSCRIBE_LIST,
					MBIM_COMMAND_TYPE_SET);

	mbim_message_set_arguments(message, "av", 2,
					"16yuuuuuuu",
					mbim_uuid_basic_connect, 6,
					MBIM_CID_SUBSCRIBER_READY_STATUS,
					MBIM_CID_RADIO_STATE,
					MBIM_CID_REGISTER_STATE,
					MBIM_CID_PACKET_SERVICE,
					MBIM_CID_SIGNAL_STATE,
					MBIM_CID_CONNECT,
					"16yuuuu", mbim_uuid_sms, 3,
					MBIM_CID_SMS_CONFIGURATION,
					MBIM_CID_SMS_READ,
					MBIM_CID_SMS_MESSAGE_STORE_STATUS);

	if (mbim_device_send(md->device, 0, message,
				NULL, NULL, NULL)) {
		md->mbim=STATE_PRESENT;
		goto other_devices;
	}


error:
	mbim_device_shutdown(md->device);

other_devices:

	if (md->init_done)
		return;

	gemalto_enable_app(modem);  /* continue with mdm interface */
}

static void mbim_device_closed_startup(void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *md = ofono_modem_get_data(modem);

	if (!md) return;

	if (!md->device) return;

	if (md->mbim!=STATE_TESTING) { /* means we have failed the MBIM_OPEN */
		/* the function is called twice, so we trace with a state */
		DBG(REDCOLOR"MBIM OPEN failed!"NOCOLOR);
		md->mbim=STATE_TESTING;
	} else if (md->mbim==STATE_TESTING) { /* process second/regular call */
		DBG("MBIM OPEN failed!");
		md->mbim=STATE_PROBE; /* reset for future attempt */
		gemalto_enable_app(modem); /* continue with other interfaces */
	}

	mbim_device_unref(md->device);
	md->device = NULL;
}

static void mbim_device_ready(void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *md = ofono_modem_get_data(modem);
	struct mbim_message *message =
		mbim_message_new(mbim_uuid_basic_connect,
					1, MBIM_COMMAND_TYPE_QUERY);

	mbim_message_set_arguments(message, "");
	mbim_device_send(md->device, 0, message, mbim_device_caps_info_cb,
		modem, NULL);
}

static int mbim_enable(struct ofono_modem *modem)
{
	const char *device;
	int fd;
	struct gemalto_data *md = ofono_modem_get_data(modem);

	DBG("modem struct: %p", modem);

	device = gemalto_get_string(modem, "NetworkControl");
	if (!device)
		goto other_devices;

	DBG("modem device: %s", device);
	fd = open(device, O_EXCL | O_NONBLOCK | O_RDWR);

	if (fd < 0)
		goto other_devices;

	DBG("device: %s opened successfully", device);
	md->device = mbim_device_new(fd, md->max_segment);
	DBG("created new device %p", md->device);

	mbim_device_set_close_on_unref(md->device, true);
	mbim_device_set_max_outstanding(md->device, md->max_outstanding);
	mbim_device_set_ready_handler(md->device,
					mbim_device_ready, modem, NULL);
	if (md->init_done)
		mbim_device_set_disconnect_handler(md->device,
				mbim_device_closed, modem, NULL);
	else
		mbim_device_set_disconnect_handler(md->device,
				mbim_device_closed_startup, modem, NULL);

	mbim_device_set_debug(md->device, gemalto_debug, "MBIM:", NULL);

	return -EINPROGRESS;

other_devices:

	if (md->init_done)
		return 0;

	return gemalto_enable_app(modem);
}
#endif

static void qmi_enable_cb(void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *md = ofono_modem_get_data(modem);
	md->qmi = STATE_PRESENT;
	gemalto_enable_app(modem); /* qmi done, continue with app interface */
}

static int qmi_enable(struct ofono_modem *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);
	const char *device;
	int fd;

	DBG("modem struct: %p", modem);

	device = gemalto_get_string(modem, "NetworkControl");
	if (!device)
		return gemalto_enable_app(modem);

	fd = open(device, O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return gemalto_enable_app(modem);

	data->device = qmi_device_new(fd);
	if (!data->device) {
		close(fd);
		return gemalto_enable_app(modem);
	}

	qmi_device_set_close_on_unref(data->device, true);

	qmi_device_set_debug(data->device, gemalto_debug, "QMI: ");

	qmi_device_discover(data->device, qmi_enable_cb, modem, NULL);

	return -EINPROGRESS;
}

static int gemalto_enable(struct ofono_modem *modem)
{
	const char *model = gemalto_get_string(modem, "Model"),
		   *conn_type = gemalto_get_string(modem, "ConnType");
	const char
		*ctl = gemalto_get_string(modem, "NetworkControl"),
		*net = gemalto_get_string(modem, "NetworkInterface");

	/* safe because no data is written even if the pointer could be 0 */
	struct gemalto_data *data = ofono_modem_get_data(modem);

	guint m=0;

	DBG("modem struct: %p, gemalto_data: %p", modem, data);

	if (!modem || !data)
		return -EINVAL;

	if (data->init_done) {
		g_at_chat_send(data->app, "AT+CFUN=4", none_prefix, cfun_enable,
								modem, NULL);

#ifdef HAVE_ELL
		if (data->mbim != STATE_ABSENT)
			mbim_enable(modem);
#endif

		return -EINPROGRESS;
	}


	data->conn = g_str_equal(conn_type,"Serial") ? GEMALTO_CONNECTION_SERIAL
						: GEMALTO_CONNECTION_USB;

	if (model) {
		data->model = strtoul(model, NULL, 16);
		m=data->model;
	}

	/* single ACM interface 02: assign application to modem */
	if (m==0xa0) {
		const char *app = gemalto_get_string(modem, "Application");
		ofono_modem_set_string(modem, "Modem", app);
	}

	/* if single ACM interface, remove possible extra devices */
	if (m==0x58 || m==0x47 || m==0x54 || m==0xa0) {
		ofono_modem_set_string(modem, "Application", NULL);
		ofono_modem_set_string(modem, "GNSS", NULL);
		ofono_modem_set_string(modem, "RSA", NULL);
		ofono_modem_set_string(modem, "MdmBis", NULL);
		ofono_modem_set_string(modem, "AppBis", NULL);
		ofono_modem_set_string(modem, "GNSSBis", NULL);
		ofono_modem_set_string(modem, "RSABis", NULL);
		data->appport = STATE_ABSENT;
		data->mdmport = STATE_PROBE_DIRECT;
	} else {
		if (m==0x55) {
			data->appport = STATE_PROBE_DIRECT_INVERSE;
			data->mdmport = STATE_PROBE_DIRECT_INVERSE;
		} else if (m==0x53 || m==0x60) {
			data->appport = STATE_PROBE_INVERSE;
			data->mdmport = STATE_PROBE_INVERSE;
		} else {
			data->appport = STATE_PROBE_DIRECT;
			data->mdmport = STATE_PROBE_DIRECT;
		}
	}

	/* pre-configure network interfaces */
	if (m==0x62 || m==0x5d || m==0x65) {
#ifdef HAVE_ELL
		data->mbim = STATE_PROBE;
#endif
	} else {
		/*
		 * note: we probe for ECM/NCM even if the port is not present
		 * (for serial connection type or serial-like)
		 */
		if (m==0x53 || m==0x60 || m==0x63)
			data->qmi=STATE_PROBE;
		/*these families have PPP only*/
		else if (m!=0x58 && m!=0x47 && m!=0x54)
			data->ecmncm = STATE_PROBE;
	}

	/* pre-configure SW features */
	if (m==0xa0) {
		data->gprs_opt=USE_CTX3;
		data->ecmncm = STATE_ABSENT;
	}
	if (m==0x63 || m==0x65 || m==0x5b || m==0x5c || m==0x5d)
		data->gina=STATE_PRESENT;

	data->init_waiting_time = 30;

	if (m==0x55)
		data->init_waiting_time = 5;

#ifdef HAVE_ELL
	if ((data->mbim==STATE_PROBE) && ctl && net) {
		data->init_waiting_time = 3;
		return mbim_enable(modem);
	}
#endif

	if ((data->qmi==STATE_PROBE) && ctl && net) {
		data->init_waiting_time = 10;
		return qmi_enable(modem);
	}

	data->vts_with_quotes = TRUE;

	if (m==0x5b || m==0x5c || m==0x5d || m==0xa0)
		data->vts_with_quotes = FALSE;

	return gemalto_enable_app(modem);
}

static void gemalto_cfun_disable_cb(gboolean ok, GAtResult *result,
					gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);

	DBG("");

	g_at_chat_cancel_all(data->app);

	if (ok)
		ofono_modem_set_powered(modem, FALSE);
}

#ifdef HAVE_ELL
static int mbim_sim_probe(void *device)
{
	struct mbim_message *message;
	/* SIM_GROUP is defined in mbimmodem.h that cannot be included */
	uint32_t SIM_GROUP=1;

	message = mbim_message_new(mbim_uuid_basic_connect,
					MBIM_CID_SUBSCRIBER_READY_STATUS,
					MBIM_COMMAND_TYPE_QUERY);
	if (!message)
		return -ENOMEM;

	mbim_message_set_arguments(message, "");

	if (!mbim_device_send(device, SIM_GROUP, message,
				NULL, NULL, NULL)) {
		mbim_message_unref(message);
		return -EIO;
	}
	return 0;
}
#endif

static void set_online_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_modem_online_cb_t cb = cbd->cb;
	struct ofono_error error;

	decode_at_error(&error, g_at_result_final_response(result));

	cb(&error, cbd->data);
}

static void gemalto_set_online(struct ofono_modem *modem, ofono_bool_t online,
		ofono_modem_online_cb_t cb, void *user_data)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);
	struct cb_data *cbd = cb_data_new(cb, user_data);
	char const *command = online ? "AT+CFUN=1" : "AT+CFUN=4";

	DBG("modem %p %s", modem, online ? "online" : "offline");

	if (g_at_chat_send(data->app, command, NULL, set_online_cb, cbd, g_free))
		return;

	CALLBACK_WITH_FAILURE(cb, cbd->data);

	g_free(cbd);
}

static void gemalto_pre_sim(struct ofono_modem *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);

	DBG("%p", modem);
	/*
	 * Call support is technically possible only after sim insertion
	 * with the module online. However the EMERGENCY_SETUP procedure of
	 * the 3GPP TS_24.008 is triggered by the same AT command,
	 * and namely 'ATD112;' and 'ATD911;'. Therefore it makes sense to
	 * add the voice support as soon as possible.
	 */

	if (data->voice_avail) {
		ofono_modem_set_integer(modem, "Gemalto_VTS_quotes",
						data->vts_with_quotes);
		ofono_voicecall_create(modem, 0, "gemaltomodem", data->app);
	}

	data->sim = ofono_sim_create(modem, OFONO_VENDOR_GEMALTO,
		"atmodem", data->app);

	if (data->sim && data->have_sim == TRUE)
		ofono_sim_inserted_notify(data->sim, TRUE);
}

static void gemalto_post_sim(struct ofono_modem *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);

#ifdef HAVE_ELL
	if (data->mbim==STATE_PRESENT) {
		/* very important to set the interface ready */
		mbim_sim_probe(data->device);
	}
#endif

	ofono_phonebook_create(modem, 0, "atmodem", data->app);
	ofono_modem_set_integer(modem, "Gemalto_Auth", data->auth_syntax);
	ofono_lte_create(modem, OFONO_VENDOR_GEMALTO, "atmodem", data->app);
}

static void cgdcont17_probe(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct gemalto_data *data = ofono_modem_get_data(user_data);

	if (ok)
		data->gprs_opt = USE_CTX17;
}

static void swwan_probe(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct gemalto_data *data = ofono_modem_get_data(user_data);

	if (ok)
		data->gprs_opt = USE_SWWAN;
}

static void autoattach_probe_and_continue(gboolean ok, GAtResult *result,
							gpointer user_data)
{
	struct ofono_modem* modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);
	GAtResultIter iter;
	struct ofono_message_waiting *mw;
	struct ofono_gprs *gprs=NULL;
	struct ofono_gprs_context *gc=NULL;

	data->autoattach=FALSE;
	ofono_modem_set_integer(modem, "Gto_Autoattach", 0);

	if (ok) {
		g_at_result_iter_init(&iter, result);
		while (g_at_result_iter_next(&iter, NULL)) {
			if (strstr(g_at_result_iter_raw_line(&iter),
					"\"enabled\"")) {
				data->autoattach=TRUE;
				ofono_modem_set_integer(modem, "Gto_Autoattach",
									1);

			}
		}
	}

#ifdef HAVE_ELL
	if (data->mbim==STATE_PRESENT) {
		gprs = ofono_gprs_create(modem, OFONO_VENDOR_GEMALTO, "atmodem",
								data->app);
		ofono_gprs_set_cid_range(gprs, 0, data->max_sessions);
		gc = ofono_gprs_context_create(modem, 0, "mbim", data->device);
	} else
#endif
		if (data->qmi==STATE_PRESENT) {
		gprs = ofono_gprs_create(modem, OFONO_VENDOR_GEMALTO, "atmodem",
								data->app);
		ofono_gprs_set_cid_range(gprs, 4, 16);
		gc = ofono_gprs_context_create(modem, 0, "qmimodem",
								data->device);
	} else if (data->gprs_opt==USE_SWWAN || data->gprs_opt==USE_CTX17 ||
						data->gprs_opt==USE_CTX3) {
		ofono_modem_set_integer(modem, "Gemalto_WWAN",
						data->gprs_opt==USE_SWWAN);
		gprs = ofono_gprs_create(modem, OFONO_VENDOR_GEMALTO, "atmodem",
								data->app);
		ofono_gprs_set_cid_range(gprs, 4, 16);
		gc = ofono_gprs_context_create(modem, 0, "gemaltowwanmodem",
								data->app);
	} else if (data->gprs_opt==USE_PPP) {
		/* plain PPP only works from mdm ports */
		gprs = ofono_gprs_create(modem, OFONO_VENDOR_GEMALTO, "atmodem",
								data->app);
		ofono_gprs_set_cid_range(gprs, 4, 16);
		gc = ofono_gprs_context_create(modem, 0, "atmodem", data->mdm);
	} /*
	   * in case of no match above, we have no gprs possibilities
	   * this is common when using the module through serial interfaces
	   * nevertheless other services (voice, gpio, gnss) could be available
	   */

	if (gc)
		ofono_gprs_context_set_type(gc,
					OFONO_GPRS_CONTEXT_TYPE_INTERNET);

	if (gprs && gc)
		ofono_gprs_add_context(gprs, gc);

	/* might have also without voicecall support  */
	ofono_ussd_create(modem, 0, "atmodem", data->app);

	if (data->voice_avail) {
		ofono_call_forwarding_create(modem, 0, "atmodem", data->app);
		ofono_call_settings_create(modem, 0, "atmodem", data->app);
		ofono_call_meter_create(modem, 0, "atmodem", data->app);
		ofono_call_barring_create(modem, 0, "atmodem", data->app);
	}

	/* modules require to be online to accept at+cnmi */
	ofono_sms_create(modem, OFONO_VENDOR_GEMALTO, "atmodem", data->app);
	mw = ofono_message_waiting_create(modem);

	if (mw)
		ofono_message_waiting_register(mw);

	ofono_netreg_create(modem, OFONO_VENDOR_GEMALTO, "atmodem", data->app);
}

static int gemalto_post_online_delayed(void *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);

	/*
	 * check module capabilities once online and SIM really ready.
	 *
	 * Note: the g_at_chat_send calls only insert the commands in a list:
	 * they are not executed synchronously
	 *
	 * Note: ofono executes each AT commands and the related callback before
	 * proceeding with the next. So continuing on the last AT command is all
	 * it takes
	 */

	if (data->ecmncm == STATE_PROBE) {
		data->gprs_opt = USE_PPP; /* fallback */
		g_at_chat_send(data->app, "AT+CGDCONT=17", NULL,
						cgdcont17_probe, modem, NULL);
		g_at_chat_send(data->app, "AT^SWWAN?", NULL, swwan_probe, modem,
									NULL);
	}

	g_at_chat_send(data->app, "AT^SCFG=\"GPRS/AutoAttach\"", NULL,
				autoattach_probe_and_continue, modem, NULL);

	return FALSE; /* to kill the timer */
}


static void gemalto_post_online(struct ofono_modem *modem)
{
	/*
	 * in this version of ofono we must wait for SIM 'really-ready'
	 * can be avoided when capturing the right URCs
	 */
	g_timeout_add_seconds(5, gemalto_post_online_delayed, modem);
}

static void gemalto_reset_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	/*
	 * Do we want to try soft reset another few times?
	 * Performing a hard reset for now.
	 */
	if (!ok) {
		return;
	}

	return;
}

static void gemalto_reset(struct ofono_modem* modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);

	DBG("");

	g_at_chat_send(data->app, "AT+CFUN=1,1", none_prefix,
			gemalto_reset_cb, NULL, NULL);
}

static void gemalto_smso_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);

	DBG("");

	if (data->mdm)
		g_at_chat_unref(data->mdm);
	data->mdm = NULL;

	if (data->app)
		g_at_chat_unref(data->app);
	data->app = NULL;

	if (ok)
		ofono_modem_set_powered(modem, FALSE);
}

static void gemalto_shutdown(struct ofono_modem *modem)
{
	struct gemalto_data *data;
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path;
	void *lratom;

	if (!modem)
		return;

	data = ofono_modem_get_data(modem);
	path = ofono_modem_get_path(modem);

	if (!data)
		return;

#ifdef HAVE_ELL
	if (data->mbim==STATE_PRESENT) {
		mbim_device_shutdown(data->device);
	}
#endif
	if (data->qmi==STATE_PRESENT) {
		qmi_device_unref(data->device);
	}

	if (data->app) {
		g_at_chat_cancel_all(data->app);
		g_at_chat_unregister_all(data->app);
	}

	if (conn && path) {
		if (g_dbus_unregister_interface(conn, path,
					HARDWARE_MONITOR_INTERFACE))
			ofono_modem_remove_interface(modem,
					HARDWARE_MONITOR_INTERFACE);

		if (g_dbus_unregister_interface(conn, path,
					GEMALTO_NITZ_TIME_INTERFACE))
			ofono_modem_remove_interface(modem,
					GEMALTO_NITZ_TIME_INTERFACE);

		if (g_dbus_unregister_interface(conn, path,
					COMMAND_PASSTHROUGH_INTERFACE))
			ofono_modem_remove_interface(modem,
					COMMAND_PASSTHROUGH_INTERFACE);
	}

	/* offline atom: it won't be removed by src/modem:flush_atoms() */
	lratom = __ofono_modem_find_atom(modem,
					OFONO_ATOM_TYPE_LOCATION_REPORTING);

	if (lratom)
		__ofono_atom_free(lratom);

	/* Shutdown the modem */
	if (data->app)
		g_at_chat_send(data->app, "AT^SMSO", none_prefix,
						gemalto_smso_cb, modem, NULL);
}

#ifdef HAVE_ELL
static void mbim_radio_off_for_disable(struct mbim_message *message, void *user)
{
	struct ofono_modem *modem = user;
	struct gemalto_data *md = ofono_modem_get_data(modem);

	DBG("%p", modem);

	mbim_device_shutdown(md->device);
}
#endif

static int gemalto_disable(struct ofono_modem *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);

#ifdef HAVE_ELL
	struct mbim_message *message;

	if (data->mbim != STATE_ABSENT) {
		message = mbim_message_new(mbim_uuid_basic_connect,
						MBIM_CID_RADIO_STATE,
						MBIM_COMMAND_TYPE_SET);
		mbim_message_set_arguments(message, "u", 0);

		if (mbim_device_send(data->device, 0, message,
				mbim_radio_off_for_disable, modem, NULL)==0)
			mbim_device_closed(modem);
	}
#endif

	DBG("%p", modem);

	if (data->app == NULL)
		return 0;

	g_at_chat_send(data->app, "AT+CFUN=4", none_prefix,
					gemalto_cfun_disable_cb, modem, NULL);
	// TODO: check when need to use another mode:
	// g_at_chat_send(chat, "AT+CFUN=7", NULL, NULL, NULL, NULL);

	return -EINPROGRESS;
}

static void powersave_stored_exec(struct ofono_modem *modem, ofono_bool_t enable)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);
	const char *vid = gemalto_get_string(modem, "Vendor");
	const char *pid = gemalto_get_string(modem, "Model");
	char store[32];
	int index;
	char *command, *prompt, *argument;
	char key[32];
	GKeyFile *f;

	if (enable)
		sprintf(store,"%s-%s/power_mode_powersave", vid, pid);
	else
		sprintf(store,"%s-%s/power_mode_normal", vid, pid);

	f = storage_open(NULL, store);

	if (!f)
		return;

	for (index=0;;index++) {
		sprintf(key, "command_%d", index);
		command = g_key_file_get_string(f, "Simple", key, NULL);

		if (!command)
			break;

		DBG("executing stored command simple: %s", command);
		g_at_chat_send(data->app, command, NULL, NULL, NULL, NULL);
	}

	for (index=0;;index++) {
		sprintf(key, "command_%d", index);
		command = g_key_file_get_string(f, "WithPrompt", key, NULL);
		sprintf(key, "prompt_%d", index);
		prompt = g_key_file_get_string(f, "WithPrompt", key, NULL);
		sprintf(key, "argument_%d", index);
		argument = g_key_file_get_string(f, "WithPrompt", key, NULL);

		if (!command || !prompt || !argument)
			break;

		DBG("executing stored command with prompt: %s", command);
		executeWithPrompt(data->app, command, prompt, argument,
			NULL, NULL, NULL);
	}

	storage_close(NULL, store, f, FALSE);
}

static void gemalto_powersave_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	struct cb_data *cbd = user_data;
	struct ofono_modem *modem = cbd->data;
	ofono_modem_set_powersave(modem, cbd->user!=NULL);
}

static void gemalto_powersave(struct ofono_modem *modem, ofono_bool_t enable)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);
	struct cb_data *cbd = cb_data_new(NULL, modem);

	powersave_stored_exec(modem, enable);

	if (enable)
		cbd->user = modem; /* doesn't matter, just checked for !=NULL */

	g_at_chat_send(data->app, "AT", none_prefix,
					gemalto_powersave_cb, cbd, g_free);
}

static struct ofono_modem_driver gemalto_driver = {
	.name		= "gemalto",
	.probe		= gemalto_probe,
	.remove		= gemalto_remove,
	.enable		= gemalto_enable,
	.disable	= gemalto_disable,
	.set_online	= gemalto_set_online,
	.pre_sim	= gemalto_pre_sim,
	.post_sim	= gemalto_post_sim,
	.post_online	= gemalto_post_online,
	.modem_reset	= gemalto_reset,
	.modem_shutdown	= gemalto_shutdown,
	.powersave	= gemalto_powersave,
};

static int gemalto_init(void)
{
	return ofono_modem_driver_register(&gemalto_driver);
}

static void gemalto_exit(void)
{
	ofono_modem_driver_unregister(&gemalto_driver);
}

OFONO_PLUGIN_DEFINE(gemalto, "Gemalto modem plugin", VERSION,
		OFONO_PLUGIN_PRIORITY_DEFAULT, gemalto_init, gemalto_exit)
