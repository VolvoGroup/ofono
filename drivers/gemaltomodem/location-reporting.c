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
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include <glib.h>
#include <gdbus.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/location-reporting.h>

#include <src/storage.h>

#include "gatchat.h"
#include "gatresult.h"
#include "gattty.h"

#include "ofono.h"
#include "common.h"

#include "gemaltomodem.h"

struct ofono_location_reporting {
	DBusMessage *pending;
	const struct ofono_location_reporting_driver *driver;
	void *driver_data;
	struct ofono_atom *atom;
	ofono_bool_t enabled;
	char *client_owner;
	guint disconnect_watch;
};

static const char *sgpsc_prefix[] = { "^SGPSC:", NULL };

#define MAX_GNSS_PROPERTIES		(64)
#define MAX_GNSS_STRLEN			(32)
#define GNSS_PROPERTY_DYNAMIC	(0x00000001)
#define GNSS_PROPERTY_STORED	(0x00000002)
#define GNSS_PROPERTY_EXCLUDE	(0x00000004)
#define GNSS_PROPERTY_VALUE_S	(0x00000100)
#define GNSS_PROPERTY_VALUE_I	(0x00000200)

typedef struct _gnss_property {
	uint type; // dynamic or stored, exclude, value_s or value_i
	char name[MAX_GNSS_STRLEN];
	union {
		char value_s[32];
		int value_i;
	};
} gnss_property;

struct gps_data {
	GAtChat *chat;
	gnss_property properties[MAX_GNSS_PROPERTIES];
};

static void gemalto_gps_disable_cb(gboolean ok, GAtResult *result,
							gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_location_reporting_disable_cb_t cb = cbd->cb;

	if (!ok) {
		struct ofono_error error;
		decode_at_error(&error, g_at_result_final_response(result));
		cb(&error, cbd->data);
		return;
	}

	CALLBACK_WITH_SUCCESS(cb, cbd->data);
}

static void gemalto_location_reporting_disable(
				struct ofono_location_reporting *lr,
				ofono_location_reporting_disable_cb_t cb,
				void *data)
{
	struct gps_data *gd = ofono_location_reporting_get_data(lr);
	struct cb_data *cbd = cb_data_new(cb, data);

	cbd->user = lr;

	if (g_at_chat_send(gd->chat, "AT^SGPSC=\"Engine\",0", sgpsc_prefix,
				gemalto_gps_disable_cb, cbd, g_free) > 0)
		return;

	CALLBACK_WITH_FAILURE(cb, data);
	g_free(cbd);
}

static int enable_data_stream(struct ofono_location_reporting *lr)
{
	struct ofono_modem *modem;
	const char *gnss_dev;
	GHashTable *options;
	GIOChannel *channel;
	int fd;

	modem = ofono_location_reporting_get_modem(lr);
	gnss_dev = ofono_modem_get_string(modem, "GNSS");
	options = g_hash_table_new(g_str_hash, g_str_equal);

	if (!gnss_dev || !*gnss_dev || !options)
		return -1;

	g_hash_table_insert(options, "Baud", "115200");
	channel = g_at_tty_open(gnss_dev, options);
	g_hash_table_destroy(options);

	if (!channel)
		return -1;

	fd = g_io_channel_unix_get_fd(channel);
	g_io_channel_set_close_on_unref(channel, FALSE);
	g_io_channel_unref(channel);

	return fd;
}

static void gemalto_sgpsc_cb(gboolean ok, GAtResult *result,
					gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_location_reporting_enable_cb_t cb = cbd->cb;
	struct ofono_location_reporting *lr = cbd->user;
	struct ofono_error error;
	int fd;

	decode_at_error(&error, g_at_result_final_response(result));

	if (!ok) {
		cb(&error, -1, cbd->data);

		return;
	}

	fd = enable_data_stream(lr);

	if (fd < 0) {
		CALLBACK_WITH_FAILURE(cb, -1, cbd->data);

		return;
	}

	cb(&error, fd, cbd->data);
	close(fd);
}

static void gemalto_location_reporting_enable(struct ofono_location_reporting *lr,
					ofono_location_reporting_enable_cb_t cb,
					void *data)
{
	struct gps_data *gd = ofono_location_reporting_get_data(lr);
	struct cb_data *cbd = cb_data_new(cb, data);

	cbd->user = lr;

	if (g_at_chat_send(gd->chat, "AT^SGPSC=\"Engine\",2", sgpsc_prefix,
				gemalto_sgpsc_cb, cbd, NULL) > 0)
		return;

	CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
	g_free(cbd);
}

static void gemalto_location_reporting_get_properties(struct ofono_location_reporting *lr, void *_dict)
{
	DBusMessageIter *dict = _dict;
	struct gps_data *gd = ofono_location_reporting_get_data(lr);
	int property_pos = 0;
	struct ofono_modem *modem = ofono_location_reporting_get_modem(lr);
	const char *port = ofono_modem_get_string(modem, "GNSS");
	const char *prop_port = "Port";

	while(property_pos<MAX_GNSS_PROPERTIES && *gd->properties[property_pos].name) {
		char *propval=gd->properties[property_pos].value_s;
		ofono_dbus_dict_append(dict, gd->properties[property_pos].name, DBUS_TYPE_STRING, &propval);
		property_pos++;
	}

	/* add port outside of the modem property list */
	DBG("%s=%s", prop_port, port);
	if(port)
		ofono_dbus_dict_append(dict, prop_port, DBUS_TYPE_STRING, &port);
}

static void change_property_list(GAtResult *result, gpointer user_data) {
	struct ofono_location_reporting *lr = user_data;
	struct gps_data *gd = ofono_location_reporting_get_data(lr);
	GAtResultIter iter;
	int property_pos;
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path = __ofono_atom_get_path(lr->atom);

	g_at_result_iter_init(&iter, result);
	/* supported format: ^SGPSC: "Nmea/Output","off" */
	while (g_at_result_iter_next(&iter, "^SGPSC:")) {
		const char *name = "";
		const char *val = "";

		if (!g_at_result_iter_next_string(&iter, &name))
			continue;
		if(g_str_equal(name,"Info"))	/* skip the "Info" property: different line format and different usage */
			continue;
		if (!g_at_result_iter_next_string(&iter, &val))
			continue;
		for(property_pos=0; property_pos<MAX_GNSS_PROPERTIES && *gd->properties[property_pos].name; property_pos++) {
			if (!g_str_equal(gd->properties[property_pos].name,name))
				continue;
			strncpy(gd->properties[property_pos].value_s,val,MAX_GNSS_STRLEN);
			ofono_dbus_signal_property_changed(conn, path,
							OFONO_LOCATION_REPORTING_INTERFACE,
							name, DBUS_TYPE_STRING, &val);
		}
	}
}

static void gemalto_location_reporting_set_property_cb(gboolean ok, GAtResult *result,
							gpointer user_data)
{
	struct ofono_location_reporting *lr = user_data;

	if (!ok || !lr)
		return;

	change_property_list(result, lr);
}

static void *gemalto_location_reporting_set_property(struct ofono_location_reporting *lr, void *_msg)
{
	DBusMessage *msg = _msg;
	struct gps_data *gd;
	DBusMessageIter iter, var;
	const char *name;
	int property_pos;

	DBG("");
	if(!lr)
		return __ofono_error_not_available(msg);

	gd = ofono_location_reporting_get_data(lr);

	if(!gd)
		return __ofono_error_not_available(msg);

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return __ofono_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __ofono_error_invalid_args(msg);

	dbus_message_iter_get_basic(&iter, &name);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return __ofono_error_invalid_args(msg);

	dbus_message_iter_recurse(&iter, &var);

	property_pos=0;
	while(property_pos<MAX_GNSS_PROPERTIES && *gd->properties[property_pos].name) {
		if (g_str_equal(name, gd->properties[property_pos].name))
		{
			char s[128];
			char *value;

			if (dbus_message_iter_get_arg_type(&var) != DBUS_TYPE_STRING)
				return __ofono_error_invalid_args(msg);

			dbus_message_iter_get_basic(&var, &value);

			if (g_str_equal(value, gd->properties[property_pos].value_s))
				return __ofono_error_not_available(msg); /* do not set the same value and do not notify change */
			sprintf(s, "AT^SGPSC=\"%s\",\"%s\"",name, value);
			DBG("setting %s", s);
			if (g_at_chat_send(gd->chat, s, sgpsc_prefix,	/* to do: report value changed */
						gemalto_location_reporting_set_property_cb, lr, NULL) > 0)
				return dbus_message_new_method_return(msg);
			return __ofono_error_not_available(msg);
		}
		property_pos++;
	}

	return __ofono_error_invalid_args(msg);
}

static void build_property_list(GAtResult *result, gpointer user_data) {
	struct ofono_location_reporting *lr = user_data;
	struct gps_data *gd = ofono_location_reporting_get_data(lr);
	GAtResultIter iter;
	int property_pos = 0;

	// TODO: clear the list, set the static properties

	while (property_pos<MAX_GNSS_PROPERTIES && *gd->properties[property_pos].name) /* skip pre-set */
		property_pos++;

	g_at_result_iter_init(&iter, result);

	/* supported format: ^SGPSC: "Nmea/Output","off" */
	while (property_pos<MAX_GNSS_PROPERTIES && g_at_result_iter_next(&iter, "^SGPSC:")) {
		const char *name = "";
		const char *val = "";

		if (!g_at_result_iter_next_string(&iter, &name))
			continue;

		if(g_str_equal(name,"Info"))	/* skip the "Info" property: different line format and different usage */
			continue;

		if (!g_at_result_iter_next_string(&iter, &val))
			continue;

		strncpy(gd->properties[property_pos].name,name,MAX_GNSS_STRLEN);
		strncpy(gd->properties[property_pos].value_s,val,MAX_GNSS_STRLEN);
		property_pos++;
	}

	property_pos=0;
	while(property_pos<MAX_GNSS_PROPERTIES && *gd->properties[property_pos].name) {
		property_pos++;
	}
}

static void gemalto_location_reporting_support_cb(gboolean ok, GAtResult *result,
							gpointer user_data)
{
	struct ofono_location_reporting *lr = user_data;

	if (!ok) {
		ofono_location_reporting_remove(lr);
		return;
	}

	build_property_list(result, user_data);
	ofono_location_reporting_register(lr);
}

static void gemalto_locrep_stored(struct ofono_location_reporting *lr) {
	struct ofono_modem *modem = ofono_location_reporting_get_modem(lr);
	struct gps_data *gd = ofono_location_reporting_get_data(lr);
	const char *vid = ofono_modem_get_string(modem, "Vendor");
	const char *pid = ofono_modem_get_string(modem, "Model");
	char store[32];
	int index;
	char *property, *value;
	char key[32];
	GKeyFile *f;
	char *command;

	sprintf(store,"%s-%s/location-reporting", vid, pid);
	f = storage_open(NULL, store);

	if (!f)
		return;

	for (index=0;;index++) {
		sprintf(key, "property_%d", index);
		property = g_key_file_get_string(f, "Properties", key, NULL);

		sprintf(key, "value_%d", index);
		value = g_key_file_get_string(f, "Properties", key, NULL);

		if(!property || !value)
			break;

		command = g_strdup_printf("AT^SGPSC=%s,%s", property, value);
		DBG("setting GNSS property: %s", command);
		g_at_chat_send(gd->chat, command, NULL, NULL, NULL, NULL);
		free(command);
	}

	storage_close(NULL, store, f, FALSE);
}

static int gemalto_location_reporting_probe(struct ofono_location_reporting *lr,
						unsigned int vendor, void *data)
{
	GAtChat *chat = data;
	struct gps_data *gd;

	gd = g_try_new0(struct gps_data, 1);

	if (gd == NULL)
		return -ENOMEM;

	gd->chat = g_at_chat_clone(chat);
	ofono_location_reporting_set_data(lr, gd);

	gemalto_locrep_stored(lr);

	g_at_chat_send(gd->chat, "AT^SGPSC?", sgpsc_prefix,
					gemalto_location_reporting_support_cb,
					lr, NULL);

	return 0;
}

static void gemalto_location_reporting_remove(struct ofono_location_reporting *lr)
{
	struct gps_data *gd = ofono_location_reporting_get_data(lr);

	// TODO: store modified params if [Settings] sync=yes

	ofono_location_reporting_set_data(lr, NULL);

	g_at_chat_unref(gd->chat);
	g_free(gd);
}

static struct ofono_location_reporting_driver driver = {
	.name			= "gemaltomodem",
	.type			= OFONO_LOCATION_REPORTING_TYPE_NMEA,
	.probe			= gemalto_location_reporting_probe,
	.remove			= gemalto_location_reporting_remove,
	.enable			= gemalto_location_reporting_enable,
	.disable		= gemalto_location_reporting_disable,
	.get_properties		= gemalto_location_reporting_get_properties,
	.set_property		= gemalto_location_reporting_set_property
};

void gemalto_location_reporting_init()
{
	ofono_location_reporting_driver_register(&driver);
}

void gemalto_location_reporting_exit()
{
	ofono_location_reporting_driver_unregister(&driver);
}
