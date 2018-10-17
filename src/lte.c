/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2016  Endocode AG. All rights reserved.
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>

#include <glib.h>
#include <gdbus.h>

#include "ofono.h"
#include <ofono/lte.h>

#include "common.h"
#include "storage.h"

#define SETTINGS_STORE "lte"
#define SETTINGS_GROUP "Settings"
#define DEFAULT_APN_KEY "AccessPointName"
#define LTE_USERNAME "Username"
#define LTE_PASSWORD "Password"
#define AUTH_TYPE "AuthenticationMethod"

struct ofono_lte {
	const struct ofono_lte_driver *driver;
	void *driver_data;
	struct ofono_atom *atom;
	char *imsi;
	GKeyFile *settings;
	DBusMessage *pending;
	struct ofono_lte_default_attach_info pending_info;
	struct ofono_lte_default_attach_info info;
};

static GSList *g_drivers = NULL;

static void lte_load_settings(struct ofono_lte *lte)
{
	char *apn;
	char *username;
	char *password;
	enum ofono_gprs_auth_method auth_method;

	if (lte->imsi == NULL)
		return;

	lte->settings = storage_open(lte->imsi, SETTINGS_STORE);

	if (lte->settings == NULL) {
		ofono_error("LTE: Can't open settings file, "
				"changes won't be persistent");
		return;
	}

	apn = g_key_file_get_string(lte->settings, SETTINGS_GROUP ,
					DEFAULT_APN_KEY, NULL);
	username = g_key_file_get_string(lte->settings, SETTINGS_GROUP ,
					LTE_USERNAME, NULL);
	password = g_key_file_get_string(lte->settings, SETTINGS_GROUP ,
					LTE_PASSWORD, NULL);
	auth_method = g_key_file_get_integer(lte->settings, SETTINGS_GROUP ,
					AUTH_TYPE, NULL);
	if (apn) {
		strcpy(lte->info.apn, apn);
		g_free(apn);
	}

	if (username) {
		strcpy(lte->info.username, username);
		g_free(username);

	}

	if (password) {
		strcpy(lte->info.password, password);
		g_free(password);

	}

	if (auth_method) {
		lte->info.auth_method = auth_method;
	}

}

static DBusMessage *lte_get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct ofono_lte *lte = data;
	const char *apn = lte->info.apn;
	const char *username = lte->info.username;
	const char *password = lte->info.password;
	char* auth_method = g_new0(char, 5);
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;

	switch (lte->info.auth_method) {
	case OFONO_GPRS_AUTH_METHOD_PAP:
		g_strlcpy(auth_method, "pap", 5);
		break;
	case OFONO_GPRS_AUTH_METHOD_CHAP:
		g_strlcpy(auth_method, "chap", 5);
		break;
	default:
		g_strlcpy(auth_method, "", 5);
		break;
	}
	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					OFONO_PROPERTIES_ARRAY_SIGNATURE,
					&dict);
	ofono_dbus_dict_append(&dict, DEFAULT_APN_KEY, DBUS_TYPE_STRING, &apn);
	ofono_dbus_dict_append(&dict, LTE_USERNAME, DBUS_TYPE_STRING, &username);
	ofono_dbus_dict_append(&dict, LTE_PASSWORD, DBUS_TYPE_STRING, &password);
	ofono_dbus_dict_append(&dict, AUTH_TYPE, DBUS_TYPE_STRING, &auth_method);
	dbus_message_iter_close_container(&iter, &dict);

	g_free(auth_method);
	return reply;
}

static void lte_set_default_attach_info_cb(const struct ofono_error *error,
						void *data)
{
	struct ofono_lte *lte = data;
	const char *path = __ofono_atom_get_path(lte->atom);
	DBusConnection *conn = ofono_dbus_get_connection();
	DBusMessage *reply;
	const char *apn = lte->info.apn;
	const char *username = lte->info.username;
	const char *password = lte->info.password;
	enum ofono_gprs_auth_method auth_method = lte->info.auth_method;

	if(error != NULL) {
		DBG("%s error %d", path, error->type);

		if (error->type != OFONO_ERROR_TYPE_NO_ERROR) {
			__ofono_dbus_pending_reply(&lte->pending,
					__ofono_error_failed(lte->pending));
			return;
		}
	}

	if (*lte->pending_info.apn) {
		g_strlcpy(lte->info.apn, lte->pending_info.apn,
			OFONO_GPRS_MAX_APN_LENGTH + 1);
	}

	if (*lte->pending_info.username) {
		g_strlcpy(lte->info.username, lte->pending_info.username,
			OFONO_GPRS_MAX_USERNAME_LENGTH + 1);
	}

	if (*lte->pending_info.password) {
		g_strlcpy(lte->info.password, lte->pending_info.password,
			OFONO_GPRS_MAX_PASSWORD_LENGTH + 1);
	}

	if (lte->pending_info.auth_method >= 0 && lte->pending_info.auth_method <= 3) {
		lte->info.auth_method = lte->pending_info.auth_method;
	}

	if (lte->settings) {

		if (strlen(lte->info.apn) == 0)
			/* Clear entry on empty APN. */
			g_key_file_remove_key(lte->settings, SETTINGS_GROUP,
						DEFAULT_APN_KEY, NULL);
		else
			g_key_file_set_string(lte->settings, SETTINGS_GROUP,
						DEFAULT_APN_KEY, lte->info.apn);

		if (strlen(lte->info.username) == 0)
			/* Clear entry on empty Username. */
			g_key_file_remove_key(lte->settings, SETTINGS_GROUP,
						LTE_USERNAME, NULL);
		else
			g_key_file_set_string(lte->settings, SETTINGS_GROUP,
						LTE_USERNAME, lte->info.username);

		if (strlen(lte->info.password) == 0)
			/* Clear entry on empty Password. */
			g_key_file_remove_key(lte->settings, SETTINGS_GROUP,
						LTE_PASSWORD, NULL);
		else
			g_key_file_set_string(lte->settings, SETTINGS_GROUP,
						LTE_PASSWORD, lte->info.password);

		if (lte->info.auth_method == 0)
			/* Clear entry on empty Authentication type. */
			g_key_file_remove_key(lte->settings, SETTINGS_GROUP,
						AUTH_TYPE, NULL);
		else
			g_key_file_set_integer(lte->settings, SETTINGS_GROUP,
						AUTH_TYPE, lte->info.auth_method);

		storage_sync(lte->imsi, SETTINGS_STORE, lte->settings);
	}

	reply = dbus_message_new_method_return(lte->pending);
	__ofono_dbus_pending_reply(&lte->pending, reply);

	ofono_dbus_signal_property_changed(conn, path,
					OFONO_CONNECTION_CONTEXT_INTERFACE,
					DEFAULT_APN_KEY,
					DBUS_TYPE_STRING, &apn);
	ofono_dbus_signal_property_changed(conn, path,
					OFONO_CONNECTION_CONTEXT_INTERFACE,
					LTE_USERNAME,
					DBUS_TYPE_STRING, &username);
	ofono_dbus_signal_property_changed(conn, path,
					OFONO_CONNECTION_CONTEXT_INTERFACE,
					LTE_PASSWORD,
					DBUS_TYPE_STRING, &password);
	ofono_dbus_signal_property_changed(conn, path,
					OFONO_CONNECTION_CONTEXT_INTERFACE,
					AUTH_TYPE,
					DBUS_TYPE_UINT32, &auth_method);

}

static DBusMessage *lte_set_default_apn(struct ofono_lte *lte,
				DBusConnection *conn, DBusMessage *msg,
				const char *apn)
{

	if (lte->driver->set_default_attach_info == NULL)
		return __ofono_error_not_implemented(msg);

	if (lte->pending)
		return __ofono_error_busy(msg);

	/* We do care about empty value: it can be used for reset. */
	if (is_valid_apn(apn) == FALSE && apn[0] != '\0')
		return __ofono_error_invalid_format(msg);

	lte->pending = dbus_message_ref(msg);

	g_strlcpy(lte->info.apn, apn, OFONO_GPRS_MAX_APN_LENGTH + 1);

	lte->driver->set_default_attach_info(lte, &lte->info,
					lte_set_default_attach_info_cb, lte);

	return dbus_message_ref(msg);;
}

static DBusMessage *lte_set_username(struct ofono_lte *lte,
				DBusConnection *conn, DBusMessage *msg,
				const char *username)
{

	void *data = lte;

	if (lte->driver->set_default_attach_info == NULL)
		return __ofono_error_not_implemented(msg);

	if (lte->pending)
		return __ofono_error_busy(msg);

	if (g_str_equal(username, lte->info.username))
		return dbus_message_new_method_return(msg);

	lte->pending = dbus_message_ref(msg);

	g_strlcpy(lte->pending_info.username, username, OFONO_GPRS_MAX_USERNAME_LENGTH + 1);

	lte_set_default_attach_info_cb(NULL, data);

	return dbus_message_ref(msg);;
}

static DBusMessage *lte_set_password(struct ofono_lte *lte,
				DBusConnection *conn, DBusMessage *msg,
				const char *password)
{
	void *data = lte;

	if (lte->driver->set_default_attach_info == NULL)
		return __ofono_error_not_implemented(msg);

	if (lte->pending)
		return __ofono_error_busy(msg);

	if (g_str_equal(password, lte->info.password))
		return dbus_message_new_method_return(msg);

	lte->pending = dbus_message_ref(msg);

	g_strlcpy(lte->pending_info.password, password, OFONO_GPRS_MAX_PASSWORD_LENGTH + 1);

	lte_set_default_attach_info_cb(NULL, data);

	return dbus_message_ref(msg);;
}

static DBusMessage *lte_set_auth_type(struct ofono_lte *lte,
				DBusConnection *conn, DBusMessage *msg,
				enum ofono_gprs_auth_method auth_method)
{
	void *data = lte;

	if (lte->driver->set_default_attach_info == NULL)
		return __ofono_error_not_implemented(msg);

	if (lte->pending)
		return __ofono_error_busy(msg);

	if (auth_method == lte->info.auth_method)
		return dbus_message_new_method_return(msg);

	/* We do care about empty value: it can be used for reset. */
	if (auth_method >= 3 && auth_method <= 0)
		return __ofono_error_invalid_format(msg);

	lte->pending = dbus_message_ref(msg);

	lte->pending_info.auth_method = auth_method;

	lte_set_default_attach_info_cb(NULL, data);

	return dbus_message_ref(msg);;
}

static DBusMessage *lte_set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct ofono_lte *lte = data;
	DBusMessageIter iter;
	DBusMessageIter var;
	const char *property;
	const char *str;
	enum ofono_gprs_auth_method auth_method;

	if (!dbus_message_iter_init(msg, &iter))
		return __ofono_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __ofono_error_invalid_args(msg);

	dbus_message_iter_get_basic(&iter, &property);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return __ofono_error_invalid_args(msg);

	dbus_message_iter_recurse(&iter, &var);

	if (!strcmp(property, DEFAULT_APN_KEY)) {
		if (dbus_message_iter_get_arg_type(&var) != DBUS_TYPE_STRING)
			return __ofono_error_invalid_args(msg);

		dbus_message_iter_get_basic(&var, &str);

		return lte_set_default_apn(lte, conn, msg, str);
	}

	if (!strcmp(property, LTE_USERNAME)) {
		if (dbus_message_iter_get_arg_type(&var) != DBUS_TYPE_STRING)
			return __ofono_error_invalid_args(msg);

		dbus_message_iter_get_basic(&var, &str);

		return lte_set_username(lte, conn, msg, str);
	}

	if (!strcmp(property, LTE_PASSWORD)) {
		if (dbus_message_iter_get_arg_type(&var) != DBUS_TYPE_STRING)
			return __ofono_error_invalid_args(msg);

		dbus_message_iter_get_basic(&var, &str);

		return lte_set_password(lte, conn, msg, str);
	}

	if (!strcmp(property, AUTH_TYPE)) {
		if (dbus_message_iter_get_arg_type(&var) != DBUS_TYPE_STRING)
			return __ofono_error_invalid_args(msg);

		dbus_message_iter_get_basic(&var, &str);

		auth_method = get_auth_type_from_str(str);

		return lte_set_auth_type(lte, conn, msg, auth_method);
	}

	return __ofono_error_invalid_args(msg);
}

static const GDBusMethodTable lte_methods[] = {
	{ GDBUS_METHOD("GetProperties",
			NULL, GDBUS_ARGS({ "properties", "a{sv}" }),
			lte_get_properties) },
	{ GDBUS_ASYNC_METHOD("SetProperty",
			GDBUS_ARGS({ "property", "s" }, { "value", "v" }),
			NULL, lte_set_property) },
	{ }
};

static const GDBusSignalTable lte_signals[] = {
	{ GDBUS_SIGNAL("PropertyChanged",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" })) },
	{ }
};

static void lte_atom_remove(struct ofono_atom *atom)
{
	struct ofono_lte *lte = __ofono_atom_get_data(atom);

	DBG("atom: %p", atom);

	if (lte == NULL)
		return;

	if (lte->settings) {
		storage_close(lte->imsi, SETTINGS_STORE, lte->settings, TRUE);
		lte->settings = NULL;
	}

	if (lte->driver && lte->driver->remove)
		lte->driver->remove(lte);

	g_free(lte->imsi);
	lte->imsi = NULL;

	g_free(lte);
}

struct ofono_lte *ofono_lte_create(struct ofono_modem *modem,
					unsigned int vendor,
					const char *driver, void *data)
{
	struct ofono_lte *lte;
	GSList *l;

	if (driver == NULL)
		return NULL;

	lte = g_try_new0(struct ofono_lte, 1);

	if (lte == NULL)
		return NULL;

	lte->atom = __ofono_modem_add_atom(modem, OFONO_ATOM_TYPE_LTE,
						lte_atom_remove, lte);

	for (l = g_drivers; l; l = l->next) {
		const struct ofono_lte_driver *drv = l->data;

		if (g_strcmp0(drv->name, driver))
			continue;

		if (drv->probe(lte, vendor, data) < 0)
			continue;

		lte->driver = drv;
		break;
	}

	DBG("LTE atom created");

	return lte;
}

int ofono_lte_driver_register(const struct ofono_lte_driver *d)
{
	DBG("driver: %p, name: %s", d, d->name);

	if (d->probe == NULL)
		return -EINVAL;

	g_drivers = g_slist_prepend(g_drivers, (void *) d);

	return 0;
}

void ofono_lte_driver_unregister(const struct ofono_lte_driver *d)
{
	DBG("driver: %p, name: %s", d, d->name);

	g_drivers = g_slist_remove(g_drivers, (void *) d);
}

static void lte_atom_unregister(struct ofono_atom *atom)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	struct ofono_modem *modem = __ofono_atom_get_modem(atom);
	const char *path = __ofono_atom_get_path(atom);

	ofono_modem_remove_interface(modem, OFONO_LTE_INTERFACE);
	g_dbus_unregister_interface(conn, path, OFONO_LTE_INTERFACE);
}

static void ofono_lte_finish_register(struct ofono_lte *lte)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	struct ofono_modem *modem = __ofono_atom_get_modem(lte->atom);
	const char *path = __ofono_atom_get_path(lte->atom);

	if (!g_dbus_register_interface(conn, path,
				OFONO_LTE_INTERFACE,
				lte_methods, lte_signals, NULL,
				lte, NULL)) {
		ofono_error("could not create %s interface",
				OFONO_LTE_INTERFACE);
		return;
	}

	ofono_modem_add_interface(modem, OFONO_LTE_INTERFACE);

	__ofono_atom_register(lte->atom, lte_atom_unregister);
}

static void lte_init_default_attach_info_cb(const struct ofono_error *error,
						void *data)
{
	struct ofono_lte *lte = data;

	ofono_lte_finish_register(lte);
}

void ofono_lte_register(struct ofono_lte *lte)
{
	struct ofono_modem *modem = __ofono_atom_get_modem(lte->atom);
	struct ofono_sim *sim = __ofono_atom_find(OFONO_ATOM_TYPE_SIM, modem);
	const char *imsi = ofono_sim_get_imsi(sim);

	if (imsi == NULL) {
		ofono_error("No sim atom required for registering LTE atom.");
		return;
	}

	lte->imsi = g_strdup(imsi);

	lte_load_settings(lte);
	if (lte->driver->set_default_attach_info) {
		lte->driver->set_default_attach_info(lte, &lte->info,
					lte_init_default_attach_info_cb, lte);
		return;
	}

	ofono_lte_finish_register(lte);
}

void ofono_lte_remove(struct ofono_lte *lte)
{
	__ofono_atom_free(lte->atom);
}

void ofono_lte_set_data(struct ofono_lte *lte, void *data)
{
	lte->driver_data = data;
}

void *ofono_lte_get_data(const struct ofono_lte *lte)
{
	return lte->driver_data;
}

struct ofono_modem *ofono_lte_get_modem(const struct ofono_lte *lte)
{
	return __ofono_atom_get_modem(lte->atom);
}