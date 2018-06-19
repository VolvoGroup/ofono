/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2008-2010  Intel Corporation. All rights reserved.
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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <glib.h>
#include <gatchat.h>
#include <gattty.h>

#define OFONO_API_SUBJECT_TO_CHANGE
#include <ofono/plugin.h>
#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/devinfo.h>
#include <ofono/netreg.h>
#include <ofono/sim.h>
#include <ofono/sms.h>
#include <ofono/gprs.h>
#include <ofono/phonebook.h>
#include <ofono/cbs.h>
#include <ofono/audio-settings.h>
#include <ofono/radio-settings.h>
#include <ofono/voicecall.h>
#include <ofono/call-forwarding.h>
#include <ofono/call-settings.h>
#include <ofono/call-barring.h>
#include <ofono/gprs-context.h>
#include <drivers/cinterionmodem/cinterionutil.h>
#include <drivers/cinterionmodem/modemmodel.h>

/* All values are in seconds */

#define DEFAULT_TIMEOUT		10
#define AT_CGDCONT_TIMEOUT	30
#define AT_SWWAN_TIMEOUT	120
#define AT_COPS_TIMEOUT		300
#define AT_CMGS_TIMEOUT		40

/*
 * Voltages below and above these values causes the ^SBC URC,
 * Since there is no "reset" URC, we must monitor AT^SBV.
 */
#define ALS3_GOOD_MIN_OPER_VOLTAGE 3500
#define ALS3_GOOD_MAX_OPER_VOLTAGE 4000

/*
 * LTE modems need to be able to set GPRS settings before the SIM is
 * unlocked to prevent getting temporarily locked out from the LTE
 * network. (A lock-out can last up to 3 hours).
 *
 * Ref: Gemalto Cinterion ALS3-E modem ATC manual v1.438.
 * Manual ID: ALS3-E_ATC_V01.438
 * Chapter: 12.4.1 (APN Handling in LTE Networks)
 *
 * The configuration for this is done during flashing of the board.
 */

static const char *none_prefix[] = { NULL };

struct cinterion_data {
	GAtChat *app;
	guint at_sbv_source;
};

static void cinterion_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	ofono_info("%s%s", prefix, str);
}

static guint cinterion_get_command_timeout(const char* cmd)
{
	/*
	 * Some AT commands may take a longer time to complete during certain
	 * conditions than what the recommendation says to allow.
	 * These AT commands need to have longer timeouts to prevent the modem
	 * from wrongly resetting.
	 * The recommendation is to reset the modem after 5 seconds of no reply.
	 */
	if (strstr(cmd, "AT+CGDCONT") != 0)
		return AT_CGDCONT_TIMEOUT;
	if (strstr(cmd, "AT^SWWAN") != 0)
		return AT_SWWAN_TIMEOUT;
	if (strstr(cmd, "AT+COPS=?") != 0)
		return AT_COPS_TIMEOUT;
	if (strstr(cmd, "AT+CMGS") != 0)
		return AT_CMGS_TIMEOUT;

	return DEFAULT_TIMEOUT;
}

static GAtChat *open_device(const char *device)
{
	GAtSyntax *syntax;
	GIOChannel *channel;
	GAtChat *chat;
	GHashTable *options;

	DBG("Opening device %s", device);

	options = g_hash_table_new(g_str_hash, g_str_equal);
	if (options == NULL)
		return NULL;

	/* cdc_acm driver requires that the baud rate is specifically set */
	g_hash_table_insert(options, "Baud", "115200");
	g_hash_table_insert(options, "RtsCts", "on");
	g_hash_table_insert(options, "Local", "on");

	channel = g_at_tty_open(device, options);
	g_hash_table_destroy(options);

	if (channel == NULL)
		return NULL;

	/*
	 * The modem will ignore any command before ^SYSSTART, since oFono may
	 * have crashed, or the modem already being booted for whatever reason,
	 * we cannot simply wait for the URC, in that case we would wait
	 * forever. Instead, we send an AT, then wait until we receive some
	 * data. Any data at all is enough, we're just waiting for a the
	 * interface to be responsive.
	 */

	/*
	 * NOTE:
	 * Premissive syntax parser is required for SMS due to non-standard
	 * formatting of the ack-string from the modem for the AT+CMGS command,
	 * the permissive parser handles that while the strict one does not.
	 * Otherwise there is very little difference between the 2 parsers.
	 */
	syntax = g_at_syntax_new_gsm_permissive();
	chat = g_at_chat_new(channel, syntax);
	g_at_syntax_unref(syntax);
	g_io_channel_unref(channel);

	if (chat == NULL)
		return NULL;

	if (getenv("OFONO_AT_DEBUG")) {
		g_at_chat_set_debug(chat, cinterion_debug, "App: ");
		DBG("Enabled AT logging.");
	}

	return chat;
}

static void cinterion_sctm_notify(GAtResult *result, gpointer user_data)
{
	GAtResultIter iter;
	gint value;

	g_at_result_iter_init(&iter, result);
	if (!user_data) {
		g_at_result_iter_next(&iter, "^SCTM_B:");
	}
	else {
		g_at_result_iter_next(&iter, "^SCTM:");
		g_at_result_iter_skip_next(&iter);
	}
	g_at_result_iter_next_number(&iter, &value);

	DBG("value=%d", value);

}

/* Treating the AT^SBV reply as an URC, makes it easier to poll */
static void cinterion_sbv_notify(GAtResult *result, gpointer user_data)
{
	GAtResultIter iter;
	gint value;

	g_at_result_iter_init(&iter, result);
	g_at_result_iter_next(&iter, "^SBV:");
	g_at_result_iter_next_number(&iter, &value);

	DBG("value=%d", value);

}

static void cinterion_sbc_notify(GAtResult *result, gpointer user_data)
{
	GAtResultIter iter;
	const char *voltage_alert;

	g_at_result_iter_init(&iter, result);
	g_at_result_iter_next(&iter, "^SBC:");
	g_at_result_iter_next_unquoted_string(&iter, &voltage_alert);

	DBG("value=%s", voltage_alert);

}

static void cinterion_exit_urc_notify(GAtResult *result, gpointer user_data)
{
	GAtResultIter iter;
	const char *error_message;

	g_at_result_iter_init(&iter, result);
	g_at_result_iter_next(&iter, "^EXIT:");
	g_at_result_iter_next_unquoted_string(&iter, &error_message);

	ofono_error("Modem crashed! Cause: %s", error_message);
}

static gboolean cinterion_sbv_poll(gpointer user_data)
{
	struct cinterion_data *data = user_data;

	g_at_chat_send(data->app, "AT^SBV", none_prefix, NULL, NULL, NULL);

	return TRUE;
}

static int cinterion_probe(struct ofono_modem *modem)
{
	struct cinterion_data *data;
	const char *app;

	DBG("%p", modem);

	data = g_try_new0(struct cinterion_data, 1);
	if (data == NULL)
		return -ENOMEM;

	app = ofono_modem_get_string(modem, "Application");

	if (app == NULL)
		return -EINVAL;

	data->app = open_device(app);

	if (data->app == NULL)
		return -EIO;

	ofono_modem_set_data(modem, data);

	g_at_chat_set_wakeup_command(data->app, "AT\r", 500, 5000);

	/* No command echo */
	g_at_chat_send(data->app, "ATE0", none_prefix, NULL, NULL, NULL);
	/* No numeric error codes */
	g_at_chat_send(data->app, "AT+CMEE=1", none_prefix, NULL, NULL, NULL);
	/*
	 * Needed to avoid Ctrl-Z to indicate that the modem has hung up
	 */
	g_at_chat_send(data->app, "AT&C0", none_prefix, NULL, NULL, NULL);

	g_at_chat_register(data->app, "^EXIT",
		cinterion_exit_urc_notify, FALSE, NULL, NULL);

	g_at_chat_send(data->app, "AT^SCFG=\"MEopMode/PwrSave\",\"enabled\",52,50", none_prefix,
					NULL, NULL, NULL);	/* Enable powersave mode */
	/*
	 * Listen to Over/Under temperature URCs
	 * Piggy-back on the URC handler for the replies from the query command
	 */
	g_at_chat_register(data->app, "^SCTM:",
		cinterion_sctm_notify, FALSE, GINT_TO_POINTER(1), NULL);
	g_at_chat_register(data->app, "^SCTM_B:",
		cinterion_sctm_notify, FALSE, NULL, NULL);
	/* Listen to Over/Under voltage URCs */
	g_at_chat_register(data->app, "^SBV:",
		cinterion_sbv_notify, FALSE, NULL, NULL);
	g_at_chat_register(data->app, "^SBC:",
		cinterion_sbc_notify, FALSE, NULL, NULL);

	/*
	 * Enable over/under temperature warning URCs
	 * in addition to the critical
	 */
	g_at_chat_send(data->app, "AT^SCTM=1", none_prefix, NULL, NULL, NULL);
	g_at_chat_send(data->app, "AT^SCTM?", none_prefix, NULL, NULL, NULL);

	return 0;
}

static void cinterion_remove(struct ofono_modem *modem)
{
	struct cinterion_data *data = ofono_modem_get_data(modem);

	DBG("%p", modem);

	g_at_chat_unregister_all(data->app);

	g_at_chat_unref(data->app);
	data->app = NULL;

	if (data->at_sbv_source) {
		g_source_remove(data->at_sbv_source);
		data->at_sbv_source = 0;
	}

	ofono_modem_set_data(modem, NULL);

	g_at_chat_set_timeout_handlers(NULL, NULL);

	g_free(data);
}

struct sim_poll_data {
	gpointer user_data;
	gboolean do_poll;
};

static void cinterion_sim_cb(gboolean ok, GAtResult *result, gpointer user_data) {
	struct sim_poll_data *params = user_data;
	GSList *lines;
	DBG("ok=%d", ok);
	DBG("result->final_or_pdu = %s", result->final_or_pdu);
	for (lines=result->lines; lines; lines = lines->next)
		DBG("lines: %s", (char*)lines->data);

	if (ok) {
		struct ofono_modem *modem = params->user_data;
		struct cinterion_data *data = ofono_modem_get_data(modem);

		data->at_sbv_source =
			g_timeout_add_seconds(60, cinterion_sbv_poll, data);
		ofono_modem_set_powered(modem, ok);
	}
	params->do_poll = !ok;
}


static gboolean cinterion_sim_poll(gpointer user_data) {
	struct sim_poll_data *params = user_data;
	struct ofono_modem *modem = params->user_data;
	struct cinterion_data *data = ofono_modem_get_data(modem);

	DBG("");

	if (params->do_poll)
		g_at_chat_send(data->app, "AT+CPIN?", none_prefix, cinterion_sim_cb, params, NULL);

	return params->do_poll;
}

static void cinterion_cfun_enable_cb(gboolean ok, GAtResult *result,
						gpointer user_data)
{
	static struct sim_poll_data params; // FIXME reentrancy

	DBG("");
	if (ok) {
		params.user_data = user_data;
		params.do_poll = TRUE;
		g_timeout_add_seconds(5, cinterion_sim_poll, &params);
	}
}

static int cinterion_enable(struct ofono_modem *modem)
{
	struct cinterion_data *data = ofono_modem_get_data(modem);

	DBG("%p", modem);

	g_at_chat_send(data->app, "AT+CFUN=4", none_prefix,
			cinterion_cfun_enable_cb, modem, NULL);

	if (data->at_sbv_source) {
		g_source_remove(data->at_sbv_source);
		data->at_sbv_source = 0;
	}

	/*
	 * Start GNSS
	 */
	g_at_chat_send(data->app, "AT^SGPSC=\"Engine\",\"0\"", none_prefix,
					NULL, NULL, NULL);	/* turn off GNSS in order to configure */
	g_at_chat_send(data->app, "AT^SGPSC=\"Power/Antenna\",\"on\"", none_prefix,
					NULL, NULL, NULL);
	g_at_chat_send(data->app, "AT^SGPSC=\"Nmea/Glonass\",\"on\"", none_prefix,
					NULL, NULL, NULL);
	g_at_chat_send(data->app, "AT^SGPSC=\"Nmea/Output\",\"on\"", none_prefix,
					NULL, NULL, NULL);
	g_at_chat_send(data->app, "AT^SGPSC=\"Engine\",\"1\"", none_prefix,
					NULL, NULL, NULL);	/* turn on GNSS */

	return -EINPROGRESS;
}

static void cinterion_cfun_disable_cb(gboolean ok, GAtResult *result,
					gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct cinterion_data *data = ofono_modem_get_data(modem);

	DBG("");

	g_at_chat_cancel_all(data->app, FALSE);

	if (ok)
		ofono_modem_set_powered(modem, FALSE);
}

static int cinterion_disable(struct ofono_modem *modem)
{
	struct cinterion_data *data = ofono_modem_get_data(modem);

	DBG("%p", modem);

	if (data->app == NULL)
		return 0;

	g_at_chat_send(data->app, "AT+CFUN=0", none_prefix,
			cinterion_cfun_disable_cb, modem, NULL);

	return -EINPROGRESS;
}

static void cinterion_set_online_cb(gboolean ok, GAtResult *result,
					gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_modem_online_cb_t cb = cbd->cb;

	if (ok)
		CALLBACK_WITH_SUCCESS(cb, cbd->data);
	else
		CALLBACK_WITH_FAILURE(cb, cbd->data);
}

static void cinterion_set_online(struct ofono_modem *modem,
				ofono_bool_t online,
				ofono_modem_online_cb_t cb,
				void *user_data)
{
	struct cinterion_data *data = ofono_modem_get_data(modem);
	struct cb_data *cbd = cb_data_new(cb, user_data);
	char const *command = online ? "AT+CFUN=1" : "AT+CFUN=4";

	DBG("modem %p %s", modem, online ? "online" : "offline");

	if (data->app == NULL)
		goto error;

	if (g_at_chat_send(data->app, command, NULL,
				cinterion_set_online_cb, cbd, g_free))
		return;

error:
	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, cbd->data);
}

static void cinterion_pre_sim(struct ofono_modem *modem)
{
	struct cinterion_data *data = ofono_modem_get_data(modem);
	struct ofono_sim *sim;

	DBG("%p", modem);

	sim = ofono_sim_create(modem, CINTERION_LTE,
				"cinterionmodem", data->app);

	if (sim)
		ofono_sim_inserted_notify(sim, TRUE);
}

static void cinterion_post_sim(struct ofono_modem *modem)
{
	struct cinterion_data *data = ofono_modem_get_data(modem);
	struct ofono_gprs *gprs;
	struct ofono_gprs_context *gc;

	DBG("%p", modem);

	ofono_devinfo_create(modem, CINTERION_LTE,
				"cinterionmodem", data->app);

	ofono_sms_create(modem, CINTERION_LTE, "cinterionmodem", data->app);

	gprs = ofono_gprs_create(modem, CINTERION_LTE,
				"cinterionmodem", data->app);
	gc = ofono_gprs_context_create(modem, CINTERION_LTE,
					"cinterionmodem", data->app);

	if (gprs && gc)
		ofono_gprs_add_context(gprs, gc);
}

static void cinterion_post_online(struct ofono_modem *modem)
{
	struct cinterion_data *data = ofono_modem_get_data(modem);

	DBG("%p", modem);

	ofono_voicecall_create(modem, CINTERION_LTE,
				"cinterionmodem", data->app);

	ofono_netreg_create(modem, CINTERION_LTE,
				"cinterionmodem", data->app);
}

static void cinterion_reset_cb(gboolean ok, GAtResult *result,
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

static void cinterion_reset(struct ofono_modem* modem)
{
	struct cinterion_data *data = ofono_modem_get_data(modem);

	DBG("");

	g_at_chat_send(data->app, "AT+CFUN=1,1", none_prefix,
			cinterion_reset_cb, NULL, NULL);
}

static void cinterion_smso_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	/* Try hard shutdown */
	if (!ok) {
		return;
	}

	return;
}

static void cinterion_shutdown(struct ofono_modem *modem)
{
	struct cinterion_data *data = ofono_modem_get_data(modem);

	DBG("");

	/* Switch timeout callback to shutdown, don't reset if we crash now */
	g_at_chat_send(data->app, "AT^SMSO", none_prefix, cinterion_smso_cb,
					NULL, NULL);
}

static void cinterion_powersave_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	ofono_modem_set_powersave(modem, TRUE);

	return;
}

static void cinterion_normal_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	ofono_modem_set_powersave(modem, FALSE);

	return;
}

static void cinterion_powersave(struct ofono_modem *modem, ofono_bool_t enable)
{
	struct cinterion_data *data = ofono_modem_get_data(modem);

	DBG("");

	if (enable) {
		g_at_chat_send(data->app, "AT+CREG=0", none_prefix,
					NULL, NULL, NULL);	/* disable URC for network */
		g_at_chat_send(data->app, "AT+CGREG=0", none_prefix,
					NULL, NULL, NULL);	/* disable URC for GPRS */
		g_at_chat_send(data->app, "AT+CNMI=2,1,0", none_prefix,
					NULL, NULL, NULL);	/* Make sure URC for SMS is enabled */
		g_at_chat_send(data->app, "AT^SGPSC=\"Engine\",\"0\"", none_prefix,
					NULL, NULL, NULL);	/* turn off GNSS */
		g_at_chat_send(data->app, "AT^SGPSC=\"Power/Antenna\",\"off\"", none_prefix,
				    NULL, NULL, NULL);  /* Power off GNSS-antenna */

		g_at_chat_send(data->app, "AT", none_prefix,
					cinterion_powersave_cb, modem, NULL);
	}
	else {
		g_at_chat_send(data->app, "AT+CREG=2", none_prefix,
					NULL, NULL, NULL);	/* enable URC for network */
		g_at_chat_send(data->app, "AT+CGREG=2", none_prefix,
					NULL, NULL, NULL);	/* enable URC for GPRS */
		g_at_chat_send(data->app, "AT^SGPSC=\"Power/Antenna\",\"on\"", none_prefix,
				    NULL, NULL, NULL);  /* Power on GNSS-antenna */
		g_at_chat_send(data->app, "AT^SGPSC=\"Engine\",\"1\"", none_prefix,
					NULL, NULL, NULL);	/* turn on GNSS */

		g_at_chat_send(data->app, "AT", none_prefix,
					cinterion_normal_cb, modem, NULL);

	}
}

static struct ofono_modem_driver cinterion_driver = {
	.name		= "cinterionLTE",
	.probe		= cinterion_probe,
	.remove		= cinterion_remove,
	.enable		= cinterion_enable,
	.disable	= cinterion_disable,
	.set_online	= cinterion_set_online,
	.pre_sim	= cinterion_pre_sim,
	.post_sim	= cinterion_post_sim,
	.post_online	= cinterion_post_online,
	.modem_reset	= cinterion_reset,
	.modem_shutdown	= cinterion_shutdown,
	.powersave	= cinterion_powersave,
};

static int cinterion_init(void)
{
	return ofono_modem_driver_register(&cinterion_driver);
}

static void cinterion_exit(void)
{
	ofono_modem_driver_unregister(&cinterion_driver);
}

OFONO_PLUGIN_DEFINE(cinterion_lte, "Cinterion LTE modem driver",
			VERSION, OFONO_PLUGIN_PRIORITY_DEFAULT,
			cinterion_init, cinterion_exit)
