#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>

#include <glib.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/gprs-context.h>

#include "gatchat.h"
#include "gatresult.h"

#include "cinterionmodem.h"
#include "modemmodel.h"

enum state {
	STATE_IDLE = 0,
	STATE_SET_APN,
	STATE_DEACTIVATING,
	STATE_ACTIVE,
};

static const char *cgcontrdp_prefix[] = { "+CGCONTRDP:", NULL };
static const char *none_prefix[] = { NULL };
static const int poll_time = 10;

struct gprs_context_data {
	GAtChat *chat;
	struct ofono_gprs_primary_context cd;
  unsigned int modem;
  unsigned int swwan_source;
	enum state state;
	ofono_gprs_context_cb_t cb;
	void *cb_data;                                  /* Callback data */
};

static void cint_cgcontrdp_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
  struct ofono_gprs_context *gc = user_data;
  struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
  struct ofono_modem* modem = ofono_gprs_context_get_modem(gc);
  GAtResultIter iter;
  const char *ip_with_netmask;
  const char *gw_with_netmask;
  const char *interface;
  char ip[16];
  char netmask[16];
  char gateway[16];
  const char *dns[2];
  unsigned int i;
  unsigned int len;
  const char* temp;

  if (!ok) {
    CALLBACK_WITH_FAILURE(gcd->cb, gcd->cb_data);
    return;
  }

  g_at_result_iter_init(&iter, result);
  g_at_result_iter_next(&iter, "+CGCONTRDP:");
  g_at_result_iter_skip_next(&iter); /* cid, do error checking? */
  g_at_result_iter_skip_next(&iter); /* bearer ID */
  g_at_result_iter_skip_next(&iter); /* APN */

  /*
   * For some reason the IP and Netmask are provided in the same field,
   * this causes a bit of a hassle when extracting the data for oFono.
   */
  if(!g_at_result_iter_next_string(&iter, &ip_with_netmask))
    goto dynamic_ip; /* No IP parameter */

  temp = ip_with_netmask;
  for (i = 0; i < 4; i++) {
    temp = strchr(temp, '.');
  }
  if(!temp)
    goto dynamic_ip; /* No netmask given */
  len = temp - ip_with_netmask;
  strncpy(ip, ip_with_netmask, len);
  temp = temp + 1;
  len = strlen(temp);
  strncpy(netmask, temp, len);

  if(!g_at_result_iter_next_string(&iter, &gw_with_netmask))
    goto dynamic_ip; /* No GW parameter */

  /* TODO: Add support for Gateway in different IP range */
  /* This also requires patching ConnMan! (and adding virtual ethernet?) */
  /* Story: http://jira.actia.se/browse/SCA-62 */
  temp = gw_with_netmask;
  for (i = 0; i < 4; i++) {
    temp = strchr(temp, '.');
  }
  /* A GW with no netmask is still valid */
  if (temp)
    len = temp - gw_with_netmask;
  else
    len = strlen(gw_with_netmask);
  strncpy(gateway, gw_with_netmask, len);
  //if (temp) {
  //  Handle GW netmask
  //}

  if (!g_at_result_iter_next_string(&iter, &(dns[0])))
    goto dynamic_ip; /* No DNS parameter */
  g_at_result_iter_next_string(&iter, &(dns[1]));

  /* TODO: Support both WWANs? */
  interface = ofono_modem_get_string(modem, "NetworkInterface1");
  DBG("Interface: %s", interface);
  DBG("IP: %s", ip);
  DBG("Netmask: %s", netmask);
  DBG("Gateway: %s", gateway);
  DBG("GW Netmask: "); /* TODO */
  DBG("Primary DNS: %s  Secondary DNS: %s", dns[0], dns[1]);
  ofono_gprs_context_set_interface(gc, interface);
  /* TODO: Does ConnMan update interface if IP changes? */
  ofono_gprs_context_set_ipv4_address(gc, ip, TRUE); /* Static? */
  ofono_gprs_context_set_ipv4_netmask(gc, netmask);
  ofono_gprs_context_set_ipv4_gateway(gc, gateway);
  ofono_gprs_context_set_ipv4_dns_servers(gc, dns);

  gcd->state = STATE_ACTIVE;

  CALLBACK_WITH_SUCCESS(gcd->cb, gcd->cb_data);

  return;

dynamic_ip:
  DBG("Incomplete CGCONTRDP structure, attempting dynamic IP.");
  interface = ofono_modem_get_string(modem, "NetworkInterface1");
  DBG("Interface: %s", interface);
  ofono_gprs_context_set_interface(gc, interface);
  ofono_gprs_context_set_ipv4_address(gc, NULL, FALSE);

  gcd->state = STATE_ACTIVE;

  CALLBACK_WITH_SUCCESS(gcd->cb, gcd->cb_data);
}

static void cint_gprs_detach(struct ofono_gprs_context *gc,
          unsigned int cid)
{
  struct gprs_context_data * gcd = ofono_gprs_context_get_data(gc);
  char buf[32];

  /* Turn off the polling for connection status */
  if (gcd->swwan_source) {
    g_source_remove(gcd->swwan_source);
  }

  if (gcd->modem == CINTERION_LTE) {
    snprintf(buf, sizeof(buf) - 1, "AT^SWWAN=0,%u", cid);
  }
  else {
    snprintf(buf, sizeof(buf) - 1, "AT+CGACT=0,%u", cid);
  }

  g_at_chat_send(gcd->chat, buf, none_prefix, NULL, NULL, NULL);

  gcd->cd.cid = 0;
  gcd->state = STATE_IDLE;

  /* Signal on Dbus that the context is deactivated */
  ofono_gprs_context_deactivated(gc, cid);
}

static void cint_swwan_notify(GAtResult *result, gpointer user_data)
{
  struct ofono_gprs_context *gc = user_data;
  int cid = 0;
  int state = 0;
  GAtResultIter iter;
  static int time_connected = 0;

  DBG("");
  g_at_result_iter_init(&iter, result);
  if (g_at_result_iter_next(&iter, "^SWWAN:")) {
    g_at_result_iter_next_number(&iter, &cid);
    g_at_result_iter_next_number(&iter, &state);
    if (state == 1) {
      struct gprs_context_data * gcd = ofono_gprs_context_get_data(gc);
      time_connected += poll_time;
      gcd->state = STATE_ACTIVE;
    }
    else {
      DBG("Connected time: %d s", time_connected);
      cint_gprs_detach(gc, cid);
      time_connected = 0;
    }
  }
}

static gboolean cint_swwan_query(gpointer user_data)
{
  struct ofono_gprs_context *gc = user_data;
  struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);

  if (gcd->state == STATE_ACTIVE) {
    g_at_chat_send(gcd->chat, "AT^SWWAN?", none_prefix, NULL, NULL, NULL);
    gcd->state = STATE_IDLE;
  }
  else {
    cint_gprs_detach(gc, gcd->cd.cid);
  }

  return TRUE;
}

static void cinterion_swwan(gboolean ok, GAtResult *result, gpointer user_data)
{
  struct ofono_gprs_context *gc = user_data;
  struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
  char buf[32];

  DBG("ok %d", ok);

  if (!ok) {
    struct ofono_error error;

    ofono_info("Cannot establish data connection");

    gcd->cd.cid = 0;
    gcd->state = STATE_IDLE;

    cint_util_decode_at_error(&error, g_at_result_final_response(result));
    gcd->cb(&error, gcd->cb_data);
    return;
  }

  /*
   * NOTE:
   * The AT+CGCONTRDP query is not a required structure for operators to
   * fill out, but we need it for the operators that do.
   */
  snprintf(buf, sizeof(buf) - 1, "AT+CGCONTRDP=%u", gcd->cd.cid);

  g_at_chat_send(gcd->chat, buf, cgcontrdp_prefix,
            cint_cgcontrdp_cb, gc, NULL);

}

static void cinterion_cgact(gboolean ok, GAtResult *result, gpointer user_data)
{
  struct ofono_gprs_context *gc = user_data;
  struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);

  DBG("ok %d", ok);

  if (!ok) {
    struct ofono_error error;

    ofono_info("Cannot establish data connection");

    gcd->cd.cid = 0;
    gcd->state = STATE_IDLE;

    cint_util_decode_at_error(&error, g_at_result_final_response(result));
    gcd->cb(&error, gcd->cb_data);
    return;
  }

  gcd->state = STATE_ACTIVE;

  struct ofono_modem* modem = ofono_gprs_context_get_modem(gc);
  const char *net = ofono_modem_get_string(modem, "NetworkInterface");
  ofono_gprs_context_set_interface(gc, net);
  ofono_gprs_context_set_ipv4_address(gc, NULL, FALSE);

  CALLBACK_WITH_SUCCESS(gcd->cb, gcd->cb_data);
}


static void cinterion_context_deact_cb(gboolean ok, GAtResult *result,
          gpointer user_data)
{
  struct ofono_gprs_context *gc = user_data;
  struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);

  DBG("ok %d", ok);

  if (!ok) {
    struct ofono_error error;

    ofono_info("Error while deactivating data connection");

    gcd->cd.cid = 0;
    gcd->state = STATE_IDLE;

    cint_util_decode_at_error(&error, g_at_result_final_response(result));
    gcd->cb(&error, gcd->cb_data);
    return;
  }

  gcd->cd.cid = 0;
  gcd->state = STATE_IDLE;

  CALLBACK_WITH_SUCCESS(gcd->cb, gcd->cb_data);
}

static int cint_gprs_context_probe(struct ofono_gprs_context *gc,
          unsigned int vendor, void *data)
{
  struct gprs_context_data *gcd = NULL;

  DBG("");

  gcd = g_try_new0(struct gprs_context_data, 1);
  if (gcd == NULL)
    return -ENOMEM;

  gcd->chat = g_at_chat_clone((GAtChat*) data);
  gcd->modem = vendor;
  ofono_gprs_context_set_data(gc, gcd);

  g_at_chat_register(gcd->chat, "^SWWAN:", cint_swwan_notify,
        FALSE, gc, NULL);

  return 0;
}

static void cint_gprs_context_remove(struct ofono_gprs_context *gc)
{
  struct gprs_context_data * gcd = NULL;

  DBG("");

  gcd = ofono_gprs_context_get_data(gc);

  if (gcd->state != STATE_IDLE)
    g_at_chat_resume(gcd->chat);

  ofono_gprs_context_set_data(gc, NULL);

  g_at_chat_unref(gcd->chat);

  g_free(gcd);
}


/* Activate context */
static void activate_primary_3(gboolean success, GAtResult *result,
		gpointer user_data) {
	struct gprs_context_data *gcd;
	gcd = ofono_gprs_context_get_data(user_data);

	DBG("cd.cid = %u", gcd->cd.cid);

	switch (gcd->modem) {
	case CINTERION_LTE: {
		char buf[32];
		snprintf(buf, sizeof(buf) - 1, "AT^SWWAN=1,%u", gcd->cd.cid);
		if (g_at_chat_send(gcd->chat, buf, none_prefix, cinterion_swwan, user_data, NULL)) {
			gcd->swwan_source = g_timeout_add_seconds(poll_time, cint_swwan_query, user_data);
			return;
		}
	}
	break;
	default: {
		char buf[32];
		snprintf(buf, sizeof(buf) - 1, "AT+CGACT=%u,1", gcd->cd.cid);
		if (g_at_chat_send(gcd->chat, buf, none_prefix, cinterion_cgact, user_data, NULL)) {
			return;
		}
	}
	}

	/*
	static void cint_cgdcont_cb(gboolean ok, GAtResult *result, gpointer user_data)
	{
	  struct ofono_gprs_context *gc = user_data;
	  struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);

	  DBG("ok %d", ok);

	  if (!ok) {
	    struct ofono_error error;

	    ofono_info("Error while configuring APN");

   return;
	  }

	  CALLBACK_WITH_SUCCESS(gcd->cb, gcd->cb_data);
	}
*/
	CALLBACK_WITH_FAILURE(gcd->cb, gcd->cb_data);
}

/* set credentials */
static void activate_primary_2(gboolean success, GAtResult *result,
		gpointer user_data) {
	struct gprs_context_data *gcd;
  struct ofono_error error;

  DBG("success = %d", success);
	gcd = ofono_gprs_context_get_data(user_data);
	if (success) { // ready to continue
		char buf[OFONO_GPRS_MAX_USERNAME_LENGTH+OFONO_GPRS_MAX_PASSWORD_LENGTH+32];

		snprintf(buf, sizeof(buf) - 1, "AT^SGAUTH=%u,1,\"%s\",\"%s\"", gcd->cd.cid, gcd->cd.password, gcd->cd.username);
		if (g_at_chat_send(gcd->chat, buf, none_prefix, activate_primary_3, user_data, NULL) > 0) {
			DBG("Sent SGAUTH, cd.cid=%d", gcd->cd.cid);
			return;
		}
		DBG("Didn't send SGAUTH");
		CALLBACK_WITH_FAILURE(gcd->cb, gcd->cb_data);
		gcd->cd.cid = 0;
	  gcd->state = STATE_IDLE;
	  return;
	}

	gcd->cd.cid = 0;
  gcd->state = STATE_IDLE;

  ofono_info("Error while configuring APN");
  cint_util_decode_at_error(&error, g_at_result_final_response(result));
  gcd->cb(&error, gcd->cb_data);
}

/*
 *  1. create context : AT+CGDCON <IP>
 *  2. set credentials : AT^SGAUTH
 *  3. activate : AT^SWWAN
 */
static void cint_gprs_activate_primary(struct ofono_gprs_context *gc,
		const struct ofono_gprs_primary_context *ctx,
		ofono_gprs_context_cb_t cb, void *data)
{
	struct gprs_context_data * gcd = NULL;

	gcd = ofono_gprs_context_get_data(gc);

	/* Require apn and credentials to continue */
	if (ctx->apn      && strlen(ctx->apn) &&
			ctx->username && strlen(ctx->username) &&
			ctx->password && strlen(ctx->password)) {
		char buf[OFONO_GPRS_MAX_APN_LENGTH + 32];

		gcd->cb = cb;
		gcd->cb_data = data;
		gcd->cd = *ctx;
		/* FIXME remove
		gcd->cd.cid = ctx->cid;
		memcpy(&gcd->cd, ctx, sizeof(gcd->cd));
		memcpy(gcd->cd.apn,      ctx->apn,      sizeof(ctx->apn));
		memcpy(gcd->cd.username, ctx->username, sizeof(ctx->username));
		memcpy(gcd->cd.password, ctx->password, sizeof(ctx->password));
		 */
		DBG("cid %u: %s, %s, %s", gcd->cd.cid, gcd->cd.apn, gcd->cd.username, gcd->cd.password);

		snprintf(buf, sizeof(buf) - 1,
				"AT+CGDCONT=%u,\"IP\",\"%s\"", gcd->cd.cid, gcd->cd.apn);
		if (g_at_chat_send(gcd->chat, buf, none_prefix,
				activate_primary_2, gc, NULL) > 0)
			return;
	}

	// FIXME prepare failure reason
	DBG("Error exit");
	CALLBACK_WITH_FAILURE(cb, data);
}

static void cint_gprs_deactivate_primary(struct ofono_gprs_context *gc,
          unsigned int cid,
          ofono_gprs_context_cb_t cb, void *data)
{
  struct gprs_context_data * gcd = NULL;
  char buf[32];

  DBG("cid %u", cid);

  gcd = ofono_gprs_context_get_data(gc);
  gcd->state = STATE_DEACTIVATING;
  gcd->cb = cb;
  gcd->cb_data = data;

  /* FIXME
   * A special form of the write command (AT+CGDCONT=<cid>) causes the values for context
<cid> to become undefined
   *  {
      gcd->state = STATE_IDLE;
      snprintf(buf, sizeof(buf) - 1, "AT+CGDCONT=%u", cid);
    }
   */

  if (gcd->modem == CINTERION_LTE) {
    snprintf(buf, sizeof(buf) - 1, "AT^SWWAN=0,%u", cid);
  }
  else {
    snprintf(buf, sizeof(buf) - 1, "AT+CGACT=0,%u", cid);
  }

  if (g_at_chat_send(gcd->chat, buf, none_prefix, cinterion_context_deact_cb, gc, NULL) > 0) {
    return;
  }

  CALLBACK_WITH_FAILURE(cb, data);
}

static void cint_gprs_detach_shutdown(struct ofono_gprs_context *gc,
          unsigned int cid)

{
  struct gprs_context_data * gcd = NULL;
  char buf[32];

  DBG("cid %u", cid);

  gcd = ofono_gprs_context_get_data(gc);

  if (gcd->modem == CINTERION_LTE) {
    snprintf(buf, sizeof(buf) - 1, "AT^SWWAN=0,%u", cid);
  }
  else {
    snprintf(buf, sizeof(buf) - 1, "AT+CGACT=0,%u", cid);
  }

  g_at_chat_send(gcd->chat, buf, none_prefix, NULL, NULL, NULL);
}

static struct ofono_gprs_context_driver driver = {
	.name      = "cinterionmodem",
  .probe      = cint_gprs_context_probe,
  .remove      = cint_gprs_context_remove,
  .activate_primary  = cint_gprs_activate_primary,
  .deactivate_primary  = cint_gprs_deactivate_primary,
  .detach_shutdown  = cint_gprs_detach_shutdown,
};

void cint_gprs_context_init(void)
{
  ofono_gprs_context_driver_register(&driver);
}

void cint_gprs_context_exit(void)
{
  ofono_gprs_context_driver_unregister(&driver);
}
