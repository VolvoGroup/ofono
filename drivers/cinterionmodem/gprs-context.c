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

struct cint_gprs_context_data {
  GAtChat *chat;
  unsigned int modem;
  enum state state;
  unsigned int active_context;
  char username[OFONO_GPRS_MAX_USERNAME_LENGTH + 1];
  char password[OFONO_GPRS_MAX_PASSWORD_LENGTH + 1];
  ofono_gprs_context_cb_t cb;
  void *cb_data;                                  /* Callback data */
};

static void cint_cgcontrdp_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
  struct ofono_gprs_context *gc = user_data;
  struct cint_gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
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

static void cinterion_swwan(gboolean ok, GAtResult *result, gpointer user_data)
{
  struct ofono_gprs_context *gc = user_data;
  struct cint_gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
  char buf[32];

  DBG("ok %d", ok);

  if (!ok) {
    struct ofono_error error;

    ofono_info("Cannot establish data connection");

    gcd->active_context = 0;
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
  snprintf(buf, sizeof(buf) - 1, "AT+CGCONTRDP=%u", gcd->active_context);

  g_at_chat_send(gcd->chat, buf, cgcontrdp_prefix,
            cint_cgcontrdp_cb, gc, NULL);

}

static void cinterion_cgact(gboolean ok, GAtResult *result, gpointer user_data)
{
  struct ofono_gprs_context *gc = user_data;
  struct cint_gprs_context_data *gcd = ofono_gprs_context_get_data(gc);

  DBG("ok %d", ok);

  if (!ok) {
    struct ofono_error error;

    ofono_info("Cannot establish data connection");

    gcd->active_context = 0;
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

static void cint_cgdcont_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
  struct ofono_gprs_context *gc = user_data;
  struct cint_gprs_context_data *gcd = ofono_gprs_context_get_data(gc);

  DBG("ok %d", ok);

  if (!ok) {
    struct ofono_error error;

    ofono_info("Error while configuring APN");

    gcd->active_context = 0;
    gcd->state = STATE_IDLE;

    cint_util_decode_at_error(&error, g_at_result_final_response(result));
    gcd->cb(&error, gcd->cb_data);
    return;
  }

  CALLBACK_WITH_SUCCESS(gcd->cb, gcd->cb_data);
}

static void cinterion_context_deact_cb(gboolean ok, GAtResult *result,
          gpointer user_data)
{
  struct ofono_gprs_context *gc = user_data;
  struct cint_gprs_context_data *gcd = ofono_gprs_context_get_data(gc);

  DBG("ok %d", ok);

  if (!ok) {
    struct ofono_error error;

    ofono_info("Error while deactivating data connection");

    gcd->active_context = 0;
    gcd->state = STATE_IDLE;

    cint_util_decode_at_error(&error, g_at_result_final_response(result));
    gcd->cb(&error, gcd->cb_data);
    return;
  }

  gcd->active_context = 0;
  gcd->state = STATE_IDLE;

  CALLBACK_WITH_SUCCESS(gcd->cb, gcd->cb_data);
}

static int cint_gprs_context_probe(struct ofono_gprs_context *gc,
          unsigned int vendor, void *data)
{
  struct cint_gprs_context_data *gcd = NULL;

  DBG("");

  gcd = g_try_new0(struct cint_gprs_context_data, 1);
  if (gcd == NULL)
    return -ENOMEM;

  gcd->chat = g_at_chat_clone((GAtChat*) data);
  gcd->modem = vendor;
  ofono_gprs_context_set_data(gc, gcd);

  /*if (getenv("OFONO_AT_DEBUG"))
    g_at_chat_set_debug(gcd->chat, cinterion_gprs_debug, "Modem: ");*/


  return 0;
}

static void cint_gprs_context_remove(struct ofono_gprs_context *gc)
{
  struct cint_gprs_context_data * gcd = NULL;

  DBG("");

  gcd = ofono_gprs_context_get_data(gc);

  if (gcd->state != STATE_IDLE)
    g_at_chat_resume(gcd->chat);

  ofono_gprs_context_set_data(gc, NULL);

  g_at_chat_unref(gcd->chat);

  g_free(gcd);
}

static void cint_gprs_set_apn(struct ofono_gprs_context *gc,
        unsigned int cid, const char* apn,
        ofono_gprs_context_cb_t cb, void *data)
{
  struct cint_gprs_context_data * gcd = NULL;
  char buf[OFONO_GPRS_MAX_APN_LENGTH + 32];

  gcd = ofono_gprs_context_get_data(gc);

  gcd->cb = cb;
  gcd->cb_data = data;

  if (apn) {
    gcd->state = STATE_SET_APN;
    snprintf(buf, sizeof(buf) - 1,
        "AT+CGDCONT=%u,\"IP\",\"%s\"", cid, apn);
  }
  else {
    gcd->state = STATE_IDLE;
    snprintf(buf, sizeof(buf) - 1, "AT+CGDCONT=%u", cid);
  }

  if (g_at_chat_send(gcd->chat, buf, none_prefix,
        cint_cgdcont_cb, gc, NULL) > 0)
    return;

  CALLBACK_WITH_FAILURE(cb, data);
}

static void cint_gprs_activate_primary(struct ofono_gprs_context *gc,
        const struct ofono_gprs_primary_context *ctx,
        ofono_gprs_context_cb_t cb, void *data)
{
  struct cint_gprs_context_data * gcd = NULL;
  char buf[64];

  DBG("cid %u", ctx->cid);

  gcd = ofono_gprs_context_get_data(gc);

  gcd->active_context = ctx->cid;
  gcd->cb = cb;
  gcd->cb_data = data;
  memcpy(gcd->username, ctx->username, sizeof(ctx->username));
  memcpy(gcd->password, ctx->password, sizeof(ctx->password));

  /* Add authentication step */
  snprintf(buf, sizeof(buf) - 1, "AT^SGAUTH=%u,1,\"%s\",\"%s\"", ctx->cid, ctx->password, ctx->username);
  if (g_at_chat_send(gcd->chat, buf, none_prefix, NULL, NULL, NULL) == 0) {
    return;
  }

  if (gcd->state == STATE_SET_APN) {
    if (gcd->modem == CINTERION_ALS3) {
      snprintf(buf, sizeof(buf) - 1, "AT^SWWAN=1,%u,1", ctx->cid);
      if (g_at_chat_send(gcd->chat, buf, none_prefix, cinterion_swwan, gc, NULL)) {
        return;
      }
    }
    else {
      snprintf(buf, sizeof(buf) - 1, "AT+CGACT=%u,1", ctx->cid);
      if (g_at_chat_send(gcd->chat, buf, none_prefix, cinterion_cgact, gc, NULL)) {
        return;
      }
    }
  }

  gcd->active_context = 0;
  gcd->state = STATE_IDLE;

  CALLBACK_WITH_FAILURE(cb, data);
}

static void cint_gprs_deactivate_primary(struct ofono_gprs_context *gc,
          unsigned int cid,
          ofono_gprs_context_cb_t cb, void *data)
{
  struct cint_gprs_context_data * gcd = NULL;
  char buf[32];

  DBG("cid %u", cid);

  gcd = ofono_gprs_context_get_data(gc);
  gcd->state = STATE_DEACTIVATING;
  gcd->cb = cb;
  gcd->cb_data = data;

  if (gcd->modem == CINTERION_ALS3) {
    snprintf(buf, sizeof(buf) - 1, "AT^SWWAN=0,%u,1", cid);
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
  struct cint_gprs_context_data * gcd = NULL;
  char buf[32];

  DBG("cid %u", cid);

  gcd = ofono_gprs_context_get_data(gc);

  if (gcd->modem == CINTERION_ALS3) {
    snprintf(buf, sizeof(buf) - 1, "AT^SWWAN=0,%u,1", cid);
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
  .set_apn    = cint_gprs_set_apn,
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
