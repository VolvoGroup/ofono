
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>
#include <gatchat.h>

#define OFONO_API_SUBJECT_TO_CHANGE
#include <ofono/plugin.h>
#include <ofono/types.h>

#include "cinterionmodem.h"

static int cint_init(void)
{
	cint_devinfo_init();
	cint_sim_init();
	cint_voicecall_init();
	cint_sms_init();
	cint_gprs_init();
	cint_gprs_context_init();
	cint_netreg_init();
	cint_cbs_init();

	return 0;
}

static void cint_exit(void)
{
	cint_devinfo_exit();
	cint_sim_exit();
	cint_voicecall_exit();
	cint_sms_exit();
	cint_gprs_exit();
	cint_gprs_context_exit();
	cint_netreg_exit();
	cint_cbs_exit();
}

OFONO_PLUGIN_DEFINE(cinterionmodem, "Cinterion modem driver", VERSION,
			OFONO_PLUGIN_PRIORITY_DEFAULT,
			cint_init, cint_exit)
