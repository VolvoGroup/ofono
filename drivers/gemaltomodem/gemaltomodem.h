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

#include <drivers/atmodem/atutil.h>
#include <ofono/gemalto.h>
#include "gemaltoutil.h"

extern void gemalto_location_reporting_init();
extern void gemalto_location_reporting_exit();

extern void gemalto_voicecall_init();
extern void gemalto_voicecall_exit();

extern void gemalto_lte_init();
extern void gemalto_lte_exit();

extern void gemalto_gprs_context_swwan_blocking_init();
extern void gemalto_gprs_context_swwan_blocking_exit();

extern void gemalto_gprs_context_swwan_init();
extern void gemalto_gprs_context_swwan_exit();

extern void gemalto_gprs_context_mbim_init();
extern void gemalto_gprs_context_mbim_exit();
