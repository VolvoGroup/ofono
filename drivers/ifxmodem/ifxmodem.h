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

#include <drivers/atmodem/atutil.h>
#include <drivers/atmodem/vendor.h>

extern void ifx_voicecall_init(void);
extern void ifx_voicecall_exit(void);

extern void ifx_audio_settings_init(void);
extern void ifx_audio_settings_exit(void);

extern void ifx_radio_settings_init(void);
extern void ifx_radio_settings_exit(void);

extern void ifx_gprs_context_init(void);
extern void ifx_gprs_context_exit(void);

extern void ifx_stk_init(void);
extern void ifx_stk_exit(void);

extern void ifx_ctm_init(void);
extern void ifx_ctm_exit(void);