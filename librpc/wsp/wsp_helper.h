/*
 *  Unix SMB/CIFS implementation.
 *
 *  Window Search Service
 *
 *  Copyright (c)  2016 Noel Power
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __LIBRPC_WSP_HELPER_H__
#define __LIBRPC_WSP_HELPER_H__

struct safearraybound;
struct wsp_hyper;

uint32_t calc_array_size(struct safearraybound *bounds, uint32_t ndims);
void uint64_to_wsp_hyper(uint64_t src, struct wsp_hyper *dest);
void wsp_hyper_to_uint64(struct wsp_hyper *src, uint64_t *dest);

#endif // __LIBRPC_WSP_HELPER_H__
