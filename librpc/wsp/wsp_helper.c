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
#include "includes.h"
#include "librpc/wsp/wsp_helper.h"
#include "bin/default/librpc/gen_ndr/ndr_wsp.h"

void uint64_to_wsp_hyper(uint64_t src, struct wsp_hyper *dest)
{
	dest->hi = (uint32_t)src;
	dest->lo = (uint32_t)(src>>32);
}

void wsp_hyper_to_uint64(struct wsp_hyper *src, uint64_t *dest)
{
	*dest = src->lo;
	*dest <<= 32;
	*dest |= src->hi;
}

uint32_t calc_array_size(struct safearraybound *bounds, uint32_t ndims)
{
	int i;
	int result = 0;

	for(i = 0; i < ndims; i++) {
		uint32_t celements = bounds[i].celements;
		if (i) {
			result = result * celements;
		} else {
			result = celements;
		}
	}
	return result;
}
