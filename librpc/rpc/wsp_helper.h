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
struct wsp_cfullpropspec;
struct wsp_cpmgetrowsin;
struct wsp_cpmgetrowsout;
struct wsp_cpmsetbindingsin;
struct wsp_hyper;

uint32_t calc_array_size(struct safearraybound *bounds, uint32_t ndims);

struct full_propset_info {
	uint32_t id;
	const char *name;
	uint16_t vtype;
	bool extra_info;
	bool in_inverted_index;
	bool is_column;
	bool can_col_be_indexed;
	uint16_t max_size;
};
char *prop_from_fullprop(TALLOC_CTX *ctx, struct wsp_cfullpropspec *fullprop);
const struct full_propset_info *get_prop_info(const char *prop_name);
const char * get_vtype_name(uint32_t type);
bool is_variable_size(uint16_t vtype);
void uint64_to_wsp_hyper(uint64_t src, struct wsp_hyper *dest);
void wsp_hyper_to_uint64(struct wsp_hyper *src, uint64_t *dest);
const char *get_store_status(uint8_t status_byte);
#endif // __LIBRPC_WSP_HELPER_H__
