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

#ifndef __WSP_SPARQL_CONV_H__
#include "bin/default/librpc/gen_ndr/ndr_wsp.h"

struct wsp_abstract_state;
struct connection_struct;
struct auth_session_info;
struct tracker_row;
/*
 * per row data, like mangled path name for row enty
 * to avoid recalculating that every time
 */
struct row_conv_data
{
	struct connection_struct *conn;
	const char *tracker_row_url; /* url from tracker */
	/* url with segments after the netbios name mangled if nesessary */
	const char *row_relative_share_path;
};

struct tracker_selected_cols
{
	int cols;
	const char **tracker_ids;
};

typedef NTSTATUS (*tracker_to_wsp_fn)(TALLOC_CTX *ctx,
			   struct wsp_cbasestoragevariant *out_val,
			   uint32_t vtype, /* wsp col type */
			   int type, /*TrackerSparqlValueType*/
			   void *tracker_val,
			   void *private_data);
struct map_data
{
	uint32_t col_with_value;
	uint32_t vtype;
	tracker_to_wsp_fn convert_fn;
};

struct binding_result_mapper
{
	uint32_t ncols;
	struct map_data *map_data;
};

bool build_mapper(TALLOC_CTX *ctx, struct wsp_ctablecolumn *columns,
		  uint32_t ncols, struct tracker_selected_cols *tracker_cols,
		  struct binding_result_mapper *mapper);

NTSTATUS build_tracker_query(TALLOC_CTX *ctx,
			     struct wsp_ccolumnset *select_cols,
			     const char* restriction_expr,
			     struct wsp_cpidmapper *pidmapper,
			     struct tracker_selected_cols *tracker_cols,
			     struct wsp_csortset *sorting,
			     bool convert_props,
			     const char **query);


bool lookup_where_id(struct wsp_abstract_state *glob_data, uint32_t where_id,
		     const char **filter_out, const char **share_out);

NTSTATUS build_restriction_expression(TALLOC_CTX *ctx,
				      struct wsp_abstract_state *glob_data,
				      struct wsp_crestrictionarray *restrictions,
				      bool convert_props,
				      const char **restrict_expr,
				      const char **share_scope,
				      uint32_t *where_id
				      );

void filter_tracker_rows(struct tracker_row **rows,
			 struct connection_struct *conn,
			 struct auth_session_info *session_info,
			 uint32_t rows_limit,
			 uint32_t *num_removed);

bool
can_access_url(struct connection_struct *conn, const char* url);
#endif /*__WSP_SPARQL_CONV_H__*/
