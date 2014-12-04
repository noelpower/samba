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

#ifndef __WSP_SRV_TRACKER_SPARQL__
#define __WSP_SRV_TRACKER_SPARQL__
#include "bin/default/librpc/gen_ndr/ndr_wsp.h"
#include "tevent.h"

struct tracker_query_info;
struct connection_struct;
struct auth_session_info;

#define TRACKER_NULL    ( 0x00000000 )
#define TRACKER_STRING  ( 0x00000001 )
#define TRACKER_INTEGER ( 0x00000002 )
#define TRACKER_BOOLEAN ( 0x00000003 )
#define TRACKER_DOUBLE  ( 0x00000004 )

union tracker_type {
	const char * string;
	uint64_t integer;
	uint16_t boolean;
	uint64_t double_val;
};

struct tracker_col_data {
	uint8_t tracker_type;
	union tracker_type type;
};

struct tracker_row {
	struct tracker_row *prev, *next;
	uint32_t ncols;
	struct tracker_col_data *columns;
};

struct tracker_getrowsout {
	uint32_t nrows;
	uint32_t nrows_remaining;
	struct tracker_row *rows;
};

struct tracker_row_list
{
	int nrows;
	struct tracker_row_data *items;
};

enum sparql_server_query_state
{
	IDLE,
	QUERY_ERROR,
	QUERY_IN_PROGRESS,
	QUERY_COMPLETE,
};

struct sparql_ctx *init_sparql(struct tevent_context *event_ctx);

struct tevent_req *glib_tracker_query_status(TALLOC_CTX *ctx,
					     struct tracker_query_info* query_ctx,
					     uint32_t *status, uint32_t *nrows);

struct tevent_req *glib_tracker_getstate(TALLOC_CTX *ctx,
					 struct sparql_ctx *sparql_ctx,
					 struct wsp_cpmcistateinout *out);


struct tevent_req *glib_tracker_getrows(TALLOC_CTX *ctx,
					struct sparql_ctx* sparql_ctx,
					struct tracker_query_info* query_ctx,
					uint32_t index,
					uint32_t nrows,
					bool reverse_fetch,
					struct tracker_getrowsout *rowsout);

struct tevent_req *glib_tracker_new_query(TALLOC_CTX *ctx,
					  struct sparql_ctx* sparql_ctx,
					  uint32_t queryid,
					  const char *query,
					  bool cache_results,
					  uint32_t results_limit,
					  struct connection_struct *conn,
					  struct auth_session_info *session_info,
					  struct tracker_query_info** query_ctx);

bool can_access_workid(struct tracker_query_info* query_ctx, uint32_t workid);
#endif
