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

#include "wsp_srv_tracker-sparql.h"
#include "bin/default/librpc/gen_ndr/ndr_wsp.h"
#include "util/tevent_ntstatus.h"
#include "util/samba_util.h"

#include "talloc.h"
#include "tevent/tevent_util.h"
#include "util/talloc_stack.h"
#include "util/debug.h"
#include "wsp_sparql_conv.h"

#undef TRUE
#undef FALSE
#include <glib.h>
#include <libtracker-sparql/tracker-sparql.h>
#include "lib/tevent_glib_glue.h"
struct sparql_ctx;

struct tracker_query_info
{
	enum sparql_server_query_state state;
	int query_id;
	GTimer *timer;
	struct sparql_ctx *sparq_ctx;
	GCancellable *cancellable;
	TrackerSparqlCursor *cur_cursor;
	struct tracker_row *row_cursor;
	uint32_t cur_index;
	uint32_t num_rows;
	uint32_t num_cols;
	uint32_t results_limit;
	bool cache_results;
	struct connection_struct *conn;
	struct auth_session_info *session_info;
	struct tracker_row *rows;
};

struct tracker_connect_info {
	TrackerSparqlConnection *connection;
	GTimer *timer;
	GCancellable *cancellable;
	struct sparql_ctx *sparql_ctx;
};

struct sparql_ctx
{
	struct tracker_connect_info *conn;

	int nqueries;
	struct tevent_context *event_ctx;
	struct tevent_glib_glue *glue;
};

struct query_state
{
	struct tracker_query_info *query;
	struct tevent_req *req;
	struct tevent_context *event_ctx;
	GCancellable *cancellable;
};

#if ASYNC_CONNECTION
static void
connection_cb(GObject      *object,
	      GAsyncResult *res,
	      gpointer      user_data)
{
	struct tracker_connect_info *conn = user_data;
	GError *error = NULL;

	conn->connection = tracker_sparql_connection_get_direct_finish(res,
								       &error);
	if (error) {
		DBG_ERR("Unexpected error getting connection %s\n",
		      error->message);
		goto out;
	}
	DBG_NOTICE("Async connection took: %.6f\n", g_timer_elapsed (conn->timer, NULL));

	if (!conn->connection) {
		DBG_ERR("Async connection error, %s\n",
			  error ? error->message : "Unknown error");
		/*
		 * #FIXME send an error back to server/parent
		 * to do that we need to tie the connectection to some
		 * existing request from the client (maybe some lazy
		 * initialisation that is triggered from *any* client message)
		 */
		goto out;
	}
out:
	if (error) {
		g_error_free(error);
	}
	if (conn->cancellable) {
		g_clear_object(&conn->cancellable);
	}
	if (conn->timer) {
		g_timer_destroy (conn->timer);
	}
	TALLOC_FREE(conn);
}
#endif

static uint8_t get_tracker_col_type(TrackerSparqlValueType type)
{
	uint8_t result;
	switch(type)
	{
		case TRACKER_SPARQL_VALUE_TYPE_URI:
		case TRACKER_SPARQL_VALUE_TYPE_STRING:
		case TRACKER_SPARQL_VALUE_TYPE_DATETIME:
			result = TRACKER_STRING;
			break;
		case TRACKER_SPARQL_VALUE_TYPE_INTEGER:
			result = TRACKER_INTEGER;
			break;
		case TRACKER_SPARQL_VALUE_TYPE_DOUBLE:
			result = TRACKER_DOUBLE;
			break;
		case TRACKER_SPARQL_VALUE_TYPE_BOOLEAN:
			result = TRACKER_BOOLEAN;
			break;
		case TRACKER_SPARQL_VALUE_TYPE_UNBOUND:
		case TRACKER_SPARQL_VALUE_TYPE_BLANK_NODE:
		default:
			result = TRACKER_NULL;
			break;
	}
	return result;
}

static void create_tracker_col_data(TALLOC_CTX *ctx,
				    TrackerSparqlCursor *cursor,
				    int col,
				    struct tracker_col_data *result)
{
	const char *tracker_str;
	char *escaped = NULL;
	TrackerSparqlValueType type =
			tracker_sparql_cursor_get_value_type(cursor, col);
	result->tracker_type = get_tracker_col_type(type);
	switch (type)
	{
		case TRACKER_SPARQL_VALUE_TYPE_URI:
		case TRACKER_SPARQL_VALUE_TYPE_STRING:
		case TRACKER_SPARQL_VALUE_TYPE_DATETIME:
			tracker_str = tracker_sparql_cursor_get_string(cursor,
								      col,
								      NULL);
			/*
			 * #TODO #FIXME we should escape further up the chain
			 *  and not here. e.g. we could unintentionally
			 *  unescape normal valid characters in a literal
			 *  string here.
			 *  Instead we should unescape in the handlers for
			 *  properties that we know contain a 'real' url.
			 */
			if (type == TRACKER_SPARQL_VALUE_TYPE_STRING) {
				escaped = g_uri_unescape_string(tracker_str,
								NULL);
				result->type.string = talloc_strdup(ctx,
								    escaped);
			} else {
				result->type.string =
					talloc_strdup(ctx, tracker_str);
			}
			if (escaped) {
				g_free(escaped);
			}
			break;
		case TRACKER_SPARQL_VALUE_TYPE_INTEGER:
			result->type.integer =
				tracker_sparql_cursor_get_integer(cursor, col);
			break;
		case TRACKER_SPARQL_VALUE_TYPE_DOUBLE:
			result->type.double_val =
				tracker_sparql_cursor_get_double(cursor, col);
			break;
		case TRACKER_SPARQL_VALUE_TYPE_BOOLEAN:
			result->type.boolean =
				tracker_sparql_cursor_get_boolean(cursor, col);
			break;
		case TRACKER_SPARQL_VALUE_TYPE_UNBOUND:
		case TRACKER_SPARQL_VALUE_TYPE_BLANK_NODE:
		default:
			break;
	}
}


static int destroy_query(struct tracker_query_info *query)
{
	g_timer_destroy (query->timer);
	if (query->cancellable) {
		/*
		 * query->cancellable is used for not just the query but
		 * any cursor iteration associated with the query
		 * If we get here we are in the middle of some async
		 * operation so we should signal that that operation to
		 * cancel. We don't unref the cancel object here, that needs
		 * to be done when the async operation finished
		 */
		g_cancellable_cancel(query->cancellable);
	}
	if (query->cur_cursor) {
		g_object_unref(query->cur_cursor);
	}
	query->sparq_ctx->nqueries--;
	return 0;
}

static void rewind_cursor_fully(struct tracker_query_info *query)
{
	tracker_sparql_cursor_rewind(query->cur_cursor);
	query->cur_index = 0;
	query->row_cursor = query->rows;
}

static void
filter_rows(struct tracker_query_info *query)
{
	filter_tracker_rows(&query->rows,
			    query->conn,
			    query->session_info,
			    query->results_limit,
			    &query->num_rows);
}

static void
cursor_cb(GObject *object, GAsyncResult *res, gpointer user_data)
{
	GError *error = NULL;
	gboolean more_results;
	TrackerSparqlCursor *cursor;
	struct tracker_query_info *query_info;
	struct query_state *state = talloc_get_type_abort(user_data,
							  struct query_state);

	cursor = TRACKER_SPARQL_CURSOR(object);
	more_results = tracker_sparql_cursor_next_finish(cursor,
							 res,
							 &error);
	if (error) {
		DBG_ERR("Could not run cursor next: %s", error->message);
		g_error_free (error);
		/*
		 * We should only get a cancel from a query that is
		 * being torn down/deleted thus the query object
		 * itself will not exist and should not be dereferenced.
		 * For an ordinary error we can clear the cancellable
		 * of the query object
		 */
		if (state->cancellable) {
			if (!g_cancellable_is_cancelled(state->cancellable)) {
				state->query->cancellable = NULL;
			}
			g_clear_object(&state->cancellable);
		}
		tevent_req_nterror(state->req, NT_STATUS_UNSUCCESSFUL);
		return;

	}

	query_info = state->query;
	query_info->cur_cursor = TRACKER_SPARQL_CURSOR (object);
	if (query_info->num_cols == 0) {
		query_info->num_cols =
			tracker_sparql_cursor_get_n_columns(query_info->cur_cursor);
	}
	DEBUG(0,("more_results %d limit %d %d\n", more_results, query_info->results_limit, !(query_info->results_limit && query_info->num_rows >= query_info->results_limit)));
	if (more_results &&
	    !(query_info->cache_results == false && query_info->results_limit &&
	      query_info->num_rows >= query_info->results_limit)) {
		if (query_info->cache_results) {
			struct tracker_row *row;
			int i;
			row = talloc_zero(query_info,
					  struct tracker_row);
			row->columns = talloc_zero_array(row,
						 struct tracker_col_data,
						 query_info->num_cols + 1);
			row->ncols = query_info->num_cols + 1;
			query_info->cur_index = query_info->num_rows;
			for (i = 0; i < query_info->num_cols; i++) {
				struct tracker_col_data *col =
					&row->columns[i];
				create_tracker_col_data(row, cursor, i, col);
			}
			DLIST_ADD_END(query_info->rows, row);
		}
		query_info->num_rows++;
		tracker_sparql_cursor_next_async(query_info->cur_cursor,
						 query_info->cancellable,
						 cursor_cb,
						 user_data);
		return;
	}
	if (query_info->cache_results) {
		/* we need to acl filter the results */
		filter_rows(query_info);
	}
	query_info->state = QUERY_COMPLETE;
	DBG_NOTICE("\nAsync cursor next took: %.6f (for all results %d rows for "
		  "tracker query %d)\n",
		   g_timer_elapsed(query_info->timer, NULL),
		   query_info->num_rows, query_info->query_id);
	if (query_info->num_rows) {
		rewind_cursor_fully(query_info);
	}
	state->query->cancellable = NULL;
	if (state->cancellable) {
		g_clear_object(&state->cancellable);
	}
	tevent_req_done(state->req);
}

static void
query_cb(GObject *object, GAsyncResult *res, gpointer user_data)
{
	TrackerSparqlCursor *cursor;
	GError *error = NULL;
	struct tracker_query_info *query;
	struct query_state *state = talloc_get_type_abort(user_data,
							  struct query_state);

	cursor =
		tracker_sparql_connection_query_finish(
			TRACKER_SPARQL_CONNECTION (object),
			res,
			&error);
	if (error) {
		DBG_ERR("Could not run query: %s", error->message);

		g_error_free (error);
		/*
		 * we can't deference the query info, it's possible that
		 * that we have gotten here as a result of the query
		 * being cancelled
		 */
		tevent_req_nterror(state->req, NT_STATUS_UNSUCCESSFUL);
		return;
	}

	query = state->query;

	DBG_NOTICE("Async query took: %.6f\n", g_timer_elapsed(query->timer,
							      NULL));

	g_timer_start(query->timer);

	query->cur_cursor = cursor;
	tracker_sparql_cursor_next_async(cursor,
					 query->cancellable,
					 cursor_cb,
					 user_data);
}

#if FOR_DEBUG
static void dump_val(struct tracker_col_data *col)
{
	switch(col->tracker_type) {
		case TRACKER_STRING:
			DBG_DEBUG("tracker_string %s\n", col->type.string);
			break;
		case TRACKER_INTEGER:
			DBG_DEBUG("tracker_int %lu\n", col->type.integer);
			break;
		case TRACKER_BOOLEAN:
			DBG_DEBUG("tracker_boolean %d\n", col->type.boolean);
			break;
		case TRACKER_DOUBLE:
			DBG_DEBUG("tracker_double %f\n",
				 (double)col->type.double_val);
			break;
		default:
			DBG_DEBUG("tracker unknown type %d\n",
				 col->tracker_type);
			break;
	}
}
#endif


struct dummy_get_rows_state
{
};

static void mov_cursor_fwd(struct tracker_query_info* query, uint32_t new_pos)
{
	struct tracker_row *row_cursor = query->row_cursor;
	while (row_cursor && query->cur_index < new_pos) {
		row_cursor = row_cursor->next;
		query->cur_index++;
		query->row_cursor = row_cursor;
	}
}

struct stats_state
{
	struct wsp_cpmcistateinout *cistateinout;
	struct tevent_req *req;
	struct sparql_ctx *sparq_ctx;
	GCancellable *cancellable;
};

static void stats_cursor_cb(GObject *object, GAsyncResult *res,
			    gpointer user_data)
{
	TrackerSparqlCursor *cursor;
	GError *error = NULL;
	gboolean more_results;
	struct stats_state *state = talloc_get_type_abort(user_data,
							  struct stats_state);

	cursor = TRACKER_SPARQL_CURSOR (object);
	more_results = tracker_sparql_cursor_next_finish(cursor,
							 res,
							 &error);

	if (error) {
		DBG_ERR("got error iterating statistics cursor, error %s\n",
		      error->message);
		g_error_free(error);
		/* #FIXME not the common shared query_info cancellable */
		if (state->cancellable) {
			g_cancellable_cancel(state->cancellable);
			g_object_unref(state->cancellable);
		}
		tevent_req_nterror(state->req, NT_STATUS_UNSUCCESSFUL);
		return;
	}

	if (more_results) {
		if (strequal(tracker_sparql_cursor_get_string (cursor, 0, NULL),
		     "nie:InformationElement")) {
			state->cistateinout->cwordlist =
			tracker_sparql_cursor_get_integer(cursor, 1);
		} else {
			tracker_sparql_cursor_next_async(cursor,
						 state->cancellable,
						 stats_cursor_cb,
						 state);
			return;
		}
	}
	//state->cistateinout->cpersistentindex = ?;
	state->cistateinout->cqueries = state->sparq_ctx->nqueries;

	//out->cfreshtest = ?;
	/* not sure if this is a good default */
	state->cistateinout->dwmergeprogress = 100;
	state->cistateinout->estate = 0;
	state->cistateinout->cfiltereddocuments =
					state->cistateinout->cwordlist;
	state->cistateinout->ctotaldocuments =
					state->cistateinout->cwordlist;
	//state->cistateinout->cpendingscans = ?;
	//state->cistateinout->dwindexsize = ?;
	//state->cistateinout->cuniquekeys = ?;
	//state->cistateinout->csecqdocuments = ?;
	//state->cistateinout->dwpropcachesize = ?;
	if (cursor) {
		g_object_unref (cursor);
	}
	/* #FIXME not the common query_info share cancellable */
	if (state->cancellable) {
		g_cancellable_cancel(state->cancellable);
		g_object_unref(state->cancellable);
	}

	tevent_req_done(state->req);
}

static void statistics_cb(GObject *object, GAsyncResult *res,
			  gpointer user_data)
{
	GError *error = NULL;
	TrackerSparqlCursor *cursor;
	struct stats_state *state = talloc_get_type_abort(user_data,
							  struct stats_state);
	cursor = tracker_sparql_connection_statistics_finish(
				TRACKER_SPARQL_CONNECTION (object),
				res,
				&error);

	if (error) {
		DBG_ERR("spaql_statistics failed, reason %s\n",
		      error->message);
		if (cursor) {
			g_object_unref (cursor);
		}
		if (state->cancellable) {
			g_clear_object(&state->cancellable);
		}
		g_error_free(error);
		tevent_req_nterror(state->req, NT_STATUS_UNSUCCESSFUL);
		return;
	}

	tracker_sparql_cursor_next_async(cursor, state->cancellable,
					 stats_cursor_cb,
					 state);
	return;
}

struct glib_query_state
{
	uint32_t *rows;
	uint32_t *status;
};

struct tevent_req *glib_tracker_query_status(
					TALLOC_CTX *ctx,
					struct tracker_query_info* query_info,
					uint32_t *status,
					uint32_t *nrows)
{
	struct glib_query_state *state;
	struct tevent_req *req;

	req = tevent_req_create(ctx, &state, struct glib_query_state);

	if (!req) {
		return NULL;
	}

	state->rows = nrows;
	state->status = status;
	*state->status = query_info->state;
	*state->rows = query_info->num_rows;
	tevent_req_done(req);
	return tevent_req_post(req, query_info->sparq_ctx->event_ctx);
}

struct tevent_req *glib_tracker_new_query(TALLOC_CTX *ctx,
					  struct sparql_ctx* sparql_ctx,
					  uint32_t queryid,
					  const char *query,
					  bool cache_results,
					  uint32_t results_limit,
					  struct connection_struct *conn,
					  struct auth_session_info *session_info,
					  struct tracker_query_info **query_ctx)
{
	struct tracker_query_info *query_info;
	struct tevent_req *req;
	struct query_state *state;

	req = tevent_req_create(ctx, &state, struct query_state);

	if (!state) {
		return NULL;
	}

     	query_info = talloc_zero(sparql_ctx, struct tracker_query_info);

	if (!query_info) {
		return NULL;
	}

	talloc_set_destructor(query_info, destroy_query);

	query_info->timer = g_timer_new ();
	query_info->sparq_ctx = sparql_ctx;
        query_info->state = QUERY_IN_PROGRESS;
        query_info->query_id = queryid;
	query_info->cancellable = g_cancellable_new();
	query_info->cache_results = cache_results;
	query_info->results_limit = results_limit;
	query_info->conn = conn;
	query_info->session_info = session_info;

	*query_ctx = query_info;

	state->event_ctx = query_info->sparq_ctx->event_ctx;
	state->req = req;
	state->query = query_info;
	state->cancellable = query_info->cancellable;
	sparql_ctx->nqueries++;

	tracker_sparql_connection_query_async(sparql_ctx->conn->connection,
					      query,
                                              query_info->cancellable,
					      query_cb, state);
	return req;
}

struct tevent_req *glib_tracker_getrows(TALLOC_CTX *ctx,
					struct sparql_ctx* sparql_ctx,
					struct tracker_query_info* query_info,
					uint32_t index, uint32_t nrows,
					bool reverse_fetch,
					struct tracker_getrowsout *rowsout)
{
	struct get_rows_state *state;

	struct tevent_req *req;

	uint32_t i,j;

	uint32_t remaining_rows;
	struct tracker_row *row_cursor;

	if (query_info->state != QUERY_COMPLETE) {
		DBG_ERR("shouldn't get here query %d is still "
			 "returning results\n",
			 query_info->query_id);
		return NULL;
	}

	req = tevent_req_create(ctx, &state, struct dummy_get_rows_state);
	if (!req) {
		DBG_ERR("out of memory error\n");
		return NULL;
	}

	remaining_rows = reverse_fetch ? (index - 1) : (query_info->num_rows - index);
	if (nrows > remaining_rows) {
		DBG_ERR("failed to get %d rows, cur index %d "
			 "total rows %d num rows available, "
			 "clipping rows returned to %d\n",
			 nrows, query_info->cur_index, query_info->num_rows,
			 remaining_rows);
		nrows = remaining_rows;
	}
	if (query_info->cur_index != index) {
		if (query_info->cur_index > index) {
			rewind_cursor_fully(query_info);
		}
		DBG_ERR("moving cursor forward to new index %d\n",
		      index);
		mov_cursor_fwd(query_info, index);
	}

	rowsout->nrows = nrows;
	rowsout->rows = talloc_zero_array(ctx,
					 struct tracker_row,
					 nrows);

	row_cursor = query_info->row_cursor;
	i = 0;
	while(row_cursor && i < nrows) {
		struct tracker_col_data *src_cols = row_cursor->columns;
		struct tracker_col_data *dest_columns =
			talloc_zero_array(rowsout->rows,
					  struct tracker_col_data,
					  row_cursor->ncols);
		rowsout->rows[i].ncols = row_cursor->ncols;
		rowsout->rows[i].columns = dest_columns;
		for  (j = 0; j < row_cursor->ncols; j++) {
			dest_columns[j] = src_cols[j];
		}
		if (reverse_fetch) {
			row_cursor = row_cursor->prev;
			query_info->cur_index--;
		}
		else {
			row_cursor = row_cursor->next;
			query_info->cur_index++;
		}
		query_info->row_cursor = row_cursor;
		i++;
	}
	rowsout->nrows_remaining = reverse_fetch ? (query_info->cur_index - 1) :
		(query_info->num_rows - query_info->cur_index );
	DBG_NOTICE("retrieved %d rows from index is now %d rows remaining %d\n",
		 nrows, query_info->cur_index, rowsout->nrows_remaining);
	tevent_req_done(req);
	tevent_req_post(req, query_info->sparq_ctx->event_ctx);
	return req;
}

struct tevent_req *glib_tracker_getstate(TALLOC_CTX *ctx,
					 struct sparql_ctx* sparql_ctx,
					 struct wsp_cpmcistateinout *out)
{
	struct tevent_req *req;
	struct stats_state *state;

	req = tevent_req_create(ctx, &state, struct stats_state);
	if (!req) {
		DBG_ERR("oom failed to create request\n");
		return NULL;
	}
	state->req = req;
	state->cistateinout = out;
	state->cancellable = g_cancellable_new();
	state->sparq_ctx = sparql_ctx;
	tracker_sparql_connection_statistics_async(sparql_ctx->conn->connection,
						   state->cancellable,
						   statistics_cb,
						   state);
	return req;
}

bool can_access_workid(struct tracker_query_info* query_ctx, uint32_t workid)
{
	/*
	 * with this specific tracker implementation the workid gives the
	 * row position of the entry we want
	 */
	uint32_t index = workid - 1;
	uint32_t i;
	struct tracker_row *item = query_ctx->rows;
	const char *url = NULL;

	/* get row at index */
	for(i = 0; i < index && item; i++, item = item->next);

	url = item->columns[0].type.string;

	return can_access_url(query_ctx->conn, url);
}

/*
 * Handle the following error from glibc
 * "GLib-WARNING **: In call to g_spawn_sync(), exit status of a
 * child process was requested but ECHILD was received by waitpid().
 * Most likely the process is ignoring SIGCHLD, or some other thread is
 * invoking waitpid() with a nonpositive first argument; either behavior
 * can break applications that use g_spawn_sync either directly or indirectly."
 * We don't spawn (afaik) any other child processes from this one so
 * resetting the signal handler to default should get rid of the error
 * and associated race it warns about
 */
static void fix_glib_weirdness(void)
{
	signal(SIGCHLD, SIG_DFL);
}

static int destroy_sparql_ctx(struct sparql_ctx *ctx)
{
	struct tracker_connect_info *conn = ctx->conn;
	if (conn) {
		if (conn->timer) {
			g_timer_destroy (conn->timer);
			conn->timer = NULL;
		}
		if (conn->cancellable) {
			g_clear_object(&conn->cancellable);
		}
		if (conn->connection) {
			g_clear_object(&conn->connection);
		}
	}
	TALLOC_FREE(ctx->glue);
	return 0;
}

struct sparql_ctx * init_sparql(struct tevent_context *event_ctx)
{
	struct tracker_connect_info *conn;
	struct sparql_ctx *sparql_ctx;
	GError *error = NULL;


	sparql_ctx = talloc_zero(NULL, struct sparql_ctx);
	if (!sparql_ctx) {
		return NULL;
	}
	talloc_set_destructor(sparql_ctx, destroy_sparql_ctx);
	sparql_ctx->event_ctx = event_ctx;

	sparql_ctx->conn = talloc_zero(sparql_ctx, struct tracker_connect_info);
	conn = sparql_ctx->conn;
	conn->timer = g_timer_new ();
	conn->sparql_ctx = sparql_ctx;
	conn->cancellable = g_cancellable_new();
	fix_glib_weirdness();
#if ASYNC_CONNECTION
	tracker_sparql_connection_get_direct_async(conn->cancellable,
						   connection_cb,
						   conn);
#else
	DBG_NOTICE("Sync connection took: %.6f\n",
		 g_timer_elapsed(conn->timer, NULL));
	/* for the moment lets connect the tracker on startup */
	conn->connection =
		tracker_sparql_connection_get(conn->cancellable,
					      &error);
	if (error || conn->connection == NULL) {
		if (error) {
			DBG_ERR("Unexpected error getting connection %s\n",
			      error->message);
			g_error_free (error);
		}
		if (conn->connection == NULL) {
			DBG_ERR("no connection to tracker\n");
		}
		TALLOC_FREE(sparql_ctx);
		return NULL;
	}
	if (conn->timer) {
		g_timer_destroy (conn->timer);
		conn->timer = NULL;
	}
	if (conn->cancellable) {
		g_clear_object(&conn->cancellable);
	}
#endif
	sparql_ctx->glue =
			samba_tevent_glib_glue_create(sparql_ctx,
						      sparql_ctx->event_ctx,
						      g_main_context_default());
	if (!sparql_ctx->glue) {
		DBG_ERR("failed to create glib/tevent integration\n");
		TALLOC_FREE(sparql_ctx);
	}
	return sparql_ctx;
}

