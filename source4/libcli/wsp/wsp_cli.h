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
#ifndef __LIBCLI_WSP_WSP_CLI
#define __LIBCLI_WSP_WSP_CLI

#include "libcli/wsp/wsp_aqs.h"

enum search_kind {
	Calendar,
	Communication,
	Contact,
	Document,
	Email,
	Feed,
	Folder,
	Game,
	InstantMessage,
	Journal,
	Link,
	Movie,
	Music,
	Note,
	Picture,
	Program,
	RecordedTV,
	SearchFolder,
	Task,
	Video,
	WebHistory,
	None,
	Unknown,
};

enum search_kind get_kind(const char* kind_str);

void init_connectin_request(TALLOC_CTX *ctx,
			    struct wsp_request* request,
			    const char* clientmachine,
			    const char* clientuser,
			    const char* server);

void create_querysearch_request(TALLOC_CTX * ctx,
				struct wsp_request* request,
				t_select_stmt *sql);

void create_setbindings_request(TALLOC_CTX * ctx,
				struct wsp_request* request,
				t_select_stmt *sql,
				uint32_t cursor);

void create_seekat_getrows_request(TALLOC_CTX * ctx,
				   struct wsp_request* request,
				   uint32_t cursor,
				   uint32_t bookmark,
				   uint32_t skip,
				   uint32_t rows,
				   uint32_t cbreserved,
				   uint32_t ulclientbase,
				   uint32_t cbrowwidth,
				   uint32_t fbwdfetch);

enum ndr_err_code extract_rowsarray(TALLOC_CTX * ctx,
				    DATA_BLOB *rows_buf,
				    bool is_64bit,
				    struct wsp_cpmsetbindingsin *bindingsin,
				    uint32_t cbreserved,
				    uint32_t ulclientbase,
				    uint32_t rows,
				    struct wsp_cbasestoragevariant **rowsarray);

struct wsp_client_ctx;
struct cli_credentials;

NTSTATUS wsp_server_connect(TALLOC_CTX *mem_ctx,
			    const char *servername,
			    struct tevent_context *ev_ctx,
			    struct cli_credentials *credential,
			    struct wsp_client_ctx **ctx);

/* simple sync api */
NTSTATUS wsp_request_response(TALLOC_CTX* ctx,
			      struct wsp_client_ctx *wsp_ctx,
			      struct wsp_request *request,
			      struct wsp_response *response,
			      DATA_BLOB *unread);

/* tmp accessors */
struct dcerpc_pipe * get_wsp_pipe(struct wsp_client_ctx *ctx);
struct smbcli_state * get_wsp_clistate(struct wsp_client_ctx *ctx);
#endif
