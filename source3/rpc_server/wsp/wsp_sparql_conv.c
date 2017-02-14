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
#include "wsp_sparql_conv.h"
#include "smbd/proto.h"
#include "libcli/security/security.h"
#include "wsp_srv_tracker-sparql.h"
#include "smbd/smbd.h"

#define IMPLEMENTED 0

struct filter_data {
	const char *share_scope;
	uint32_t where_id;
};

static const char scheme[] = "file://";
static NTSTATUS get_relative_share_path(TALLOC_CTX *ctx, const char *url,
					 const char **relative_share_path,
					 struct share_params *params);

struct tracker_detail;

static NTSTATUS scope_filter_helper(TALLOC_CTX *ctx,
				    struct tracker_detail *detail,
				    struct wsp_crestriction *restric,
				    const char **filter,
				    void *priv_data);

static NTSTATUS author_filter_helper(TALLOC_CTX *ctx,
				    struct tracker_detail *detail,
				    struct wsp_crestriction *restric,
				    const char **filter,
				    void *priv_data);

static NTSTATUS album_filter_helper(TALLOC_CTX *ctx,
				    struct tracker_detail *detail,
				    struct wsp_crestriction *restric,
				    const char **filter,
				    void *priv_data);

static NTSTATUS itemtype_filter_helper(TALLOC_CTX *ctx,
				     struct tracker_detail *detail,
				     struct wsp_crestriction *restric,
				     const char **filter,
				     void *priv_data);

static NTSTATUS item_folder_path_filter(TALLOC_CTX *ctx,
				     struct tracker_detail *detail,
				     struct wsp_crestriction *restric,
				     const char **filter,
				     void *priv_data);

static NTSTATUS all_filter_helper(TALLOC_CTX *ctx,
				  struct tracker_detail *detail,
				  struct wsp_crestriction *restric,
				  const char **filter,
				  void *priv_data);

static NTSTATUS kind_filter_helper(TALLOC_CTX *ctx,
				   struct tracker_detail *detail,
				   struct wsp_crestriction *restric,
				   const char **filter,
				   void *priv_data);

static NTSTATUS omit_filter_helper(TALLOC_CTX *ctx,
				   struct tracker_detail *detail,
				   struct wsp_crestriction *restric,
				   const char **filter,
				   void *priv_data);

static NTSTATUS convert_entryid(TALLOC_CTX *ctx,
			    struct wsp_cbasestoragevariant *out_val,
			    uint32_t vtype,
			    int type,
			    void *tracker_val,
			    void *private_data)
{
	NTSTATUS status;
	if (vtype != VT_VARIANT) {
		DBG_ERR("currently not handling non-VARIANT row results\n");
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}
	out_val->vtype = VT_I4;
	out_val->vvalue.vt_i4 = *(uint32_t*)(tracker_val);
	status = NT_STATUS_OK;
out:
	return status;
}


static NTSTATUS convert_filetime(TALLOC_CTX *ctx,
			     struct wsp_cbasestoragevariant *out_val,
			     uint32_t vtype,
			     int type, /*TrackerSparqlValueType*/
			     void *tracker_val,
			     void *private_data)
{
	NTSTATUS status;
	/*
	 * Tracker time is a string with format xsd:dateTime
	 * [-]CCYY-MM-DDThh:mm:ss[Z|(+|-)hh:mm]
	 */
	const char* datetime = (const char*)tracker_val;
	struct tm utc_time;
	time_t unixtime;
	uint64_t filetime;
	struct wsp_hyper *p_hyper = &out_val->vvalue.vt_filetime;
	if (vtype != VT_VARIANT) {
		DBG_ERR("currently not handling non-VARIANT row results\n");
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}
	if (!strptime(datetime, "%FT%TZ", &utc_time)) {
		char *tmp = talloc_strdup(ctx, datetime);
		char *dot; //, *;
		/*
		 * it's possible the millsecs are tagged on after the time
		 * and before the timezone, we'll ignore them if that is
		 * the case.
		 */
		dot = strrchr(tmp,'.');
		if (dot) {
			*dot = 'Z';
			if (!strptime(tmp, "%FT%TZ", &utc_time)) {
				DBG_ERR("failed to convert date-time %s\n",
					datetime);
				status = NT_STATUS_UNSUCCESSFUL;
				goto out;
			}
		} else {
			DBG_ERR("failed to convert date-time %s\n", datetime);
			status = NT_STATUS_UNSUCCESSFUL;
			goto out;
		}
	}

	unixtime = timegm(&utc_time);

	/* https://support.microsoft.com/en-us/kb/167296 */
	filetime = ((unixtime * 10000000) + 116444736000000000);
	out_val->vtype = VT_FILETIME;
	uint64_to_wsp_hyper(filetime, p_hyper);
	status = NT_STATUS_OK;
out:
	return status;
}

static NTSTATUS convert_path(TALLOC_CTX *ctx,
			 struct wsp_cbasestoragevariant *out_val,
			 uint32_t vtype,
			 int type, /*TrackerSparqlValueType*/
			 void *tracker_val,
			 void *private_data)
{
	const char *tracker_url = (const char*)tracker_val;
	const char *wsp_url;
	struct row_conv_data *data = (struct row_conv_data*)private_data;
	NTSTATUS status;
	if (vtype != VT_VARIANT) {
		DBG_ERR("currently not handling non-VARIANT row results\n");
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}

	if (data->tracker_row_url == NULL) {
		tracker_url = (const char*)tracker_val;
		data->tracker_row_url = tracker_url;
	} else {
		tracker_url = data->tracker_row_url;
	}

	/*
	 * use the mangled url (with share name replacing share path) is we
	 * already have it
	 */
	if (data->row_relative_share_path == NULL) {
		if (!NT_STATUS_IS_OK(get_relative_share_path(ctx, tracker_url,
					    &data->row_relative_share_path,
					    data->conn->params))) {
			// #FIXME
			DBG_ERR("error getting share path but %s\n",
			        data->row_relative_share_path);
			status = NT_STATUS_INVALID_PARAMETER;
			goto out;
		}
	}

	if (data->row_relative_share_path != NULL) {
		wsp_url = talloc_asprintf(ctx, "%s%s", scheme,
					  data->row_relative_share_path);
		out_val->vtype = VT_LPWSTR;
		out_val->vvalue.vt_lpwstr.value = wsp_url;
	}
	status = NT_STATUS_OK;
out:
	return status;
}

static NTSTATUS convert_filesize(TALLOC_CTX *ctx,
			     struct wsp_cbasestoragevariant *out_val,
			     uint32_t vtype,
			     int type, /*TrackerSparqlValueType*/
			     void *tracker_val,
			     void *private_data)
{
	NTSTATUS status;
	uint64_t size = 0;
	struct wsp_hyper *p_hyper = &out_val->vvalue.vt_ui8;
	if (vtype != VT_VARIANT) {
		DBG_ERR("currently not handling non-VARIANT row results\n");
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}
	size = *(uint64_t*)tracker_val;
	out_val->vtype = VT_UI8;
	uint64_to_wsp_hyper(size, p_hyper);
	status = NT_STATUS_OK;
out:
	return status;
}

static NTSTATUS convert_kind(TALLOC_CTX *ctx,
			 struct wsp_cbasestoragevariant *out_val,
			 uint32_t vtype,
			 int type, /*TrackerSparqlValueType*/
			 void *tracker_val,
			 void *private_data)
{
	NTSTATUS status;
	const char *val;
	if (vtype != VT_VARIANT) {
		DBG_ERR("currently not handling non-VARIANT row results\n");
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}
	val = (const char*)(tracker_val);
	if (strstr(val, "image/") == val) {/* startswith */
		out_val->vtype = VT_VECTOR | VT_LPWSTR;
		out_val->vvalue.vt_lpwstr_v.vvector_elements = 1;
		out_val->vvalue.vt_lpwstr_v.vvector_data =
			talloc_zero_array(ctx, struct vt_lpwstr,
				out_val->vvalue.vt_lpwstr_v.vvector_elements);
		out_val->vvalue.vt_lpwstr_v.vvector_data[0].value =
			talloc_strdup(ctx, "picture");
	}
	status = NT_STATUS_OK;
out:
	return status;
}

static NTSTATUS convert_itemtype(TALLOC_CTX *ctx,
			     struct wsp_cbasestoragevariant *out_val,
			     uint32_t vtype,
			     int type, /*TrackerSparqlValueType*/
			     void *tracker_val,
			     void *private_data)
{
	NTSTATUS status;
	const char *filename;
	const char *ext;
	if (vtype != VT_VARIANT) {
		DBG_ERR("currently not handling non-VARIANT row results\n");
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}
	filename = (const char*)(tracker_val);
	ext = strrchr(filename, '.');
	if (ext) {
		out_val->vtype = VT_LPWSTR;
		out_val->vvalue.vt_lpwstr.value = talloc_strdup(ctx, ext);
	}
	status = NT_STATUS_OK;
out:
	return status;
}

static NTSTATUS convert_stringval(TALLOC_CTX *ctx,
			      struct wsp_cbasestoragevariant *out_val,
			      uint32_t vtype,
			      int type, /*TrackerSparqlValueType*/
			      void *tracker_val,
			      void *private_data)
{
	NTSTATUS status;
	const char *filename;
	if (vtype != VT_VARIANT) {
		DBG_ERR("currently not handling non-VARIANT row results\n");
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;;
	}
	filename = (const char*)(tracker_val);
	out_val->vtype = VT_LPWSTR;
	out_val->vvalue.vt_lpwstr.value = talloc_strdup(ctx, filename);
	status = NT_STATUS_OK;
out:
	return status;
}

struct {
	const char *ext; /* extension to match */
	const char *item_type; /* type string to return */
} item_type_map [] = {
	{"png", "PNG Image"},
	{"jpg", "JPEG image"},
	{"bmp", "Bitmap image"},
};

static NTSTATUS convert_itemtypetext(TALLOC_CTX *ctx,
				 struct wsp_cbasestoragevariant *out_val,
				 uint32_t vtype,
				 int type, /*TrackerSparqlValueType*/
				 void *tracker_val,
				 void *private_val)
{
	NTSTATUS status;
	const char *filename;
	const char *ext;
	if (vtype != VT_VARIANT) {
		DBG_ERR("currently not handling non-VARIANT row results\n");
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}
	filename = (const char*)(tracker_val);
	if (filename == NULL) {
		DBG_ERR("Error no filename from tracker\n");
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}
	ext = strrchr(filename, '.');
	if (ext) {
		int i;
		out_val->vtype = VT_LPWSTR;
		ext++;
		for (i = 0; i < ARRAY_SIZE(item_type_map); i++) {
			if (strequal(ext, item_type_map->ext)) {
				out_val->vvalue.vt_lpwstr.value =
					talloc_strdup(ctx,
						item_type_map[i].item_type);
		}
		if (out_val->vvalue.vt_lpwstr.value == NULL)
			out_val->vvalue.vt_lpwstr.value =
				talloc_asprintf(ctx, "%s File", ext);
		}
		status = NT_STATUS_OK;
	} else {
		DBG_ERR("couldn't get extension from filename %s\n",
		      filename);
		status = NT_STATUS_INVALID_PARAMETER;
	}
out:
	return status;
}

static NTSTATUS get_sharename_from_path(TALLOC_CTX *ctx, const char *path,
					 char **share_name, char **share_path)
{
	int i;
	int matchlen = 0;
	int snum = -1;
	int num_services = lp_numservices();
	if (!share_name) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	for (i = 0; i < num_services; i++) {
		char *service_path =  lp_path(ctx, i);
		/* if the path starts with share path */
		if (strstr(path, service_path) == path) {
			/* find the share that most (best) matches path */
			if (strlen(service_path) > matchlen) {
				snum = i;
				matchlen = strlen(service_path);
			}
		}
		TALLOC_FREE(service_path);
	}
	if (snum == -1) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (share_path) {
		*share_path = lp_path(ctx, snum);
	}
	*share_name = lp_servicename(ctx, snum);
	return NT_STATUS_OK;
}

static const char * mangle_path(TALLOC_CTX *ctx, const char *relative_path,
		       struct share_params *params)
{
	/* step through each segment and assess if it needs mangling */
	const char *sep = "/";
	char *copy = talloc_strdup(ctx, relative_path);
	char *curr = copy;
	char *prev = NULL;
	const char *result = NULL;
	char *p = NULL;
	const char *end_of_string = copy + strlen(copy);
	const char *end_last_seg = NULL;
	struct segment_info
	{
		struct segment_info *prev, *next;
		const char *startpos;
		int num_chars;
	};
	struct segment_info *infos = NULL;
	struct segment_info *info = NULL;
	int max_size = 0;
	bool mangled = false;

	/* see if the path starts with '/' */
	while ((curr = strstr(curr, sep)) != NULL) {
		max_size++;
		if (prev) {
			int num_chars = curr - prev - 1;
			if (num_chars) {
				bool needs_mangle = false;
				info = talloc_zero(ctx, struct segment_info);
				info->startpos = prev + 1;
				info->num_chars = num_chars;
				end_last_seg = info->startpos + num_chars;

				*curr = '\0';
				needs_mangle =
					mangle_must_mangle(prev + 1, params);

				if (needs_mangle) {
					char mname[13];
					name_to_8_3(prev + 1, mname, false,
						params);
					info->num_chars = strlen(mname);
					info->startpos = talloc_strdup(info,
									mname);
					mangled = true;
				}
				*curr = '/';
				max_size += info->num_chars;
				DLIST_ADD_END(infos, info);
			}
		}
		prev = curr;
		curr++;
	}

	if (!mangled) {
		/*
		 * if no path seqments were mangled then just return the
		 * path we were passed
		 */
		result = relative_path;
		goto out;
	}

	max_size += (end_of_string - end_last_seg);
	p = talloc_zero_array(ctx, char, max_size + 1);

	result = p;
	/* build path from existing segments or mangled ones */
	for (info = infos; info; info = info->next) {
		*p = '/';
		p++;
		memcpy(p, info->startpos, info->num_chars);
		p += info->num_chars;
	}
	memcpy(p, end_last_seg, end_of_string - end_last_seg);
out:
	for (info = infos; info;) {
		struct segment_info *next = info->next;
		TALLOC_FREE(info);
		info = next;
	}
	TALLOC_FREE(copy);
	return result;
}

/* return NETBIOSNAME/SHARE/xyz for file:///local_share_path/xyz */
static NTSTATUS get_relative_share_path(TALLOC_CTX *ctx, const char *url,
					 const char **relative_share_path,
					 struct share_params *params)
{
	char *s = NULL;
	char *local_share_path = NULL;
	char *share_name = NULL;
	char *share_path = NULL;
	if (!url) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	s = strcasestr(url, scheme);
	if (!s) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	local_share_path = talloc_strdup(ctx, s + strlen(scheme));

	/* find share name */
	if (!NT_STATUS_IS_OK(get_sharename_from_path(ctx,
						     local_share_path,
						     &share_name,
						     &share_path))) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	s = local_share_path + strlen(share_path);
	if (params) {
		TALLOC_CTX *tmp_ctx = talloc_new(ctx);
		/* attempt to mangle the relative share path part */
		const char *tmp = mangle_path(tmp_ctx, s, params);
		*relative_share_path = talloc_asprintf(ctx,
						      "%s/%s%s",
						      lp_netbios_name(),
						      share_name,
						      tmp);
		TALLOC_FREE(tmp_ctx);
	} else {
		*relative_share_path = talloc_asprintf(ctx,
						       "%s/%s%s",
						       lp_netbios_name(),
						       share_name,
						       s);
	}
	return NT_STATUS_OK;
}

static NTSTATUS convert_folderpath(TALLOC_CTX *ctx,
			       struct wsp_cbasestoragevariant *out_val,
			       uint32_t vtype,
			       int type, /*TrackerSparqlValueType*/
			       void *tracker_val,
			       void *private_data)
{
	NTSTATUS status;
	char *result = NULL;
	const char* url;
	struct row_conv_data *data = (struct row_conv_data *)private_data;
	if (vtype != VT_VARIANT) {
		DBG_ERR("currently not handling non-VARIANT row results\n");
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}

	if (data->tracker_row_url == NULL) {
		url = (const char*)tracker_val;
		data->tracker_row_url = url;
		/* get the NETBIOS/SHARENAME/xyz path associate with this url */
		status = get_relative_share_path(ctx, url,
						 &data->row_relative_share_path,
						 data->conn->params);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
	} else {
		url = data->tracker_row_url;
	}

	if (data->row_relative_share_path != NULL) {
		result = talloc_asprintf(ctx, "//%s",
					 data->row_relative_share_path);
	}

	if (result) {
		/* strip final '/' */
		char *slash = strrchr(result, '/');
		if (slash) {
			*slash = 0;
			/* replace '/' with '\' */
			string_replace(result, '/', '\\');
		}
		out_val->vtype = VT_LPWSTR;
		out_val->vvalue.vt_lpwstr.value = result;
	}
	status = NT_STATUS_OK;
out:
	return status;
}

static NTSTATUS convert_folderpath_narrow(TALLOC_CTX *ctx,
				      struct wsp_cbasestoragevariant *out_val,
				      uint32_t vtype,
				      int type, /*TrackerSparqlValueType*/
				      void *tracker_val,
				      void *private_data)
{
	NTSTATUS status;
	char* result =  NULL;
	char *tmp = NULL;
	const char* url;
	struct row_conv_data *data = (struct row_conv_data *)private_data;
	if (vtype != VT_VARIANT) {
		DBG_ERR("currently not handling non-VARIANT row results\n");
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}
	if (data->tracker_row_url == NULL) {
		url = (const char*)tracker_val;
		data->tracker_row_url = url;
	} else {
		url = data->tracker_row_url;
	}
	/* get the NETBIOS/SHARENAME/xyz path associate with this url */
	if (data->row_relative_share_path == NULL) {
		status = get_relative_share_path(ctx,
						 url,
						 &data->row_relative_share_path,
						 data->conn->params);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
	}
	if (data->row_relative_share_path != NULL) {
		/* strip final '/' */
		char *remainder = NULL;
		char *slash;
		tmp = talloc_strdup(ctx, data->row_relative_share_path);
		slash = strrchr(tmp, '/');
		if (slash) {
			*slash = '\0';
		}
		/* split NETBIOS/SHARENAME and xyz portions */
		slash = strchr(tmp, '/');
		if (!slash) {
			status = NT_STATUS_INVALID_PARAMETER;
			goto out;
		}
		slash = strchr(slash + 1, '/');
		/* tmp points to NETBIOS/SHARENAME */
		if (slash) {
			char *last_slash = strrchr(slash, '/');
			if (last_slash) {
				slash = last_slash;
			}
			*slash = '\0';
			remainder = (slash + 1);
		} else {
			/*
			 * there is no subdirectory, make remainder poing to
			 * empty string, e.g. just point at end of tmp
			 */
			remainder = tmp + strlen(tmp);
		}
		result = talloc_asprintf(ctx, "%s (//%s)",
				remainder, tmp);
	}
	if (result) {
		/* replace '/' with '\' */
		string_replace(result, '/', '\\');
		out_val->vtype = VT_LPWSTR;
		out_val->vvalue.vt_lpwstr.value = result;
	} else {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}
	status = NT_STATUS_OK;
out:
	return status;
}

static NTSTATUS convert_fileattrs(TALLOC_CTX *ctx,
			     struct wsp_cbasestoragevariant *out_val,
			     uint32_t vtype,
			     int type, /*TrackerSparqlValueType*/
			     void *tracker_val,
			     void *private_data)
{
	NTSTATUS status;
	struct smb_filename *smb_fname = NULL;
	struct row_conv_data *data = (struct row_conv_data *)private_data;
	const char *tracker_row_url = (const char*)tracker_val;
	uint32_t dosmode = 0;

	if (tracker_row_url) {
		const char *path = tracker_row_url + strlen("file://");
		int ret;
		smb_fname =
			synthetic_smb_fname(ctx, path, NULL, NULL, 0);
		if (!smb_fname) {
			status = NT_STATUS_UNSUCCESSFUL;
			goto out;
		}
		ret = SMB_VFS_STAT(data->conn, smb_fname);
		if ((ret == -1) && (errno == ENOENT)) {
			status = NT_STATUS_UNSUCCESSFUL;
			DBG_ERR("vfs_stat failed for %s\n", path);
			goto out;
		}
		dosmode = dos_mode(data->conn, smb_fname);
	} else {
		DBG_ERR("no url to get fileattributes from\n");
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}
	/*
	 * somehow from the file's unix permission we need  to
	 * get something representitive of FileAttributes values
	 */
	/* for testing hard code a value */
	out_val->vtype = VT_UI4;
	out_val->vvalue.vt_ui4 = dosmode;
	status = NT_STATUS_OK;
out:
	return status;
}

#if IMPLEMENTED
static NTSTATUS convert_gaoflags(TALLOC_CTX *ctx,
			     struct wsp_cbasestoragevariant *out_val,
			     uint32_t vtype,
			     int type, /*TrackerSparqlValueType*/
			     void *tracker_val,
			     void *private_data)
{
	NTSTATUS status;
	/*
	 * somehow from the file's unix permission we need  to
	 * get something representitive of SFGAOFlags
	 */
	/* for testing hard code a value */
	out_val->vtype = VT_UI4;
	out_val->vvalue.vt_ui4 = 0x40400177;
	status = NT_STATUS_OK;
	return status;
}

static NTSTATUS convert_rank(TALLOC_CTX *ctx,
			 struct wsp_cbasestoragevariant *out_val,
			 uint32_t vtype,
			 int type, /*TrackerSparqlValueType*/
			 void *tracker_val,
			 void *private_data)
{
	NTSTATUS status;
	out_val->vtype = VT_I4;
	out_val->vvalue.vt_i4 = 980;
	status = NT_STATUS_OK;
	return status;
}

static NTSTATUS convert_cacheid(TALLOC_CTX *ctx,
			 struct wsp_cbasestoragevariant *out_val,
			 uint32_t vtype,
			 int type, /*TrackerSparqlValueType*/
			 void *tracker_val,
			 void *private_data)
{
	NTSTATUS status;
	/* just insert bogus value, is it needed ?*/
	static uint64_t gen = 0x1cf6a0d61d11bba;

	uint64_t id = gen++;
	struct wsp_hyper *p_hyper = &out_val->vvalue.vt_ui8;
	out_val->vtype = VT_UI8;
	uint64_to_wsp_hyper(id, p_hyper);
	status = NT_STATUS_OK;
	return status;
}

#endif

struct tracker_detail {
	const char *wsp_id;
	const char *tracker_id;
	NTSTATUS (*filt_helper)(TALLOC_CTX *ctx,
				struct tracker_detail *detail,
				struct wsp_crestriction *restric,
				const char **filter,
				void *private_data);
	tracker_to_wsp_fn convert_fn;
} prop_to_tracker_iri_map[] = {
	/* is a free text search thingy */
	{"All", NULL, all_filter_helper, NULL},
	/*
	 * http://msdn.microsoft.com/en-us/library/windows/desktop/aa380376%28v=vs.85%29.aspx
	 * indicates that this property set is the Summary Information Property
	 * Set, but... no indication of what those property ids(s) are
	 */
	{"f29f85e0-4ff9-1068-ab91-08002b27b3d9/24", NULL, NULL},
	{"f29f85e0-4ff9-1068-ab91-08002b27b3d9/26", NULL, NULL},
	{"Path", "nie:url", NULL, convert_path},
	/*
	 * scope is not determined by a relationship (or one I can see) but
	 * could be determined by an extra 'where' clause doing a regrex
	 * on the nie:url value above, perhaps there is another way.
	 */

	{"Scope", "nie:url", scope_filter_helper, NULL},
	{"System.Author", NULL, author_filter_helper, NULL},
	{"System.Music.AlbumTitle", NULL, album_filter_helper, NULL},
	{"System.Contact.FullName", NULL, NULL},
	{"System.DateAccessed", "nfo:fileLastAccessed", NULL, convert_filetime},
	{"System.DateModified", "nfo:fileLastModified", NULL, convert_filetime},

	{"System.FileName", "nfo:fileName", NULL, convert_stringval },
	{"System.ItemAuthors", NULL, author_filter_helper,  NULL},
	{"System.ItemFolderPathDisplay", "nie:url", item_folder_path_filter, convert_folderpath },
	/*
	 * needs to be synthesized, format is
	 * "\\NETBIOS\SHARE\path.."
	 */
	{"System.ItemFolderPathDisplayNarrow", "nie:url", NULL, convert_folderpath_narrow},
	{"System.ItemDate", "nfo:fileLastModified", NULL, convert_filetime },
	{"System.ItemNameDisplay", "nfo:fileName", NULL, convert_stringval },
//	{"System.ItemNamePrefix", "nfo:fileName", NULL },
	/* needs to be synthesised (is the extension) */
	{"System.ItemType", "nfo:fileName", itemtype_filter_helper, convert_itemtype },
	{"00000000-0000-0000-0000-000000000000/#SYSTEM.STRUCTUREDQUERY.VIRTUAL.TYPE", "nfo:fileName", itemtype_filter_helper, convert_itemtype },
	/* needs to be synthesised (is something like "JPEG image" etc) */
	{"System.ItemTypeText", "nfo:fileName", NULL, convert_itemtypetext },
	{"System.ItemName", "nfo:fileName", NULL, convert_stringval },
	{"System.ItemURL", "nie:url", NULL, convert_path},
	{"System.Keywords", NULL, NULL, NULL},
	/*
	 * again needs to be synthesized, actually is a vector and has a value
	 * like 'picture' when returned
	 */
	{"System.Kind", "nie:mimeType", kind_filter_helper, convert_kind },
	{"System.MIMEType", "nie:mimeType", NULL, convert_stringval },
	{"System.Message.FromName", "nmo:from", NULL, NULL},
	{"System.Music.AlbumTitle", "nmm:musicAlbum", NULL, NULL},
	{"System.Music.Genre", "nmm:genre", NULL, NULL},
	{"System.ParsingName", "nfo:fileName", NULL, convert_stringval },
	/* we need to synthesize this */
	{"System.Search.EntryID", "nie:isStoredAs", NULL, convert_entryid},
	/*
	 * needs to be synthesized (needs file url) on windows
	 * http://msdn.microsoft.com/en-us/library/windows/desktop/bb762589%28v=vs.85%29.aspx
	 * describes the flags, (usually retrieved from
	 * IShellFolder::GetAttributesOf, and additionally the
	 * SFGAO_PKEYSFGAOMASK = 0x81044000 values are masked out
	 */
	/* has no relevence afaik on linux */
	{"System.Shell.OmitFromView", NULL, omit_filter_helper},
	{"System.Size", "nfo:fileSize", NULL, convert_filesize },
	{"System.Subject", "nmo:messageSubject", NULL, convert_stringval},
	{"System.Title", "nie:title", NULL, convert_stringval},
	{"System.Important.Unknown", "nie:url", NULL, convert_entryid},
	/*
	 * FileAttributes values are described by
	 * http://msdn.microsoft.com/en-us/library/windows/desktop/gg258117%28v=vs.85%29.aspx, doesn't seem to be returned by tracker but we could
	 */
	{"System.FileAttributes", "nie:url", NULL, convert_fileattrs},
#if IMPLEMENTED
	{"System.ThumbnailCacheId", "nie:url", NULL, convert_cacheid},
	{"System.SFGAOFlags", "nie:url", NULL, convert_gaoflags},
	{"System.DateCreated", "nfo:fileLastAccessed", NULL, convert_filetime},
	{"System.Search.Rank", "nie:url", NULL, convert_rank},
#endif
};

static struct tracker_detail *get_tracker_detail(const char *wsp_id)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(prop_to_tracker_iri_map); i++) {
		if (strequal(prop_to_tracker_iri_map[i].wsp_id, wsp_id)) {
			return &prop_to_tracker_iri_map[i];
		}
	}
	return NULL;
}

static NTSTATUS get_share_path(TALLOC_CTX *ctx, const char *share,
				  char **share_path)
{
	int snum;
	char *service = NULL;
	char *path = NULL;
	if (share_path == NULL || share == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	snum = find_service(ctx, share, &service);
	if ((snum == -1) || (service == NULL)) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	path = lp_path(ctx, snum);
	if (path == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	*share_path = path;
	return NT_STATUS_OK;
}

static NTSTATUS get_share(TALLOC_CTX *ctx,
			  const char *win_url,
			  const char **shareout)
{
	char *share;
	char *s;
	if (win_url == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	s = strcasestr(win_url, scheme);

	if (s == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	s = s + strlen(scheme);

	share = talloc_strdup(ctx, s);
	s = strchr(share, '/');

	if (s == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	};

	share = talloc_strdup(ctx, s + 1);
	s = strchr(share, '/');
	if (s) {
		*s = '\0';
	}
	*shareout = share;
	return NT_STATUS_OK;
}

/* need to replace file://NETBIOS/SHARENAME with file:///local-path */
static NTSTATUS replace_share_in_url(TALLOC_CTX *ctx, const char* path,
				     const char **local_path)
{
	const char *result = NULL;
	const char *share;
	char *share_path;
	const char *tmp;
	NTSTATUS status = get_share(ctx, path, &share);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = get_share_path(ctx, share, &share_path);
	if (!NT_STATUS_IS_OK(get_share_path(ctx, share, &share_path))) {
		return status;
	}

	tmp = strcasestr(path, share);
	if (tmp) {
		result = talloc_asprintf(ctx, "file://%s%s",
			share_path, tmp + strlen(share));
	}
	status = NT_STATUS_OK;
	*local_path = result;
	return status;
}

static NTSTATUS item_folder_path_filter(TALLOC_CTX *ctx,
				     struct tracker_detail *detail,
				     struct wsp_crestriction *restric,
				     const char **filter,
				     void *priv_data)
{
	const char *filter_str = NULL;
	const char *prop_val = NULL;
	char *lower = NULL;
	NTSTATUS status;
	if (restric->ultype == RTCONTENT) {
		prop_val = restric->restriction.ccontentrestriction.pwcsphrase;
	} else if (restric->ultype == RTPROPERTY) {
		prop_val = variant_as_string(ctx,
				&restric->restriction.cpropertyrestriction.prval,
				false);
	} else {
		DBG_ERR("helper failed for restriction type %d\n",
		        restric->ultype);
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}
	lower = talloc_strdup(ctx, prop_val);
	if (!strlower_m(lower)) {
		/* if we can't convert, warn and soldier on */
		DBG_ERR("couldn't convert %s to lower case\n", prop_val);
	}

	filter_str = talloc_asprintf(ctx,
				     "fn:contains(fn:lower-case(nie:url(?u)),"
				     "\'/%s\')",
				     lower);
	*filter = filter_str;
	status = NT_STATUS_OK;
done:
	return status;
}


static NTSTATUS album_filter_helper(TALLOC_CTX *ctx,
				     struct tracker_detail *detail,
				     struct wsp_crestriction *restric,
				     const char **filter,
				     void *priv_data)
{
	const char *filter_str = NULL;
	const char *prop_val = NULL;
	char *lower = NULL;
	NTSTATUS status;
	if (restric->ultype == RTCONTENT) {
		prop_val = restric->restriction.ccontentrestriction.pwcsphrase;
	} else if (restric->ultype == RTPROPERTY) {
		prop_val = variant_as_string(ctx,
				&restric->restriction.cpropertyrestriction.prval,
				false);
	} else {
		DBG_ERR("helper failed for restriction type %d\n",
		      restric->ultype);
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}
	prop_val = restric->restriction.ccontentrestriction.pwcsphrase;
	lower = talloc_strdup(ctx, prop_val);
	if (!strlower_m(lower)) {
		/* if we can't convert, warn and soldier on */
		DBG_ERR("couldn't convert %s to lower case\n", prop_val);
	}

	filter_str =
		talloc_asprintf(ctx,
				"fn:contains(fn:lower-case(nie:title("
				"nmm:musicAlbum(?u))),\'%s\')",
				lower);
	*filter = filter_str;
	status = NT_STATUS_OK;
done:
	return status;
}

static NTSTATUS author_filter_helper(TALLOC_CTX *ctx,
				     struct tracker_detail *detail,
				     struct wsp_crestriction *restric,
				     const char **filter,
				     void *priv_data)
{
	const char *filter_str = NULL;
	const char *prop_val = NULL;
	char *lower = NULL;
	NTSTATUS status;
	if (restric->ultype == RTCONTENT) {
		prop_val = restric->restriction.ccontentrestriction.pwcsphrase;
	} else if (restric->ultype == RTPROPERTY) {
		prop_val = variant_as_string(ctx,
				&restric->restriction.cpropertyrestriction.prval,
				false);
	} else {
		DBG_ERR("helper failed for restriction type %d\n",
		      restric->ultype);
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}
	lower = talloc_strdup(ctx, prop_val);
	if (!strlower_m(lower)) {
		/* if we can't convert, warn and soldier on */
		DBG_ERR("couldn't convert %s to lower case\n", prop_val);
	}

	filter_str = talloc_asprintf(ctx,
				     "fn:starts-with(fn:lower-case(nco:"
				     "fullname(nco:publisher(?u))), \'%s\')",
				     lower);
	*filter = filter_str;
	status = NT_STATUS_OK;
done:
	return status;
}

static NTSTATUS itemtype_filter_helper(TALLOC_CTX *ctx,
				     struct tracker_detail *detail,
				     struct wsp_crestriction *restric,
				     const char **filter,
				     void *priv_data)
{
	const char *filter_str = NULL;
	const char *prop_val = NULL;
	char *lower = NULL;
	NTSTATUS status;
	if (restric->ultype == RTCONTENT) {
		prop_val = restric->restriction.ccontentrestriction.pwcsphrase;
	} else if (restric->ultype == RTPROPERTY) {
		prop_val = variant_as_string(ctx,
				&restric->restriction.cpropertyrestriction.prval,
				false);
	} else {
		DBG_ERR("helper failed for restriction type %d\n", restric->ultype);
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}
	lower = talloc_strdup(ctx, prop_val);
	if (!strlower_m(lower)) {
		/* if we can't convert, warn and soldier on */
		DBG_ERR("couldn't convert %s to lower case\n", prop_val);
	}

	filter_str = talloc_asprintf(ctx, "fn:ends-with(fn:lower-case(nfo:fileName(?u)), \'.%s\')", lower);
	*filter = filter_str;
	status = NT_STATUS_OK;
done:
	return status;
}

static NTSTATUS scope_filter_helper(TALLOC_CTX *ctx,
				    struct tracker_detail *detail,
				    struct wsp_crestriction *restric,
				    const char **filter,
				    void *priv_data)
{
	const char *filter_str = NULL;
	const char *prop_val = NULL;
	struct filter_data *data = (struct filter_data *)priv_data;

	NTSTATUS status;

	if (restric->ultype != RTPROPERTY) {
		DBG_ERR("scope_filter_helper failed for restriction type %d\n",
 		      restric->ultype);
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}
	prop_val = variant_as_string(ctx, &restric->restriction.cpropertyrestriction.prval, false);

	if (!data->share_scope) {
		status = get_share(ctx, prop_val, &data->share_scope);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}
	}
	status = replace_share_in_url(ctx, prop_val, &prop_val);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	filter_str = talloc_asprintf(ctx, "tracker:uri-is-descendant "
					  "('%s', nie:url (?u))",
						prop_val);
	*filter = filter_str;
	status = NT_STATUS_OK;
done:
	return status;
}

/*
 * This is pretty lame, really would be better to additionally use
 * fts:match terms, but... I can only see how to use these in the WHERE
 * clause which isn't afaics flexible enough when used in addition to other
 * 'restrictions'
 */
static NTSTATUS all_filter_helper(TALLOC_CTX *ctx,
				  struct tracker_detail *detail,
				  struct wsp_crestriction *restric,
				  const char **filter,
				  void *priv_data)
{
	const char *filter_str = NULL;
	const char *prop_val = NULL;
	char *lower;
	NTSTATUS status;

	if (restric->ultype != RTCONTENT) {
		DBG_ERR("scope_filter_helper failed for restriction type %d\n",
		      restric->ultype);
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	prop_val = restric->restriction.ccontentrestriction.pwcsphrase;
	lower = talloc_strdup(ctx, prop_val);
	if (!strlower_m(lower)) {
		/* if we can't convert, warn and soldier on */
		DBG_ERR("couldn't convert %s to lower case\n", prop_val);
	}
	if (restric->restriction.ccontentrestriction.ulgeneratemethod) {
		filter_str =
			talloc_asprintf(
					ctx,
					"fn:contains(fn:lower-case("
					"nie:plainTextContent(?u)), \'%s\')"
					" || fn:contains(fn:lower-case("
					"nie:title(?u)),\'%s\') ||"
					" fn:starts-with(fn:lower-case("
					"nfo:fileName(?u)), \'%s\')",
					lower,
					lower,
					lower);
	} else {
		filter_str =
			talloc_asprintf(ctx,
					"nie:plainTextContent(?u) = \'%s\' ||"
					" nie:title(?f) = \'%s\'",
					prop_val,
					prop_val);
	}
	*filter = filter_str;
	status = NT_STATUS_OK;
done:
	TALLOC_FREE(lower);
	return status;
}

static NTSTATUS omit_filter_helper(TALLOC_CTX *ctx,
				   struct tracker_detail *detail,
				   struct wsp_crestriction *restric,
				   const char **filter,
				   void *priv_data)
{
	const char *filter_str = talloc_strdup(ctx,"");
	const char *prop_val = NULL;
	const char *tmp = NULL;
	struct wsp_cpropertyrestriction *cprop;
	struct wsp_ccontentrestriction *ccont;
	NTSTATUS status;
	/*
	 * assume OmitFromView always is 'false' since there is no such thing
	 * afaik as ommiting files from view in 'nix-land
	 */
	switch(restric->ultype) {
		case RTPROPERTY: {
			cprop = &restric->restriction.cpropertyrestriction,
			tmp = variant_as_string(ctx, &cprop->prval, false);
			prop_val = talloc_strdup(ctx, tmp);
			filter_str = talloc_asprintf(ctx,
						"(false %s %s)",
						op_as_string(restric),
						prop_val);
			break;
		}
		case RTCONTENT: {
			ccont = &restric->restriction.ccontentrestriction;
			prop_val =
				talloc_strdup(ctx,ccont->pwcsphrase);
			filter_str = talloc_asprintf(ctx,
						     "(false = %s)",
						     prop_val);
			break;
		}
		default:
			DBG_ERR("omit_filter_helper failed for restriction"
				 " type %d\n", restric->ultype);
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}
	*filter = filter_str;
	status = NT_STATUS_OK;
done:
	return status;
}
const static struct {
	const char *kind;
	const char *rdf_type;
} kind_rdf_type_map []= {
	{"Calendar", NULL},
	{"Communication", NULL},
	{"Contact", NULL},
	/*
	 * note nfo:TextDocument will match spreadsheets even, nfo:Spreadsheet
	 * wont match libreoffice calc spreadsheets though
	 */
	{"Document", "nfo:TextDocument"},
	{"Email", NULL},
	{"Feed", NULL},
	{"Folder", "nfo:Folder"},
	{"Game", NULL},
	{"InstantMessage", NULL},
	{"Journal", NULL},
	{"Link", NULL},
	{"Movie", NULL},
	{"Music", "nmm:MusicPiece"},
	{"Note", NULL},
	{"Picture", "nfo:Image"},
	{"Program", NULL},
	{"RecordedTV", NULL},
	{"SearchFolder", NULL},
	{"Task", NULL},
	{"Video", "nfo:Video"},
	{"WebHistory", NULL},
};

static const char * get_rdftype_for_kind(const char *kind)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(kind_rdf_type_map); i++) {
		if (strequal(kind, kind_rdf_type_map[i].kind)) {
			return kind_rdf_type_map[i].rdf_type;
		}
	}
	return NULL;
}

static NTSTATUS kind_filter_helper(TALLOC_CTX *ctx,
				   struct tracker_detail *detail,
				   struct wsp_crestriction *restric,
				   const char **filter,
				   void *priv_data)
{
	const char *filter_str = talloc_strdup(ctx,"");
	char *prop_val = NULL;
	const char *rdf_type;
	struct wsp_cpropertyrestriction *cprop;
	struct wsp_ccontentrestriction *ccont;
	const char *tmp;
	NTSTATUS status;
	switch(restric->ultype) {
		case RTPROPERTY: {
			cprop = &restric->restriction.cpropertyrestriction;
			tmp = variant_as_string(ctx, &cprop->prval, false);
			prop_val = talloc_strdup(ctx, tmp);
			break;
		}
		case RTCONTENT: {
			ccont = &restric->restriction.ccontentrestriction;
			prop_val = talloc_strdup(ctx, ccont->pwcsphrase);
			break;
		}
		default:
			DBG_ERR("scope_filter_helper failed for restriction"
				 " type %d\n", restric->ultype);
			status = NT_STATUS_INVALID_PARAMETER;
			goto done;
			break;
	}

#if 0
/* could alernatively use media type  */
		if (strequal(prop_val, "Picture")) {
			filter_str = talloc_asprintf(ctx, "fn:starts-with(nie:mimeType(?u), 'image/')");
		} else if (strequal(prop_val, "Music")) {
			filter_str = talloc_asprintf(ctx, "fn:starts-with(nie:mimeType(?u), 'audio/')");
		} 
#endif
	if (!strlen(filter_str)) {
		/*
		 * using the type is one one of handling 'Kind' maybe
		 * media type is better
		 */
		rdf_type = get_rdftype_for_kind(prop_val);

		/* convert */
		if (rdf_type) {
			filter_str = talloc_asprintf(ctx,
						"?type IN (%s)", rdf_type);
		}
	}
	*filter = filter_str;
	status = NT_STATUS_OK;
done:
	return status;
}

struct tracker_pair_list
{
	struct 	tracker_pair_list *next, *prev;
	const char* key;
	struct tracker_detail * value;	
};

struct sparql_conv
{
	struct tracker_pair_list *select;
};

static bool list_contains_value(struct sparql_conv *sparql_conv,
			        struct tracker_detail *value)
{
	struct tracker_pair_list *item = sparql_conv->select;
	for (; item; item = item->next) {
		if (item->value && strequal(item->value->tracker_id,
					    value->tracker_id)) {
			return true;
		}
	}
	return false;
}

static void add_select_term_from_prop(TALLOC_CTX *ctx,
				     struct sparql_conv *sparql_conv,
				     const char *prop)
{
	struct tracker_detail *detail = get_tracker_detail(prop);
	struct tracker_pair_list *item;
	if (detail && detail->tracker_id) {
	 	/* limit tracker select items so columns are unique */
		if (list_contains_value(sparql_conv, detail)) {
			return;
		}
		item = talloc_zero(sparql_conv, struct tracker_pair_list);
		item->key = talloc_strdup(item, prop);
		item->value = detail;
		DLIST_ADD_END(sparql_conv->select, item);
	}
}

static void get_select(TALLOC_CTX *ctx,
			struct wsp_ccolumnset *columnset,
			struct wsp_cpidmapper *pidmapper,
			struct sparql_conv *sparql_conv)
{
	int i;
	if (!columnset) {
		return;
	}

	/*
	 * always insert url into select (and also into the where clause),
	 * this gives us a starting point to filter from, also it allows
	 * to use the property 'method' in select for retrieval (which
	 * avoids the penalties imposed by using 'OPTIONAL' in sparql query)
	 */
	add_select_term_from_prop(ctx, sparql_conv, "Path");
	for (i=0; i < columnset->count; i++) {
		int pid_index = columnset->indexes[i];
		struct wsp_cfullpropspec *prop_spec =
				&pidmapper->apropspec[pid_index];
		char *prop = prop_from_fullprop(ctx, prop_spec);
		add_select_term_from_prop(ctx, sparql_conv, prop);
		TALLOC_FREE(prop);
	}
}

static NTSTATUS rtcontent_to_string(TALLOC_CTX *ctx,
				    struct wsp_ccontentrestriction *content,
				    struct tracker_detail *detail,
				    const char **presult)
{
	const char *result = talloc_strdup(ctx, "");
	NTSTATUS status = NT_STATUS_OK;
	if (content->ulgeneratemethod) {
		result = talloc_asprintf(ctx, "regex(%s(?u),\'^%s\')",
					     detail->tracker_id,
					     content->pwcsphrase);
	} else {
		/* exact match */
		result = talloc_asprintf(ctx, "%s(?u) =\'%s\'",
					     detail->tracker_id,
					     content->pwcsphrase);
	}
	*presult = result;
	return status;
}

static NTSTATUS rtproperty_to_string(TALLOC_CTX *ctx,
				const char *operator,
				struct wsp_cpropertyrestriction *restrict_prop,
				struct tracker_detail *detail,
				const char **presult)
{
	const char *value = variant_as_string(ctx, &restrict_prop->prval, true);
	const char *result = talloc_strdup(ctx, "");
	NTSTATUS status = NT_STATUS_OK;
	result = talloc_asprintf(ctx, "%s(?u) %s %s", detail->tracker_id,
				 operator,
				 value);
	*presult = result;
	return status;
}

static NTSTATUS rtpropertycontainer_to_string(TALLOC_CTX *ctx,
					struct wsp_abstract_state *glob_data,
					struct wsp_crestriction *restriction,
					void *priv_data,
					const char **presult)
{
	struct wsp_cfullpropspec *prop_spec = get_full_prop(restriction);
	const char *prop = prop_from_fullprop(ctx, prop_spec);
	struct tracker_detail *detail = get_tracker_detail(prop);
	const char *result = talloc_strdup(ctx, "");
	NTSTATUS status = NT_STATUS_OK;
	if (detail && detail->tracker_id && !detail->filt_helper) {
		if (detail->filt_helper) {
			status = detail->filt_helper(ctx, detail,
						     restriction,
						     &result,
						     priv_data);
		} else {
			if (restriction->ultype == RTPROPERTY) {
				struct wsp_cpropertyrestriction *cprop;
				const char *operator =
					op_as_string(restriction);
				cprop = &restriction->restriction.cpropertyrestriction;
				status = rtproperty_to_string(ctx,
							      operator,
							      cprop,
							      detail,
							      &result);
			} else if (restriction->ultype == RTCONTENT) {
				struct wsp_ccontentrestriction *ccont;
				ccont =	&restriction->restriction.ccontentrestriction;
				status = rtcontent_to_string(ctx,
							     ccont,
							     detail,
							     &result);
			}
		}
	} else if (detail && detail->filt_helper) {
		status = detail->filt_helper(ctx, detail, restriction,
					     &result,
					     priv_data);
	}
	*presult = result;
	return status;
}

static NTSTATUS rtnatlang_to_string(TALLOC_CTX *ctx,
				struct wsp_abstract_state *glob_data,
				struct wsp_crestriction *restriction,
				const char **presult)
{
	struct wsp_cfullpropspec *prop_spec = get_full_prop(restriction);
	const char *prop = prop_from_fullprop(ctx, prop_spec);
	struct tracker_detail *detail = get_tracker_detail(prop);
	const char *result = talloc_strdup(ctx, "");
	struct wsp_cnatlanguagerestriction *cnat;
	NTSTATUS status;
	prop = prop_from_fullprop(ctx, prop_spec);
	detail = get_tracker_detail(prop);
	if (restriction->ultype != RTNATLANGUAGE) {
		DBG_ERR("unexpected type %d, expected RTNATLANGUAGE\n",
		      restriction->ultype);
		status = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}
	cnat = &restriction->restriction.cnatlanguagerestriction;
	if (detail && detail->tracker_id) {
		result = talloc_asprintf(ctx, "%s(?u)=%s",
					 detail->tracker_id,
					 cnat->pwcsphrase);
	}
	status = NT_STATUS_OK;
done:
	*presult = result;
	return status;
}

static NTSTATUS rtreusewhere_to_string(TALLOC_CTX *ctx,
					struct wsp_abstract_state *glob_data,
					struct wsp_crestriction *restriction,
					const char **result)
{
	int where_id;
	const char *tmp;
	NTSTATUS status;
	*result = talloc_strdup(ctx, "");
	where_id = restriction->restriction.reusewhere.whereid;
	DBG_DEBUG("SHARE reusewhereid %d\n", where_id);
	/*
	* Try get a previously built whereid string,
	* It's quite possible that a whereid points to a
	* restrictions set associated with a whereid that no
	* longer exists (e.g. the associated query has been
	* released). That's why we don't search for the
	* restriction array, instead we expect the
	* restriction string to be stored.
	* Note: the documentation is ambiguous about this,
	* it states the whereid refers to an open queries
	* restriction set, that's true but it failes to point
	* out that the restriction set (of the open query)
	* itself could have been built using a whereid that
	* is now 'released' thus we won't find the associated
	* restriction set of that 'nested' whereid
	*/
	tmp = get_where_restriction_string(glob_data, where_id);
	if (tmp && strlen(tmp)) {
		*result = talloc_strdup(ctx, tmp);
		DBG_NOTICE("detected a where id RTREUSEWHERE id=%d result = %s\n",
		      restriction->restriction.reusewhere.whereid,
		      tmp ? tmp : "None");
	} else {
		/*
		* this assumes the reason we have
		* no whereid string is because there is no
		* index, it's a pretty valid assumption
		* but I think getting the status from
		* maybe get_where_restriction_string might
		* be better
		*/
		DBG_ERR("no whereid => this share is not indexed\n");
		tmp = talloc_asprintf(ctx, "insert expression for WHEREID = %d",
				      restriction->restriction.reusewhere.whereid);
		/*
		 * if glob_data == NULL then we are more than likely being
		 * called from wsp_to_sparql and we don't want to propagate the
		 * status for this case
		 */
		if (glob_data != NULL) {
			status = NT_STATUS(0x80070003);
			goto done;
		}
	}
	status = NT_STATUS_OK;
done:
	*result = tmp;
	return status;
}

static const char* get_sort_string(TALLOC_CTX *ctx,
				   struct wsp_cpidmapper *pidmapper,
				   struct wsp_csortset *sorting)
{
	int i;
	int sort_index= 0;
	const char * sort_by[sorting->count];
	struct wsp_csort *order = sorting->sortarray;
	const char* sort_str = NULL;
	ZERO_STRUCT(sort_by);

	if (sorting->count == 0) {
		DBG_DEBUG("function called with a sorting->count of zero,"
			  " returning NULL");
	}
	for (i = 0; i < sorting->count; i++) {
		int pid_index = order[i].pidcolimn;
		struct wsp_cfullpropspec *prop_spec =
			&pidmapper->apropspec[pid_index];
		char *prop = prop_from_fullprop(ctx, prop_spec);
		struct tracker_detail *detail =
			get_tracker_detail(prop);

		/* search sparql_conv for a match to the sort term */
		if (detail && detail->tracker_id) {
			int j;
			if (order[i].dworder != QUERY_SORTASCEND &&
				order[i].dworder != QUERY_DESCEND) {
				DBG_ERR("Unknown sort order %d\n", order[i].dworder);
				return NULL;
			}
			if (sort_str == NULL) {
				sort_str =
					talloc_asprintf(ctx,
							"ORDER BY");
			}
			if (order[i].dworder) {
				sort_str = talloc_asprintf(ctx,
					"%s ASC(%s(?u))",
					sort_str,
					detail->tracker_id);
			} else {
				sort_str = talloc_asprintf(ctx,
					"%s DESC(%s(?u))",
					sort_str,
					detail->tracker_id);
			}
			/* don't try and order by the same col again */
			if (sort_index) {
				for (j = 0; j < sort_index; j++) {
					if (strequal(detail->tracker_id,
					     sort_by[j])) {
						DBG_INFO("### Already sorting by %s\n", detail->tracker_id);
						break;
					}
					else {
						sort_by[sort_index++] =
							detail->tracker_id;
					}
				}
			} else {
				sort_by[sort_index++] =
						detail->tracker_id;
			}
		}
	}
	return sort_str;
}
/*
 * convert_props if false won't attempt to convert wsp restriction
 * properties to tracker properties
 */
NTSTATUS build_tracker_query(TALLOC_CTX *ctx,
			     struct wsp_ccolumnset *select_cols,
			     const char* restriction_expr,
			     struct wsp_cpidmapper *pidmapper,
			     struct tracker_selected_cols *tracker_cols,
			     struct wsp_csortset *sorting,
			     bool convert_props,
			     const char **query)
{
	const char *select_str = NULL;
	const char *where_str = NULL;
	const char *filter_str = restriction_expr;
	const char *query_str = NULL;
	const char *sort_str = NULL;

	struct tracker_pair_list *item = NULL;
	struct sparql_conv *sparql_conv = talloc_zero(ctx, struct sparql_conv);
	bool has_kind = false;
	NTSTATUS status = NT_STATUS_OK;

	get_select(ctx,select_cols, pidmapper, sparql_conv);
	item = sparql_conv->select;

	/* add 1 for the default Path item we always add */
	tracker_cols->tracker_ids = talloc_zero_array(ctx, const char *, select_cols->count + 1);
	if (item) {
		select_str = talloc_strdup(ctx, "SELECT");
		for (; item; item = item->next) {
			/* skip those we can't handle */
			if (item->key) {
				int i = tracker_cols->cols;
				select_str =
					talloc_asprintf(
						ctx,
						("%s %s(?u)"),
						select_str,
						item->value->tracker_id);
				tracker_cols->tracker_ids[i] =
					talloc_strdup(ctx,
						      item->value->tracker_id);
				tracker_cols->cols++;
			}
		}
		talloc_realloc(ctx, tracker_cols->tracker_ids, char *,
			       tracker_cols->cols);
	}
	if (filter_str && strlen(filter_str)) {
		filter_str = talloc_asprintf(ctx, ("FILTER%s"),
					     filter_str);
	}

	if (strstr(filter_str, "?type IN ")) {
		/* System.Kind is used in restrictions */
		has_kind = true;
	}
	if (has_kind) {
		where_str = talloc_strdup(ctx, "WHERE{?u nie:url ?url . ?u rdf:type ?type");
	} else {
		where_str = talloc_strdup(ctx, "WHERE{?u nie:url ?url");
	}

	if (sorting) {
		sort_str = get_sort_string(ctx, pidmapper, sorting);
		if (sort_str == NULL) {
			DBG_DEBUG("a SortSet was given, but no sort_str created\n");
			return NT_STATUS_INVALID_PARAMETER;
		}
	}

	where_str = talloc_asprintf(ctx, "%s %s}", where_str,
		strlen(filter_str) ? filter_str : "");
	query_str = talloc_asprintf(ctx, "%s %s %s", select_str, where_str,
			sort_str ? sort_str : "");
	*query = query_str;
	return status;
}

bool build_mapper(TALLOC_CTX *ctx, struct wsp_ctablecolumn *columns, uint32_t ncols,  struct tracker_selected_cols *tracker_cols,
		  struct binding_result_mapper *mapper)
{
	int i, j;
	/*
	 * walk through the bindings and find if any returned tracker cols
	 * match
	 *
	 */
	mapper->map_data = talloc_zero_array(ctx, struct map_data, ncols);
	mapper->ncols = ncols;
	for (i = 0; i < ncols; i++) {
		const char *wsp_id = prop_from_fullprop(ctx,
							  &columns[i].propspec);

		struct tracker_detail *conv = get_tracker_detail(wsp_id);
		mapper->map_data[i].vtype = VT_NULL;
		if (conv && conv->tracker_id) {
			for (j = 0; j < tracker_cols->cols; j++) {
				if (strequal(conv->tracker_id,
					     tracker_cols->tracker_ids[j])
				    && conv->convert_fn) {
					/*
					 * store the col where we can find
					 * the tracker value we can use to
					 * convert or synthesize into wsp
					 * property value
					 */
					if (strequal(wsp_id,
					     "System.Search.EntryID")
					   ||(strequal(wsp_id,
					     "System.Important.Unknown"))) {
						DBG_DEBUG("special handling for %s\n", wsp_id);
						mapper->map_data[i].col_with_value = tracker_cols->cols;
					} else {
						mapper->map_data[i].col_with_value = j;
					}
					mapper->map_data[i].convert_fn =
							conv->convert_fn;
					mapper->map_data[i].vtype =
							columns[i].vtype;
					DBG_DEBUG("mapping binding[%d] %s to tracker returned col %d %s\n", i, conv->wsp_id, j, tracker_cols->tracker_ids[j]);
					break;
				}
			}
		}
	}
	return true;
}


static NTSTATUS infix(TALLOC_CTX *ctx,
		      struct wsp_abstract_state *glob_data,
		      struct wsp_crestriction *restriction,
		      void *priv_data,
		      const char **result);

static NTSTATUS print_restriction(TALLOC_CTX *ctx,
				  struct wsp_abstract_state *glob_data,
				  struct wsp_crestriction *restriction,
				  const char** presult,
				  void *priv_data)
{
	const char *result = NULL;
	const char *tmp;
	NTSTATUS status = NT_STATUS_OK;

	if (is_operator(restriction)) {
		result = op_as_string(restriction);
	} else {
		switch(restriction->ultype) {
			case RTCONTENT:
			case RTPROPERTY: {
				status = rtpropertycontainer_to_string(ctx,
							   glob_data,
							   restriction,
							   priv_data,
							   &tmp);
				if (strlen(tmp)) {
					result = tmp;
				}
				break;
			}
			case RTNATLANGUAGE:
				status = rtnatlang_to_string(ctx,
							     glob_data,
							     restriction,
							     &tmp);
				if (strlen(tmp)) {
					result = tmp;
				}
				break;
			case RTCOERCE_ABSOLUTE: {
				struct wsp_crestriction *child_restrict =
					restriction->restriction.ccoercionrestriction_abs.childres;
				status = infix(ctx, glob_data, child_restrict, priv_data, &result);
				break;
			}
			case RTREUSEWHERE: {
				if (priv_data) {
					struct filter_data *data =
						(struct filter_data *)priv_data;
					data->where_id =
						restriction->restriction.reusewhere.whereid;
				}
				tmp = NULL;
				status = rtreusewhere_to_string(ctx,
							glob_data,
							restriction,
							&tmp);
				if (tmp && strlen(tmp)) {
					result = tmp;
				}
				break;
			}
		}
	}
	*presult = result;
	return status;
}

static bool is_andor(struct wsp_crestriction *restriction)
{
	if (restriction->ultype == RTAND || restriction->ultype == RTOR) {
		return true;
	}
	return false;
}

static NTSTATUS infix(TALLOC_CTX *ctx, struct  wsp_abstract_state *glob_data,
			 struct wsp_crestriction *restriction,
			 void *priv_data,
			 const char **result)
{
	const char *tmp = NULL;
	const char *token = NULL;
	const char *left_node = NULL;
	const char *right_node = NULL;
	struct wsp_crestriction *left = NULL;
	struct wsp_crestriction *right = NULL;
	NTSTATUS status;
	if (!restriction) {
		return NT_STATUS_UNSUCCESSFUL;
	}
	if (is_operator(restriction)) {
		if (is_andor(restriction)) {
			struct wsp_cnoderestriction *cnodes =
				&restriction->restriction.cnoderestriction;
			if (cnodes->cnode) {
				left = &cnodes->panode[0];
				if (cnodes->cnode > 1) {
					right = &cnodes->panode[1];
				}
			}
		} else {
			right = restriction->restriction.restriction.restriction;
		}
	}
	if (left) {
		status = infix(ctx, glob_data, left, priv_data, &left_node);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}
	status = print_restriction(ctx, glob_data, restriction, &token, priv_data);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (right) {
		status = infix(ctx, glob_data, right, priv_data, &right_node);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	if (is_operator(restriction)) {
		if (is_andor(restriction) == false && right_node && strlen(right_node)) {
			tmp = talloc_asprintf(ctx, "(%s%s)",
				token,
				right_node);
		} else if (left_node && strlen(left_node) && right_node && strlen(right_node)) {
			tmp = talloc_asprintf(ctx, "(%s%s%s)", left_node,
							token, right_node);
		} else {
			tmp = talloc_asprintf(ctx, "(%s%s)",
					left_node ? left_node : "",
					right_node ? right_node : "");
		}
	} else {
		tmp = talloc_asprintf(ctx, "%s%s%s",
				left_node ? left_node : "",
				token ? token : "",
				right_node ? right_node : "");
	}

	if (strequal(tmp, "()")) {
		tmp = NULL;
	}
	*result = tmp;
	return status;
}

NTSTATUS build_restriction_expression(TALLOC_CTX *ctx,
		       struct wsp_abstract_state *glob_data,
		       struct wsp_crestrictionarray *restrictarray,
		       bool convert_props,
		       const char **restrict_expr,
		       const char** share_scope,
		       uint32_t *where_id)
{
	const char * query = NULL;
	NTSTATUS status = NT_STATUS_OK;
	struct filter_data data;

	ZERO_STRUCT(data);
	if (restrictarray->count) {
		if (convert_props == false) {
			query =
				raw_restriction_to_string(ctx,
						&restrictarray->restrictions[0]);
			if (!query) {
				status = NT_STATUS_INVALID_PARAMETER;
			}
		} else {
			status = infix(ctx,
				      glob_data,
				      &restrictarray->restrictions[0],
				      &data,
				      &query);
		}
	}
	*restrict_expr = query;
	*share_scope = data.share_scope;
	*where_id = data.where_id;
	return status;
}

static bool can_open_url(struct connection_struct *conn, const char* url)
{
	const char* local_share_path = NULL;
	struct smb_filename *smb_fname = NULL;
	bool result;
	files_struct *fsp = NULL;
	int info;
	TALLOC_CTX *ctx = talloc_init("url");
	NTSTATUS status;
	local_share_path = talloc_strdup(ctx, url + strlen(scheme));
#if 0
	/*
	 * #TODO in smbd the relative path is used here (afaik), however trying
	 * that here fails (get an OBJECT_NOT_FOUND) it seems to expect
	 * the parents of the url to be cached I think,
	 * (but I am guessing I am not tapping into the correct  way of doing
	 * things).
	 * if we use filename_convert perhaps we could cache the mangled name
	 * that I am guessing is returned instead of manually doing that later
	 * in the code
	 */
	status = filename_convert(ctx, conn, 0,
				  local_share_path, ucf_flags,
				  NULL, /* ppath_contains_wcards */
				  &smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("failed converting %s %s\n", local_share_path, nt_errstr(status));
		result = false;
		goto out;
	}
#else
	smb_fname = synthetic_smb_fname(ctx, local_share_path, NULL, NULL, 0);
	if (!smb_fname) {
		result = false;
		goto out;
	}
	if ((SMB_VFS_STAT(conn, smb_fname) == -1) && (errno == ENOENT)) {
		result = false;
		goto out;
	}

#endif

	status = SMB_VFS_CREATE_FILE(conn,
				     NULL,
				     0, /* root_dir_fid */
				     smb_fname,
				     /* 0x120089 stolen from debug of share access, need to breakdown the flags */
				     0x120089,
				     5,
				     1,
				     64,
				     0,
				     INTERNAL_OPEN_ONLY,
				     NULL,
				     0,
				     0, /* private_flags */
				     NULL,
				     NULL,
				     &fsp,
				     &info,
				     NULL,
				     NULL);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("failed to open file %s %s\n", url, nt_errstr(status));
		result = false;
		goto out;
	}
	result = true;
	close_file(NULL, fsp, NORMAL_CLOSE);
out:
	TALLOC_FREE(ctx);
	return result;
}

bool
can_access_url(struct connection_struct *conn, const char* url)
{
	/*
	 * seems the easiest way to test if we have permission is to try open
	 * file pointed by the url for reading.
	 */
	return can_open_url(conn, url);
}

void filter_tracker_rows(struct tracker_row **rows,
			 struct connection_struct *conn,
			 struct auth_session_info *session_info,
			 uint32_t rows_limit,
			 uint32_t *num_rows)
{
	struct tracker_row *list = *rows;
	struct tracker_row *item = list;
	TALLOC_CTX *frame = talloc_stackframe();
	int id = 1;
	become_user_by_session(conn, session_info);
	/*
	 * #TODO think about limiting the number of returned rows here
	 * maybe we should even think about limiting the number of unfiltered
	 * rows we read (before filtering)
	 */
	while (item) {
		struct tracker_row *next = item->next;
		struct tracker_col_data *col =
					&item->columns[0];
		const char *url = col->type.string;
		if (!can_access_url(conn, url)) {
			DLIST_REMOVE(list, item);
			TALLOC_FREE(item);
			(*num_rows)--;
		} else {
			/* populate EntryId in extra 'hidden' column*/
			item->columns[item->ncols - 1].tracker_type =
				TRACKER_INTEGER;
			item->columns[item->ncols - 1].type.integer = id++;
			if (rows_limit && (id - 1 >= rows_limit)) {
				item = next;
				while(item) {
					next = item->next;
					DLIST_REMOVE(list, item);
					TALLOC_FREE(item);
					(*num_rows)--;
					item = next;
				}
				goto out;
			}
		}

		item = next;
	}
out:
	*rows = list;
	unbecome_user();
	TALLOC_FREE(frame);
}
