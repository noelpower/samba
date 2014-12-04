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

#ifndef __WSP_SRV_SPARQL__
#define __WSP_SRV_SPARQL__
#include "bin/default/librpc/gen_ndr/ndr_wsp.h"

struct messaging_context;
struct tevent_context;
struct named_pipe_client;
struct wspd_client_state;
struct gss_state;
struct wsp_client_data;


struct wspd_client_state
{
	struct wsp_abstract_state *wsp_abstract_state;
	struct wsp_client_data *client_data;
};

struct tevent_req *do_wsp_request_send(TALLOC_CTX *ctx,
				       struct wspd_client_state *client_state);
void client_disconnected(struct wspd_client_state *state);
struct wspd_client_state *create_client_state(struct named_pipe_client *npc,
					      struct gss_state *gss_state);
struct gss_state *gss_state_create(struct tevent_context *event_ctx,
				   struct messaging_context *msg_ctx);
bool gss_init(struct gss_state *state);
/* not specified by MS-WSP */
typedef struct wsp_abstract_state *(*Init_fn)(struct tevent_context *event_ctx,
			struct messaging_context *msg_ctx);
/* not specified by MS-WSP */
typedef struct wsp_ctablecolumn *(*GetBindings_fn)(struct wspd_client_state *client_state,
						   uint32_t QueryIdentifier,
						   uint32_t CursorHandle,
						   uint32_t *ncols);
typedef bool (*IsCatalogAvailable_fn)(struct wspd_client_state *client_state,
				      const char *CatalogName);
typedef void (*GetServerVersions_fn)(struct wspd_client_state* client_state,
				     uint32_t *dwWinVerMajor,
				     uint32_t *dwWinVerMinor,
				     uint32_t *dwNLSVerMajor,
				     uint32_t *dwNLSVerMinor,
				     uint32_t *serverVersion,
				     bool *supportsVersioningInfo);
typedef struct tevent_req *(*GetState_fn)(TALLOC_CTX *ctx,
					  struct wspd_client_state *client_state,
					  struct wsp_cpmcistateinout *out);
typedef void (*StoreClientInformation_fn)(struct wspd_client_state *wspd_client_state,
					  uint32_t QueryIdentifier,
					  struct wsp_cpmconnectin *ConnectMessage,
					  uint32_t NamedPipeHandle);

typedef struct wsp_cpmconnectin *(*GetClientInformation_fn)(struct wspd_client_state *wsp_client, uint32_t QueryIdentifier);
typedef struct tevent_req *(*RunNewQuery_fn)(
				TALLOC_CTX *ctx,
				struct wspd_client_state *client_state,
				uint32_t QueryIdentifier,
				struct wsp_ccolumnset *ProjectionColumnsOffsets,
				struct wsp_crestrictionarray *RestrictionSet,
				struct wsp_csortset *SortOrders,
				struct wsp_ccategorizationset *Groupings,
				struct wsp_crowsetproperties *RowSetProperties,
				struct wsp_cpidmapper *PidMapper,
				struct wsp_ccolumngrouparray *GroupArray,
				uint32_t Lcid, uint32_t *QueryParametersError,
				uint32_t **CursorHandlesList,
				bool *fTrueSequential, bool *fWorkidUnique,
				bool *CanQueryNew);
typedef bool (*ClientQueryHasCursorHandle_fn)(struct wspd_client_state *wspd_client_state,
					      uint32_t QueryIdentifier,
					      uint32_t CursorHandle);
typedef struct tevent_req *(*GetQueryStatus_fn)(TALLOC_CTX *ctx,
						struct wspd_client_state *wspd_client_state,
						uint32_t QueryIdentifier,
						uint32_t *QueryStatus);

typedef struct tevent_req *(*GetRatioFinishedParams_fn)(TALLOC_CTX *ctx,
						struct wspd_client_state *wspd_client_state,
						uint32_t QueryIdentifier,
						uint32_t CursorHandle,
						uint32_t *rdwRatioFinishedDenominator,
						uint32_t *rdwRatioFinishedNumerator,
						uint32_t *cRows,
						uint32_t *fNewRows);
typedef uint32_t (*GetApproximatePosition_fn)(struct wspd_client_state *wspd_client_state,
					      uint32_t QueryIdentifier,
					      uint32_t CursorHandle,
					      uint32_t Bmk);
typedef uint32_t (*GetWhereid_fn)(struct wspd_client_state *wspd_client_state,
				  uint32_t QueryIdentifier);
typedef struct tevent_req *(*GetExpensiveProperties_fn)(TALLOC_CTX *ctx,
							struct wspd_client_state *wspd_client_state,
							uint32_t QueryIdentifier,
							uint32_t CursorHandle,
							/* out */
							uint32_t *rcRowsTotal,
							uint32_t *rdwResultCount,
							uint32_t *Maxrank);
typedef bool (*HasBindings_fn)(struct wspd_client_state *wspd_client_state,
			       uint32_t QueryIdentifier,
			       uint32_t CursorHandle);
typedef uint32_t (*GetBookmarkPosition_fn)(struct wspd_client_state *wspd_client_state,
					   uint32_t QueryIdentifier,
					   uint32_t CursorHandle,
					   uint32_t bmkHandle);
typedef void (*SetNextGetRowsPosition_fn)(struct wspd_client_state *wspd_client_state,
					  uint32_t QueryIdentifier,
					  uint32_t CursorHandle,
					  uint32_t Chapter,
					  uint32_t Index);

typedef uint32_t (*GetNextGetRowsPosition_fn)(struct wspd_client_state *wspd_client_state,
					      uint32_t QueryIdentifier,
					      uint32_t CursorHandle,
					      uint32_t Chapter);
typedef struct tevent_req *(*GetRows_fn)(TALLOC_CTX *ctx,
					 struct wspd_client_state *wspd_client_state,
					 uint32_t QueryIdentifier,
					 uint32_t CursorHandle,
					 uint32_t NumRowsRequested,
					 uint32_t FetchForward,
					 /* out */
					 struct wsp_cbasestoragevariant **RowsArray,
					 bool *NoMoreRowsToReturn,
					 uint32_t *NumRowsReturned,
					 uint32_t *Error);
typedef bool (*HasAccessToWorkid_fn)(struct wspd_client_state *wspd_client_state,
				     uint32_t QueryIdentifier,
				     uint32_t Workid);
typedef bool (*HasAccessToProperty_fn)(struct wspd_client_state *wspd_client_state,
				       uint32_t QueryIdentifier,
				       struct wsp_cfullpropspec *PropSpec);

typedef void (*GetPropertyValueForWorkid_fn)(struct wspd_client_state *wspd_client_state,
					     uint32_t QueryIdentifier,
					     uint32_t Workid,
					     struct wsp_cfullpropspec *PropSpec,
					     struct wsp_serializedpropertyvalue *property,
					     bool *ValueExists);
typedef void (*SetBindings_fn)(struct wspd_client_state *wspd_client_state,
			       uint32_t QueryIdentifier,
			       uint32_t CursorHandle,
			       struct wsp_ctablecolumn *Columns,
			       uint32_t nColumns);
typedef void (*GetQueryStatusChanges_fn)(struct wspd_client_state *wspd_client_state,
					 uint32_t QueryIdentifier,
					 uint32_t CursorHandle,
			       		 /* out */
			       		 uint32_t *LatestChange,
					 bool *ChangesPresent);
typedef uint32_t (*ReleaseCursor_fn)(struct wspd_client_state *wspd_client_state,
				     uint32_t QueryIdentifier,
				     uint32_t CursorHandle);
typedef struct tevent_req *(*ReleaseQuery_fn)(TALLOC_CTX* ctx,
					      struct wspd_client_state *wspd_client_state,
					      uint32_t QueryIdentifier);
typedef bool (*FindNextOccurrenceIndex_fn)(struct wspd_client_state *wspd_client_state,
					   uint32_t QueryIdentifier,
					   uint32_t *PrevOccCoordinatesList,
					   uint32_t numPrevItems,
					   /* out */
					   uint32_t *NextOccCoordinatesList,
					   uint32_t *numNextItems);

typedef void (*GetLastUnretrievedEvent_fn)(struct wspd_client_state *wspd_client_state,
					   uint32_t QueryIdentifier,
					   /* out */
					   uint32_t *Wid,
					   uint8_t *EventType,
					   bool *MoreEvents,
					   uint8_t *RowsetItemState,
					   uint8_t *ChangedItemState,
					   uint8_t *RowsetEvent,
					   uint64_t *RowsetEventData1,
					   uint64_t *RowsetEventData2);
typedef NTSTATUS (*GetQueryStatistics_fn)(struct wspd_client_state *wspd_client_state,
					  uint32_t QueryIdentifier,
					  uint32_t *NumIndexedItems,
					  uint32_t *NumOutstandingAdds,
					  uint32_t *NumOutstandingModifies);
typedef NTSTATUS (*SetScopePriority_fn)(struct wspd_client_state *wspd_client_state,
					uint32_t QueryIdentifier,
					uint32_t Priority);

typedef void (*FilterOutScopeStatisticsMessages_fn)(struct wspd_client_state *wspd_client_state,
						    uint32_t QueryIdentifier);
typedef void (*Inflect_fn)(struct wspd_client_state *wspd_client_state,
			   const char* phrase,
			   /* out */
			   const char **inflections,
			   uint32_t inflectionsCount);
typedef void (*GenerateScopeStatisticsEvent_fn)(struct wspd_client_state *wspd_client_state,
						uint32_t QueryIdentifier);


struct wsp_abstract_interface
{
	Init_fn Initialise;
	IsCatalogAvailable_fn IsCatalogAvailable;
	GetServerVersions_fn GetServerVersions;
	GetState_fn GetState_send;
	StoreClientInformation_fn StoreClientInformation;
	GetClientInformation_fn GetClientInformation;
	RunNewQuery_fn RunNewQuery_send;
	ClientQueryHasCursorHandle_fn ClientQueryHasCursorHandle;
	GetQueryStatus_fn GetQueryStatus_send;
	GetRatioFinishedParams_fn GetRatioFinishedParams_send;
	GetApproximatePosition_fn GetApproximatePosition;
	GetWhereid_fn GetWhereid;
	GetExpensiveProperties_fn GetExpensiveProperties_send;
	HasBindings_fn HasBindings;
	GetBookmarkPosition_fn GetBookmarkPosition;
	SetNextGetRowsPosition_fn SetNextGetRowsPosition;
	GetNextGetRowsPosition_fn GetNextGetRowsPosition;
	GetRows_fn GetRows_send;
	HasAccessToWorkid_fn HasAccessToWorkid;
	HasAccessToProperty_fn HasAccessToProperty;
	GetPropertyValueForWorkid_fn GetPropertyValueForWorkid;
	GetQueryStatusChanges_fn GetQueryStatusChanges;
	SetBindings_fn SetBindings;
	GetBindings_fn GetBindings;
	ReleaseCursor_fn ReleaseCursor;
	ReleaseQuery_fn ReleaseQuery_send;
	FindNextOccurrenceIndex_fn FindNextOccurrenceIndex;
	GetLastUnretrievedEvent_fn GetLastUnretrievedEvent;
	GetQueryStatistics_fn GetQueryStatistics;
	SetScopePriority_fn SetScopePriority;
	FilterOutScopeStatisticsMessages_fn FilterOutScopeStatisticsMessages;
	Inflect_fn Inflect;
	GenerateScopeStatisticsEvent_fn GenerateScopeStatisticsEvent;
};

struct pipes_struct *get_pipe(struct wspd_client_state* client_state);
#endif// __WSP_SRV_SPARQL__
