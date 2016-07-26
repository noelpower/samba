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

struct full_guid_propset {
	struct GUID guid;
	const struct full_propset_info *prop_info;
};

static const struct full_propset_info guid_properties_0[] = {
	{0x64,"System.Calendar.IsOnline",VT_BOOL, true, false, true, false, 2},
	{0,NULL}
};

static const struct full_propset_info guid_properties_1[] = {
	{0x64,"System.Contact.OtherAddressStreet",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_2[] = {
	{0x64,"System.ThumbnailCacheId",VT_UI8, true, false, true, false, 8},
	{0,NULL}
};

static const struct full_propset_info guid_properties_3[] = {
	{0x2,"System.DRM.IsProtected",VT_BOOL, true, false, true, false, 2},
	{0,NULL}
};

static const struct full_propset_info guid_properties_4[] = {
	{0x64,"System.Calendar.OptionalAttendeeNames",VT_LPWSTR | VT_VECTOR, true, true, true, false, 256},
	{0,NULL}
};

static const struct full_propset_info guid_properties_5[] = {
	{0x64,"System.Calendar.ShowTimeAs",VT_UI2, true, false, true, false, 2},
	{0,NULL}
};

static const struct full_propset_info guid_properties_6[] = {
	{0x3,"System.Kind",VT_LPWSTR | VT_VECTOR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_7[] = {
	{0x8,"System.Message.HasAttachments",VT_BOOL, true, false, true, false, 2},
	{0x5,"System.Priority",VT_UI2, true, false, true, false, 2},
	{0,NULL}
};

static const struct full_propset_info guid_properties_8[] = {
	{0x64,"System.ParentalRatingReason",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_9[] = {
	{0x64,"System.Contact.OtherAddressCountry",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_10[] = {
	{0x9,"System.Status",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_11[] = {
	{0x64,"System.DateArchived",VT_FILETIME, true, false, true, false, 8},
	{0,NULL}
};

static const struct full_propset_info guid_properties_12[] = {
	{0x64,"System.Contact.CarTelephone",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_13[] = {
	{0x5,"System.ComputerName",VT_LPWSTR, true, false, true, false, 512},
	{0x8,"System.ItemPathDisplayNarrow",VT_LPWSTR, true, false, true, false, 520},
	{0xb,"System.ItemType",VT_LPWSTR, true, true, true, false, 512},
	{0x18,"System.ParsingName",VT_LPWSTR, true, true, true, false, 520},
	{0x19,"System.SFGAOFlags",VT_UI4, true, false, true, false, 4},
	{0x9,"PercivedType",VT_I4, false, false, false, true, 0},
	{0xc,"FileCount",VT_UI8, false, false, false, true, 0},
	{0xe,"TotalFileSize",VT_UI8, false, false, false, true, 0},
	{0,NULL}
};

static const struct full_propset_info guid_properties_14[] = {
	{0x64,"System.Calendar.ResponseStatus",VT_UI2, true, false, true, false, 2},
	{0,NULL}
};

static const struct full_propset_info guid_properties_15[] = {
	{0x64,"System.Task.BillingInformation",VT_LPWSTR, true, true, false, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_16[] = {
	{0x64,"System.Calendar.Duration",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_17[] = {
	{0x64,"System.Message.SenderName",VT_LPWSTR, true, true, true, false, 256},
	{0,NULL}
};

static const struct full_propset_info guid_properties_18[] = {
	{0x64,"System.Document.DocumentID",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_19[] = {
	{0x64,"System.RecordedTV.NetworkAffiliation",VT_LPWSTR, true, false, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_20[] = {
	{0x64,"System.PriorityText",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_21[] = {
	{0x64,"System.Contact.Children",VT_LPWSTR | VT_VECTOR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_22[] = {
	{0x64,"System.RecordedTV.RecordingTime",VT_FILETIME, true, false, true, false, 8},
	{0,NULL}
};

static const struct full_propset_info guid_properties_23[] = {
	{0x64,"System.FlagColorText",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_24[] = {
	{0x64,"System.Contact.OtherAddressPostalCode",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_25[] = {
	{0x64,"System.Photo.SharpnessText",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_26[] = {
	{0x64,"System.Contact.OtherAddress",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_27[] = {
	{0x2,"System.Search.AutoSummary",VT_LPWSTR, true, false, true, false, 2048},
	{0,NULL}
};

static const struct full_propset_info guid_properties_28[] = {
	{0x64,"System.Contact.BusinessAddress",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_29[] = {
	{0x64,"System.IsIncomplete",VT_BOOL, true, false, true, false, 2},
	{0,NULL}
};

static const struct full_propset_info guid_properties_30[] = {
	{0x64,"System.Contact.EmailAddress2",VT_LPWSTR, true, true, true, false, 256},
	{0,NULL}
};

static const struct full_propset_info guid_properties_31[] = {
	{0x64,"System.Contact.BusinessTelephone",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_32[] = {
	{0x64,"System.RecordedTV.StationName",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_33[] = {
	{0xa,"System.ContentUrl",VT_LPWSTR, true, true, true, false, 4168},
	{0x9,"System.ItemUrl",VT_LPWSTR, true, true, true, false, 4168},
	{0x5,"System.Search.EntryID",VT_I4, true, false, true, false, 4},
	{0x4,"System.Search.HitCount",VT_I4, true, false, true, false, 4},
	{0x3,"System.Search.Rank",VT_I4, true, false, true, false, 4},
	{0x8,"System.Search.ReverseFileName",VT_LPWSTR, true, true, true, false, 520},
	{0x2,"RankVector",VT_UI4 | VT_VECTOR, false, false, false, true, 0},
	{0x6,"All",VT_LPWSTR, false, false, false, true, 0},
	{0xf,"System.Important.Unknown",VT_I4, false, false, false, true, 0},
	{0,NULL}
};

static const struct full_propset_info guid_properties_34[] = {
	{0x64,"System.Image.CompressionText",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_35[] = {
	{0x64,"System.Contact.HomeAddressState",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_36[] = {
	{0x64,"System.Contact.EmailAddress3",VT_LPWSTR, true, true, true, false, 256},
	{0,NULL}
};

static const struct full_propset_info guid_properties_37[] = {
	{0x64,"System.Music.IsCompilation",VT_BOOL, true, false, true, false, 2},
	{0,NULL}
};

static const struct full_propset_info guid_properties_38[] = {
	{0x64,"System.Communication.FollowupIconIndex",VT_I4, true, false, true, false, 4},
	{0,NULL}
};

static const struct full_propset_info guid_properties_39[] = {
	{0x64,"System.Photo.TagViewAggregate",VT_LPWSTR | VT_VECTOR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_40[] = {
	{0x64,"System.Message.ToDoTitle",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_41[] = {
	{0x64,"System.Search.Store",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_42[] = {
	{0x64,"System.FileName",VT_LPWSTR, true, true, true, false, 520},
	{0,NULL}
};

static const struct full_propset_info guid_properties_43[] = {
	{0x64,"System.Contact.HomeAddressStreet",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_44[] = {
	{0x64,"System.Contact.HomeAddressPostalCode",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_45[] = {
	{0x64,"System.Contact.BusinessHomePage",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_46[] = {
	{0x64,"System.Message.ConversationID",VT_LPWSTR, true, true, true, false, 512},
	{0x65,"System.Message.ConversationIndex",VT_BLOB_OBJECT, true, false, true, false, 1024},
	{0,NULL}
};

static const struct full_propset_info guid_properties_47[] = {
	{0x64,"System.Calendar.RequiredAttendeeNames",VT_LPWSTR | VT_VECTOR, true, true, true, false, 256},
	{0,NULL}
};

static const struct full_propset_info guid_properties_48[] = {
	{0xb,"System.Copyright",VT_LPWSTR, true, true, true, false, 512},
	{0xd,"System.Media.ClassPrimaryID",VT_LPWSTR, true, false, true, false, 512},
	{0xe,"System.Media.ClassSecondaryID",VT_LPWSTR, true, false, true, false, 512},
	{0x18,"System.Media.CollectionGroupID",VT_LPWSTR, true, false, true, false, 512},
	{0x19,"System.Media.CollectionID",VT_LPWSTR, true, false, true, false, 512},
	{0x12,"System.Media.ContentDistributor",VT_LPWSTR, true, false, true, false, 512},
	{0x1a,"System.Media.ContentID",VT_LPWSTR, true, false, true, false, 512},
	{0x1b,"System.Media.CreatorApplication",VT_LPWSTR, true, true, true, false, 512},
	{0x1c,"System.Media.CreatorApplicationVersion",VT_LPWSTR, true, true, true, false, 512},
	{0xf,"System.Media.DVDID",VT_LPWSTR, true, false, true, false, 512},
	{0x24,"System.Media.EncodedBy",VT_LPWSTR, true, true, true, false, 512},
	{0x10,"System.Media.MCDI",VT_LPWSTR, true, false, true, false, 512},
	{0x11,"System.Media.MetadataContentProvider",VT_LPWSTR, true, false, true, false, 512},
	{0x16,"System.Media.Producer",VT_LPWSTR | VT_VECTOR, true, true, true, false, 256},
	{0x26,"System.Media.ProtectionType",VT_LPWSTR, true, false, true, false, 512},
	{0x27,"System.Media.ProviderRating",VT_LPWSTR, true, false, true, false, 512},
	{0x28,"System.Media.ProviderStyle",VT_LPWSTR, true, false, true, false, 512},
	{0x1e,"System.Media.Publisher",VT_LPWSTR, true, true, true, false, 512},
	{0x23,"System.Media.UniqueFileIdentifier",VT_LPWSTR, true, false, true, false, 512},
	{0x29,"System.Media.UserNoAutoInfo",VT_LPWSTR, true, false, true, false, 512},
	{0x22,"System.Media.UserWebUrl",VT_LPWSTR, true, false, true, false, 4168},
	{0x17,"System.Media.Writer",VT_LPWSTR | VT_VECTOR, true, true, true, false, 256},
	{0x13,"System.Music.Composer",VT_LPWSTR | VT_VECTOR, true, true, true, false, 256},
	{0x1f,"System.Music.Period",VT_LPWSTR, true, true, true, false, 512},
	{0x15,"System.ParentalRating",VT_LPWSTR, true, true, true, false, 512},
	{0x9,"System.Rating",VT_UI4, true, false, true, false, 4},
	{0x14,"System.Video.Director",VT_LPWSTR | VT_VECTOR, true, true, true, false, 256},
	{0,NULL}
};

static const struct full_propset_info guid_properties_49[] = {
	{0x64,"System.Message.ProofInProgress",VT_BOOL, true, false, true, false, 2},
	{0,NULL}
};

static const struct full_propset_info guid_properties_50[] = {
	{0x64,"System.Contact.PrimaryAddressPostOfficeBox",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_51[] = {
	{0x64,"System.Calendar.IsRecurring",VT_BOOL, true, false, true, false, 2},
	{0,NULL}
};

static const struct full_propset_info guid_properties_52[] = {
	{0x64,"System.Contact.HomeAddress",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_53[] = {
	{0x64,"System.ItemParticipants",VT_LPWSTR | VT_VECTOR, true, true, true, false, 256},
	{0,NULL}
};

static const struct full_propset_info guid_properties_54[] = {
	{0x64,"System.Media.DateReleased",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_55[] = {
	{0x64,"System.Journal.Contacts",VT_LPWSTR | VT_VECTOR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_56[] = {
	{0x64,"System.Contact.Gender",VT_LPWSTR, true, true, true, false, 512},
	{0x65,"System.Contact.GenderValue",VT_UI2, true, false, true, false, 2},
	{0,NULL}
};

static const struct full_propset_info guid_properties_57[] = {
	{0x67,"System.Message.MessageClass",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_58[] = {
	{0x64,"System.FlagColor",VT_UI2, true, false, true, false, 2},
	{0,NULL}
};

static const struct full_propset_info guid_properties_59[] = {
	{0x64,"System.Calendar.OrganizerName",VT_LPWSTR, true, true, true, false, 256},
	{0,NULL}
};

static const struct full_propset_info guid_properties_60[] = {
	{0x3,"System.Link.TargetSFGAOFlagsStrings",VT_LPWSTR | VT_VECTOR, true, true, false, false, 512},
	{0x2,"System.Shell.SFGAOFlagsStrings",VT_LPWSTR | VT_VECTOR, true, true, false, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_61[] = {
	{0x64,"System.Photo.PeopleNames",VT_LPWSTR | VT_VECTOR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_62[] = {
	{0x7,"System.Audio.ChannelCount",VT_UI4, true, false, true, false, 4},
	{0x4,"System.Audio.EncodingBitrate",VT_UI4, true, false, true, false, 4},
	{0x5,"System.Audio.SampleRate",VT_UI4, true, false, true, false, 4},
	{0x6,"System.Audio.SampleSize",VT_UI4, true, false, true, false, 4},
	{0x3,"System.Media.Duration",VT_UI8, true, false, true, false, 8},
	{0,NULL}
};

static const struct full_propset_info guid_properties_63[] = {
	{0x2,"DBPROP_CI_CATALOG_NAME",VT_LPWSTR, false, false, false, true, 0},
	{0x3,"DBPROP_CI_INCLUDE_SCOPES",VT_LPWSTR | VT_VECTOR, false, false, false, true, 0},
	{0x4,"DBPROP_CI_SCOPE_FLAGS",VT_I4 | VT_VECTOR, false, false, false, true, 0},
	{0x7,"DBPROP_CI_QUERY_TYPE",VT_I4, false, false, false, true, 0},
	{0,NULL}
};

static const struct full_propset_info guid_properties_64[] = {
	{0x2,"DBPROP_MACHINE",VT_BSTR, false, false, false, true, 0},
	{0x3,"DBPROP_CLIENT_CLSID",VT_CLSID, false, false, false, true, 0},
	{0,NULL}
};

static const struct full_propset_info guid_properties_65[] = {
	{0x4752,"System.DateImported",VT_FILETIME, true, false, true, false, 8},
	{0x103,"System.Image.Compression",VT_UI2, true, false, true, false, 2},
	{0x9202,"System.Photo.Aperture",VT_R8, true, false, true, false, 8},
	{0x10f,"System.Photo.CameraManufacturer",VT_LPWSTR, true, true, true, false, 512},
	{0x110,"System.Photo.CameraModel",VT_LPWSTR, true, true, true, false, 512},
	{0x9003,"System.Photo.DateTaken",VT_FILETIME, true, false, true, false, 8},
	{0x4748,"System.Photo.Event",VT_LPWSTR | VT_VECTOR, true, true, true, false, 512},
	{0x9204,"System.Photo.ExposureBias",VT_R8, true, false, true, false, 8},
	{0x8822,"System.Photo.ExposureProgram",VT_UI4, true, false, true, false, 4},
	{0x829a,"System.Photo.ExposureTime",VT_R8, true, false, true, false, 8},
	{0x9209,"System.Photo.Flash",VT_UI1, true, false, true, false, 1},
	{0x829d,"System.Photo.FNumber",VT_R8, true, false, true, false, 8},
	{0x920a,"System.Photo.FocalLength",VT_R8, true, false, true, false, 8},
	{0x8827,"System.Photo.ISOSpeed",VT_UI2, true, false, true, false, 2},
	{0x9208,"System.Photo.LightSource",VT_UI4, true, false, true, false, 4},
	{0x9207,"System.Photo.MeteringMode",VT_UI2, true, false, true, false, 2},
	{0x112,"System.Photo.Orientation",VT_UI2, true, false, true, false, 2},
	{0x9201,"System.Photo.ShutterSpeed",VT_R8, true, false, true, false, 8},
	{0x9206,"System.Photo.SubjectDistance",VT_R8, true, false, true, false, 8},
	{0x131,"System.SoftwareUsed",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_66[] = {
	{0x64,"System.Contact.TTYTDDTelephone",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_67[] = {
	{0x2f,"System.Contact.Birthday",VT_FILETIME, true, false, true, false, 8},
	{0x41,"System.Contact.HomeAddressCity",VT_LPWSTR, true, true, true, false, 512},
	{0x14,"System.Contact.HomeTelephone",VT_LPWSTR, true, true, true, false, 512},
	{0x6,"System.Contact.JobTitle",VT_LPWSTR, true, true, true, false, 512},
	{0x47,"System.Contact.MiddleName",VT_LPWSTR, true, true, true, false, 256},
	{0x23,"System.Contact.MobileTelephone",VT_LPWSTR, true, true, true, false, 512},
	{0x4a,"System.Contact.NickName",VT_LPWSTR, true, true, true, false, 256},
	{0x7,"System.Contact.OfficeLocation",VT_LPWSTR, true, true, true, false, 512},
	{0x45,"System.Contact.PersonalTitle",VT_LPWSTR, true, true, true, false, 512},
	{0x30,"System.Contact.PrimaryEmailAddress",VT_LPWSTR, true, true, true, false, 256},
	{0x19,"System.Contact.PrimaryTelephone",VT_LPWSTR, true, true, true, false, 512},
	{0x49,"System.Contact.Suffix",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_68[] = {
	{0x64,"System.Photo.PhotometricInterpretationText",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_69[] = {
	{0x64,"System.Contact.OtherAddressPostOfficeBox",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_70[] = {
	{0x64,"System.Calendar.ReminderTime",VT_FILETIME, true, false, true, false, 8},
	{0,NULL}
};

static const struct full_propset_info guid_properties_71[] = {
	{0x64,"System.Calendar.RequiredAttendeeAddresses",VT_LPWSTR | VT_VECTOR, true, true, true, false, 256},
	{0,NULL}
};

static const struct full_propset_info guid_properties_72[] = {
	{0x64,"System.Calendar.OrganizerAddress",VT_LPWSTR, true, true, true, false, 256},
	{0,NULL}
};

static const struct full_propset_info guid_properties_73[] = {
	{0x64,"System.Photo.WhiteBalanceText",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_74[] = {
	{0x2,"System.Link.TargetParsingPath",VT_LPWSTR, true, false, true, false, 520},
	{0x8,"System.Link.TargetSFGAOFlags",VT_UI4, true, false, true, false, 4},
	{0,NULL}
};

static const struct full_propset_info guid_properties_75[] = {
	{0x64,"System.IsAttachment",VT_BOOL, true, false, true, false, 2},
	{0,NULL}
};

static const struct full_propset_info guid_properties_76[] = {
	{0x64,"System.Photo.GainControlText",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_77[] = {
	{0x64,"System.Contact.Hobbies",VT_LPWSTR | VT_VECTOR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_78[] = {
	{0x64,"System.Contact.HomeAddressPostOfficeBox",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_79[] = {
	{0x64,"System.Contact.CompanyMainTelephone",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_80[] = {
	{0x64,"System.IsFlagged",VT_BOOL, true, false, true, false, 2},
	{0,NULL}
};

static const struct full_propset_info guid_properties_81[] = {
	{0x64,"System.Contact.FirstName",VT_LPWSTR, true, true, true, false, 256},
	{0,NULL}
};

static const struct full_propset_info guid_properties_82[] = {
	{0xa,"System.IsEncrypted",VT_BOOL, true, false, true, false, 2},
	{0,NULL}
};

static const struct full_propset_info guid_properties_83[] = {
	{0x64,"System.Media.AverageLevel",VT_UI4, true, false, true, false, 4},
	{0,NULL}
};

static const struct full_propset_info guid_properties_84[] = {
	{0x5,"System.MIMEType",VT_LPWSTR, true, true, true, false, 512},
	{0x9,"System.Search.AccessCount",VT_UI4, true, false, true, false, 4},
	{0x8,"System.Search.GatherTime",VT_FILETIME, true, false, true, false, 8},
	{0xb,"System.Search.LastIndexedTotalTime",VT_R8, true, false, true, false, 8},
	{0,NULL}
};

static const struct full_propset_info guid_properties_85[] = {
	{0x64,"System.Calendar.OptionalAttendeeAddresses",VT_LPWSTR | VT_VECTOR, true, true, true, false, 256},
	{0,NULL}
};

static const struct full_propset_info guid_properties_86[] = {
	{0x64,"System.ProviderItemID",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_87[] = {
	{0x64,"System.Contact.BusinessAddressCountry",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_88[] = {
	{0x64,"System.Contact.EmailName",VT_LPWSTR, true, true, true, false, 256},
	{0,NULL}
};

static const struct full_propset_info guid_properties_89[] = {
	{0x64,"System.Photo.FocalLengthInFilm",VT_UI2, true, false, true, false, 2},
	{0,NULL}
};

static const struct full_propset_info guid_properties_90[] = {
	{0x64,"System.IsDeleted",VT_BOOL, true, false, true, false, 2},
	{0,NULL}
};

static const struct full_propset_info guid_properties_91[] = {
	{0x64,"System.Contact.IMAddress",VT_LPWSTR | VT_VECTOR, true, true, true, false, 256},
	{0,NULL}
};

static const struct full_propset_info guid_properties_92[] = {
	{0x64,"System.DateAcquired",VT_FILETIME, true, false, true, false, 8},
	{0,NULL}
};

static const struct full_propset_info guid_properties_93[] = {
	{0x64,"System.DateCompleted",VT_FILETIME, true, false, true, false, 8},
	{0,NULL}
};

static const struct full_propset_info guid_properties_94[] = {
	{0x64,"System.ItemName",VT_LPWSTR, true, false, true, false, 520},
	{0,NULL}
};

static const struct full_propset_info guid_properties_95[] = {
	{0x64,"System.Contact.PrimaryAddressPostalCode",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_96[] = {
	{0x26,"System.Media.SubTitle",VT_LPWSTR, true, true, true, false, 512},
	{0x5,"System.Media.Year",VT_UI4, true, false, true, false, 4},
	{0xd,"System.Music.AlbumArtist",VT_LPWSTR, true, true, true, false, 256},
	{0x64,"System.Music.AlbumID",VT_LPWSTR, true, true, true, false, 2048},
	{0x4,"System.Music.AlbumTitle",VT_LPWSTR, true, true, true, false, 512},
	{0x2,"System.Music.Artist",VT_LPWSTR | VT_VECTOR, true, true, true, false, 256},
	{0x23,"System.Music.BeatsPerMinute",VT_LPWSTR, true, true, true, false, 512},
	{0x24,"System.Music.Conductor",VT_LPWSTR | VT_VECTOR, true, true, true, false, 256},
	{0x21,"System.Music.ContentGroupDescription",VT_LPWSTR, true, false, true, false, 512},
	{0xb,"System.Music.Genre",VT_LPWSTR | VT_VECTOR, true, true, true, false, 512},
	{0x22,"System.Music.InitialKey",VT_LPWSTR, true, true, true, false, 512},
	{0xc,"System.Music.Lyrics",VT_LPWSTR, true, true, false, false, 512},
	{0x27,"System.Music.Mood",VT_LPWSTR, true, true, true, false, 512},
	{0x25,"System.Music.PartOfSet",VT_LPWSTR, true, false, true, false, 512},
	{0x7,"System.Music.TrackNumber",VT_UI4, true, false, true, false, 4},
	{0,NULL}
};

static const struct full_propset_info guid_properties_97[] = {
	{0x64,"System.Document.ClientID",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_98[] = {
	{0x64,"System.Photo.ExposureProgramText",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_99[] = {
	{0x12,"System.ApplicationName",VT_LPWSTR, true, true, true, false, 512},
	{0x4,"System.Author",VT_LPWSTR | VT_VECTOR, true, true, true, false, 256},
	{0x6,"System.Comment",VT_LPWSTR, true, true, true, false, 2048},
	{0x10,"System.Document.CharacterCount",VT_I4, true, false, true, false, 4},
	{0xc,"System.Document.DateCreated",VT_FILETIME, true, false, true, false, 8},
	{0xb,"System.Document.DatePrinted",VT_FILETIME, true, false, true, false, 8},
	{0xd,"System.Document.DateSaved",VT_FILETIME, true, false, true, false, 8},
	{0x8,"System.Document.LastAuthor",VT_LPWSTR, true, true, true, false, 256},
	{0xe,"System.Document.PageCount",VT_I4, true, false, true, false, 4},
	{0x9,"System.Document.RevisionNumber",VT_LPWSTR, true, true, true, false, 512},
	{0xa,"System.Document.TotalEditingTime",VT_UI8, true, false, true, false, 8},
	{0xf,"System.Document.WordCount",VT_I4, true, false, true, false, 4},
	{0x5,"System.Keywords",VT_LPWSTR | VT_VECTOR, true, true, true, false, 512},
	{0x3,"System.Subject",VT_LPWSTR, true, true, true, false, 520},
	{0x2,"System.Title",VT_LPWSTR, true, true, true, false, 520},
	{0x7,"DocTemplate",VT_LPWSTR, false, false, false, true, 0},
	{0x11,"DocThumbnail",VT_BLOB_OBJECT, false, false, false, true, 0},
	{0,NULL}
};

static const struct full_propset_info guid_properties_100[] = {
	{0x64,"System.Note.ColorText",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_101[] = {
	{0x64,"System.Photo.MeteringModeText",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_102[] = {
	{0x2,"System.Link.TargetExtension",VT_LPWSTR | VT_VECTOR, true, true, false, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_103[] = {
	{0x64,"System.Contact.BusinessAddressState",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_104[] = {
	{0x64,"System.Photo.OrientationText",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_105[] = {
	{0x64,"System.Contact.Label",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_106[] = {
	{0x64,"System.Calendar.Location",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_107[] = {
	{0x64,"System.Photo.SaturationText",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_108[] = {
	{0x64,"System.Contact.PrimaryAddressCity",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_109[] = {
	{0x64,"System.Contact.Anniversary",VT_FILETIME, true, false, true, false, 8},
	{0,NULL}
};

static const struct full_propset_info guid_properties_110[] = {
	{0x64,"System.Contact.FileAsName",VT_LPWSTR, true, true, true, false, 256},
	{0,NULL}
};

static const struct full_propset_info guid_properties_111[] = {
	{0x64,"System.GPS.Date",VT_FILETIME, true, false, true, false, 8},
	{0,NULL}
};

static const struct full_propset_info guid_properties_112[] = {
	{0x2,"System.Contact.JA.CompanyNamePhonetic",VT_LPWSTR, true, true, true, false, 256},
	{0x3,"System.Contact.JA.FirstNamePhonetic",VT_LPWSTR, true, true, true, false, 512},
	{0x4,"System.Contact.JA.LastNamePhonetic",VT_LPWSTR, true, true, true, false, 256},
	{0,NULL}
};

static const struct full_propset_info guid_properties_113[] = {
	{0x64,"System.Communication.SecurityFlags",VT_I4, true, false, true, false, 4},
	{0,NULL}
};

static const struct full_propset_info guid_properties_114[] = {
	{0x64,"System.Identity",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_115[] = {
	{0x64,"System.Contact.BusinessAddressPostOfficeBox",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_116[] = {
	{0x64,"System.FileExtension",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_117[] = {
	{0x64,"System.AcquisitionID",VT_I4, true, false, true, false, 4},
	{0,NULL}
};

static const struct full_propset_info guid_properties_118[] = {
	{0x64,"System.Contact.EmailAddresses",VT_LPWSTR | VT_VECTOR, true, true, true, false, 256},
	{0,NULL}
};

static const struct full_propset_info guid_properties_119[] = {
	{0x2,"System.Category",VT_LPWSTR | VT_VECTOR, true, true, true, false, 512},
	{0xf,"System.Company",VT_LPWSTR, true, true, true, false, 512},
	{0x1b,"System.ContentStatus",VT_LPWSTR, true, true, true, false, 512},
	{0x1a,"System.ContentType",VT_LPWSTR, true, true, true, false, 512},
	{0x4,"System.Document.ByteCount",VT_I4, true, false, true, false, 4},
	{0x9,"System.Document.HiddenSlideCount",VT_I4, true, false, true, false, 4},
	{0x5,"System.Document.LineCount",VT_I4, true, false, true, false, 4},
	{0xe,"System.Document.Manager",VT_LPWSTR, true, true, true, false, 512},
	{0x6,"System.Document.ParagraphCount",VT_I4, true, false, true, false, 4},
	{0x3,"System.Document.PresentationFormat",VT_LPWSTR, true, true, true, false, 512},
	{0x7,"System.Document.SlideCount",VT_I4, true, false, true, false, 4},
	{0x1d,"System.Document.Version",VT_LPWSTR, true, false, true, false, 512},
	{0x1c,"System.Language",VT_LPWSTR, true, true, true, false, 512},
	{0x8,"DocNoteCount",VT_I4, false, false, false, true, 0},
	{0xd,"DocPartTitles",VT_LPWSTR | VT_VECTOR, false, false, false, true, 0},
	{0,NULL}
};

static const struct full_propset_info guid_properties_120[] = {
	{0x64,"System.Communication.TaskStatus",VT_UI2, true, false, true, false, 2},
	{0,NULL}
};

static const struct full_propset_info guid_properties_121[] = {
	{0x64,"System.Contact.LastName",VT_LPWSTR, true, true, true, false, 256},
	{0,NULL}
};

static const struct full_propset_info guid_properties_122[] = {
	{0x64,"System.Communication.DateItemExpires",VT_FILETIME, true, false, true, false, 8},
	{0,NULL}
};

static const struct full_propset_info guid_properties_123[] = {
	{0x64,"System.ImportanceText",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_124[] = {
	{0x64,"System.Search.ContainerHash",VT_LPWSTR, true, true, false, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_125[] = {
	{0x64,"System.Contact.BusinessFaxNumber",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_126[] = {
	{0xa,"System.Video.Compression",VT_LPWSTR, true, true, true, false, 512},
	{0x8,"System.Video.EncodingBitrate",VT_UI4, true, false, true, false, 4},
	{0x2c,"System.Video.FourCC",VT_UI4, true, false, true, false, 4},
	{0x4,"System.Video.FrameHeight",VT_UI4, true, false, true, false, 4},
	{0x6,"System.Video.FrameRate",VT_UI4, true, false, true, false, 4},
	{0x3,"System.Video.FrameWidth",VT_UI4, true, false, true, false, 4},
	{0x2a,"System.Video.HorizontalAspectRatio",VT_UI4, true, false, true, false, 4},
	{0x9,"System.Video.SampleSize",VT_UI4, true, false, true, false, 4},
	{0x2,"System.Video.StreamName",VT_LPWSTR, true, true, true, false, 512},
	{0x2b,"System.Video.TotalBitrate",VT_UI4, true, false, true, false, 4},
	{0x2d,"System.Video.VerticalAspectRatio",VT_UI4, true, false, true, false, 4},
	{0,NULL}
};

static const struct full_propset_info guid_properties_127[] = {
	{0x1a,"System.IconIndex",VT_I4, true, false, true, false, 4},
	{0x2,"System.Link.TargetUrl",VT_LPWSTR, true, true, true, false, 4168},
	{0,NULL}
};

static const struct full_propset_info guid_properties_128[] = {
	{0x64,"System.IsFlaggedComplete",VT_BOOL, true, false, true, false, 2},
	{0,NULL}
};

static const struct full_propset_info guid_properties_129[] = {
	{0x64,"System.Task.Owner",VT_LPWSTR, true, true, true, false, 256},
	{0,NULL}
};

static const struct full_propset_info guid_properties_130[] = {
	{0x64,"System.ItemFolderPathDisplayNarrow",VT_LPWSTR, true, true, true, false, 520},
	{0,NULL}
};

static const struct full_propset_info guid_properties_131[] = {
	{0x64,"System.Photo.ProgramModeText",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_132[] = {
	{0x64,"System.Contact.PrimaryAddressCountry",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_133[] = {
	{0x2,"System.Shell.OmitFromView",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_134[] = {
	{0x64,"System.Contact.OtherAddressState",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_135[] = {
	{0x64,"System.Message.AttachmentContents",VT_LPWSTR, true, true, false, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_136[] = {
	{0x64,"System.Communication.TaskStatusText",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_137[] = {
	{0x64,"System.Communication.HeaderItem",VT_BOOL, true, false, true, false, 2},
	{0,NULL}
};

static const struct full_propset_info guid_properties_138[] = {
	{0x64,"System.Contact.EmailAddress",VT_LPWSTR, true, true, true, false, 256},
	{0,NULL}
};

static const struct full_propset_info guid_properties_139[] = {
	{0x64,"System.Contact.FullName",VT_LPWSTR, true, true, true, false, 256},
	{0,NULL}
};

static const struct full_propset_info guid_properties_140[] = {
	{0x64,"System.Document.Division",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_141[] = {
	{0x64,"System.Contact.BusinessAddressPostalCode",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_142[] = {
	{0x64,"System.ItemNamePrefix",VT_LPWSTR, true, false, true, false, 520},
	{0,NULL}
};

static const struct full_propset_info guid_properties_143[] = {
	{0x64,"System.Photo.DigitalZoom",VT_R8, true, false, true, false, 8},
	{0,NULL}
};

static const struct full_propset_info guid_properties_144[] = {
	{0x64,"System.SourceItem",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_145[] = {
	{0x64,"System.Photo.WhiteBalance",VT_UI4, true, false, true, false, 4},
	{0,NULL}
};

static const struct full_propset_info guid_properties_146[] = {
	{0x64,"System.SensitivityText",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_147[] = {
	{0x2,"MSIDXSPROP_ROWSETQUERYSTATUS",VT_I4, false, false, false, true, 0},
	{0x3,"MSIDXSPROP_COMMAND_LOCALE_STRING",VT_BSTR, false, false, false, true, 0},
	{0x4,"MSIDXSPROP_QUERY_RESTRICTION",VT_BSTR, false, false, false, true, 0},
	{0x5,"MSIDXSPROP_PARSE_TREE",VT_BSTR, false, false, false, true, 0},
	{0x6,"MSIDXSPROP_MAX_RANK",VT_I4, false, false, false, true, 0},
	{0x7,"MSIDXSPROP_RESULTS_FOUND",VT_I4, false, false, false, true, 0},
	{0,NULL}
};

static const struct full_propset_info guid_properties_148[] = {
	{0x64,"System.Photo.MaxAperture",VT_R8, true, false, true, false, 8},
	{0,NULL}
};

static const struct full_propset_info guid_properties_149[] = {
	{0x64,"System.Calendar.Resources",VT_LPWSTR | VT_VECTOR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_150[] = {
	{0x64,"System.Contact.OtherAddressCity",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_151[] = {
	{0x64,"System.Music.DisplayArtist",VT_LPWSTR, true, true, true, false, 256},
	{0,NULL}
};

static const struct full_propset_info guid_properties_152[] = {
	{0x64,"System.Message.SenderAddress",VT_LPWSTR, true, true, true, false, 256},
	{0,NULL}
};

static const struct full_propset_info guid_properties_153[] = {
	{0x64,"System.Contact.PrimaryAddressState",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_154[] = {
	{0x64,"System.StartDate",VT_FILETIME, true, false, true, false, 8},
	{0,NULL}
};

static const struct full_propset_info guid_properties_155[] = {
	{0x10,"System.DateAccessed",VT_FILETIME, true, false, true, false, 8},
	{0xf,"System.DateCreated",VT_FILETIME, true, false, true, false, 8},
	{0xe,"System.DateModified",VT_FILETIME, true, false, true, false, 8},
	{0xd,"System.FileAttributes",VT_UI4, true, false, true, false, 4},
	{0x15,"System.FileFRN",VT_UI8, true, false, true, false, 8},
	{0x2,"System.ItemFolderNameDisplay",VT_LPWSTR, true, true, true, false, 512},
	{0xa,"System.ItemNameDisplay",VT_LPWSTR, true, true, true, false, 520},
	{0x4,"System.ItemTypeText",VT_LPWSTR, true, true, true, false, 512},
	{0x13,"System.Search.Contents",VT_LPWSTR, true, true, false, false, 512},
	{0xc,"System.Size",VT_UI8, true, false, true, false, 8},
	{0x3,"ClassId",VT_CLSID, false, false, false, true, 0},
	{0x8,"FileIndex",VT_UI8, false, false, false, true, 0},
	{0x9,"USN",VT_I8, false, false, false, true, 0},
	{0xb,"Path",VT_LPWSTR, false, false, false, true, 0},
	{0x12,"AllocSize",VT_I8, false, false, false, true, 0},
	{0x14,"ShortFilename",VT_LPWSTR, false, false, false, true, 0},
	{0x16,"Scope",VT_LPWSTR, false, false, false, true, 0},
	{0,NULL}
};

static const struct full_propset_info guid_properties_156[] = {
	{0x64,"System.Contact.BusinessAddressStreet",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_157[] = {
	{0x64,"System.Sensitivity",VT_UI2, true, false, true, false, 2},
	{0,NULL}
};

static const struct full_propset_info guid_properties_158[] = {
	{0x64,"System.Contact.HomeAddressCountry",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_159[] = {
	{0x64,"System.Task.CompletionStatus",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_160[] = {
	{0x10,"System.Software.DateLastUsed",VT_FILETIME, true, true, true, false, 8},
	{0,NULL}
};

static const struct full_propset_info guid_properties_161[] = {
	{0x64,"System.Contact.Department",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_162[] = {
	{0x64,"System.Calendar.ShowTimeAsText",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_163[] = {
	{0x4,"System.FileOwner",VT_LPWSTR, true, true, true, false, 256},
	{0,NULL}
};

static const struct full_propset_info guid_properties_164[] = {
	{0x64,"System.RecordedTV.OriginalBroadcastDate",VT_FILETIME, true, false, true, false, 8},
	{0,NULL}
};

static const struct full_propset_info guid_properties_165[] = {
	{0x64,"System.IsFolder",VT_BOOL, true, false, true, false, 2},
	{0,NULL}
};

static const struct full_propset_info guid_properties_166[] = {
	{0x64,"System.DueDate",VT_FILETIME, true, false, true, false, 8},
	{0,NULL}
};

static const struct full_propset_info guid_properties_167[] = {
	{0x3,"System.FileDescription",VT_LPWSTR, true, true, false, false, 512},
	{0x6,"System.OriginalFileName",VT_LPWSTR, true, true, true, false, 520},
	{0x7,"System.Software.ProductName",VT_LPWSTR, true, true, false, false, 512},
	{0x8,"System.Software.ProductVersion",VT_LPWSTR, true, true, false, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_168[] = {
	{0x64,"System.MileageInformation",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_169[] = {
	{0x7,"System.RecordedTV.ChannelNumber",VT_UI4, true, false, true, false, 4},
	{0xf,"System.RecordedTV.DateContentExpires",VT_FILETIME, true, false, true, false, 8},
	{0x2,"System.RecordedTV.EpisodeName",VT_LPWSTR, true, true, true, false, 512},
	{0x10,"System.RecordedTV.IsATSCContent",VT_BOOL, true, false, true, false, 2},
	{0xc,"System.RecordedTV.IsClosedCaptioningAvailable",VT_BOOL, true, false, true, false, 2},
	{0x11,"System.RecordedTV.IsDTVContent",VT_BOOL, true, false, true, false, 2},
	{0x12,"System.RecordedTV.IsHDContent",VT_BOOL, true, false, true, false, 2},
	{0xd,"System.RecordedTV.IsRepeatBroadcast",VT_BOOL, true, false, true, false, 2},
	{0xe,"System.RecordedTV.IsSAP",VT_BOOL, true, false, true, false, 2},
	{0x3,"System.RecordedTV.ProgramDescription",VT_LPWSTR, true, true, true, false, 2048},
	{0x5,"System.RecordedTV.StationCallSign",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_170[] = {
	{0x64,"System.Audio.PeakValue",VT_UI4, true, false, true, false, 4},
	{0,NULL}
};

static const struct full_propset_info guid_properties_171[] = {
	{0x64,"System.ItemDate",VT_FILETIME, true, false, true, false, 8},
	{0,NULL}
};

static const struct full_propset_info guid_properties_172[] = {
	{0x64,"System.Contact.SpouseName",VT_LPWSTR, true, true, true, false, 256},
	{0,NULL}
};

static const struct full_propset_info guid_properties_173[] = {
	{0x64,"System.Message.Flags",VT_I4, true, false, true, false, 4},
	{0,NULL}
};

static const struct full_propset_info guid_properties_174[] = {
	{0x64,"System.Contact.AssistantTelephone",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_175[] = {
	{0x64,"System.KindText",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_176[] = {
	{0x64,"System.Photo.ContrastText",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_177[] = {
	{0x7,"System.Image.BitDepth",VT_UI4, true, false, true, false, 4},
	{0xd,"System.Image.Dimensions",VT_LPWSTR, true, true, true, false, 512},
	{0x5,"System.Image.HorizontalResolution",VT_R8, true, false, true, false, 8},
	{0x3,"System.Image.HorizontalSize",VT_UI4, true, false, true, false, 4},
	{0x6,"System.Image.VerticalResolution",VT_R8, true, false, true, false, 8},
	{0x4,"System.Image.VerticalSize",VT_UI4, true, false, true, false, 4},
	{0xc,"System.Media.FrameCount",VT_UI4, true, false, true, false, 4},
	{0,NULL}
};

static const struct full_propset_info guid_properties_178[] = {
	{0x64,"System.Message.IsFwdOrReply",VT_I4, true, false, true, false, 4},
	{0,NULL}
};

static const struct full_propset_info guid_properties_179[] = {
	{0x64,"System.ItemAuthors",VT_LPWSTR | VT_VECTOR, true, true, true, false, 256},
	{0,NULL}
};

static const struct full_propset_info guid_properties_180[] = {
	{0x64,"System.Contact.TelexNumber",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_181[] = {
	{0x64,"System.Communication.PolicyTag",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_182[] = {
	{0x64,"System.Contact.HomeFaxNumber",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_183[] = {
	{0x64,"System.FlagStatusText",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_184[] = {
	{0x64,"System.Contact.AssistantName",VT_LPWSTR, true, true, true, false, 256},
	{0,NULL}
};

static const struct full_propset_info guid_properties_185[] = {
	{0x64,"System.Message.ToDoFlags",VT_I4, true, false, true, false, 4},
	{0,NULL}
};

static const struct full_propset_info guid_properties_186[] = {
	{0x64,"System.RatingText",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_187[] = {
	{0x64,"System.Document.Contributor",VT_LPWSTR | VT_VECTOR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_188[] = {
	{0x64,"System.Contact.CallbackTelephone",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_189[] = {
	{0x64,"System.EndDate",VT_FILETIME, true, false, true, false, 8},
	{0,NULL}
};

static const struct full_propset_info guid_properties_190[] = {
	{0x64,"System.Media.DateEncoded",VT_FILETIME, true, false, true, false, 8},
	{0,NULL}
};

static const struct full_propset_info guid_properties_191[] = {
	{0x64,"System.Photo.FlashText",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_192[] = {
	{0x64,"System.Photo.FlashFired",VT_BOOL, true, false, true, false, 2},
	{0,NULL}
};

static const struct full_propset_info guid_properties_193[] = {
	{0x64,"System.Contact.Profession",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_194[] = {
	{0x64,"System.Contact.PagerTelephone",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_195[] = {
	{0x2,"DBPROP_USECONTENTINDEX",VT_BOOL, false, false, false, true, 0},
	{0x3,"DBPROP_DEFERNONINDEXEDTRIMMING",VT_BOOL, false, false, false, true, 0},
	{0x4,"DBPROP_USEEXTENDEDDBTYPES",VT_BOOL, false, false, false, true, 0},
	{0x5,"DBPROP_IGNORENOISEONLYCLAUSES",VT_BOOL, false, false, false, true, 0},
	{0x6,"DBPROP_GENERICOPTIONS_STRING",VT_BSTR, false, false, false, true, 0},
	{0x7,"DBPROP_FIRSTROWS",VT_BOOL, false, false, false, true, 0},
	{0x8,"DBPROP_DEFERCATALOGVERIFICATION",VT_BOOL, false, false, false, true, 0},
	{0xa,"DBPROP_GENERATEPARSETREE",VT_BOOL, false, false, false, true, 0},
	{0xc,"DBPROP_FREETEXTANYTERM",VT_BOOL, false, false, false, true, 0},
	{0xd,"DBPROP_FREETEXTUSESTEMMING",VT_BOOL, false, false, false, true, 0},
	{0xe,"DBPROP_IGNORESBRI",VT_BOOL, false, false, false, true, 0},
	{0x10,"DBPROP_ENABLEROWSETEVENTS",VT_BOOL, false, false, false, true, 0},
	{0,NULL}
};

static const struct full_propset_info guid_properties_196[] = {
	{0x64,"System.Contact.BusinessAddressCity",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_197[] = {
	{0x64,"System.Media.SubscriptionContentId",VT_LPWSTR, true, false, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_198[] = {
	{0x64,"System.Contact.PrimaryAddressStreet",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_199[] = {
	{0x64,"System.Project",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_200[] = {
	{0x64,"System.Note.Color",VT_UI2, true, false, true, false, 2},
	{0,NULL}
};

static const struct full_propset_info guid_properties_201[] = {
	{0x9,"System.Communication.AccountName",VT_LPWSTR, true, true, true, false, 512},
	{0x12,"System.Contact.WebPage",VT_LPWSTR, true, true, true, false, 4168},
	{0xc,"System.FlagStatus",VT_I4, true, false, true, false, 4},
	{0xb,"System.Importance",VT_I4, true, false, true, false, 4},
	{0xa,"System.IsRead",VT_BOOL, true, false, true, false, 2},
	{0x6,"System.ItemFolderPathDisplay",VT_LPWSTR, true, true, true, false, 520},
	{0x7,"System.ItemPathDisplay",VT_LPWSTR, true, true, true, false, 520},
	{0x15,"System.Message.AttachmentNames",VT_LPWSTR | VT_VECTOR, true, true, true, false, 512},
	{0x2,"System.Message.BccAddress",VT_LPWSTR | VT_VECTOR, true, true, true, false, 256},
	{0x3,"System.Message.BccName",VT_LPWSTR | VT_VECTOR, true, true, true, false, 256},
	{0x4,"System.Message.CcAddress",VT_LPWSTR | VT_VECTOR, true, true, true, false, 256},
	{0x5,"System.Message.CcName",VT_LPWSTR | VT_VECTOR, true, true, true, false, 256},
	{0x14,"System.Message.DateReceived",VT_FILETIME, true, false, true, false, 8},
	{0x13,"System.Message.DateSent",VT_FILETIME, true, false, true, false, 8},
	{0xd,"System.Message.FromAddress",VT_LPWSTR | VT_VECTOR, true, true, true, false, 256},
	{0xe,"System.Message.FromName",VT_LPWSTR | VT_VECTOR, true, true, true, false, 256},
	{0xf,"System.Message.Store",VT_LPWSTR, true, false, true, false, 512},
	{0x10,"System.Message.ToAddress",VT_LPWSTR | VT_VECTOR, true, true, true, false, 256},
	{0x11,"System.Message.ToName",VT_LPWSTR | VT_VECTOR, true, true, true, false, 256},
	{0,NULL}
};

static const struct full_propset_info guid_properties_202[] = {
	{0x64,"System.Journal.EntryType",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};

static const struct full_propset_info guid_properties_203[] = {
	{0x64,"System.Contact.MailingAddress",VT_LPWSTR, true, true, true, false, 512},
	{0,NULL}
};


static struct full_guid_propset full_propertyset[] = {
	{{0xBFEE9149, 0xE3E2, 0x49A7, {0xA8, 0x62}, {0xC0, 0x59, 0x88, 0x14, 0x5C, 0xEC}},guid_properties_0},
	{{0xFF962609, 0xB7D6, 0x4999, {0x86, 0x2D}, {0x95, 0x18, 0x0D, 0x52, 0x9A, 0xEA}},guid_properties_1},
	{{0x446D16B1, 0x8DAD, 0x4870, {0xA7, 0x48}, {0x40, 0x2E, 0xA4, 0x3D, 0x78, 0x8C}},guid_properties_2},
	{{0xAEAC19E4, 0x89AE, 0x4508, {0xB9, 0xB7}, {0xBB, 0x86, 0x7A, 0xBE, 0xE2, 0xED}},guid_properties_3},
	{{0x09429607, 0x582D, 0x437F, {0x84, 0xC3}, {0xDE, 0x93, 0xA2, 0xB2, 0x4C, 0x3C}},guid_properties_4},
	{{0x5BF396D4, 0x5EB2, 0x466F, {0xBD, 0xE9}, {0x2F, 0xB3, 0xF2, 0x36, 0x1D, 0x6E}},guid_properties_5},
	{{0x1E3EE840, 0xBC2B, 0x476C, {0x82, 0x37}, {0x2A, 0xCD, 0x1A, 0x83, 0x9B, 0x22}},guid_properties_6},
	{{0x9C1FCF74, 0x2D97, 0x41BA, {0xB4, 0xAE}, {0xCB, 0x2E, 0x36, 0x61, 0xA6, 0xE4}},guid_properties_7},
	{{0x10984E0A, 0xF9F2, 0x4321, {0xB7, 0xEF}, {0xBA, 0xF1, 0x95, 0xAF, 0x43, 0x19}},guid_properties_8},
	{{0x8F167568, 0x0AAE, 0x4322, {0x8E, 0xD9}, {0x60, 0x55, 0xB7, 0xB0, 0xE3, 0x98}},guid_properties_9},
	{{0x000214A1, 0x0000, 0x0000, {0xC0, 0x00}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x46}},guid_properties_10},
	{{0x43F8D7B7, 0xA444, 0x4F87, {0x93, 0x83}, {0x52, 0x27, 0x1C, 0x9B, 0x91, 0x5C}},guid_properties_11},
	{{0x8FDC6DEA, 0xB929, 0x412B, {0xBA, 0x90}, {0x39, 0x7A, 0x25, 0x74, 0x65, 0xFE}},guid_properties_12},
	{{0x28636AA6, 0x953D, 0x11D2, {0xB5, 0xD6}, {0x00, 0xC0, 0x4F, 0xD9, 0x18, 0xD0}},guid_properties_13},
	{{0x188C1F91, 0x3C40, 0x4132, {0x9E, 0xC5}, {0xD8, 0xB0, 0x3B, 0x72, 0xA8, 0xA2}},guid_properties_14},
	{{0xD37D52C6, 0x261C, 0x4303, {0x82, 0xB3}, {0x08, 0xB9, 0x26, 0xAC, 0x6F, 0x12}},guid_properties_15},
	{{0x293CA35A, 0x09AA, 0x4DD2, {0xB1, 0x80}, {0x1F, 0xE2, 0x45, 0x72, 0x8A, 0x52}},guid_properties_16},
	{{0x0DA41CFA, 0xD224, 0x4A18, {0xAE, 0x2F}, {0x59, 0x61, 0x58, 0xDB, 0x4B, 0x3A}},guid_properties_17},
	{{0xE08805C8, 0xE395, 0x40DF, {0x80, 0xD2}, {0x54, 0xF0, 0xD6, 0xC4, 0x31, 0x54}},guid_properties_18},
	{{0x2C53C813, 0xFB63, 0x4E22, {0xA1, 0xAB}, {0x0B, 0x33, 0x1C, 0xA1, 0xE2, 0x73}},guid_properties_19},
	{{0xD98BE98B, 0xB86B, 0x4095, {0xBF, 0x52}, {0x9D, 0x23, 0xB2, 0xE0, 0xA7, 0x52}},guid_properties_20},
	{{0xD4729704, 0x8EF1, 0x43EF, {0x90, 0x24}, {0x2B, 0xD3, 0x81, 0x18, 0x7F, 0xD5}},guid_properties_21},
	{{0xA5477F61, 0x7A82, 0x4ECA, {0x9D, 0xDE}, {0x98, 0xB6, 0x9B, 0x24, 0x79, 0xB3}},guid_properties_22},
	{{0x45EAE747, 0x8E2A, 0x40AE, {0x8C, 0xBF}, {0xCA, 0x52, 0xAB, 0xA6, 0x15, 0x2A}},guid_properties_23},
	{{0x95C656C1, 0x2ABF, 0x4148, {0x9E, 0xD3}, {0x9E, 0xC6, 0x02, 0xE3, 0xB7, 0xCD}},guid_properties_24},
	{{0x51EC3F47, 0xDD50, 0x421D, {0x87, 0x69}, {0x33, 0x4F, 0x50, 0x42, 0x4B, 0x1E}},guid_properties_25},
	{{0x508161FA, 0x313B, 0x43D5, {0x83, 0xA1}, {0xC1, 0xAC, 0xCF, 0x68, 0x62, 0x2C}},guid_properties_26},
	{{0x560C36C0, 0x503A, 0x11CF, {0xBA, 0xA1}, {0x00, 0x00, 0x4C, 0x75, 0x2A, 0x9A}},guid_properties_27},
	{{0x730FB6DD, 0xCF7C, 0x426B, {0xA0, 0x3F}, {0xBD, 0x16, 0x6C, 0xC9, 0xEE, 0x24}},guid_properties_28},
	{{0x346C8BD1, 0x2E6A, 0x4C45, {0x89, 0xA4}, {0x61, 0xB7, 0x8E, 0x8E, 0x70, 0x0F}},guid_properties_29},
	{{0x38965063, 0xEDC8, 0x4268, {0x84, 0x91}, {0xB7, 0x72, 0x31, 0x72, 0xCF, 0x29}},guid_properties_30},
	{{0x6A15E5A0, 0x0A1E, 0x4CD7, {0xBB, 0x8C}, {0xD2, 0xF1, 0xB0, 0xC9, 0x29, 0xBC}},guid_properties_31},
	{{0x1B5439E7, 0xEBA1, 0x4AF8, {0xBD, 0xD7}, {0x7A, 0xF1, 0xD4, 0x54, 0x94, 0x93}},guid_properties_32},
	{{0x49691C90, 0x7E17, 0x101A, {0xA9, 0x1C}, {0x08, 0x00, 0x2B, 0x2E, 0xCD, 0xA9}},guid_properties_33},
	{{0x3F08E66F, 0x2F44, 0x4BB9, {0xA6, 0x82}, {0xAC, 0x35, 0xD2, 0x56, 0x23, 0x22}},guid_properties_34},
	{{0xC89A23D0, 0x7D6D, 0x4EB8, {0x87, 0xD4}, {0x77, 0x6A, 0x82, 0xD4, 0x93, 0xE5}},guid_properties_35},
	{{0x644D37B4, 0xE1B3, 0x4BAD, {0xB0, 0x99}, {0x7E, 0x7C, 0x04, 0x96, 0x6A, 0xCA}},guid_properties_36},
	{{0xC449D5CB, 0x9EA4, 0x4809, {0x82, 0xE8}, {0xAF, 0x9D, 0x59, 0xDE, 0xD6, 0xD1}},guid_properties_37},
	{{0x83A6347E, 0x6FE4, 0x4F40, {0xBA, 0x9C}, {0xC4, 0x86, 0x52, 0x40, 0xD1, 0xF4}},guid_properties_38},
	{{0xB812F15D, 0xC2D8, 0x4BBF, {0xBA, 0xCD}, {0x79, 0x74, 0x43, 0x46, 0x11, 0x3F}},guid_properties_39},
	{{0xBCCC8A3C, 0x8CEF, 0x42E5, {0x9B, 0x1C}, {0xC6, 0x90, 0x79, 0x39, 0x8B, 0xC7}},guid_properties_40},
	{{0xA06992B3, 0x8CAF, 0x4ED7, {0xA5, 0x47}, {0xB2, 0x59, 0xE3, 0x2A, 0xC9, 0xFC}},guid_properties_41},
	{{0x41CF5AE0, 0xF75A, 0x4806, {0xBD, 0x87}, {0x59, 0xC7, 0xD9, 0x24, 0x8E, 0xB9}},guid_properties_42},
	{{0x0ADEF160, 0xDB3F, 0x4308, {0x9A, 0x21}, {0x06, 0x23, 0x7B, 0x16, 0xFA, 0x2A}},guid_properties_43},
	{{0x8AFCC170, 0x8A46, 0x4B53, {0x9E, 0xEE}, {0x90, 0xBA, 0xE7, 0x15, 0x1E, 0x62}},guid_properties_44},
	{{0x56310920, 0x2491, 0x4919, {0x99, 0xCE}, {0xEA, 0xDB, 0x06, 0xFA, 0xFD, 0xB2}},guid_properties_45},
	{{0xDC8F80BD, 0xAF1E, 0x4289, {0x85, 0xB6}, {0x3D, 0xFC, 0x1B, 0x49, 0x39, 0x92}},guid_properties_46},
	{{0xB33AF30B, 0xF552, 0x4584, {0x93, 0x6C}, {0xCB, 0x93, 0xE5, 0xCD, 0xA2, 0x9F}},guid_properties_47},
	{{0x64440492, 0x4C8B, 0x11D1, {0x8B, 0x70}, {0x08, 0x00, 0x36, 0xB1, 0x1A, 0x03}},guid_properties_48},
	{{0x9098F33C, 0x9A7D, 0x48A8, {0x8D, 0xE5}, {0x2E, 0x12, 0x27, 0xA6, 0x4E, 0x91}},guid_properties_49},
	{{0xDE5EF3C7, 0x46E1, 0x484E, {0x99, 0x99}, {0x62, 0xC5, 0x30, 0x83, 0x94, 0xC1}},guid_properties_50},
	{{0x315B9C8D, 0x80A9, 0x4EF9, {0xAE, 0x16}, {0x8E, 0x74, 0x6D, 0xA5, 0x1D, 0x70}},guid_properties_51},
	{{0x98F98354, 0x617A, 0x46B8, {0x85, 0x60}, {0x5B, 0x1B, 0x64, 0xBF, 0x1F, 0x89}},guid_properties_52},
	{{0xD4D0AA16, 0x9948, 0x41A4, {0xAA, 0x85}, {0xD9, 0x7F, 0xF9, 0x64, 0x69, 0x93}},guid_properties_53},
	{{0xDE41CC29, 0x6971, 0x4290, {0xB4, 0x72}, {0xF5, 0x9F, 0x2E, 0x2F, 0x31, 0xE2}},guid_properties_54},
	{{0xDEA7C82C, 0x1D89, 0x4A66, {0x94, 0x27}, {0xA4, 0xE3, 0xDE, 0xBA, 0xBC, 0xB1}},guid_properties_55},
	{{0x3C8CEE58, 0xD4F0, 0x4CF9, {0xB7, 0x56}, {0x4E, 0x5D, 0x24, 0x44, 0x7B, 0xCD}},guid_properties_56},
	{{0xCD9ED458, 0x08CE, 0x418F, {0xA7, 0x0E}, {0xF9, 0x12, 0xC7, 0xBB, 0x9C, 0x5C}},guid_properties_57},
	{{0x67DF94DE, 0x0CA7, 0x4D6F, {0xB7, 0x92}, {0x05, 0x3A, 0x3E, 0x4F, 0x03, 0xCF}},guid_properties_58},
	{{0xAAA660F9, 0x9865, 0x458E, {0xB4, 0x84}, {0x01, 0xBC, 0x7F, 0xE3, 0x97, 0x3E}},guid_properties_59},
	{{0xD6942081, 0xD53B, 0x443D, {0xAD, 0x47}, {0x5E, 0x05, 0x9D, 0x9C, 0xD2, 0x7A}},guid_properties_60},
	{{0xE8309B6E, 0x084C, 0x49B4, {0xB1, 0xFC}, {0x90, 0xA8, 0x03, 0x31, 0xB6, 0x38}},guid_properties_61},
	{{0x64440490, 0x4C8B, 0x11D1, {0x8B, 0x70}, {0x08, 0x00, 0x36, 0xB1, 0x1A, 0x03}},guid_properties_62},
	{{0xA9BD1526, 0x6A80, 0x11D0, {0x8C, 0x9D}, {0x00, 0x20, 0xAF, 0x1D, 0x74, 0x0E}},guid_properties_63},
	{{0xAFAFACA5, 0xB5D1, 0x11D0, {0x8C, 0x62}, {0x00, 0xC0, 0x4F, 0xC2, 0xDB, 0x8D}},guid_properties_64},
	{{0x14B81DA1, 0x0135, 0x4D31, {0x96, 0xD9}, {0x6C, 0xBF, 0xC9, 0x67, 0x1A, 0x99}},guid_properties_65},
	{{0xAAF16BAC, 0x2B55, 0x45E6, {0x9F, 0x6D}, {0x41, 0x5E, 0xB9, 0x49, 0x10, 0xDF}},guid_properties_66},
	{{0x176DC63C, 0x2688, 0x4E89, {0x81, 0x43}, {0xA3, 0x47, 0x80, 0x0F, 0x25, 0xE9}},guid_properties_67},
	{{0x821437D6, 0x9EAB, 0x4765, {0xA5, 0x89}, {0x3B, 0x1C, 0xBB, 0xD2, 0x2A, 0x61}},guid_properties_68},
	{{0x8B26EA41, 0x058F, 0x43F6, {0xAE, 0xCC}, {0x40, 0x35, 0x68, 0x1C, 0xE9, 0x77}},guid_properties_69},
	{{0x72FC5BA4, 0x24F9, 0x4011, {0x9F, 0x3F}, {0xAD, 0xD2, 0x7A, 0xFA, 0xD8, 0x18}},guid_properties_70},
	{{0x0BA7D6C3, 0x568D, 0x4159, {0xAB, 0x91}, {0x78, 0x1A, 0x91, 0xFB, 0x71, 0xE5}},guid_properties_71},
	{{0x744C8242, 0x4DF5, 0x456C, {0xAB, 0x9E}, {0x01, 0x4E, 0xFB, 0x90, 0x21, 0xE3}},guid_properties_72},
	{{0x6336B95E, 0xC7A7, 0x426D, {0x86, 0xFD}, {0x7A, 0xE3, 0xD3, 0x9C, 0x84, 0xB4}},guid_properties_73},
	{{0xB9B4B3FC, 0x2B51, 0x4A42, {0xB5, 0xD8}, {0x32, 0x41, 0x46, 0xAF, 0xCF, 0x25}},guid_properties_74},
	{{0xF23F425C, 0x71A1, 0x4FA8, {0x92, 0x2F}, {0x67, 0x8E, 0xA4, 0xA6, 0x04, 0x08}},guid_properties_75},
	{{0xC06238B2, 0x0BF9, 0x4279, {0xA7, 0x23}, {0x25, 0x85, 0x67, 0x15, 0xCB, 0x9D}},guid_properties_76},
	{{0x5DC2253F, 0x5E11, 0x4ADF, {0x9C, 0xFE}, {0x91, 0x0D, 0xD0, 0x1E, 0x3E, 0x70}},guid_properties_77},
	{{0x7B9F6399, 0x0A3F, 0x4B12, {0x89, 0xBD}, {0x4A, 0xDC, 0x51, 0xC9, 0x18, 0xAF}},guid_properties_78},
	{{0x8589E481, 0x6040, 0x473D, {0xB1, 0x71}, {0x7F, 0xA8, 0x9C, 0x27, 0x08, 0xED}},guid_properties_79},
	{{0x5DA84765, 0xE3FF, 0x4278, {0x86, 0xB0}, {0xA2, 0x79, 0x67, 0xFB, 0xDD, 0x03}},guid_properties_80},
	{{0x14977844, 0x6B49, 0x4AAD, {0xA7, 0x14}, {0xA4, 0x51, 0x3B, 0xF6, 0x04, 0x60}},guid_properties_81},
	{{0x90E5E14E, 0x648B, 0x4826, {0xB2, 0xAA}, {0xAC, 0xAF, 0x79, 0x0E, 0x35, 0x13}},guid_properties_82},
	{{0x09EDD5B6, 0xB301, 0x43C5, {0x99, 0x90}, {0xD0, 0x03, 0x02, 0xEF, 0xFD, 0x46}},guid_properties_83},
	{{0x0B63E350, 0x9CCC, 0x11D0, {0xBC, 0xDB}, {0x00, 0x80, 0x5F, 0xCC, 0xCE, 0x04}},guid_properties_84},
	{{0xD55BAE5A, 0x3892, 0x417A, {0xA6, 0x49}, {0xC6, 0xAC, 0x5A, 0xAA, 0xEA, 0xB3}},guid_properties_85},
	{{0xF21D9941, 0x81F0, 0x471A, {0xAD, 0xEE}, {0x4E, 0x74, 0xB4, 0x92, 0x17, 0xED}},guid_properties_86},
	{{0xB0B87314, 0xFCF6, 0x4FEB, {0x8D, 0xFF}, {0xA5, 0x0D, 0xA6, 0xAF, 0x56, 0x1C}},guid_properties_87},
	{{0xCC6F4F24, 0x6083, 0x4BD4, {0x87, 0x54}, {0x67, 0x4D, 0x0D, 0xE8, 0x7A, 0xB8}},guid_properties_88},
	{{0xA0E74609, 0xB84D, 0x4F49, {0xB8, 0x60}, {0x46, 0x2B, 0xD9, 0x97, 0x1F, 0x98}},guid_properties_89},
	{{0x5CDA5FC8, 0x33EE, 0x4FF3, {0x90, 0x94}, {0xAE, 0x7B, 0xD8, 0x86, 0x8C, 0x4D}},guid_properties_90},
	{{0xD68DBD8A, 0x3374, 0x4B81, {0x99, 0x72}, {0x3E, 0xC3, 0x06, 0x82, 0xDB, 0x3D}},guid_properties_91},
	{{0x2CBAA8F5, 0xD81F, 0x47CA, {0xB1, 0x7A}, {0xF8, 0xD8, 0x22, 0x30, 0x01, 0x31}},guid_properties_92},
	{{0x72FAB781, 0xACDA, 0x43E5, {0xB1, 0x55}, {0xB2, 0x43, 0x4F, 0x85, 0xE6, 0x78}},guid_properties_93},
	{{0x6B8DA074, 0x3B5C, 0x43BC, {0x88, 0x6F}, {0x0A, 0x2C, 0xDC, 0xE0, 0x0B, 0x6F}},guid_properties_94},
	{{0x18BBD425, 0xECFD, 0x46EF, {0xB6, 0x12}, {0x7B, 0x4A, 0x60, 0x34, 0xED, 0xA0}},guid_properties_95},
	{{0x56A3372E, 0xCE9C, 0x11D2, {0x9F, 0x0E}, {0x00, 0x60, 0x97, 0xC6, 0x86, 0xF6}},guid_properties_96},
	{{0x276D7BB0, 0x5B34, 0x4FB0, {0xAA, 0x4B}, {0x15, 0x8E, 0xD1, 0x2A, 0x18, 0x09}},guid_properties_97},
	{{0xFEC690B7, 0x5F30, 0x4646, {0xAE, 0x47}, {0x4C, 0xAA, 0xFB, 0xA8, 0x84, 0xA3}},guid_properties_98},
	{{0xF29F85E0, 0x4FF9, 0x1068, {0xAB, 0x91}, {0x08, 0x00, 0x2B, 0x27, 0xB3, 0xD9}},guid_properties_99},
	{{0x46B4E8DE, 0xCDB2, 0x440D, {0x88, 0x5C}, {0x16, 0x58, 0xEB, 0x65, 0xB9, 0x14}},guid_properties_100},
	{{0xF628FD8C, 0x7BA8, 0x465A, {0xA6, 0x5B}, {0xC5, 0xAA, 0x79, 0x26, 0x3A, 0x9E}},guid_properties_101},
	{{0x7A7D76F4, 0xB630, 0x4BD7, {0x95, 0xFF}, {0x37, 0xCC, 0x51, 0xA9, 0x75, 0xC9}},guid_properties_102},
	{{0x446F787F, 0x10C4, 0x41CB, {0xA6, 0xC4}, {0x4D, 0x03, 0x43, 0x55, 0x15, 0x97}},guid_properties_103},
	{{0xA9EA193C, 0xC511, 0x498A, {0xA0, 0x6B}, {0x58, 0xE2, 0x77, 0x6D, 0xCC, 0x28}},guid_properties_104},
	{{0x97B0AD89, 0xDF49, 0x49CC, {0x83, 0x4E}, {0x66, 0x09, 0x74, 0xFD, 0x75, 0x5B}},guid_properties_105},
	{{0xF6272D18, 0xCECC, 0x40B1, {0xB2, 0x6A}, {0x39, 0x11, 0x71, 0x7A, 0xA7, 0xBD}},guid_properties_106},
	{{0x61478C08, 0xB600, 0x4A84, {0xBB, 0xE4}, {0xE9, 0x9C, 0x45, 0xF0, 0xA0, 0x72}},guid_properties_107},
	{{0xC8EA94F0, 0xA9E3, 0x4969, {0xA9, 0x4B}, {0x9C, 0x62, 0xA9, 0x53, 0x24, 0xE0}},guid_properties_108},
	{{0x9AD5BADB, 0xCEA7, 0x4470, {0xA0, 0x3D}, {0xB8, 0x4E, 0x51, 0xB9, 0x94, 0x9E}},guid_properties_109},
	{{0xF1A24AA7, 0x9CA7, 0x40F6, {0x89, 0xEC}, {0x97, 0xDE, 0xF9, 0xFF, 0xE8, 0xDB}},guid_properties_110},
	{{0x3602C812, 0x0F3B, 0x45F0, {0x85, 0xAD}, {0x60, 0x34, 0x68, 0xD6, 0x94, 0x23}},guid_properties_111},
	{{0x897B3694, 0xFE9E, 0x43E6, {0x80, 0x66}, {0x26, 0x0F, 0x59, 0x0C, 0x01, 0x00}},guid_properties_112},
	{{0x8619A4B6, 0x9F4D, 0x4429, {0x8C, 0x0F}, {0xB9, 0x96, 0xCA, 0x59, 0xE3, 0x35}},guid_properties_113},
	{{0xA26F4AFC, 0x7346, 0x4299, {0xBE, 0x47}, {0xEB, 0x1A, 0xE6, 0x13, 0x13, 0x9F}},guid_properties_114},
	{{0xBC4E71CE, 0x17F9, 0x48D5, {0xBE, 0xE9}, {0x02, 0x1D, 0xF0, 0xEA, 0x54, 0x09}},guid_properties_115},
	{{0xE4F10A3C, 0x49E6, 0x405D, {0x82, 0x88}, {0xA2, 0x3B, 0xD4, 0xEE, 0xAA, 0x6C}},guid_properties_116},
	{{0x65A98875, 0x3C80, 0x40AB, {0xAB, 0xBC}, {0xEF, 0xDA, 0xF7, 0x7D, 0xBE, 0xE2}},guid_properties_117},
	{{0x84D8F337, 0x981D, 0x44B3, {0x96, 0x15}, {0xC7, 0x59, 0x6D, 0xBA, 0x17, 0xE3}},guid_properties_118},
	{{0xD5CDD502, 0x2E9C, 0x101B, {0x93, 0x97}, {0x08, 0x00, 0x2B, 0x2C, 0xF9, 0xAE}},guid_properties_119},
	{{0xBE1A72C6, 0x9A1D, 0x46B7, {0xAF, 0xE7}, {0xAF, 0xAF, 0x8C, 0xEF, 0x49, 0x99}},guid_properties_120},
	{{0x8F367200, 0xC270, 0x457C, {0xB1, 0xD4}, {0xE0, 0x7C, 0x5B, 0xCD, 0x90, 0xC7}},guid_properties_121},
	{{0x428040AC, 0xA177, 0x4C8A, {0x97, 0x60}, {0xF6, 0xF7, 0x61, 0x22, 0x7F, 0x9A}},guid_properties_122},
	{{0xA3B29791, 0x7713, 0x4E1D, {0xBB, 0x40}, {0x17, 0xDB, 0x85, 0xF0, 0x18, 0x31}},guid_properties_123},
	{{0xBCEEE283, 0x35DF, 0x4D53, {0x82, 0x6A}, {0xF3, 0x6A, 0x3E, 0xEF, 0xC6, 0xBE}},guid_properties_124},
	{{0x91EFF6F3, 0x2E27, 0x42CA, {0x93, 0x3E}, {0x7C, 0x99, 0x9F, 0xBE, 0x31, 0x0B}},guid_properties_125},
	{{0x64440491, 0x4C8B, 0x11D1, {0x8B, 0x70}, {0x08, 0x00, 0x36, 0xB1, 0x1A, 0x03}},guid_properties_126},
	{{0x5CBF2787, 0x48CF, 0x4208, {0xB9, 0x0E}, {0xEE, 0x5E, 0x5D, 0x42, 0x02, 0x94}},guid_properties_127},
	{{0xA6F360D2, 0x55F9, 0x48DE, {0xB9, 0x09}, {0x62, 0x0E, 0x09, 0x0A, 0x64, 0x7C}},guid_properties_128},
	{{0x08C7CC5F, 0x60F2, 0x4494, {0xAD, 0x75}, {0x55, 0xE3, 0xE0, 0xB5, 0xAD, 0xD0}},guid_properties_129},
	{{0xDABD30ED, 0x0043, 0x4789, {0xA7, 0xF8}, {0xD0, 0x13, 0xA4, 0x73, 0x66, 0x22}},guid_properties_130},
	{{0x7FE3AA27, 0x2648, 0x42F3, {0x89, 0xB0}, {0x45, 0x4E, 0x5C, 0xB1, 0x50, 0xC3}},guid_properties_131},
	{{0xE53D799D, 0x0F3F, 0x466E, {0xB2, 0xFF}, {0x74, 0x63, 0x4A, 0x3C, 0xB7, 0xA4}},guid_properties_132},
	{{0xDE35258C, 0xC695, 0x4CBC, {0xB9, 0x82}, {0x38, 0xB0, 0xAD, 0x24, 0xCE, 0xD0}},guid_properties_133},
	{{0x71B377D6, 0xE570, 0x425F, {0xA1, 0x70}, {0x80, 0x9F, 0xAE, 0x73, 0xE5, 0x4E}},guid_properties_134},
	{{0x3143BF7C, 0x80A8, 0x4854, {0x88, 0x80}, {0xE2, 0xE4, 0x01, 0x89, 0xBD, 0xD0}},guid_properties_135},
	{{0xA6744477, 0xC237, 0x475B, {0xA0, 0x75}, {0x54, 0xF3, 0x44, 0x98, 0x29, 0x2A}},guid_properties_136},
	{{0xC9C34F84, 0x2241, 0x4401, {0xB6, 0x07}, {0xBD, 0x20, 0xED, 0x75, 0xAE, 0x7F}},guid_properties_137},
	{{0xF8FA7FA3, 0xD12B, 0x4785, {0x8A, 0x4E}, {0x69, 0x1A, 0x94, 0xF7, 0xA3, 0xE7}},guid_properties_138},
	{{0x635E9051, 0x50A5, 0x4BA2, {0xB9, 0xDB}, {0x4E, 0xD0, 0x56, 0xC7, 0x72, 0x96}},guid_properties_139},
	{{0x1E005EE6, 0xBF27, 0x428B, {0xB0, 0x1C}, {0x79, 0x67, 0x6A, 0xCD, 0x28, 0x70}},guid_properties_140},
	{{0xE1D4A09E, 0xD758, 0x4CD1, {0xB6, 0xEC}, {0x34, 0xA8, 0xB5, 0xA7, 0x3F, 0x80}},guid_properties_141},
	{{0xD7313FF1, 0xA77A, 0x401C, {0x8C, 0x99}, {0x3D, 0xBD, 0xD6, 0x8A, 0xDD, 0x36}},guid_properties_142},
	{{0xF85BF840, 0xA925, 0x4BC2, {0xB0, 0xC4}, {0x8E, 0x36, 0xB5, 0x98, 0x67, 0x9E}},guid_properties_143},
	{{0x668CDFA5, 0x7A1B, 0x4323, {0xAE, 0x4B}, {0xE5, 0x27, 0x39, 0x3A, 0x1D, 0x81}},guid_properties_144},
	{{0xEE3D3D8A, 0x5381, 0x4CFA, {0xB1, 0x3B}, {0xAA, 0xF6, 0x6B, 0x5F, 0x4E, 0xC9}},guid_properties_145},
	{{0xD0C7F054, 0x3F72, 0x4725, {0x85, 0x27}, {0x12, 0x9A, 0x57, 0x7C, 0xB2, 0x69}},guid_properties_146},
	{{0xAA6EE6B0, 0xE828, 0x11D0, {0xB2, 0x3E}, {0x00, 0xAA, 0x00, 0x47, 0xFC, 0x01}},guid_properties_147},
	{{0x08F6D7C2, 0xE3F2, 0x44FC, {0xAF, 0x1E}, {0x5A, 0xA5, 0xC8, 0x1A, 0x2D, 0x3E}},guid_properties_148},
	{{0x00F58A38, 0xC54B, 0x4C40, {0x86, 0x96}, {0x97, 0x23, 0x59, 0x80, 0xEA, 0xE1}},guid_properties_149},
	{{0x6E682923, 0x7F7B, 0x4F0C, {0xA3, 0x37}, {0xCF, 0xCA, 0x29, 0x66, 0x87, 0xBF}},guid_properties_150},
	{{0xFD122953, 0xFA93, 0x4EF7, {0x92, 0xC3}, {0x04, 0xC9, 0x46, 0xB2, 0xF7, 0xC8}},guid_properties_151},
	{{0x0BE1C8E7, 0x1981, 0x4676, {0xAE, 0x14}, {0xFD, 0xD7, 0x8F, 0x05, 0xA6, 0xE7}},guid_properties_152},
	{{0xF1176DFE, 0x7138, 0x4640, {0x8B, 0x4C}, {0xAE, 0x37, 0x5D, 0xC7, 0x0A, 0x6D}},guid_properties_153},
	{{0x48FD6EC8, 0x8A12, 0x4CDF, {0xA0, 0x3E}, {0x4E, 0xC5, 0xA5, 0x11, 0xED, 0xDE}},guid_properties_154},
	{{0xB725F130, 0x47EF, 0x101A, {0xA5, 0xF1}, {0x02, 0x60, 0x8C, 0x9E, 0xEB, 0xAC}},guid_properties_155},
	{{0xDDD1460F, 0xC0BF, 0x4553, {0x8C, 0xE4}, {0x10, 0x43, 0x3C, 0x90, 0x8F, 0xB0}},guid_properties_156},
	{{0xF8D3F6AC, 0x4874, 0x42CB, {0xBE, 0x59}, {0xAB, 0x45, 0x4B, 0x30, 0x71, 0x6A}},guid_properties_157},
	{{0x08A65AA1, 0xF4C9, 0x43DD, {0x9D, 0xDF}, {0xA3, 0x3D, 0x8E, 0x7E, 0xAD, 0x85}},guid_properties_158},
	{{0x084D8A0A, 0xE6D5, 0x40DE, {0xBF, 0x1F}, {0xC8, 0x82, 0x0E, 0x7C, 0x87, 0x7C}},guid_properties_159},
	{{0x841E4F90, 0xFF59, 0x4D16, {0x89, 0x47}, {0xE8, 0x1B, 0xBF, 0xFA, 0xB3, 0x6D}},guid_properties_160},
	{{0xFC9F7306, 0xFF8F, 0x4D49, {0x9F, 0xB6}, {0x3F, 0xFE, 0x5C, 0x09, 0x51, 0xEC}},guid_properties_161},
	{{0x53DA57CF, 0x62C0, 0x45C4, {0x81, 0xDE}, {0x76, 0x10, 0xBC, 0xEF, 0xD7, 0xF5}},guid_properties_162},
	{{0x9B174B34, 0x40FF, 0x11D2, {0xA2, 0x7E}, {0x00, 0xC0, 0x4F, 0xC3, 0x08, 0x71}},guid_properties_163},
	{{0x4684FE97, 0x8765, 0x4842, {0x9C, 0x13}, {0xF0, 0x06, 0x44, 0x7B, 0x17, 0x8C}},guid_properties_164},
	{{0x09329B74, 0x40A3, 0x4C68, {0xBF, 0x07}, {0xAF, 0x9A, 0x57, 0x2F, 0x60, 0x7C}},guid_properties_165},
	{{0x3F8472B5, 0xE0AF, 0x4DB2, {0x80, 0x71}, {0xC5, 0x3F, 0xE7, 0x6A, 0xE7, 0xCE}},guid_properties_166},
	{{0x0CEF7D53, 0xFA64, 0x11D1, {0xA2, 0x03}, {0x00, 0x00, 0xF8, 0x1F, 0xED, 0xEE}},guid_properties_167},
	{{0xFDF84370, 0x031A, 0x4ADD, {0x9E, 0x91}, {0x0D, 0x77, 0x5F, 0x1C, 0x66, 0x05}},guid_properties_168},
	{{0x6D748DE2, 0x8D38, 0x4CC3, {0xAC, 0x60}, {0xF0, 0x09, 0xB0, 0x57, 0xC5, 0x57}},guid_properties_169},
	{{0x2579E5D0, 0x1116, 0x4084, {0xBD, 0x9A}, {0x9B, 0x4F, 0x7C, 0xB4, 0xDF, 0x5E}},guid_properties_170},
	{{0xF7DB74B4, 0x4287, 0x4103, {0xAF, 0xBA}, {0xF1, 0xB1, 0x3D, 0xCD, 0x75, 0xCF}},guid_properties_171},
	{{0x9D2408B6, 0x3167, 0x422B, {0x82, 0xB0}, {0xF5, 0x83, 0xB7, 0xA7, 0xCF, 0xE3}},guid_properties_172},
	{{0xA82D9EE7, 0xCA67, 0x4312, {0x96, 0x5E}, {0x22, 0x6B, 0xCE, 0xA8, 0x50, 0x23}},guid_properties_173},
	{{0x9A93244D, 0xA7AD, 0x4FF8, {0x9B, 0x99}, {0x45, 0xEE, 0x4C, 0xC0, 0x9A, 0xF6}},guid_properties_174},
	{{0xF04BEF95, 0xC585, 0x4197, {0xA2, 0xB7}, {0xDF, 0x46, 0xFD, 0xC9, 0xEE, 0x6D}},guid_properties_175},
	{{0x59DDE9F2, 0x5253, 0x40EA, {0x9A, 0x8B}, {0x47, 0x9E, 0x96, 0xC6, 0x24, 0x9A}},guid_properties_176},
	{{0x6444048F, 0x4C8B, 0x11D1, {0x8B, 0x70}, {0x08, 0x00, 0x36, 0xB1, 0x1A, 0x03}},guid_properties_177},
	{{0x9A9BC088, 0x4F6D, 0x469E, {0x99, 0x19}, {0xE7, 0x05, 0x41, 0x20, 0x40, 0xF9}},guid_properties_178},
	{{0xD0A04F0A, 0x462A, 0x48A4, {0xBB, 0x2F}, {0x37, 0x06, 0xE8, 0x8D, 0xBD, 0x7D}},guid_properties_179},
	{{0xC554493C, 0xC1F7, 0x40C1, {0xA7, 0x6C}, {0xEF, 0x8C, 0x06, 0x14, 0x00, 0x3E}},guid_properties_180},
	{{0xEC0B4191, 0xAB0B, 0x4C66, {0x90, 0xB6}, {0xC6, 0x63, 0x7C, 0xDE, 0xBB, 0xAB}},guid_properties_181},
	{{0x660E04D6, 0x81AB, 0x4977, {0xA0, 0x9F}, {0x82, 0x31, 0x31, 0x13, 0xAB, 0x26}},guid_properties_182},
	{{0xDC54FD2E, 0x189D, 0x4871, {0xAA, 0x01}, {0x08, 0xC2, 0xF5, 0x7A, 0x4A, 0xBC}},guid_properties_183},
	{{0xCD102C9C, 0x5540, 0x4A88, {0xA6, 0xF6}, {0x64, 0xE4, 0x98, 0x1C, 0x8C, 0xD1}},guid_properties_184},
	{{0x1F856A9F, 0x6900, 0x4ABA, {0x95, 0x05}, {0x2D, 0x5F, 0x1B, 0x4D, 0x66, 0xCB}},guid_properties_185},
	{{0x90197CA7, 0xFD8F, 0x4E8C, {0x9D, 0xA3}, {0xB5, 0x7E, 0x1E, 0x60, 0x92, 0x95}},guid_properties_186},
	{{0xF334115E, 0xDA1B, 0x4509, {0x9B, 0x3D}, {0x11, 0x95, 0x04, 0xDC, 0x7A, 0xBB}},guid_properties_187},
	{{0xBF53D1C3, 0x49E0, 0x4F7F, {0x85, 0x67}, {0x5A, 0x82, 0x1D, 0x8A, 0xC5, 0x42}},guid_properties_188},
	{{0xC75FAA05, 0x96FD, 0x49E7, {0x9C, 0xB4}, {0x9F, 0x60, 0x10, 0x82, 0xD5, 0x53}},guid_properties_189},
	{{0x2E4B640D, 0x5019, 0x46D8, {0x88, 0x81}, {0x55, 0x41, 0x4C, 0xC5, 0xCA, 0xA0}},guid_properties_190},
	{{0x6B8B68F6, 0x200B, 0x47EA, {0x8D, 0x25}, {0xD8, 0x05, 0x0F, 0x57, 0x33, 0x9F}},guid_properties_191},
	{{0x2D152B40, 0xCA39, 0x40DB, {0xB2, 0xCC}, {0x57, 0x37, 0x25, 0xB2, 0xFE, 0xC5}},guid_properties_192},
	{{0x7268AF55, 0x1CE4, 0x4F6E, {0xA4, 0x1F}, {0xB6, 0xE4, 0xEF, 0x10, 0xE4, 0xA9}},guid_properties_193},
	{{0xD6304E01, 0xF8F5, 0x4F45, {0x8B, 0x15}, {0xD0, 0x24, 0xA6, 0x29, 0x67, 0x89}},guid_properties_194},
	{{0xA7AC77ED, 0xF8D7, 0x11CE, {0xA7, 0x98}, {0x00, 0x20, 0xF8, 0x00, 0x80, 0x25}},guid_properties_195},
	{{0x402B5934, 0xEC5A, 0x48C3, {0x93, 0xE6}, {0x85, 0xE8, 0x6A, 0x2D, 0x93, 0x4E}},guid_properties_196},
	{{0x9AEBAE7A, 0x9644, 0x487D, {0xA9, 0x2C}, {0x65, 0x75, 0x85, 0xED, 0x75, 0x1A}},guid_properties_197},
	{{0x63C25B20, 0x96BE, 0x488F, {0x87, 0x88}, {0xC0, 0x9C, 0x40, 0x7A, 0xD8, 0x12}},guid_properties_198},
	{{0x39A7F922, 0x477C, 0x48DE, {0x8B, 0xC8}, {0xB2, 0x84, 0x41, 0xE3, 0x42, 0xE3}},guid_properties_199},
	{{0x4776CAFA, 0xBCE4, 0x4CB1, {0xA2, 0x3E}, {0x26, 0x5E, 0x76, 0xD8, 0xEB, 0x11}},guid_properties_200},
	{{0xE3E0584C, 0xB788, 0x4A5A, {0xBB, 0x20}, {0x7F, 0x5A, 0x44, 0xC9, 0xAC, 0xDD}},guid_properties_201},
	{{0x95BEB1FC, 0x326D, 0x4644, {0xB3, 0x96}, {0xCD, 0x3E, 0xD9, 0x0E, 0x6D, 0xDF}},guid_properties_202},
	{{0xC0AC206A, 0x827E, 0x4650, {0x95, 0xAE}, {0x77, 0xE2, 0xBB, 0x74, 0xFC, 0xC9}},guid_properties_203},
};

const struct full_propset_info *get_propset_info_with_guid(
						const char *prop_name,
						struct GUID *propset_guid)
{
	int i;
	struct full_guid_propset *guid_propset = NULL;
	const struct full_propset_info *result = NULL;
	for (i = 0; i < ARRAY_SIZE(full_propertyset); i++) {
		const struct full_propset_info *item = NULL;
		guid_propset = &full_propertyset[i];
		item = guid_propset->prop_info;
		while (item->id) {
			if (strequal(prop_name, item->name)) {
				*propset_guid = guid_propset->guid;
				result = item;
				break;
			}
			item++;
		}
		if (result) {
			break;
		}
	}
	return result;
}

const struct full_propset_info *get_prop_info(const char *prop_name)
{
	const struct full_propset_info *result = NULL;
	struct GUID guid;
	result = get_propset_info_with_guid(prop_name, &guid);
	return result;
}

char *prop_from_fullprop(TALLOC_CTX *ctx, struct wsp_cfullpropspec *fullprop)
{
	int i;
	char *result = NULL;
	const struct full_propset_info *item = NULL;
	bool search_by_id = (fullprop->ulkind == PRSPEC_PROPID);

	for (i = 0; i < ARRAY_SIZE(full_propertyset); i++) {
		/* find propset */
		if (GUID_equal(&fullprop->guidpropset,
			       &full_propertyset[i].guid)) {
			item = full_propertyset[i].prop_info;
			break;
		}
	}
	if (item) {
		while (item->id) {
			if (search_by_id) {
				if( fullprop->name_or_id.prspec == item->id) {
					result = talloc_strdup(ctx, item->name);
					break;
				}
			} else if (strcmp(item->name,
					fullprop->name_or_id.propname.vstring)
					== 0) {
				result = talloc_strdup(ctx, item->name);
				break;
			}
			item++;
		}
	}

	if (!result) {
		result = GUID_string(ctx, &fullprop->guidpropset);

		if (search_by_id) {
			result = talloc_asprintf(result, "%s/%d", result,
						 fullprop->name_or_id.prspec);
		} else {
			result = talloc_asprintf(result, "%s/%s", result,
					fullprop->name_or_id.propname.vstring);
		}
	}
	return result;
}

static const struct {
	uint32_t id;
	const char *name;
} typename_map[] = {
	{VT_EMPTY, "Empty"},
	{VT_NULL, "Null"},
	{VT_I2, "VT_I2"},
	{VT_I4, "VT_I4"},
	{VT_I4, "VT_I4"},
	{VT_R4, "VT_R4"},
	{VT_R8, "VT_R8"},
	{VT_CY, "VT_CY"},
	{VT_DATE, "VT_DATE"},
	{VT_BSTR, "VT_BSTR"},
	{VT_I1, "VT_I1"},
	{VT_UI1, "VT_UI1"},
	{VT_UI2, "VT_UI2"},
	{VT_UI4, "VT_UI4"},
	{VT_I8, "VT_I8"},
	{VT_UI8, "VT_UI8"},
	{VT_INT, "VT_INT"},
	{VT_UINT, "VT_UINT"},
	{VT_ERROR, "VT_ERROR"},
	{VT_BOOL, "VT_BOOL"},
	{VT_VARIANT, "VT_VARIANT"},
	{VT_DECIMAL, "VT_DECIMAL"},
	{VT_FILETIME, "VT_FILETIME"},
	{VT_BLOB, "VT_BLOB"},
	{VT_BLOB_OBJECT, "VT_BLOB_OBJECT"},
	{VT_CLSID, "VT_CLSID"},
	{VT_LPSTR, "VT_LPSTR"},
	{VT_LPWSTR, "VT_LPWSTR"},
	{VT_COMPRESSED_LPWSTR, "VT_COMPRESSED_LPWSTR"},
};

const char * get_vtype_name(uint32_t type)
{
	const char *type_name = NULL;
	static char result_buf[255];
	int i;
	uint32_t temp = type & ~(VT_VECTOR | VT_ARRAY);
	for (i = 0; i < ARRAY_SIZE(typename_map); i++) {
		if (temp == typename_map[i].id) {
			type_name = typename_map[i].name;
			break;
		}
	}
	if (type & VT_VECTOR) {
		snprintf(result_buf, sizeof(result_buf), "Vector | %s", type_name);
	} else if (type & VT_ARRAY) {
		snprintf(result_buf, sizeof(result_buf), "Array | %s", type_name);
	} else {
		snprintf(result_buf, sizeof(result_buf), "%s", type_name);
	}
	return result_buf;
}

bool is_variable_size(uint16_t vtype)
{
	bool result;
	switch(vtype) {
		case VT_LPWSTR:
		case VT_BSTR:
		case VT_BLOB:
		case VT_BLOB_OBJECT:
		case VT_VARIANT:
			result = true;
			break;
		default:
			result = false;
			break;
	}
	return result;
}

const char *get_store_status(uint8_t status_byte)
{
	const char *result;
	switch(status_byte) {
		case 0:
			result = "StoreStatusOk";
			break;
		case 1:
			result = "StoreStatusDeferred";
			break;
		case 2:
			result = "StoreStatusNull";
			break;
		default:
			result = "Unknown Status";
			break;
	}
	return result;
}

void set_variant_lpwstr(TALLOC_CTX *ctx,
			struct wsp_cbasestoragevariant *vvalue,
			const char *string_val)
{
	vvalue->vtype = VT_LPWSTR;
	vvalue->vvalue.vt_lpwstr.value = talloc_strdup(ctx, string_val);
}

void set_variant_i4(TALLOC_CTX *ctx,
		    struct wsp_cbasestoragevariant *vvalue,
		    uint32_t val)
{
	vvalue->vtype = VT_I4;
	vvalue->vvalue.vt_i4 = val;
}

void set_variant_vt_bool(TALLOC_CTX *ctx,
			struct wsp_cbasestoragevariant *variant,
			bool bval)
{
	variant->vtype = VT_BOOL;
	variant->vvalue.vt_bool = bval;
}

static void fill_int32_vec(TALLOC_CTX* ctx,
			    int32_t **pdest,
			    int32_t* ivector, uint32_t elems)
{
	int i;
	int32_t *dest = talloc_zero_array(ctx, int32_t, elems);
	for ( i = 0; i < elems; i++ ) {
		dest[ i ] = ivector[ i ];
	}
	*pdest = dest;
}

void set_variant_i4_vector(TALLOC_CTX *ctx,
			   struct wsp_cbasestoragevariant *variant,
			   int32_t* ivector, uint32_t elems)
{
	variant->vtype = VT_VECTOR | VT_I4;
	variant->vvalue.vt_i4_vec.vvector_elements = elems;
	fill_int32_vec(ctx, &variant->vvalue.vt_i4_vec.vvector_data, ivector, elems);
}

static void fill_string_vec(TALLOC_CTX* ctx,
				struct wsp_cbasestoragevariant *variant,
				const char **strings, uint16_t elems)
{
	int i;
	variant->vvalue.vt_lpwstr_v.vvector_elements = elems;
	variant->vvalue.vt_lpwstr_v.vvector_data = talloc_zero_array(ctx,
							struct vt_lpwstr,
							elems);

	for( i = 0; i < elems; i++ ) {
		variant->vvalue.vt_lpwstr_v.vvector_data[ i ].value = talloc_strdup(ctx, strings[ i ]);
	}
}

static void fill_bstr_vec(TALLOC_CTX *ctx,
		  struct vt_bstr **pvector,
		  const char **strings, uint16_t elems)
{
	int i;
	struct vt_bstr *vdata = talloc_zero_array(ctx, struct vt_bstr, elems);

	for( i = 0; i < elems; i++ ) {
		vdata [ i ].value = talloc_strdup(ctx, strings[ i ]);
	}
	*pvector = vdata;
}

void set_variant_bstr(TALLOC_CTX *ctx, struct wsp_cbasestoragevariant *variant,
			const char *string_val)
{
	variant->vtype = VT_BSTR;
	variant->vvalue.vt_bstr.value = talloc_strdup(ctx, string_val);
}

void set_variant_lpwstr_vector(TALLOC_CTX *ctx,
			      struct wsp_cbasestoragevariant *variant,
			      const char **string_vals, uint32_t elems)
{
	variant->vtype = VT_LPWSTR | VT_VECTOR;
	fill_string_vec(ctx, variant, string_vals, elems);
}

void set_variant_array_bstr(TALLOC_CTX *ctx,
			   struct wsp_cbasestoragevariant *variant,
			   const char **string_vals, uint16_t elems)
{
	variant->vtype = VT_BSTR | VT_ARRAY;
	variant->vvalue.vt_bstr_array.cdims = 1;
	variant->vvalue.vt_bstr_array.ffeatures = 0;

	variant->vvalue.vt_bstr_array.rgsabound =
		talloc_zero_array(ctx, struct safearraybound, 1);

	variant->vvalue.vt_bstr_array.rgsabound[0].celements = elems;
	variant->vvalue.vt_bstr_array.rgsabound[0].ilbound = 0;
	variant->vvalue.vt_bstr_array.cbelements = 0;
	fill_bstr_vec(ctx, &variant->vvalue.vt_bstr_array.vdata,
		      string_vals, elems);
	/*
	 * if cbelements is the num bytes per elem it kindof means each
	 * string in the array must be the same size ?
	 */

	if (elems >0) {
		variant->vvalue.vt_bstr_array.cbelements =
			strlen_m_term(variant->vvalue.vt_bstr_array.vdata[0].value)*2;
	}
}

/* create single dim array of vt_i4 */
void set_variant_array_i4(TALLOC_CTX *ctx,
			 struct wsp_cbasestoragevariant *variant,
			 int32_t *vals, uint16_t elems)
{
	/* #TODO see if we can combine with other set_variant_array methods */
	variant->vtype = VT_I4 | VT_ARRAY;
	variant->vvalue.vt_i4_array.cdims = 1;
	variant->vvalue.vt_i4_array.ffeatures = 0;

	variant->vvalue.vt_i4_array.rgsabound =
		talloc_zero_array(ctx, struct safearraybound, 1);

	variant->vvalue.vt_i4_array.rgsabound[0].celements = elems;
	variant->vvalue.vt_i4_array.rgsabound[0].ilbound = 0;
	variant->vvalue.vt_i4_array.cbelements = sizeof(uint32_t);
	fill_int32_vec(ctx, &variant->vvalue.vt_i4_array.vdata, vals, elems);
}

const char *genmeth_to_string(uint32_t genmethod)
{
	const char *result;
	switch (genmethod) {
		case 0:
			result = "equals";
			break;
		case 1:
			result = "starts with";
			break;
		case 2:
			result = "matches inflection";
			break;
		default:
			result = "ERROR, unknown generate method";
			break;
	}
	return result;
}

bool is_operator(struct wsp_crestriction *restriction) {
	bool result;
	switch(restriction->ultype) {
		case RTAND:
		case RTOR:
		case RTNOT:
			result = true;
			break;
		default:
			result = false;
			break;
	}
	return result;
}

const char *op_as_string(struct wsp_crestriction *restriction)
{
	const char *op = NULL;
	if (is_operator(restriction)) {
		switch(restriction->ultype) {
			case RTAND:
				op = " && ";
				break;
			case RTOR:
				op = " || ";
				break;
			case RTNOT:
				op = "!";
				break;
		}
	} else if (restriction->ultype == RTPROPERTY) {
		struct wsp_cpropertyrestriction *prop_restr =
			&restriction->restriction.cpropertyrestriction;
		switch (prop_restr->relop & 0XF) {
			case PREQ:
				op = "=";
				break;
			case PRNE:
				op = "!=";
				break;
			case PRGE:
				op = ">=";
				break;
			case PRLE:
				op = "<=";
				break;
			case PRLT:
				op = "<";
				break;
			case PRGT:
				op = ">";
				break;
			default:
				break;
		}
	} else if (restriction->ultype == RTCONTENT) {
		struct wsp_ccontentrestriction *content = NULL;
		content = &restriction->restriction.ccontentrestriction;
		op = genmeth_to_string(content->ulgeneratemethod);
	} else if (restriction->ultype == RTNATLANGUAGE) {
		op = "=";
	}
	return op;
}

struct wsp_cfullpropspec *get_full_prop(struct wsp_crestriction *restriction)
{
	struct wsp_cfullpropspec *result;
	switch (restriction->ultype) {
		case RTPROPERTY:
			result = &restriction->restriction.cpropertyrestriction.property;
			break;
		case RTCONTENT:
			result = &restriction->restriction.ccontentrestriction.property;
			break;
		case RTNATLANGUAGE:
			result = &restriction->restriction.cnatlanguagerestriction.property;
			break;
		default:
			result = NULL;
			break;
	}
	return result;
}

const char *variant_as_string(TALLOC_CTX *ctx,
			struct wsp_cbasestoragevariant *value, bool quote)
{
	const char* result = NULL;
	switch(value->vtype) {
		case VT_I4:
		case VT_UI4:
		case VT_INT:
		case VT_UINT:
		case VT_I2:
		case VT_UI2:
			result = talloc_asprintf(ctx, "%d",
						 value->vvalue.vt_i4);
			break;
		case VT_I8:
		case VT_UI8:
		case VT_R8:
		case VT_CY:
		case VT_DATE:
		case VT_FILETIME: {
			uint64_t val;
			wsp_hyper_to_uint64(&value->vvalue.vt_ui8, &val);
			result = talloc_asprintf(ctx, "0x%" PRIx64,
						 val);
			break;
		}
		case VT_LPWSTR:
			result = talloc_asprintf(ctx, "%s%s%s",
						quote ? "\'" : "",
						value->vvalue.vt_lpwstr.value,
						quote ? "\'" : "");
			break;
		case VT_LPWSTR | VT_VECTOR: {
			int num_elems =
			value->vvalue.vt_lpwstr_v.vvector_elements;
			int i;
			for(i = 0; i < num_elems; i++) {
				struct vt_lpwstr_vec *vec;
				const char *val;
				vec = &value->vvalue.vt_lpwstr_v;
				val = vec->vvector_data[i].value;
				result =
					talloc_asprintf(ctx,
							"%s%s%s%s%s",
							result ? result : "",
							i ? "," : "",
							quote ? "\'" : "",
							val,
							quote ? "\'" : "");
			}
			break;
		}
		default:
			DBG_INFO("#FIXME unsupported type 0x%x\n",
				value->vtype);
			break;
	}
	return result;
}

static NTSTATUS restriction_node_to_string(TALLOC_CTX *ctx,
			 struct wsp_crestriction *restriction,
			 const char **str_result)
{
	const char *result = NULL;
	struct wsp_cfullpropspec *full_prop = get_full_prop(restriction);
	const char *op_str = op_as_string(restriction);
	const char *propname = NULL;
	const char *value = NULL;
	NTSTATUS status = NT_STATUS_OK;
	if (is_operator(restriction)) {
		result = talloc_strdup(ctx, op_str);
		goto out;
	}

	if (restriction->ultype == RTPROPERTY
	|| restriction->ultype == RTCONTENT
	|| restriction->ultype == RTNATLANGUAGE) {
		if (full_prop) {
			propname = prop_from_fullprop(ctx, full_prop);
		}
		if (propname == NULL) {
			DBG_ERR("Unknown propname\n");
			status = NT_STATUS_UNSUCCESSFUL;
			goto out;
		}
	}
	if (op_str == NULL) {
		DBG_WARNING("Unknow operation for prop %s\n", propname);
	}
	switch(restriction->ultype) {
		case RTCONTENT: {
			struct wsp_ccontentrestriction *content = NULL;
			content =
				&restriction->restriction.ccontentrestriction;
			value = talloc_strdup(ctx, content->pwcsphrase);
			result = talloc_asprintf(ctx, "RTCONTENT %s %s %s", propname, op_str, value);
			break;
		}
		case RTPROPERTY: {
			struct wsp_cpropertyrestriction *prop =
				&restriction->restriction.cpropertyrestriction;
			struct wsp_cbasestoragevariant *variant = &prop->prval;
			value = variant_as_string(ctx, variant, true);
			result = talloc_asprintf(ctx, "RTPROPERTY %s %s %s", propname, op_str, value);
			break;
		}
		case RTNATLANGUAGE: {
			struct wsp_cnatlanguagerestriction *cnat =
				&restriction->restriction.cnatlanguagerestriction;
			result = talloc_asprintf(ctx,
						"RTNATLANGUAGE %s %s %s",
						propname,
						op_str,
						cnat->pwcsphrase);

			break;
		}
		case RTCOERCE_ABSOLUTE: {
			struct wsp_crestriction *child_restrict =
				restriction->restriction.ccoercionrestriction_abs.childres;
			result = raw_restriction_to_string(ctx, child_restrict);
			if (!result) {
				status = NT_STATUS_UNSUCCESSFUL;
			}
			break;
		}
		case RTREUSEWHERE: {
			uint32_t id =
				restriction->restriction.reusewhere.whereid;
			result = talloc_asprintf(ctx,
					"insert expression for WHEREID = %d",
					id);

			break;
		}
		default:
			DBG_ERR("## unknown type 0x%x\n", restriction->ultype);
			status = NT_STATUS_INVALID_PARAMETER;
			break;
	}
out:
	*str_result = result;
	return status;
}

static NTSTATUS infix_restriction(TALLOC_CTX *ctx,
			 struct wsp_crestriction *restriction,
			 const char **str_result)
{
	const char *tmp = *str_result;
	const char *token = NULL;
	struct wsp_crestriction *left = NULL;
	struct wsp_crestriction *right = NULL;
	NTSTATUS status;
	if (!restriction) {
		status = NT_STATUS_OK;
		goto out;
	}
	if (is_operator(restriction)) {
		if (restriction->ultype == RTAND
		|| restriction->ultype == RTOR) {
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
		tmp = talloc_asprintf(ctx, "%s(", tmp ? tmp : "");
	}
	status = infix_restriction(ctx, left, &tmp);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	status = restriction_node_to_string(ctx, restriction, &token);

	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}
	tmp = talloc_asprintf(ctx, "%s%s", tmp ? tmp : "", token);

	status = infix_restriction(ctx, right, &tmp);

	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	if (is_operator(restriction)) {
		tmp = talloc_asprintf(ctx, "%s)",tmp);
	}
	*str_result = tmp;
out:
	return status;
}

const char *raw_restriction_to_string(TALLOC_CTX *ctx,
				  struct wsp_crestriction *restriction)
{
	const char *result = NULL;
	infix_restriction(ctx, restriction, &result);
	return result;
}
