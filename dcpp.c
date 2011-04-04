/* vim: ft=c ff=unix fenc=utf-8
 * file: dcpp.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#define PURPLE_PLUGINS

#include <libpurple/plugin.h>
#include <libpurple/account.h>
#include <libpurple/version.h>
#include <libpurple/accountopt.h>

#include "dcpp.h"

#define TODO() fprintf (stderr, "%s: %s -> %s ()\n", __FILE__, __TIME__, __func__)
#define TODO2(X, Y) fprintf (stderr, "%s: %s -> %s (" X ")\n", __FILE__, __TIME__, __func__, Y)

static GList*
dcpp_status_types (PurpleAccount *account)
{
	PurpleStatusType *type;
	GList *types = NULL;

	type = purple_status_type_new(PURPLE_STATUS_AVAILABLE, NULL, NULL, TRUE);
	types = g_list_append(types, type);

	type = purple_status_type_new(PURPLE_STATUS_OFFLINE, NULL, NULL, TRUE);
	types = g_list_append(types, type);

	return types;
}

static void
dcpp_get_info (PurpleConnection *gc, const char *who)
{
	TODO ();
}

static void
dcpp_set_status (PurpleAccount *account, PurpleStatus *status)
{
	TODO ();
}

static const char*
dcpp_blist_icon (PurpleAccount *a, PurpleBuddy *b)
{
	return "irc";
}

static GList *
dcpp_chat_join_info (PurpleConnection *gc)
{
	return NULL;
}

static GHashTable *
dcpp_chat_info_defaults (PurpleConnection *gc, const char *chat_name)
{
	GHashTable *defaults;
	defaults = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
	if (chat_name != NULL)
		g_hash_table_insert(defaults, "channel", g_strdup(chat_name));
	return defaults;
}

/* DC++ key func */
inline static int
dcpp_key_nesc(char b)
{
	return (b == 0 || b == 5 || b == 124 || b == 96 || b == 126 || b == 36);
}

inline static char*
dcpp_key_esc (char *key, size_t len, int cc)
{
	char *line;
	size_t c;
	size_t offset;
	if (cc >= 0)
		line = g_new0 (char, len + (10 * cc) + 1);
	else
		return NULL;
	c = 0;
	while (c < len)
	{
		if (dcpp_key_nesc (key[c]))
		{
			snprintf (&(line[offset]), 11, "/%%DCN%0*d%%/", 3, key[c]);
			offset += 10;
		}
		else
		{
			line[offset] = key[c];
			offset ++;
		}
		c ++;
	}
	return line;
}

inline static char*
dcpp_extract_key (char *lock, int elen) {
	size_t len;
	size_t i;
	char *key;
	char *key_o;
	char v1;
	size_t extra;
	if (elen == -1)
		len = strlen (lock);
	else
		len = elen;
    if(len < 3)
        return NULL;
	key = g_new0 (char, len);
    v1 = (char)(lock[0] ^ 5);
    v1 = (char)(((v1 >> 4) | (v1 << 4)) & 0xff);
    key[0] = v1;
    for (i = 1; i< len; i++)
	{
        v1 = (char)(lock[i] ^ lock[i-1]);
        v1 = (char)(((v1 >> 4) | (v1 << 4)) & 0xff);
        key[i] = v1;
        if(dcpp_key_nesc(key[i]))
            extra++;
	}
    key[0] = (char)(key[0] ^ key[len - 1]);
    if(dcpp_key_nesc(key[0]))
        extra++;
    key_o = dcpp_key_esc (key, len, extra);
	g_free (key);
	return key_o;
}

/* parse DC++ traffic */
inline static void
dcpp_input_parse (PurpleConnection *gc, gint source, char *input)
{
	char *message;
	char *username;
	char *message3;
	char *buffer;
	size_t end;
	size_t username_len;
	username = (char*)purple_account_get_username (gc->account);
	username_len = strlen (username);
	/* TODO2 ("%s", input); */
	if (input[0] == '$')
	{
		/* CMD */
		if (!strncmp ("$Lock ", input, 6))
		{
			end = 0;
			while ((&(input[6]))[end] != ' ' && (&(input[6]))[end] != '\0')
				end ++;
			message = dcpp_extract_key (&(input[6]), end);
			if (message)
			{
				message3 = (char*)purple_account_get_string (gc->account,
						"description", "");
				end = strlen (message) + (username_len * 2) + 132;
				buffer = g_new0 (char, end);
				snprintf (buffer, end, "$Key %s|$ValidateNick %s|"\
						"$GetNickList|$Version 1.0091|"\
						"$MyINFO $ALL %s %s"\
						"<Pidgin V:%d.%d.%d,M:P,H:2/2/0,S:10>$ "\
						"$20%c$.$53687091200$|", message,
						username, username, message3,
						PURPLE_MAJOR_VERSION, PURPLE_MINOR_VERSION,
						PURPLE_MICRO_VERSION, 1);
				g_free (message);
				fprintf (stderr, "b'%s'\n", buffer);
				if (write (source, buffer, end) != end)
					purple_connection_error_reason (gc,
							PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
							"Error send packet");
				g_free (buffer);
			}
		}
		else
		if (!strncmp ("$Hello ", input, 7))
		{
			if (!strcmp (username, &(input[7])))
			{
				fprintf (stderr, "AUTH_OK\n");
				purple_connection_set_state (gc, PURPLE_CONNECTED);
			}
		}
		else
		if (!strncmp ("$HubName ", input, 9))
		{
		}
		else
		if (!strncmp ("$GetPass", input, 8))
		{
			message3 = (char*)purple_account_get_password (gc->account);
			if (message3)
			{
				username_len = strlen (message3);
				if (username_len)
				{
					username_len += 10;
					buffer = g_new (char, username_len);
					snprintf (buffer, username_len, "$MyPass %s|", message3);
					if (write (source, buffer, username_len) != username_len)
						purple_connection_error_reason (gc,
								PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
								"Error send packet");
					g_free (buffer);
				}
			}
		}
		else
		if (!strncmp ("$BadPass", input, 8))
		{
			purple_connection_error_reason (gc,
					PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
					"Bad password");
		}
		else
		if (!strncmp ("$ValidateDenide", input, 15))
		{
			purple_connection_error_reason (gc,
					PURPLE_CONNECTION_ERROR_INVALID_USERNAME,
					"Nick validation fail");
		}
	}
	else
	{
		/* message */
	}
}

/* callback funcs */
static void
dcpp_input_cb (gpointer data, gint source, PurpleInputCondition cond)
{
	PurpleConnection *gc = data;
	struct dcpp_t *dcpp = gc->proto_data;
	size_t lv;
	size_t offset;
	size_t offsetl;
	/* if connection close */
	if (!dcpp)
	{
		purple_connection_error_reason (gc,
				PURPLE_CONNECTION_ERROR_NETWORK_ERROR, "Dead connection data");
		purple_connection_set_state (gc, PURPLE_DISCONNECTED);
		return;
	}
	/* get strings */
	lv = read (source, dcpp->inbuf, sizeof (dcpp->inbuf));
	if (lv == 0)
	{
		purple_connection_error_reason (gc,
				PURPLE_CONNECTION_ERROR_NETWORK_ERROR, "Disconnected");
		return;
	}
	/* split */
	offset = 0;
	offsetl = 0;
	do
	{
		if (dcpp->inbuf[offset] == '|')
		{
			if ((dcpp->offset + (offset - offsetl)) &&
					(dcpp->offset + (offset - offsetl)) < sizeof (dcpp->line))
			{
				memcpy (&(dcpp->line[dcpp->offset]), &(dcpp->inbuf[offsetl]),
						offset - offsetl);
				dcpp->line[dcpp->offset + (offset - offsetl)] = '\0';
				dcpp_input_parse (gc, source, dcpp->line);
			}
			dcpp->offset = 0;
			offsetl = offset + 1;
		}
	}
	while (++ offset < lv);
	if (offsetl < lv)
	{
		memcpy (&(dcpp->line[dcpp->offset]), &(dcpp->inbuf[offsetl]), lv - offsetl);
		dcpp->offset = lv - offsetl;
	}
}

static void
dcpp_login_cb (gpointer data, gint source, const gchar *error_message)
{
	PurpleConnection *gc = data;
	purple_connection_update_progress (gc,"Login", 2, 3);
	gc->inpa = purple_input_add (source, PURPLE_INPUT_READ, dcpp_input_cb, gc);
	if (gc->inpa < 1)
	{
		purple_connection_error_reason (gc,
				PURPLE_CONNECTION_ERROR_NETWORK_ERROR, "Can't start read");
		return;
	}
}

static void
dcpp_login (PurpleAccount *account)
{
	PurpleConnection *gc;
	const char *username;
	username = purple_account_get_username (account);
	gc = purple_account_get_connection (account);
	purple_connection_update_progress (gc,"Connecting", 1, 3);

	gc->proto_data = g_new0 (struct dcpp_t, 1);

	if (purple_proxy_connect (gc, account,
				purple_account_get_string (account, "server", ""),
				purple_account_get_int (account, "port", 411), dcpp_login_cb,
				gc) == NULL)
	{
		purple_connection_error_reason (gc,
				PURPLE_CONNECTION_ERROR_NETWORK_ERROR, "Unable to connect");
	}
}

static void
dcpp_close(PurpleConnection *gc)
{
	if (gc->proto_data)
		g_free (gc->proto_data);
	if (gc->inpa)
		purple_input_remove (gc->inpa);
	TODO ();
}

static int
dcpp_im_send (PurpleConnection *gc, const char *who, const char *what,
		PurpleMessageFlags flags)
{
	TODO ();
	return TRUE;
}

static void
dcpp_chat_join (PurpleConnection *gc, GHashTable *data)
{
	TODO ();
}

static char *
dcpp_get_chat_name (GHashTable *data)
{
	TODO ();
	return g_strdup(g_hash_table_lookup(data, "channel"));
}

static void
dcpp_chat_leave (PurpleConnection *gc, int id)
{
	TODO ();
}

static int
dcpp_chat_send (PurpleConnection *gc, int id, const char *what,
		PurpleMessageFlags flags)
{
	TODO ();
	return 0;
}

static void
dcpp_keepalive (PurpleConnection *gc)
{
	TODO ();
}

static gboolean
load_plugin (PurplePlugin *plugin)
{
	return TRUE;
}

static PurplePluginProtocolInfo prpl_info =
{
	OPT_PROTO_CHAT_TOPIC | OPT_PROTO_PASSWORD_OPTIONAL,
	NULL,					/* user_splits */
	NULL,					/* protocol_options */
	NO_BUDDY_ICONS,		/* icon_spec */
	dcpp_blist_icon,		/* list_icon */
	NULL,			/* list_emblems */
	NULL,					/* status_text */
	NULL,					/* tooltip_text */
	dcpp_status_types,		/* away_states */
	NULL,					/* blist_node_menu */
	dcpp_chat_join_info,	/* chat_info */
	dcpp_chat_info_defaults,	/* chat_info_defaults */
	dcpp_login,		/* login */
	dcpp_close,		/* close */
	dcpp_im_send,		/* send_im */
	NULL,					/* set_info */
	NULL,					/* send_typing */
	dcpp_get_info,		/* get_info */
	dcpp_set_status,		/* set_status */
	NULL,					/* set_idle */
	NULL,					/* change_passwd */
	NULL,		/* add_buddy */
	NULL,					/* add_buddies */
	NULL,	/* remove_buddy */
	NULL,					/* remove_buddies */
	NULL,					/* add_permit */
	NULL,					/* add_deny */
	NULL,					/* rem_permit */
	NULL,					/* rem_deny */
	NULL,					/* set_permit_deny */
	dcpp_chat_join,		/* join_chat */
	NULL,					/* reject_chat */
	dcpp_get_chat_name,	/* get_chat_name */
	NULL,	/* chat_invite */
	dcpp_chat_leave,		/* chat_leave */
	NULL,					/* chat_whisper */
	dcpp_chat_send,		/* chat_send */
	dcpp_keepalive,		/* keepalive */
	NULL,					/* register_user */
	NULL,					/* get_cb_info */
	NULL,					/* get_cb_away */
	NULL,					/* alias_buddy */
	NULL,					/* group_buddy */
	NULL,					/* rename_group */
	NULL,					/* buddy_free */
	NULL,					/* convo_closed */
	purple_normalize_nocase,	/* normalize */
	NULL,					/* set_buddy_icon */
	NULL,					/* remove_group */
	NULL,					/* get_cb_real_name */
	NULL,	/* set_chat_topic */
	NULL,					/* find_blist_chat */
	NULL,	/* roomlist_get_list */
	NULL,	/* roomlist_cancel */
	NULL,					/* roomlist_expand_category */
	NULL,					/* can_receive_file */
	NULL,	/* send_file */
	NULL,	/* new_xfer */
	NULL,					/* offline_message */
	NULL,					/* whiteboard_prpl_ops */
	NULL,			/* send_raw */
	NULL,					/* roomlist_room_serialize */
	NULL,                   /* unregister_user */
	NULL,                   /* send_attention */
	NULL,                   /* get_attention_types */
	sizeof(PurplePluginProtocolInfo),    /* struct_size */
	NULL,                    /* get_account_text_table */
	NULL,                    /* initiate_media */
	NULL,					 /* get_media_caps */
	NULL,					 /* get_moods */
	NULL,					 /* set_public_alias */
	NULL					 /* get_public_alias */
};

static PurplePluginInfo info =
{
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_PROTOCOL,                             /**< type           */
	NULL,                                             /**< ui_requirement */
	0,                                                /**< flags          */
	NULL,                                             /**< dependencies   */
	PURPLE_PRIORITY_DEFAULT,                            /**< priority       */
	"prpl-noktoborus-dcpp",                             /**< id             */
	"DC++",                                            /**< name           */
	"0.1",                                  /**< version        */
	"DC++ Protocol Plugin",                        /**  summary        */
	"Direct Connect, welcome new suck",    /**  description    */
	NULL,                                             /**< author         */
	"http://example.org",                             /**< homepage       */
	load_plugin,                                      /**< load           */
	NULL,                                             /**< unload         */
	NULL,                                             /**< destroy        */
	NULL,                                             /**< ui_info        */
	&prpl_info,                                       /**< extra_info     */
	NULL,                                             /**< prefs_info     */
	NULL,
	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static void
_init_plugin (PurplePlugin *plugin)
{
	PurpleAccountOption *o;

	o = purple_account_option_string_new ("Encodings", "encoding", "UTF-8");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, o);

	o = purple_account_option_string_new ("Description", "description", "");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, o);

	o = purple_account_option_string_new ("Server", "server",
			"dc.vladlink.lan");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, o);

	o = purple_account_option_int_new ("Port", "port", 4111);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, o);
}

PURPLE_INIT_PLUGIN (dcpp, _init_plugin, info)

