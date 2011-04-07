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

#if DEBUG
# define TODO() \
	fprintf (stderr, "%s: %s -> %s ()\n", __FILE__, __TIME__, __func__)
# define TODO2(X, Y) \
	fprintf (stderr, "%s: %s -> %s (" X ")\n", __FILE__, __TIME__, __func__, Y)

size_t
_write (int fd, char *buf, size_t len)
{
	size_t w;
	w = write (fd, buf, len);
	fprintf (stderr, "WRITE (%d, %p='%s', %u) -> %u\n", fd, (void*)buf, buf,
			len, w);
	return w;
}
# define write(X, Y, Z) _write (X, Y, Z)
#else
# define TODO()
# define TODO2(X, Y)
#endif

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
	struct proto_chat_entry *pce;
	/* code */
	pce = g_new0 (struct proto_chat_entry, 1);
	pce->label = "Channel";
	pce->identifier = "channel";
	pce->required = TRUE;
	/* return */
	return g_list_append (NULL, pce);
}

static GHashTable *
dcpp_chat_info_defaults (PurpleConnection *gc, const char *chat_name)
{
	TODO2 ("%s", chat_name);
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
	char *username;
	char *message;
	char *message3;
	char *buffer;
	size_t end;
	size_t username_len;
	GList *users;
	GList *flags;
	struct dcpp_t *dcpp;
	PurpleConversation *convy;
	dcpp = gc->proto_data;
	if (!dcpp || !(dcpp->user_server))
		return;
	username = dcpp->user_server[0];
	username_len = strlen (username);
	convy = purple_find_conversation_with_account (
			PURPLE_CONV_TYPE_CHAT, "#", gc->account);
	/* parse */
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
				end = strlen (message) + username_len + 22;
				buffer = g_new0 (char, end);
				snprintf (buffer, end, "$Key %s|$ValidateNick %s|",
						message, username);
				g_free (message);
				end = strlen (buffer);
				if (write (source, buffer, end) != end)
					purple_connection_error_reason (gc,
							PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
							"Error send Key");
				g_free (buffer);
			}
		}
		else
		if (!strncmp ("$Hello ", input, 7))
		{
			if (!strcmp (username, &(input[7])))
			{
				end = username_len + 105;
				buffer = g_new0 (char, end);
				snprintf (buffer, end, "$Version 1.0091|$GetNickList|"\
						"$MyINFO $ALL %s "\
						"<Pidgin V:%d.%d.%d,M:P,H:2/2/0,S:10>$ $"\
						"20%c$.$53687091200$|", username,
						PURPLE_MAJOR_VERSION, PURPLE_MINOR_VERSION,
						PURPLE_MICRO_VERSION, 1);
				end = strlen (buffer);
				if (write (source, buffer, end) != end)
					purple_connection_error_reason (gc,
							PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
							"Error send MyINFO");
				g_free (buffer);
				purple_connection_set_state (gc, PURPLE_CONNECTED);
				if (!convy || PURPLE_CONV_CHAT (convy)->left)
					serv_got_joined_chat (gc, 0, "#");
			}
		}
		else
		if (!strncmp ("$OpList ", input, 8))
		{
			if (!convy)
				return;
			message3 = message = &(input[8]);
			while (message ++)
			{
				if (*message == '\0' || *(message + 1) == '\0')
					break;
				if (*message == '$'  && *(message + 1) == '$')
				{
					*message = '\0';
					if (purple_conv_chat_find_user (PURPLE_CONV_CHAT (convy),
								message3))
					{
						purple_conv_chat_user_set_flags (
								PURPLE_CONV_CHAT (convy), message3,
								PURPLE_CBFLAGS_OP);
					}
					message3 = message + 2;
				}
			}
		}
		else
		if (!strncmp ("$NickList ", input, 10))
		{
			if (!convy)
				return;
			users = NULL;
			flags = NULL;
			purple_conv_chat_clear_users (PURPLE_CONV_CHAT (convy));
			message3 = message = &(input[10]);
			while (message ++)
			{
				if (*message == '\0' || *(message + 1) == '\0')
					break;
				if (*message == '$' && *(message + 1) == '$')
				{
					*message = '\0';
					users = g_list_prepend (users, message3);
					flags = g_list_prepend (flags,
							GINT_TO_POINTER (PURPLE_CBFLAGS_VOICE));
					message3 = message + 2;
				}
			}
			if (users)
			{
				purple_conv_chat_add_users (PURPLE_CONV_CHAT (convy), users,
						NULL, flags, FALSE);
				g_list_free (users);
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
					username_len = strlen (buffer);
					if (write (source, buffer, username_len) != username_len)
						purple_connection_error_reason (gc,
								PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
								"Error send password");
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
					PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
					"Nick validation fail");
		}
		else
		if (!strncmp ("$MyINFO $ALL ", input, 13))
		{
			message3 = message = &(input[13]);
			while (message ++)
			{
				if (*message == ' ' || *message == '\0')
					break;
			}
			*message = '\0';
			if (!purple_conv_chat_find_user (PURPLE_CONV_CHAT (convy),
						message3))
			{
				purple_conv_chat_add_user (PURPLE_CONV_CHAT (convy),
						message3, NULL, PURPLE_CBFLAGS_VOICE, TRUE);
			}
		}
		else
		if (!strncmp ("$Quit ", input, 6))
		{
			if (!strcmp (username, &(input[6])))
			{
				purple_connection_error_reason (gc,
						PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
						"Dropped from hub");
			}
			else
			if (purple_conv_chat_find_user (PURPLE_CONV_CHAT (convy),
						&(input[6])))
			{
				purple_conv_chat_remove_user (PURPLE_CONV_CHAT (convy),
						&(input[6]), NULL);
			}
		}
		else
		if (!strncmp ("$To: ", input, 5))
		{
			message = &(input[5]);
			while (++ message)
				if (*message == '$' || *message == '\0')
					break;
			if (*message != '\0')
			{
				message ++;
				if (*message == '<')
				{
					message3 = ++ message;
					while (++ message)
						if (*message == '>' || *message == '\0')
							break;
					*message = '\0';
					serv_got_im (gc, message3, message + 2,
							PURPLE_MESSAGE_RECV, time(NULL));
				}
			}
		}
	}
	else
	{
		if (!convy || PURPLE_CONV_CHAT (convy)->left)
			serv_got_joined_chat (gc, 0, "#");
		message3 = message = input;
		if (input[0] == '<')
		{
			message3 = message = &(input[1]);
			while (++ message)
				if (*message == '>' || *message == '\0')
					break;
			*message = '\0';
			buffer = purple_unescape_text (message + 2);
			message = purple_markup_escape_text (buffer, -1);
			purple_conv_chat_write (PURPLE_CONV_CHAT (convy),
					message3, message, PURPLE_MESSAGE_RECV, time (NULL));
			g_free (message);
			g_free (buffer);
		}
		else
		if (input[0] == '*')
		{
			message3 = message = &(input[3]);
			while (*(message ++))
				if (*message == ' ')
					break;
			if (*message)
			{
				*message = '\0';
				message ++;
				end = strlen (message) + 5;
				buffer = g_new0 (char, end);
				snprintf (buffer, end, "/me %s", message);
				message = purple_unescape_text (buffer);
				g_free (buffer);
				buffer = purple_markup_escape_text (message, -1);
				purple_conv_chat_write (PURPLE_CONV_CHAT (convy), message3,
						message, PURPLE_MESSAGE_RECV, time (NULL));
				g_free (buffer);
				g_free (message);
			}
		}
		else
		{
			TODO2 ("%s", input);
			purple_conv_chat_write (PURPLE_CONV_CHAT (convy),
					NULL, input, PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_RECV,
					time (NULL));
		}
	}
}

/* callback funcs */
static void
dcpp_input_cb (gpointer data, gint source, PurpleInputCondition cond)
{
	PurpleConnection *gc = data;
	struct dcpp_t *dcpp = gc->proto_data;
	char *tmp;
	char *charset;
	size_t lv;
	size_t lve;
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
	lv = read (source, dcpp->inbuf, DCPP_INPUT_SZ);
	dcpp->inbuf[lv] = '\0';
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
			lve = offset - offsetl;
			/* resize string */
			if (dcpp->offset + lv > dcpp->line_sz)
			{
				tmp = g_renew (char, dcpp->line,
						dcpp->line_sz + DCPP_LINE_SZ + 1);
				dcpp->line = tmp;
			}
			/* */
			if (dcpp->offset + lve)
			{
				memcpy (&(dcpp->line[dcpp->offset]), &(dcpp->inbuf[offsetl]),
						lve);
				dcpp->line[dcpp->offset + lve] = '\0';
				/* convert input */
				charset = (char*)purple_account_get_string (gc->account,
						"charset", "UTF-8");
				if (g_ascii_strcasecmp ("UTF-8", charset))
				{
					charset = g_convert_with_fallback (dcpp->line, -1, "UTF-8",
							charset, NULL, NULL, NULL, NULL);
					if (charset)
					{
						tmp = purple_utf8_salvage (charset);
						g_free (charset);
					}
					else
						tmp = purple_utf8_salvage (dcpp->line);
				}
				else
					tmp = purple_utf8_salvage (dcpp->line);
				/* execute process, if conversion success */
				if (tmp)
				{
					dcpp_input_parse (gc, source, tmp);
					/* free memory */
					g_free (tmp);
				}
			}
			dcpp->offset = 0;
			offsetl = offset + 1;
		}
	}
	while (++ offset < lv);
	if (offsetl < lv)
	{
		lve = lv - offsetl;
		if (dcpp->line_sz - dcpp->offset < lve)
		{
			tmp = g_renew (char, dcpp->line,
					dcpp->line_sz + DCPP_LINE_SZ + 1);
			dcpp->line = tmp;
		}
		memcpy (&(dcpp->line[dcpp->offset]), &(dcpp->inbuf[offsetl]), lve);
		dcpp->offset += lve;
	}
}

static void
dcpp_login_cb (gpointer data, gint source, const gchar *error_message)
{
	struct dcpp_t *dcpp;
	PurpleConnection *gc = data;
	if (source < 0)
		purple_connection_error_reason (gc,
				PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				"Can't connect to server");
	dcpp = gc->proto_data;
	if (dcpp)
		dcpp->fd = source;
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
	struct dcpp_t *dcpp;
	username = purple_account_get_username (account);
	gc = purple_account_get_connection (account);
	purple_connection_update_progress (gc,"Connecting", 1, 3);

	dcpp = g_new0 (struct dcpp_t, 1);
	dcpp->user_server = g_strsplit (username, "|", 2);
	purple_connection_set_display_name (gc, dcpp->user_server[0]);
	dcpp->line = g_new0 (char, DCPP_LINE_SZ + 1);
	if (dcpp->line)
		dcpp->line_sz = DCPP_LINE_SZ;
	dcpp->fd = -1;
	gc->proto_data = dcpp;

	if (purple_proxy_connect (gc, account, dcpp->user_server[1],
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
	struct dcpp_t *dcpp;
	dcpp = gc->proto_data;
	gc->proto_data = NULL;
	if (dcpp)
	{
		if (dcpp->line)
			g_free (dcpp->line);
		if (dcpp->user_server)
			g_strfreev (dcpp->user_server);
		g_free (dcpp);
	}
	if (gc->inpa > 0)
	{
		purple_input_remove (gc->inpa);
		gc->inpa = 0;
	}
	TODO ();
}

static int
dcpp_send (PurpleConnection *gc, const char *who, const char *what)
{
	struct dcpp_t *dcpp;
	char *username;
	size_t username_len;
	size_t text_len;
	char *charset;
	char *buffer;
	char *text;
	char *tmp;
	TODO ();
	dcpp = gc->proto_data;
	if (!dcpp || dcpp->fd == -1)
		return 0;
	/* prepare */
	username = dcpp->user_server[0];
	username_len = strlen (username);
	text = purple_unescape_html (what);
	text_len = strlen (text);
	charset = (char*)purple_account_get_string (gc->account, "charset",
			"UTF-8");
	/* build */
	if (!who)
	{
		text_len = text_len + 5 + username_len;
		buffer = g_new0 (char, text_len);
		snprintf (buffer, text_len, "<%s> %s|", username, text);
	}
	else
	{
		text_len = text_len + strlen (who) + 19 + (username_len * 2);
		buffer = g_new0 (char, text_len);
		snprintf (buffer, text_len, "$To: %s From: %s $<%s> %s|", who,
				username, username, text);
	}
	g_free (text);
	if (g_ascii_strcasecmp ("UTF-8", charset))
	{
		tmp = g_convert_with_fallback (buffer, -1, charset, "UTF-8", NULL,
				NULL, &text_len, NULL);
	}
	else
		tmp = buffer;
	/* send */
	if (tmp)
	{
		if (write (dcpp->fd, tmp, text_len) != text_len)
		{
				purple_connection_error_reason (gc,
						PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
						"Error send line");
		}
		/* free */
		if (tmp != buffer)
			g_free (tmp);
	}
	g_free (buffer);
	return TRUE;
}

static int
dcpp_im_send (PurpleConnection *gc, const char *who, const char *what,
		PurpleMessageFlags flags)
{
	return dcpp_send (gc, who, what);
}

static void
dcpp_chat_join (PurpleConnection *gc, GHashTable *data)
{
	PurpleConversation *convy;
	convy = purple_find_conversation_with_account ( PURPLE_CONV_TYPE_CHAT,
			"#", gc->account);
	if (!convy || PURPLE_CONV_CHAT (convy)->left)
		serv_got_joined_chat (gc, 0, "#");
}

static char *
dcpp_get_chat_name (GHashTable *data)
{
	TODO2 ("%s", (char*)g_hash_table_lookup (data, "channel"));
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
	return dcpp_send (gc, NULL, what);
}

static void
dcpp_keepalive (PurpleConnection *gc)
{
	struct dcpp_t *dcpp;
	dcpp = gc->proto_data;
	if (!dcpp)
		return;
	if (dcpp->fd == -1)
	{
		purple_connection_error_reason (gc,
				PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				"Zero hub fd");
		return;
	}
	if (!write (dcpp->fd, "|", 1))
		purple_connection_error_reason (gc,
				PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				"Timeout");
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
	PurpleAccountUserSplit *s;
	PurpleAccountOption *o;

	s = purple_account_user_split_new ("Server", "mychillhub.com", '|');
	prpl_info.user_splits = g_list_append (prpl_info.user_splits, s);

	o = purple_account_option_string_new ("Hub charset", "charset", "UTF-8");
	prpl_info.protocol_options = g_list_append (prpl_info.protocol_options, o);

	o = purple_account_option_int_new ("Port", "port", 411);
	prpl_info.protocol_options = g_list_append (prpl_info.protocol_options, o);
}

PURPLE_INIT_PLUGIN (dcpp, _init_plugin, info)

