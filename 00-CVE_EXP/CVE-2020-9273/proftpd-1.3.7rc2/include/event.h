/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2003-2016 The ProFTPD Project team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, The ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

/* Event management */

#ifndef PR_EVENT_H
#define PR_EVENT_H

/* Register a handler for the given event.  The registered handler
 * callback function takes two arguments: a pointer to some event-specific
 * data and a pointer to some user-defined data.  This user-defined data
 * is set as the last argument in this registration function, and may be
 * NULL.
 *
 * The return value is zero if the registration succeeded, and -1 if
 * there was an error (in which case, errno will be set appropriately).
 *
 * Note that the registered event name is assumed to be a string constant;
 * the Event API stores a pointer to the given string, not a duplicate
 * of it.
 */
int pr_event_register(module *m, const char *event,
  void (*cb)(const void *, void *), void *user_data);

/* Remove the given event handler from the event registration lists.  The
 * return value is zero if successful, and -1 if there was an error (in
 * which case, errno will be set appropriately).
 *
 * If the module pointer is non-NULL, the event handler being unregistered
 * must have been registered by that module.  If the event name is
 * non-NULL, then only the handler for that specific event is unregistered;
 * otherwise, all events for the given module will be unregistered.  If the
 * callback pointer is non-NULL, the event handler being unregistered must be
 * that specific handler.
 *
 * This arrangement means that it is possible, though considered terribly
 * impolite, for the caller to unregister all handlers for a given event,
 * regardless of registree, using:
 *
 *  pr_event_unregister(NULL, event_name, NULL);
 *
 * Although rare, there are cases where this kind of blanket unregistration
 * is necessary.  More common will be the case where a module needs to
 * unregister all of its event listeners at once:
 *
 *  pr_event_unregister(&my_module, NULL, NULL);
 */
int pr_event_unregister(module *m, const char *event,
  void (*cb)(const void *, void *));

/* Generate an event.  The named event is dispatched to any handlers that
 * have registered an interest in handling this event.  Any event-specific
 * data is sent to the registered handlers.
 */
void pr_event_generate(const char *event, const void *event_data);

/* Returns the number of registered listeners for the given event,
 * or -1 (with errno set appropriately) if there was an error.
 */
int pr_event_listening(const char *event);

/* Dump Events information. */
void pr_event_dump(void (*)(const char *, ...));

#endif /* PR_EVENT_H */
