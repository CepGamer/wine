/*
 * Copyright (C) 2016 Sergei Bolotov
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef __WINEMIME_H
#define __WINEMIME_H

#include "wine/list.h"

typedef HRESULT (*EXTENSION_KEY_HANDLER)(const WCHAR *, void *);

BOOL WINAPI winemime_build_native_mime_types(const char *, struct list *);
BOOL WINAPI winemime_mime_type_for_extension(struct list *, const WCHAR *, const char *, char **, BOOL *);
HRESULT WINAPI winemime_enumerate_registry_extensions(HKEY, EXTENSION_KEY_HANDLER, void *);
BOOL WINAPI winemime_add_mime_association(const WCHAR *, const char *, const WCHAR *, const char *, BOOL *);
BOOL WINAPI winemime_remove_mime_association(const WCHAR *);

#endif /* __WINEMIME_H */
