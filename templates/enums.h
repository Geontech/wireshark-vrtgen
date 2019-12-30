/*
 * Copyright (C) 2019 Geon Technologies, LLC
 *
 * This file is part of wireshark-vrtgen.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef ENUMS_H
#define ENUMS_H
/*% for enum in enums %*/
typedef enum {
/*%-    for value in enum['values'] %*/
    {{value.label}} = {{value.value}},
/*%-    endfor %*/
    {{enum.name|upper}}_MAX = {{enum['values'][-1]['label']}}
} {{enum.type}};

const value_string {{enum.strings}}[] = {
/*%-    for value in enum['values'] %*/
    { {{value.label}}, "{{value.string}}" },
/*%-    endfor %*/
    { 0, NULL }
};
/*% endfor %*/
#endif /* ENUMS_H */
