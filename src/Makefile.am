#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Authors:
# 2011-
#    Oscar Koeroo <okoeroo@gmail.nl>
#

EXTRACOMPILEFLAGS = \
    -g -Wall \
    -Wuninitialized \
    -Wbad-function-cast \
    -Wmissing-prototypes -Wnested-externs -Wpointer-arith \
    -Wcast-qual -Wchar-subscripts -Winline \
    -Wredundant-decls -Wno-long-long \
    -Wshadow

#    -Wshadow -Wstrict-prototypes


AM_CPPFLAGS = \
	$(LCMAPS_CFLAGS) \
	-D'SYSCONFDIR="@sysconfdir@"' \
	-D'LCMAPS_DB_FILE="@LCMAPS_DB_FILE@"' \
	-D'LCMAPS_MODULEDIR_SFX="@LCMAPS_MODULEDIR_SFX@"' \
        $(ADD_THESE_DEFINES)

sbin_PROGRAMS = lcmapsd

lcmapsd_SOURCES = \
        lcmapsd_common.h \
        lcmapsd_common.c \
        lcmapsd_fullssl.h \
        lcmapsd_fullssl.c \
        lcmapsd_httprest.h \
        lcmapsd_httprest.c \
        main.c

lcmapsd_CFLAGS = ${EXTRACOMPILEFLAGS}
