# Himmelcloak native Keycloak authentication
# Copyright (C) 2026 Damon Bun, Joshua Conklin, Kevin Torrecampo,
# Aidan Garske, Harrison Barrett, and Harman Samra
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
# Print only the Keycloak login and code exchange event fields needed for the test trace.
# Session and token identifiers from the raw server log are omitted.
function value(line, key, parts, quoted) {
    split(line, parts, key "=\"")
    if (length(parts) < 2) {
        return ""
    }
    split(parts[2], quoted, "\"")
    return quoted[1]
}

/type="(LOGIN|CODE_TO_TOKEN)(_ERROR)?"/ {
    printf "[keycloak server] %s client=%s user=%s grant=%s", \
        value($0, "type"), value($0, "clientId"), \
        value($0, "username"), value($0, "grant_type")
    error = value($0, "error")
    if (error != "") {
        printf " error=%s", error
    }
    print ""
    seen = 1
}

END {
    if (!seen) {
        print "(no LOGIN or CODE_TO_TOKEN events appeared in Keycloak logs)"
    }
}
