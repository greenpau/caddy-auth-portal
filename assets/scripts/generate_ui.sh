#!/bin/bash
set -e

printf "Generating default UI templates\n"

declare -a _PAGES
declare -a _NAMES
_PAGES[${#_PAGES[@]}]="saml_login"
_NAMES[${#_NAMES[@]}]="saml_login"
_PAGES[${#_PAGES[@]}]="forms_login"
_NAMES[${#_NAMES[@]}]="forms_login"
_PAGES[${#_PAGES[@]}]="forms_portal"
_NAMES[${#_NAMES[@]}]="forms_portal"
_PAGES[${#_PAGES[@]}]="forms_ldap_login"
_NAMES[${#_NAMES[@]}]="forms_ldap_login"
_PAGES[${#_PAGES[@]}]="forms_whoami"
_NAMES[${#_NAMES[@]}]="forms_whoami"
_PAGES[${#_PAGES[@]}]="forms_register"
_NAMES[${#_NAMES[@]}]="forms_register"
_PAGES[${#_PAGES[@]}]="forms_generic"
_NAMES[${#_NAMES[@]}]="forms_generic"
_PAGES[${#_PAGES[@]}]="forms_settings"
_NAMES[${#_NAMES[@]}]="forms_settings"

printf "package ui\n\n" > pkg/ui/pages.go
printf "var defaultPageTemplates = map[string]string{\n" >> pkg/ui/pages.go
for INDEX in "${!_PAGES[@]}"; do
    _PAGENAME=${_NAMES[$INDEX]};
    _PAGEFILE=${_PAGES[$INDEX]};
    printf "\"${_PAGENAME}\": \`" >> pkg/ui/pages.go
    cat assets/templates/${_PAGEFILE}.template >> pkg/ui/pages.go
    truncate -s -1 pkg/ui/pages.go
    printf "\`,\n" >> pkg/ui/pages.go
done
printf "}\n" >> pkg/ui/pages.go
go fmt pkg/ui/pages.go
