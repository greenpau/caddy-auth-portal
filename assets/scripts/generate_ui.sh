#!/bin/bash
set -e

printf "Generating default UI templates\n"

UI_FILE=pkg/ui/pages.go

declare -a _THEMES
declare -a _PAGES
declare -a _NAMES
_THEMES[${#_THEMES[@]}]="basic"
_PAGES[${#_PAGES[@]}]="login"
_PAGES[${#_PAGES[@]}]="portal"
_PAGES[${#_PAGES[@]}]="whoami"
_PAGES[${#_PAGES[@]}]="register"
_PAGES[${#_PAGES[@]}]="generic"
_PAGES[${#_PAGES[@]}]="settings"

printf "package ui\n\n" > ${UI_FILE}
printf "// PageTemplates stores UI templates.\n" >> ${UI_FILE}
printf "var PageTemplates = map[string]string{\n" >> ${UI_FILE}

for THEME_ID in "${!_THEMES[@]}"; do
    THEME_NAME=${_THEMES[$THEME_ID]};
    echo "Generating theme ${THEME_NAME}";
    for PAGE_ID in "${!_PAGES[@]}"; do
        PAGE_NAME=${_PAGES[$PAGE_ID]};
        echo "At page ${PAGE_NAME}";
        printf "\"${THEME_NAME}/${PAGE_NAME}\": \`" >> ${UI_FILE}
        cat assets/templates/${THEME_NAME}/${PAGE_NAME}.template >> ${UI_FILE}
        truncate -s -1 ${UI_FILE}
        printf "\`,\n" >> ${UI_FILE}
    done
done

printf "}\n" >> ${UI_FILE}
go fmt ${UI_FILE}
