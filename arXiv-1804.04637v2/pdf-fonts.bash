#!/bin/bash  
#  
# print font names found in PDF written by OS X Quartz PDFContext   
usage () {  
    printf "Usage:\n"  
    printf "pdf-fonts.sh filename-1.pdf filename-2.pdf\n"  
    printf "pdf-fonts.sh *.pdf\n"  
    exit 1  
}  
for f in "$@"  
do  
#output sorted uniq font names  
unset GREP_OPTIONS  
printf "\n=== %s ===\n" "$f"  
egrep -a -o '\+\b(.*\s)\b' "$f" | cut -d '/' -f1 | sort -u   
[[ $? > 0 ]] && usage  
done  
exit 0  

