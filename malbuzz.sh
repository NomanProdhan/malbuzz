#!/bin/bash

function banner() {
    echo "  __  __       _ ____                "
    echo " |  \/  |     | |  _ \               "
    echo " | \  / | __ _| | |_) |_   _ ________"
    echo " | |\/| |/ _\` | |  _ <| | | |_  /_  /"
    echo " | |  | | (_| | | |_) | |_| |/ / / / "
    echo " |_|  |_|\__,_|_|____/ \__,_/___/___|"
    echo -e "+-----------------------------------+"
    echo -e "|\tAuthor : NomanProdhan  \t    |"
    echo -e "+-----------------------------------+\n"
}

function helpDoc() {
    echo "Usage : $0 <option> <value>"
    echo -e "\nAvailable Options:"
    echo "------------------"
    echo -e " -h\t: Search using SHA256 hash of the malware sample."
    echo -e " -t\t: Search using Trend Micro Locality Sensitive Hash (TLSH) of the malware sample."
    echo -e " -e\t: Search using Trend Micro ELF Hash (TELF) of the malware sample."
    echo -e " -g\t: Search using gimphash."
    echo -e " -i\t: Search using imphash."
    echo -e " -d\t: In case the file is a PE executable, search using DHASH of the samples icon."
    echo -e " -c\t: Search using ClamAV signature."
    echo -e " -y\t: Search YARA rule. You can get a list of malware samples associated with a specific YARA rule."
    echo -e " -S\t: Search using malware family. Example : RedLineStealer, Ransomware etc."
    echo -e " -T\t: Search using Tag. Example : BotNet, DDoS BotNet, EXE etc."
    echo -e " -D\t: Download a malware sample using SHA256 hash."
    echo -e " -f\t: Select a file to search. It will do a SHA256SUM of the file and search for it."
    echo -e "\nExample Usage"
    echo "------------------"
    echo -e " $0 -h a9b267ea23a944e317cbae01826907002dfbd2ec28b05960f3bfbb7f61b33948\n"
}

function parsingSingleData() {
    flag=$(echo "$1" | jq -r ".query_status")
    if [ "$flag" == "hash_not_found" ]; then
        echo "No results !"
    elif [ "$flag" == "illegal_hash" ]; then
        echo "Invalid SHA256 hash !"
    fi

    if [ "$flag" == "ok" ]; then
        data=$(echo "$1" | jq -r '.data[0]')
        file_name=$(echo "$data" | jq -r '.file_name')
        file_type_mime=$(echo "$data" | jq -r '.file_type_mime')
        file_type=$(echo "$data" | jq -r '.file_type')
        origin_country=$(echo "$data" | jq -r '.origin_country')
        signature=$(echo "$data" | jq -r '.signature')
        first_seen=$(echo "$data" | jq -r '.first_seen')
        file_size=$(echo "$data" | jq -r '.file_size')
        imphash=$(echo "$data" | jq -r '.imphash')
        md5_hash=$(echo "$data" | jq -r '.md5_hash')
        tlsh=$(echo "$data" | jq -r '.tlsh')
        telfhash=$(echo "$data" | jq -r '.telfhash')
        telfhash=$(echo "$data" | jq -r '.telfhash')
        gimphash=$(echo "$data" | jq -r '.gimphash')
        ssdeep=$(echo "$data" | jq -r '.ssdeep')
        dhash_icon=$(echo "$data" | jq -r '.dhash_icon')
        sha256_hash=$(echo "$data" | jq -r '.sha256_hash')
        reporter=$(echo "$data" | jq -r '.reporter')
        tags=$(echo "$data" | jq -r '.tags | map(tostring) | join(", ")')
        delivery_method=$(echo "$data" | jq -r '.delivery_method')
        calmAV=$(echo "$data" | jq -r '.intelligence | .clamav[]')

        echo -e "\n------Basic Information------"
        echo -e "File Name\t: $file_name"
        echo -e "File Type Mime\t: $file_type_mime"
        echo -e "File Type \t: $file_type"
        echo -e "First Seen \t: $first_seen"
        echo -e "File Size \t: $file_size bytes"
        echo -e "Reporter \t: $reporter"
        echo -e "Origin Country \t: $origin_country"
        echo -e "Family \t\t: $signature"
        echo -e "Tags \t\t: $tags"
        echo -e "Delivery Method : $delivery_method"
        echo -e "CalmAV \t\t: $calmAV"

        echo -e "\n------HASH------"
        echo -e "MD5 Hash \t: $md5_hash"
        echo -e "SHA256 Hash \t: $sha256_hash"
        echo -e "IMPHASH \t: $imphash"
        echo -e "TELFHASH \t: $telfhash"
        echo -e "GIMPHASH \t: $gimphash"
        echo -e "SSDEEPP \t: $ssdeep"
        echo -e "DHASH ICON \t: $dhash_icon"
        echo -e "TLSH \t\t: $tlsh"

        echo -e "\n------File Information------"
        file_information=$(echo "$data" | jq -r 'try .file_information[] | try .context + "\t\t: " + try .value | select(. != null and . != "")')
        echo "$file_information"

        echo -e "\n------Intelligence------"
        intel=$(echo "$data" | jq -r 'try .vendor_intel[] | try .analysis_url + try .link | select(. != null and . != "")')
        echo -e "$intel"

        yara_rules=$(echo "$data" | jq -r 'try .yara_rules[] 
        | "Rule Name \t: " + .rule_name + "\nAuthor \t\t: " + .author + "\nDescription \t: " + .description + "\n"')
        echo -e "\n------YARA Rules------"
        echo -e "$yara_rules"
    fi
}

function parsingMultiData() {
    flag=$(echo "$1" | jq -r ".query_status")
    if [ "$flag" == "no_results" ]; then
        echo "No results !"
    elif [ "$flag" == "illegal_tlsh" ]; then
        echo "Invalid TLSH !"
    elif [ "$flag" == "illegal_telfhash" ]; then
        echo "Invalid TELFHASH !"
    elif [ "$flag" == "illegal_imphash" ]; then
        echo "Invalid IMPHASH !"
    elif [ "$flag" == "illegal_gimphash" ]; then
        echo "Invalid GIMPHASH !"
    elif [ "$flag" == "illegal_dhash_icon" ]; then
        echo "Invalid DHASH !"
    elif [ "$flag" == "illegal_clamav" ]; then
        echo "Invalid CalmAV signature !"
    elif [ "$flag" == "clamav_not_found" ]; then
        echo "No results !"
    elif [ "$flag" == "illegal_yara_rule" ]; then
        echo "Invalid YARA rule !"
    elif [ "$flag" == "yara_not_found" ]; then
        echo "No results !"
    elif [ "$flag" == "illegal_signature" ]; then
        echo "Invalid family !"
    elif [ "$flag" == "signature_not_found" ]; then
        echo "No results !"
    elif [ "$flag" == "tag_not_found" ]; then
        echo "No results !"
    elif [ "$flag" == "illegal_tag" ]; then
        echo "Invalid tag !"
    fi
    if [ "$flag" == "ok" ]; then
        echo -e "\n+---------------------------------+"
        echo -e "|\t  Search Results\t  |"
        echo -e "+---------------------------------+"
        data=$(echo "$1" | jq -r '.data[] 
        | "File Name \t: " + .file_name 
        + "\nFile Type \t: " + .file_type  
        + "\nFile Type Mime \t: " + .file_type_mime 
        + "\nReporter \t: " + .reporter  
        + "\nFirst Seen \t: " + .first_seen
        + "\nFamily \t\t: " + .signature 
        + "\nSHA256 Hash \t: " + .sha256_hash 
        + "\n"')
        echo "$data"
    fi
}

function searchHash() {
    echo "Searching using SHA256...."
    echo -e "Hash : $1 \n"
    data=$(curl -s -X POST https://mb-api.abuse.ch/api/v1/ -d "query=get_info&hash=$1")
    parsingSingleData "$data" "$1"
}

function searchTag() {
    echo "Searching using Tag...."
    echo -e "Tag : $1 \n"
    data=$(curl -s -X POST https://mb-api.abuse.ch/api/v1/ -d "query=get_taginfo&tag=$1&limit=50")
    parsingMultiData "$data"
}

function searchCalmAV() {
    echo "Searching using ClamAV signature...."
    echo -e "Signature : $1 \n"
    data=$(curl -s -X POST https://mb-api.abuse.ch/api/v1/ -d "query=get_clamavinfo&clamav=$1&limit=50")
    parsingMultiData "$data"
}

function searchTLSH() {
    echo "Searching using TLSH...."
    echo -e "Hash : $1 \n"
    data=$(curl -s -X POST https://mb-api.abuse.ch/api/v1/ -d "query=get_tlsh&tlsh=$1&limit=50")
    parsingMultiData "$data"
}

function searchTELF() {
    echo "Searching using TELF hash...."
    echo -e "Hash : $1 \n"
    data=$(curl -s -X POST https://mb-api.abuse.ch/api/v1/ -d "query=get_telfhash&telfhash=$1&limit=50")
    parsingMultiData "$data"
}

function searchGIMP() {
    echo "Searching using gimphash...."
    echo -e "Hash : $1 \n"
    data=$(curl -s -X POST https://mb-api.abuse.ch/api/v1/ -d "query=get_gimphash&gimphash=$1&limit=50")
    parsingMultiData "$data"
}

function searchDHASH() {
    echo "Searching using DHASH...."
    echo -e "Hash : $1 \n"
    data=$(curl -s -X POST https://mb-api.abuse.ch/api/v1/ -d "query=get_dhash_icon&dhash_icon=$1&limit=50")
    parsingMultiData "$data"
}

function searchYARA() {
    echo "Searching using YARA rule...."
    echo -e "YARA Rule : $1 \n"
    data=$(curl -s -X POST https://mb-api.abuse.ch/api/v1/ -d "query=get_yarainfo&yara_rule=$1&limit=50")
    parsingMultiData "$data"
}

function searchFamily() {
    echo "Searching using malware family...."
    echo -e "Family : $1 \n"
    data=$(curl -s -X POST https://mb-api.abuse.ch/api/v1/ -d "query=get_siginfo&signature=$1&limit=50")
    parsingMultiData "$data"
}

function downloadFile() {
    echo "Downloading sample using SHA256 hash...."
    echo -e "Hash : $1 \n"
    data=$(curl -s -X POST https://mb-api.abuse.ch/api/v1/ -d "query=get_info&hash=$1")
    flag=$(echo "$data" | jq -r ".query_status")
    if [ "$flag" == "hash_not_found" ]; then
        echo "Couldn't find any file with that hash !"
    elif [ "$flag" == "illegal_hash" ]; then
        echo "Invalid SHA256 hash !"
    fi
    if [ "$flag" == "ok" ]; then
        echo -e "Zip Password : infected\n"
        data=$(curl -X POST https://mb-api.abuse.ch/api/v1/ -d "query=get_file&sha256_hash=$1" -o "$1.zip")
    fi

}

function searchFile() {
    echo -e "File : $1\n"
    if [ -f "$1" ]; then
        fHash=($(sha256sum "$1"))
        searchHash "$fHash"
    else
        echo "Invalid file !"
    fi
}

banner
if ! type curl >/dev/null 2>&1; then
    echo "curl is requried to run this tool. Please install curl."
    exit
fi
if ! type jq >/dev/null 2>&1; then
    echo "jq is requried to run this tool. Please install jq."
    exit
fi
if ! type sha256sum >/dev/null 2>&1; then
    echo "sha256sum is requried to run this tool. Please install sha256sum."
    exit
fi

h_flag=0
t_flag=0
e_flag=0
g_flag=0
d_flag=0
c_flag=0
y_flag=0
S_flag=0
T_flag=0
D_flag=0
f_flag=0
while getopts ":h:t:e:g:d:c:y:S:T:D:f:" u_option; do
    case $u_option in
    h)
        h_flag=1
        h_value=$OPTARG
        ;;
    t)
        t_flag=1
        t_value=$OPTARG
        ;;
    e)
        e_flag=1
        e_value=$OPTARG

        ;;
    g)
        g_flag=1
        g_value=$OPTARG

        ;;
    d)
        d_flag=1
        d_value=$OPTARG

        ;;
    c)
        c_flag=1
        c_value=$OPTARG

        ;;
    y)

        y_flag=1
        y_value=$OPTARG

        ;;
    S)
        S_flag=1
        S_value=$OPTARG

        ;;
    T)
        T_flag=1
        T_value=$OPTARG
        ;;
    D)
        D_flag=1
        D_value=$OPTARG

        ;;
    f)
        f_flag=1
        f_value=$OPTARG
        ;;

    \?)
        echo -e "Invalid option: -$OPTARG \n" >&2
        helpDoc
        exit
        ;;
    :)
        echo -e "Option -$OPTARG requires a value.\n" >&2
        helpDoc
        exit
        ;;
    esac
done

flagVal=$((h_flag + t_flag + e_flag + g_flag + d_flag + c_flag + y_flag + S_flag + T_flag + D_flag + f_flag))

if [[ $flagVal -ne 1 && $flagVal -ne 0 ]]; then
    echo -e "You can use one option at a time !\n" >&2
    helpDoc
    exit
fi

if [[ $OPTIND -eq 1 ]]; then
    helpDoc
    exit
fi

if [[ h_flag -eq 1 ]]; then
    searchHash "$h_value"
    exit
fi

if [[ t_flag -eq 1 ]]; then
    searchTLSH "$t_value"
    exit
fi

if [[ e_flag -eq 1 ]]; then
    searchTELF "$e_value"
    exit
fi

if [[ g_flag -eq 1 ]]; then
    searchGIMP "$g_value"
    exit
fi

if [[ d_flag -eq 1 ]]; then
    searchDHASH "$d_value"
    exit
fi

if [[ c_flag -eq 1 ]]; then
    searchCalmAV "$c_value"
    exit
fi

if [[ y_flag -eq 1 ]]; then
    searchYARA "$y_value"
    exit
fi

if [[ S_flag -eq 1 ]]; then
    searchFamily "$S_value"
    exit
fi

if [[ T_flag -eq 1 ]]; then
    searchTag "$T_value"
    exit
fi

if [[ D_flag -eq 1 ]]; then
    downloadFile "$D_value"
    exit
fi

if [[ f_flag -eq 1 ]]; then
    searchFile "$f_value"
    exit
fi
