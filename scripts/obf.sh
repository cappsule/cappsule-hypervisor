#!/bin/bash

# Obfuscate symbols used by a Linux kernel module.

set -e
readonly ARGS="$@"


# get symbols from binary
get_syms()
{
	nm --debug-syms "$1" \
		| grep -v '^ ' \
		| cut -d ' ' -f 3 \
		| sort -u
}

# don't rename symbols required by the Linux kernel
filter_syms()
{
	local pattern=''

	pattern+='^$'
	pattern+='\|__UNIQUE_ID_srcversion1\|__UNIQUE_ID_vermagic0'
	pattern+='\|__module_depends\|__this_module\|init_module\|cleanup_module'
	pattern+='\|____versions\|null'

	grep -v "$pattern"
}

# generate new symbols
gen_map()
{
	local mapfile=$1
	local i=0

	# reset map file
	echo -n '' > "$mapfile"

	while read sym; do
		printf "$sym s%x\n" $i >> "$mapfile"
		i=$((i+1))
	done

	# sort map file for better readability
	sort --output="$mapfile" "$mapfile"
}

# replace symbols
obfuscate()
{
	local mapfile="$1"
	local infile="$2"

	objcopy --verbose --redefine-syms="$mapfile" "$infile"
}

main()
{
	if [ $# -ne 2 ]; then
		echo "Usage: $0 <obj.ko> <result-symbols.map>"
		exit 1
	fi

	local filename="$1"
	local mapfile="$2"

	get_syms $filename \
		| filter_syms \
		| shuf \
		| gen_map "$mapfile"

	obfuscate "$mapfile" "$filename"
}

main $ARGS
