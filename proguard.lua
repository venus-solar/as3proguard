--[[
lua proguad.lua -i INDIR -b INBIN -o OUTNAME -n WORDLEN -h
--]]

INDIR = ""
INBIN = ""
OUTNAME = "proguard_out.swf"
WORDLEN = 6
WORDLEN_LIMIT = 5
PRINT_HELP = false
DEBUG_VERBOSE = 1
DEBUG_DEBUG = 2
DEBUG_WARN = 3
DEBUG_ERROR = 4
DEBUG_LV = DEBUG_WARN
DEBUG_ENABLE = true

PATTERN1 = "private var "
PATTERN2 = "public var "
PATTERN3 = "private const "
PATTERN4 = "public const "

stop_proceed = false
on_windows = true
fVarList = {}
dict = {}

function loge (...)
	if (DEBUG_LV <= DEBUG_ERROR) then
		print("ERROR " .. ...)
	end
end

function logw (...)
	if (DEBUG_LV <= DEBUG_WARN) then
		print("WARN " .. ...)
	end
end

function logd (...)
	if (DEBUG_LV <= DEBUG_DEBUG and DEBUG_ENABLE) then
		print("DEBUG " .. ...)
	end
end

function logv (...)
	if (DEBUG_LV <= DEBUG_VERBOSE and DEBUG_ENABLE) then
		print("VERBOSE " .. ...)
	end
end

function print_help()
	local help_info = [[
lua proguad.lua -i INDIR -b INBIN -o OUTNAME -n WORDLEN -h
	-i) input directory for scan, must have 
	-b) input binary for proguard, must have 
	-o) outname, option
	-n) word length, the higher, the easier to succeed and reverse engineering hack
	-h) print this help info
	]]
	print(help_info)
end

function create_map()
	for i = 1, string.byte("Z") - string.byte("A") + 1 do
		dict [i] = string.char(string.byte("A") + i - 1)
	end

	for i = 1, string.byte("z") - string.byte("a") + 1 do
		dict [i] = string.char(string.byte("a") + i - 1)
	end

	dict[#dict + 1] = "?"
	dict[#dict + 1] = "_"

	logd("dump dict +++")
	for i = 1, #dict do
		logd(dict[i])
	end
	logd("dump dict ---")
end

function parse_parameters()
	logv("parse_parameters +++")
	for i = 1, #arg do
		if (arg[i] == "-i") then
			INDIR = arg[i+1]
		elseif (arg[i] == "-b") then
			INBIN = arg[i+1]
		elseif (arg[i] == "-o") then
			OUTNAME = arg[i+1]
		elseif (arg[i] == "-n") then
			WORDLEN = arg[i+1]
		elseif (arg[i] == "-h") then
			PRINT_HELP = true
			stop_proceed = true
		end
	end

	if (INDIR == "") then
		logw("Need input directory")
		stop_proceed = true
	end

	if (INBIN == "") then
		logw("Need input binary")
		stop_proceed = true
	end

	if (WORDLEN <= WORDLEN_LIMIT) then
		logw("word length is too small, proguard may NOT work properly!\n")
	end


	logd("dump paramters +++")
	logd("input dir: " .. INDIR)
	logd("input bin:" .. INBIN)
	logd("outname: " .. OUTNAME)
	logd("wordlen: " .. WORDLEN)
	logd("dump paramters ---")
	logv("parse_parameters ---")
end

function scan_createtables_win(_dir)
	logv("scan_createtables_win +++")
	local i, fList = 0, {}
	for fname in io.popen("dir " .. _dir .. "\\*.as" .. " /b") : lines() do
		i = i + 1
		fList[i] = fname
	end
	logv("scan_createtables_win ---")
	return fList
end

function scan_createtables_linux(_dir)
	logv("scan_createtables_linux +++")
	local i, fList = 0, {}
	for fname in io.popen("ls -d " .. _dir .. "/*.as") : lines() do
		i = i + 1
		fList[i] = fname
	end
	logv("scan_createtables_linux ---") 
	return fList
end

function proguard_gen(k)
	logv("proguard_gen +++")
	local t = {}
	for i = 1, #k do
		t[#t + 1] = dict[math.random(#dict)]
	end
	local s = table.concat(t)
	logv("proguard_gen ---")
	return s
end

function scan_createtables(_dir)
	logv("scan_createtables +++")
	local fList = {}
	if (on_windows)	then
		fList = scan_createtables_win(_dir)
	else
		fList = scan_createtables_linux(_dir)
	end

	-- scan files and create VarList
	for i = 1, #fList do
		local fIn = io.open(fList[i], "r")
		local fInData = fIn:read("*a")

		for fVar in string.gmatch(fInData, PATTERN1 .. "%w") do
			fVarList[fVar] = true
		end

		for fVar in string.gmatch(fInData, PATTERN2 .. "%w") do
			fVarList[fVar] = true
		end

		for fVar in string.gmatch(fInData, PATTERN3 .. "%w") do
			fVarList[fVar] = true
		end

		for fVar in string.gmatch(fInData, PATTERN4 .. "%w") do
			fVarList[fVar] = true
		end
		io.close(fIn)
	end

	-- sort from longest to shortest
	table.sort(fVarList, function (a, b) return string.len(a) > string.len(b) end)

	-- calc random tables
	for k, _ in pairs(fVarList) do
		local randomV = proguard_gen(k)
		fVarList[k] = randomV
	end

	logv("generate random table file +++")
	local fTable = io.open("RandomTable", "w")
	local fTableT = {}
	for k, v in pairs(fVarList) do
		fTableT[#fTableT + 1] = k .. " "
		fTableT[#fTableT + 1] = v .. "\n"
	end
	local fTableS = table.concat(fTableT)
	fTable:write(fTableS)
	io.close(fTable)
	logv("generate random table file ---")
	logv("scan_createtables ---")
end

function proguard_bin(_table, _bin)
	logv("proguard_bin +++")
	local fBin = io.open(INBIN, "r")
	local fBinData = fBin:read("*a")
	for k, v in pairs(_table) do
		string.gsub(fBinData, k, v)
	end
	local fBinOut = io.open(OUTNAME, "w")
	fBinOut:write(fBinData)
	io.close(fBin)
	io.close(fBinOut)
	logv("proguard_bin ---") 
end

function main()
	parse_parameters()

	if (PRINT_HELP) then
		print_help()
	end

	if (not stop_proceed) then
		create_map()
		scan_createtables(INDIR)
		proguard_bin(fVarList, INBIN)
	else
		logw("stop proceed, check your parameters!")
	end
end

main()
