## Prerquisites
1. Project files structure refers to Flash builder, for example, all source files are under one folder such as folder src. Binary file is under another directory such as Debug.

2. lua needs be installed because this program is writteny by lua. Of course you can port it in other language.

## How to use
1. Decompress binary file before doing proguard

2. lua proguard.lua -i INPUTDIR -b INPUTBIN -o OUTNAME -n WORDLEN

3. Compress OUTNAME into new binary output

4. Check if new binary works or not (YOUR new binary may NOT work, considering you replace something which should NOT be replaced!). If it doesn't work, goto step 2 and change input paramters
