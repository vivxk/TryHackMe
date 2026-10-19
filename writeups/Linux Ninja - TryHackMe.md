
First find the files and copy them to current working directory, or continue by using the -exec flag in find command.
	
`find . -type f '(' -name '8V2L' -o -name 'bny0' -o -name 'c4ZX' -o -name 'D8B3' -o -name 'FHl1' -o -name 'oiMO' -o -name 'PFbD' -o -name 'rmfX' -o -name 'SRSq' -o -name 'uqyw' -o -name 'v2Vb' -o -name 'X1Uy' ')' -exec cp {} . ';'`

**Task 1**
- Which of the above files are owned by the best-group group(enter the answer separated by spaces in alphabetical order)
	- using`  find / -type f -group best-group -printf "%f\n" 2>/dev/null` we get 
	  **D8B3 v2Vb**
- Which of these files contain an IP address?
	- using ` find . -type f -exec grep -EnH '([0-9]{1,3}\.){3}[0-9]{1,3}' {} +`, we get **oiMO**
- Which file has the SHA1 hash of 9d54da7584015647ba052173b84d45e8007eba94?
	- ` sha1sum * | grep 9d54da7584015647ba052173b84d45e8007eba94`, **c4ZX**
- Which file contains 230 lines?
	- `wc -l *`, all files have 209 lines, the only file missing is **bny0**
- Which file's owner has an ID of 502?
	- using `find / -type f \( -name 8vL -o -name bny0 -o -name c4ZX -o -name DB83 -o -name FHl1 -o -name oiM0 -o -name PFbD -o -name rmfX -o -name SRSq -o -name uqyw -o -name v2Vb -o -name XIUy \) -exec ls -ln {} \; 2>/dev/null` ,we  have **X1Uy**
- Which file is executable by everyone?
	- using `find / -type f \( -name 8V2L -o -name bny0 -o -name c4ZX -o -name DB83 -o -name FHl1 -o -name oiM0 -o -name PFbD -o -name rmfX -o -name SRSq -o -name uqyw -o -name v2Vb -o -name XIUy \) -exec ls -lanh {} \; 2>/dev/null`, we get **8V2L**

