# KPOT-string-decrypter

IDA python scripts for decrypting KPOT stealer's strings and setting those as comments next to the var that would receive them during runtime. It works as follows:

- Gets the offset that's passed on eax to either decryption function (there are two, which is why this repo has two scripts), either using `mov` or `pop eax`.

- Decrypts the string on an array by reading its corresponding size and XOR key

- Prints the decrypted string and the offset of where it was set as a comment, as well as *any strings it couldn't decrypt* (see `Important Considerations` below)

# Important Considerations

- There are a few instances in the code where the malware will use a different method than those accounted for in the scripts. You can find those cases by following the addresses with the message `Could not decrypt xref:` and decrypt them by supplying the offset manually to the relevant functions.

- The script converts the decrypted array into a string via `decode()`. In my experience there are three byte arrays decrypted by KPOT that are not strings, which causes the script to crash. These are the offsets that are ignored in `kpot-string-decrypter-pt1.py`.
	- The offsets corresponding to these might change between samples (I haven't checked). If that happens, adding a line to `search_offset()` that prints the current address can help you find where the script is crashing.
	- To decrypt these strings manually, all you need to do is change the return of `decrypt_str()` to `return(newarray.hex())`.

- To know which of the two scripts to use, check the decryption routine - pt1 is meant for the sub that does only a byte XOR, while pt2 is meant for the one that does `AND 0xFF` after the XOR.