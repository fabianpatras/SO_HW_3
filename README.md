Name: Anton-Fabian Patras

Group: 334CB

# Assignment 3 ELF Loader

## Main idea
* When the executable is started is generates `page faults` for each memory acces to a new page.
* There is a `signal handler` that gets triggered every time a `page fault` is generated.
* The `signal handler` first has to see in which `segment` the `page fault` occured.
	* This is done in `signal_handler` by comparing the address at which the `page fault` occured to the start address and end address of each segment
	* If there is no segment then it's a true invalid acces and `Segmentation fault` is delivered
* After the segment is found, we have to find informations about the `page` that contains the `address` of the `page fault`
* If the page was already mapped then the access didn't have the right permisions and `Segmentation fault` is delivered
* If the page isn't mapped then we map it:
	* For bss address we map with the `MAP_ANONYMOUS` flag on
* To see what kind of mapping it has to be made we compare the `page_start` and `page_end` to the `file_size` of that segment
	* If `file_size` is between those two then the page could have `.bss` data as well and we have to map accordingly