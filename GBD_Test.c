/* Digital Forensics - Spring 2016 
 * 
 * GBD_Test.c - This is just a test file which contains main function 
 * to test the GDB functionality.
 * @author - Anoop S Somashekar
*/

#include "GBD.h"

int main(int argc, char* argv[])
{
    if(argc < 3)
    {
	    printf("Invalid argument format: Usage %s \\dev\\sdx1 inode_number\n", argv[0]);
        exit(1);
    }
    char *dName = argv[1];
    int inodeNumber = atoi(argv[2]);
    int fileWrite = 0;
    if(argc > 3)
        fileWrite = 1;
    int fd = open(argv[1],O_RDONLY);
    if(fd < 0)
    {
        fputs("memory error",stderr); 
        exit (2);
    }

    gBlockSize = bgdGetBlockSize(dName);
    gBlockGroupCount = bgdGetNumberofBlockGroups(dName);
    gGrpDescTable = bgdGetGrpDescTable(dName, 0, fileWrite);

    /*int i, j;
    for(i=0;i<gBlockGroupCount;++i)
    {
        if(!bgdIsPowerOf3_5_7(i))
            continue;
        else
            for(j=i+1;j<gBlockGroupCount;++j)
            {
                if(bgdIsPowerOf3_5_7(j))            
                    printf("The group descriptor table at block groups %2d and %2d are identical  -  %d\n", i,j, compareGrpDesc(i, j, dName));
            }
    }*/
    bgdReadFromInode(inodeNumber, dName);
    free(gGrpDescTable);
    return 0;	
}
