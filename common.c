/* Digital Forensics - Spring 2016 
 * 
 * common.c - common functions are defined in this file.
 * @author - Anoop S Somashekar
*/

#include "common.h"

//returns the maximum element from 2 numbers 
int max(int a, int b)
{
    if(a > b)
      return a;
    else
      return b;  
}

//Group descriptor will be duplicated at 0,1 ans powers of 3, 5, 7
//For e.g it is duplicated at block group number 0, 1, 3, 5, 7, 9, 25, 27, 49, 81, 125 etc....
long long getGroupDescStartOffset(int index)
{
    //blockSize * 8 gives the number of blocks in a block group
    //index is the block group number from which we need the block group descriptor table
    //Since first block of any block group is super block, 1 is added to get the starting offset for group desc table
    //(index * blockSize * 8 + 1) is the block number. Since we need byte offset to read the data, it is multiplied
    //by blocksize.
    long long value = (index * blockSize * 8) + 1;
    value *= blockSize; 
    return value;
}

//returns the block size for the given drive name
int getBlockSize(char driveName[])
{
    int fd = open(driveName,O_RDONLY);
    if(fd < 0)
    {
        fputs("memory error",stderr); 
        exit (2);
    }

    int offset = SUPER_BLOCK_OFFSET + BLOCK_SIZE_VALUE_OFFSET;
    int blockSize;
    unsigned char buffer[4];	
    lseek(fd,offset,SEEK_CUR);
    read (fd,buffer,sizeof(int));
    memcpy(&blockSize,buffer, sizeof(int));
    blockSize = MIN_BLOCK_SIZE << blockSize;
    return blockSize;    	           	
}

//returns the total number of block groups in the group descriptor table
int getNumberofBlockGroups(char driveName[])
{
    int fd = open(driveName,O_RDONLY);
    if(fd < 0)
    {
        fputs("memory error",stderr);
        exit (2);
    }

    int offset = SUPER_BLOCK_OFFSET;
    int totalNumOfInodes, totalNumOfBlocks, numOfBlocksInGroup, numOfInodesInGroup;
    unsigned char buffer[4];

    //read 4 bytes data(int) i.e. total number of inodes
    lseek(fd,offset,SEEK_CUR);
    read (fd,buffer,sizeof(int));
    memcpy(&totalNumOfInodes,buffer, sizeof(int));

   //read 4 bytes of int data i.e. total number of blocks
    read (fd,buffer,sizeof(int));
    memcpy(&totalNumOfBlocks,buffer, sizeof(int));
    
    //read 4 bytes of data(int) i.e. number of blocks in a group at offset 32
    lseek(fd,NUM_OF_BLOCKS_IN_A_GROUP_REL_OFFSET,SEEK_CUR);
    read (fd,buffer,sizeof(int));
    memcpy(&numOfBlocksInGroup,buffer, sizeof(int));
    
    //read 4 bytes of data(int) i.e. number of indoes in a group at a relative offset 40   
    lseek(fd,NUM_OF_INODES_IN_A_GROUP_REL_OFFSET,SEEK_CUR);
    read (fd,buffer,sizeof(int));
    memcpy(&numOfInodesInGroup,buffer, sizeof(int));
    
    int numOfBlockGroups1 = totalNumOfInodes / numOfInodesInGroup;
    int numOfBlockGroups2 = totalNumOfBlocks / numOfBlocksInGroup;
    return max(numOfBlockGroups1, numOfBlockGroups2);
}

//Function returns 1 if the number is power of 3 or 5 or 7. Else returns 0.
int isPowerOf3_5_7(int number)
{
    int num = number;
    if(num == 0)
        return 1;

    //If the number is power of 3
    while(num % 9 == 0)
    {
        num /= 9;
    }
    
    if (num == 1 || num == 3)
        return 1;

    num = number;
    //If the number is power of 5
    while(num % 5 == 0)
    {
        num /= 5;
    }

    if(num == 1)
        return 1;

    num = number;
    //If the number is power of 7
    while(num % 7 == 0)
    {
        num /= 7;
    }

    if(num == 1)
        return 1;

    //If the number is neither power of 3 or 5 or 7 then return 0.
    return 0;
}

