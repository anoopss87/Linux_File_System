/* Digital Forensics - Spring 2016 
 * 
 * GBD.c - writes the group descriptor table data into the output file(hex dump as well as key:value).
 * compares group descriptor table of 2 different block group number.
 * @author - Anoop S Somashekar
*/

#include "GBD.h"
extern struct ext3_group_desc *gGrpDescTable;

//returns the maximum element from 2 numbers 
int bgdMax(int a, int b)
{
    if(a > b)
      return a;
    else
      return b;  
}

/*Group descriptor will be duplicated at 0,1 ans powers of 3, 5, 7
  For e.g it is duplicated at block group number 0, 1, 3, 5, 7, 9, 25, 27, 49, 81, 125 etc....*/
long long bgdGetGroupDescStartOffset(int index)
{
    /*blockSize * 8 gives the number of blocks in a block group
     index is the block group number from which we need the block group descriptor table
     Since first block of any block group is super block, 1 is added to get the starting offset for group desc table
     (index * blockSize * 8 + 1) is the block number. Since we need byte offset to read the data, it is multiplied
     by blocksize.*/
    long long value = (index * gBlockSize * 8) + 1;
    value *= gBlockSize; 
    return value;
}

//returns the block size for the given drive name
int bgdGetBlockSize(char driveName[])
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
int bgdGetNumberofBlockGroups(char driveName[])
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
    return bgdMax(numOfBlockGroups1, numOfBlockGroups2);
}

/*Function returns 1 if the number is power of 3 or 5 or 7. 
  Else returns 0. */
int bgdIsPowerOf3_5_7(int number)
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
   
/*returns 1 if group descriptor table at blkGrpNum1 and blkGrpNum2 are identical.
 else returns 0*/
int bgdCompareGrpDesc(int blkGrpNum1, int blkGrpNum2, char driveName[])
{
    int fd1 = open(driveName, O_RDONLY);
    int fd2 = open(driveName, O_RDONLY);
    long long offset1 = bgdGetGroupDescStartOffset(blkGrpNum1);
    long long offset2 = bgdGetGroupDescStartOffset(blkGrpNum2);

    lseek64(fd1,offset1,SEEK_SET);
    lseek64(fd2,offset2,SEEK_SET);

    int bg_iterator = 0;
    struct ext3_group_desc * gdesc1 = (struct ext3_group_desc *)malloc(sizeof(struct ext3_group_desc));
    struct ext3_group_desc * gdesc2 = (struct ext3_group_desc *)malloc(sizeof(struct ext3_group_desc));

    char *buff1 = (char *)malloc(sizeof(struct ext3_group_desc));
    char *buff2 = (char *)malloc(sizeof(struct ext3_group_desc));
    while(bg_iterator < gBlockGroupCount)
    {
        read(fd1,buff1,sizeof(struct ext3_group_desc));
        memcpy((void *)gdesc1,(void *)buff1,sizeof(struct ext3_group_desc));

        read(fd2,buff2,sizeof(struct ext3_group_desc));
        memcpy((void *)gdesc2,(void *)buff2,sizeof(struct ext3_group_desc));

        if(gdesc1->bg_block_bitmap != gdesc2->bg_block_bitmap ||
           gdesc1->bg_inode_bitmap != gdesc2->bg_inode_bitmap ||
           gdesc1->bg_inode_table != gdesc2->bg_inode_table ||
           gdesc1->bg_free_blocks_count != gdesc2->bg_free_blocks_count ||
           gdesc1->bg_free_inodes_count != gdesc2->bg_free_inodes_count)
         {
             return 0;
         }
         else
             bg_iterator++;
    }
    return 1;
}

//iterate all the block groups in a group descriptor table and output its contents to an output file named "output.txt"
struct ext3_group_desc * bgdGetGrpDescTable(char driveName[], int blockGroupNo, int fileWrite)
{
    long long offset =0;
    FILE* output_file;
    FILE* hex_dump;
    int index;
    char *buff = (char *)malloc(sizeof(struct ext3_group_desc));
    struct ext3_group_desc * gdesc = (struct ext3_group_desc *)malloc(sizeof(struct ext3_group_desc));

    //structure to store all block group descriptors 
    struct ext3_group_desc *gDescTable = (struct ext3_group_desc *)malloc(gBlockGroupCount * sizeof(struct ext3_group_desc));    

    //The different fields in the block group descriptor
    unsigned char block_group_descriptor[8][30] = {"Blocks bitmap block","Inodes bitmap block","Inode table block","Free blocks count","Free inodes count","Used dirs count"/*,"bg_pad","bg_reserved"*/};
    int fd = open(driveName,O_RDONLY);
    if(fd < 0)
    {
        fputs("memory error",stderr);
        exit (2);
    }

    //block group desc table size is one block group desc size(32) * total number of block groups
    int blockGroupTblSize = gBlockGroupCount * BLOCK_GROUP_DESC_SIZE;
    unsigned char buffer[blockGroupTblSize];
    offset = bgdGetGroupDescStartOffset(blockGroupNo);

    //Go to the first block group descriptor in the second block	
    lseek64(fd,offset,SEEK_SET);
	
    //create output file if required
    if(fileWrite)
    {
        char fileName[MAX_FILENAME_LENGTH];
        sprintf(fileName, "output%d.txt", blockGroupNo);
        output_file = fopen(fileName,"write");
        //open the file for hex dump
        memset(fileName, 0, MAX_FILENAME_LENGTH);
        sprintf(fileName, "hexdump%d.txt", blockGroupNo);
        hex_dump = fopen(fileName, "write");
    }

    //read block group desc table into buffer which will be used for hex dump
    int retVal = read(fd, buffer, blockGroupTblSize);
    if(retVal  <= 0)
    {
        fprintf(stderr, "unable to read disk, retVal = %d\n", retVal);
        return;
    }

    //hex dump i.e 16 bytes in each line
    if(fileWrite)
    {
        int byteCount = 0;
        for(index=0;index<blockGroupTblSize;index++)
        {
            fprintf(hex_dump, "%02x ", buffer[index]);
            byteCount++;
            if(byteCount == HEX_DUMP_LINE_SIZE)
            {
                fprintf(hex_dump, "\n");
                byteCount = 0;
            }
        }
    }

    if(fileWrite)
    {
        //print the group descriptor field descriptions in the output file
        for(index=0;index<8;++index)
        {
            fprintf(output_file,"%s    ", block_group_descriptor[index]);
        }	

        fprintf(output_file,"\n");
    }
	lseek64(fd,offset,SEEK_SET);
    //iterate through all the group descriptors in the group descriptor table
    int bg_iterator = 0;
    while(bg_iterator < gBlockGroupCount)
    {
        //read each group descriptor and write it to output file.
        read(fd,buff,sizeof(struct ext3_group_desc));
        memcpy((void *)&gDescTable[bg_iterator], (void *)buff, sizeof(struct ext3_group_desc));

        if(fileWrite)
        {
            memcpy((void *)gdesc,(void *)buff,sizeof(struct ext3_group_desc));
            fprintf(output_file, "%15ld|", gdesc->bg_block_bitmap);
            fprintf(output_file, "%18ld|", gdesc->bg_inode_bitmap);
            fprintf(output_file, "%20ld|", gdesc->bg_inode_table);
            fprintf(output_file, "%22d|", gdesc->bg_free_blocks_count);
            fprintf(output_file, "%18d|", gdesc->bg_free_inodes_count);
            fprintf(output_file, "%16d\n", gdesc->bg_used_dirs_count);
        }
        bg_iterator++;
    }
    if(fileWrite)
    {
        close(output_file);
        close(hex_dump);
    }
    free(gdesc);
    return gDescTable;
}

/* Reads the single indirect block address at blockNumber and
   prints the data at fDataOutput and block addresses at fBlockAddr */
void bgdReadSingleIndirectBlocks(int blockNumber, FILE *fDataOutput, int fp, int fileSizeInBlocks, FILE *fBlockAddr)
{
    char *data = (char *)malloc(gBlockSize);
    long long offset = blockNumber * gBlockSize;
    lseek64(fp, offset, SEEK_SET);
    memset((void *)data, 0, gBlockSize);
    read(fp, data, gBlockSize);
    int addr;
    int counter = 1;
    int maxCount = fileSizeInBlocks - DIRECT_BLOCKS_COUNT;
    if(maxCount > SINGLE_INDIRECT_BLOCKS_COUNT)
        maxCount = SINGLE_INDIRECT_BLOCKS_COUNT;

    while(counter <= maxCount)
    {
        memcpy(&addr, (void *)data, sizeof(int));
        if(addr > 0)
        {
            char *content = (char *)malloc(gBlockSize);
            long long byteOffset = addr * gBlockSize;
            lseek64(fp, byteOffset, SEEK_SET);
            read(fp, content, gBlockSize);
            //printf("%s", content);
            fprintf(fDataOutput, "%s", content);
            fprintf(fBlockAddr, "%7d ", addr);
            if(counter % 16 == 0)
                fprintf(fBlockAddr, "\n");
            memset((void *)content, 0, gBlockSize);
        }
        else
        {
            break;
        }
        data += sizeof(int);
        counter++;
    }
    printf(".......Finished Indirect Block.........and the counter is %d\n", counter);
    fprintf(fBlockAddr, "\n\n");
    //free(data);
}

/* Reads the double indirect block address at blockNumber and
   prints the data at fDataOutput and block addresses at fBlockAddr */
void bgdReadDoubleIndirectBlocks(int blockNumber, FILE *fDataOutput, int fp, int fileSizeInBlocks, FILE *fBlockAddr)
{
    char *data = (char *)malloc(gBlockSize);
    long long offset = blockNumber * gBlockSize;
    lseek64(fp, offset, SEEK_SET);
    memset((void *)data, 0, gBlockSize);
    read(fp, data, gBlockSize);
    int addr;
    int counter = 0;
    int maxCount = fileSizeInBlocks - DIRECT_BLOCKS_COUNT - SINGLE_INDIRECT_BLOCKS_COUNT;
    if(maxCount > DOUBLE_INDIRECT_BLOCKS_COUNT)
        maxCount = DOUBLE_INDIRECT_BLOCKS_COUNT;

    printf("... Double Indirect Block and max count is %d\n", maxCount);

    while(counter < maxCount)
    {
        memcpy(&addr, (void *)data, sizeof(int));
        if(addr > 0)
        {
            bgdReadSingleIndirectBlocks(addr, fDataOutput, fp, fileSizeInBlocks, fBlockAddr);
            printf("Finished single indirect block %d in double indirect block\n", counter+1);
        }
        else 
            break;
        data += sizeof(int);
        counter++;
    }
    //free(data);
}

/* Reads the triple indirect block address at blockNumber and
   prints the data at fDataOutput and block addresses at fBlockAddr */
void bgdReadTripleIndirectBlocks(int blockNumber, FILE *fDataOutput, int fp, int fileSizeInBlocks, FILE *fBlockAddr)
{
    char *data = (char *)malloc(gBlockSize);
    long long offset = blockNumber * gBlockSize;
    lseek64(fp, offset, SEEK_SET);
    memset((void *)data, 0, gBlockSize);
    read(fp, data, gBlockSize);
    int addr;
    int counter = 0;
    int maxCount = fileSizeInBlocks - DIRECT_BLOCKS_COUNT - SINGLE_INDIRECT_BLOCKS_COUNT - DOUBLE_INDIRECT_BLOCKS_COUNT;
    /*if(maxCount > TRIPLE_INDIRECT_BLOCKS_COUNT)
        maxCount = TRIPLE_INDIRECT_BLOCKS_COUNT;*/

    printf("... Triple Indirect Block and max count is %d\n", maxCount);

    while(counter < maxCount)
    {
        memcpy(&addr, (void *)data, sizeof(int));
        if(addr > 0)
        {
            bgdReadDoubleIndirectBlocks(addr, fDataOutput, fp, fileSizeInBlocks, fBlockAddr);
            printf("Finished double indirect block %d in triple indirect block\n", counter+1);
        }
        else 
            break;
        data += sizeof(int);
        counter++;
    }
    //free(data);
}

/* Reads all the data blocks for the given inode number */
void bgdReadFromInode(int inode, char dName[])
{
    char *buffer = (char *)malloc(DEFAULT_EXT3_INODE_SIZE);
    struct ext3_inode *inode_tab = (struct ext3_inode *)malloc(DEFAULT_EXT3_INODE_SIZE);
    int blockGroupNo, inodeTableIndex;

    //get the block group number where the file resides
    blockGroupNo = inode / gBlockSize;

    //get the index of the inode table
    inodeTableIndex = (inode % gBlockSize) - 1;

    //read inode table starting block number from group descriptor table
    long inodeTableBlockNum = gGrpDescTable[blockGroupNo].bg_inode_table;

    //calculate the offset in bytes for the file seek
    long long offset = (inodeTableBlockNum * gBlockSize) + (inodeTableIndex * DEFAULT_EXT3_INODE_SIZE);
    int fd = open(dName, O_RDONLY);
    lseek64(fd,offset,SEEK_SET);
    read(fd, buffer, DEFAULT_EXT3_INODE_SIZE);
    memcpy((void *)inode_tab, (void *)buffer, DEFAULT_EXT3_INODE_SIZE);
    int fileSizeInBlocks;
    printf("File size is %d\n", inode_tab->i_size);
    if(inode_tab->i_size % gBlockSize == 0)
        fileSizeInBlocks = inode_tab->i_size / gBlockSize;
    else
        fileSizeInBlocks = (inode_tab->i_size / gBlockSize) + 1;
    
    char *data = (char *)malloc(gBlockSize);
    memset((void *)data, 0, gBlockSize);
    int index = 0;
    int fp = open(dName, O_RDONLY);
    int blockNumber;

    char fileName[MAX_FILENAME_LENGTH];
    sprintf(fileName, "inode%d.txt", inode);
    FILE *file_data = fopen(fileName,"write");
    memset((void *)fileName, 0, MAX_FILENAME_LENGTH);
    sprintf(fileName, "baddr_inode%d.txt", inode);
    FILE *block_addr = fopen(fileName, "write");

    printf("File Size in Blocks is %d\n", fileSizeInBlocks);

    //direct blocks
    if(fileSizeInBlocks <= DIRECT_BLOCKS_COUNT || 
       fileSizeInBlocks > DIRECT_BLOCKS_COUNT)
    {
        int maxCount = fileSizeInBlocks;
        if(maxCount > DIRECT_BLOCKS_COUNT)
            maxCount = DIRECT_BLOCKS_COUNT;

        fprintf(block_addr, "The direct block addresses are:\n");

        while(index < maxCount)
        {
            blockNumber = inode_tab->i_block[index++];        
            offset = blockNumber * gBlockSize;
            lseek64(fp, offset, SEEK_SET);
            printf("Direct Block Address is %d\n", blockNumber);
            read(fp, data, gBlockSize);
            //printf("%s", data);
            fprintf(file_data, "%s", data);
            fprintf(block_addr, "%d ", blockNumber);
        }
        fprintf(block_addr, "\n\n");        
    }

    //single indirect blocks
    if(fileSizeInBlocks > DIRECT_BLOCKS_COUNT &&
       (fileSizeInBlocks <= SINGLE_INDIRECT_BLOCKS_COUNT ||
       fileSizeInBlocks > SINGLE_INDIRECT_BLOCKS_COUNT))
    {
        blockNumber = inode_tab->i_block[index++];
        fprintf(block_addr, "The Single Indirect block addresses are:\n");
        bgdReadSingleIndirectBlocks(blockNumber, file_data, fp, fileSizeInBlocks, block_addr);
        fprintf(block_addr, "\n\n");
    }

    //second indirect blocks
    if(fileSizeInBlocks > SINGLE_INDIRECT_BLOCKS_COUNT &&
           (fileSizeInBlocks <= DOUBLE_INDIRECT_BLOCKS_COUNT ||
            fileSizeInBlocks > DOUBLE_INDIRECT_BLOCKS_COUNT))
    {
        blockNumber = inode_tab->i_block[index++];
        fprintf(block_addr, "The Double Indirect block addresses are:\n");
        bgdReadDoubleIndirectBlocks(blockNumber, file_data, fp, fileSizeInBlocks, block_addr);
        fprintf(block_addr, "\n\n");
    }

    //triple indirect blocks
    if(fileSizeInBlocks > DOUBLE_INDIRECT_BLOCKS_COUNT)
    {
        blockNumber = inode_tab->i_block[index++];
        fprintf(block_addr, "The Triple Indirect block addresses are:\n");
        bgdReadTripleIndirectBlocks(blockNumber, file_data, fp, fileSizeInBlocks, block_addr);
    }
    close(file_data);
    close(block_addr);
    free(buffer);
    free(inode_tab);
    free(data);
}

char *bgdGetBlockGroupInfo(int blockGroupNum)
{
    char *bgdInfo = (char *)malloc(BLOCK_GROUP_INFO_MAX_SIZE);
    memset((void *)bgdInfo, 0, BLOCK_GROUP_INFO_MAX_SIZE);
    char target[BLOCK_GROUP_FIELD_MAX_SIZE] = {0};
    sprintf(target, "%ld", gGrpDescTable[blockGroupNum].bg_block_bitmap);
    strcpy(bgdInfo, target);
    strcat(bgdInfo, "|");
    memset((void *)target, 0, BLOCK_GROUP_FIELD_MAX_SIZE);
    sprintf(target, "%ld", gGrpDescTable[blockGroupNum].bg_inode_bitmap);
    strcat(bgdInfo, target);
    strcat(bgdInfo, "|");
    memset((void *)target, 0, BLOCK_GROUP_FIELD_MAX_SIZE);
    sprintf(target, "%ld", gGrpDescTable[blockGroupNum].bg_inode_table);
    strcat(bgdInfo, target);
    strcat(bgdInfo, "|");
    memset((void *)target, 0, BLOCK_GROUP_FIELD_MAX_SIZE);
    sprintf(target, "%d", gGrpDescTable[blockGroupNum].bg_free_inodes_count);
    strcat(bgdInfo, target);
    strcat(bgdInfo, "|");
    memset((void *)target, 0, BLOCK_GROUP_FIELD_MAX_SIZE);
    sprintf(target, "%d", gGrpDescTable[blockGroupNum].bg_free_blocks_count);
    strcat(bgdInfo, target);
    strcat(bgdInfo, "|");
    memset((void *)target, 0, BLOCK_GROUP_FIELD_MAX_SIZE);
    sprintf(target, "%d", gGrpDescTable[blockGroupNum].bg_used_dirs_count);
    strcat(bgdInfo, target);
    return bgdInfo;
}
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
