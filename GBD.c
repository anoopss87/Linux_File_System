/* Digital Forensics - Spring 2016 
 * 
 * GBD.c - writes the group descriptor table data into the output file(hex dump as well as key:value).
 * compares group descriptor table of 2 different block group number.
 * @author - Anoop S Somashekar
*/

#include "common.h"

//returns 1 if group descriptor table at blkGrpNum1 and blkGrpNum2 are identical.
//else returns 0
int compareGrpDesc(int blkGrpNum1, int blkGrpNum2, char driveName[])
{
    int fd1 = open(driveName, O_RDONLY);
    int fd2 = open(driveName, O_RDONLY);
    long long offset1 = getGroupDescStartOffset(blkGrpNum1);
    long long offset2 = getGroupDescStartOffset(blkGrpNum2);

    lseek64(fd1,offset1,SEEK_SET);
    lseek64(fd2,offset2,SEEK_SET);

    int bg_iterator = 0;
    struct ext3_group_desc * gdesc1 = (struct ext3_group_desc *)malloc(sizeof(struct ext3_group_desc));
    struct ext3_group_desc * gdesc2 = (struct ext3_group_desc *)malloc(sizeof(struct ext3_group_desc));

    char *buff1 = (char *)malloc(sizeof(struct ext3_group_desc));
    char *buff2 = (char *)malloc(sizeof(struct ext3_group_desc));
    while(bg_iterator < blockGroupCount)
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
void getGrpDescTable(char driveName[], int blockGroupNo)
{
    long long offset =0;
    FILE* output_file;
    FILE* hex_dump;
    int index;
    char *buff = (char *)malloc(sizeof(struct ext3_group_desc));
    struct ext3_group_desc * gdesc = (struct ext3_group_desc *)malloc(sizeof(struct ext3_group_desc));

    //The different fields in the block group descriptor
    unsigned char block_group_descriptor[8][30] = {"Blocks bitmap block","Inodes bitmap block","Inode table block","Free blocks count","Free inodes count","Used dirs count"/*,"bg_pad","bg_reserved"*/};
    int fd = open(driveName,O_RDONLY);
    if(fd < 0)
    {
        fputs("memory error",stderr);
        exit (2);
    }

    //block group desc table size is one block group desc size(32) * total number of block groups
    int blockGroupTblSize = blockGroupCount * BLOCK_GROUP_DESC_SIZE;
    unsigned char buffer[blockGroupTblSize];

    offset = getGroupDescStartOffset(blockGroupNo);

    //Go to the first block group descriptor in the second block	
    lseek64(fd,offset,SEEK_SET);
	
    //open the file for output writing
    char fileName[15];
    sprintf(fileName, "output%d.txt", blockGroupNo);
    output_file = fopen(fileName,"write");
    //open the file for hex dump
    memset(fileName, 0, sizeof(fileName));
    sprintf(fileName, "hexdump%d.txt", blockGroupNo);
    hex_dump = fopen(fileName, "write");


    //read block group desc table into buffer which will be used for hex dump
    int retVal = read(fd, buffer, blockGroupTblSize);
    if(retVal  <= 0)
    {
        fprintf(stderr, "unable to read disk, retVal = %d\n", retVal);
        return;
    }

    //hex dump i.e 16 bytes in each line
    int byteCount = 0;
    for(index=0;index<blockGroupTblSize;index++)
    {
        fprintf(hex_dump, "%02x ", buffer[index]);
        byteCount++;
        if(byteCount == 16)
        {
            fprintf(hex_dump, "\n");
            byteCount = 0;
        }
    }

    //print the group descriptor field descriptions in the output file
    for(index=0;index<8;++index)
    {
        fprintf(output_file,"%s    ", block_group_descriptor[index]);
    }	

    fprintf(output_file,"\n");
	lseek64(fd,offset,SEEK_SET);

    //iterate through all the group descriptors in the group descriptor table
    int bg_iterator = 0;
    while(bg_iterator < blockGroupCount)
    {
        //read each group descriptor and write it to output file.
        read(fd,buff,sizeof(struct ext3_group_desc));
        memcpy((void *)gdesc,(void *)buff,sizeof(struct ext3_group_desc));
        fprintf(output_file, "%15ld|", gdesc->bg_block_bitmap);
        fprintf(output_file, "%18ld|", gdesc->bg_inode_bitmap);
        fprintf(output_file, "%20ld|", gdesc->bg_inode_table);
        fprintf(output_file, "%22d|", gdesc->bg_free_blocks_count);
        fprintf(output_file, "%18d|", gdesc->bg_free_inodes_count);
        fprintf(output_file, "%16d\n", gdesc->bg_used_dirs_count);
        //fprintf(output_file, "%9d|    ", gdesc->bg_pad);
        //fprintf(output_file, "%ld, %ld, %ld\n", gdesc->bg_reserved[0], gdesc->bg_reserved[1], gdesc->bg_reserved[2]);
        bg_iterator++;
    }
    close(output_file);
}

int main(int argc, char* argv[])
{
    if(argc < 2 || argc > 2)
    {
	    printf("Invalid argument format: Usage %s \\dev\\sdx1\n", argv[0]);
        exit(1);
    }
    char *dName = argv[1];

    int fd = open(argv[1],O_RDONLY);
    if(fd < 0)
    {
        fputs("memory error",stderr); 
        exit (2);
    }
    blockSize = getBlockSize(dName);
    blockGroupCount = getNumberofBlockGroups(dName);
    //getGrpDescTable(dName, 0);
    //getGrpDescTable(dName, 49);
    
    int i, j;
    for(i=0;i<blockGroupCount;++i)
    {
        if(!isPowerOf3_5_7(i))
            continue;
        else
            for(j=i+1;j<blockGroupCount;++j)
            {
                if(isPowerOf3_5_7(j))            
                    printf("The group descriptor table at block groups %2d and %2d are identical  -  %d\n", i,j, compareGrpDesc(i, j, dName));
            }
    }

    return 0;	
}
